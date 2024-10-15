/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| FILE NAME: nsl-tcpcomp-singthr.cpp                                |*/
/*| ----------                                                        |*/
/*|  routines for single-thread TCPCOMP                               |*/
/*|    only for Unix and C++ programs (contains class)                |*/
/*|  03.06.10 KB                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#include <stddef.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "hob-unix01.h"
#include <hob-netw-01.h>
#include <hob-tcpcomp-singthr.hpp>
#ifdef HL_MACOSX
#include <sys/uio.h> /* due to writev() */
#endif

#ifndef HL_UNIX
#define D_TCP_ERROR WSAGetLastError()
#define D_TCP_CLOSE closesocket
//#define D_CHARSET_IP ied_chs_ansi_819       /* ANSI 819                */
#else
#define D_TCP_ERROR errno
#define D_TCP_CLOSE close
//#define D_CHARSET_IP ied_chs_ascii_850      /* ASCII 850               */
#endif

#define DEF_SEND_WRITEV        32           /* for writev()            */

#ifdef TRACEHL1
extern "C" int m_hl1_printf( char *, ... );
static void m_console_out( char *, int );

static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
#endif

enum ied_ret_conn {                         /* returned from TCP connect() */
   ied_rcc_ok,                              /* connect done            */
   ied_rcc_block,                           /* connect is blocking     */
   ied_rcc_error_socket,                    /* error from socket       */
   ied_rcc_needs_bind,                      /* error bind needed       */
   ied_rcc_error_bind,                      /* error from bind         */
   ied_rcc_error_conn                       /* error from connect      */
};

extern "C" BOOL m_poll_arr_add( struct dsd_sithr_poll_1 * );
extern "C" BOOL m_poll_arr_del( struct dsd_sithr_poll_1 * );

static void m_pc_acc_poll( struct dsd_sithr_poll_1 * );
static int m_sub_conn_round_robin( class dsd_tcpcomp * );
static enum ied_ret_conn m_sub_conn_start( class dsd_tcpcomp *, int );
static void m_pc_tc_poll( struct dsd_sithr_poll_1 * );

struct dsd_gather_i_1 {                     /* gather input data       */
   struct dsd_gather_i_1 *adsc_next;        /* next in chain           */
   char *     achc_ginp_cur;                /* current position        */
   char *     achc_ginp_end;                /* end of input data       */
};

/*+-------------------------------------------------------------------+*/
/*| non-blocking accept.                                              |*/
/*+-------------------------------------------------------------------+*/

/** start listen on TCP port                                           */
class dsd_nblock_acc * dsd_nblock_acc::mc_startlisten( int imp_socket,
                                                       struct dsd_acccallback *adsp_callback,
                                                       void * vpp_userfld ) {
   BOOL       bol1;                         /* working variable        */
   class dsd_nblock_acc *adsl_nblock_acc;

#ifdef TRACEHL1
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T called dsd_nblock_acc::mc_startlisten()",
                 __LINE__ );
#endif
   adsl_nblock_acc = new dsd_nblock_acc();
   memset( adsl_nblock_acc, 0, sizeof(class dsd_nblock_acc) );
   adsl_nblock_acc->adsc_callback = adsp_callback;
   adsl_nblock_acc->vpc_userfld = vpp_userfld;
   adsl_nblock_acc->dsc_sithr_poll_1.amc_p_compl_poll = &m_pc_acc_poll;  /* callback event POLL */
   bol1 = m_poll_arr_add( &adsl_nblock_acc->dsc_sithr_poll_1 );
   adsl_nblock_acc->dsc_sithr_poll_1.adsc_pollfd->fd = imp_socket;  /* file descriptor */
   adsl_nblock_acc->dsc_sithr_poll_1.adsc_pollfd->events = POLLIN;
   return adsl_nblock_acc;
} /* end dsd_nblock_acc::mc_startlisten()                              */

/** start listen on TCP port, no allocated memory                      */
int dsd_nblock_acc::mc_startlisten_fix( int imp_socket,
                                        struct dsd_acccallback *adsp_callback,
                                        void * vpp_userfld ) {
   BOOL       bol1;                         /* working variable        */

#ifdef TRACEHL1
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T called dsd_nblock_acc::mc_startlisten_fix()",
                 __LINE__ );
#endif
   memset( this, 0, sizeof(class dsd_nblock_acc) );
   this->adsc_callback = adsp_callback;
   this->vpc_userfld = vpp_userfld;
   this->dsc_sithr_poll_1.amc_p_compl_poll = &m_pc_acc_poll;  /* callback event POLL */
   bol1 = m_poll_arr_add( &this->dsc_sithr_poll_1 );
// to-do 19.09.11 KB check return code
   this->dsc_sithr_poll_1.adsc_pollfd->fd = imp_socket;  /* file descriptor */
   this->dsc_sithr_poll_1.adsc_pollfd->events = POLLIN;
   return 0;
} /* end dsd_nblock_acc::mc_startlisten_fix()                          */

/** stop listen, no allocated memory                                   */
int dsd_nblock_acc::mc_stoplistener_fix( void ) {
   int        iml_rc;                       /* return code             */
   BOOL       bol1;                         /* working variable        */

#ifdef TRACEHL1
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T called dsd_nblock_acc::mc_stoplistener_fix()",
                 __LINE__ );
#endif
   iml_rc = close( this->dsc_sithr_poll_1.adsc_pollfd->fd );
// to-do 22.09.11 KB check error
// if (iml_rc != 0) {                       /* error occured           */
//   adsc_callback->amc_errorcallback(this, vpc_userfld, (char*)"Error closing socket", errno, ERRORAT_ENDSESSION); // AGAG
// }
   bol1 = m_poll_arr_del( &this->dsc_sithr_poll_1 );
// to-do 19.09.11 KB check return code
   return 0;
} /* end dsd_nblock_acc::mc_stoplistener_fix()                         */

/** callback event POLL for accept                                     */
static void m_pc_acc_poll( struct dsd_sithr_poll_1 *adsp_sp1 ) {
   int        iml_socket_client;
   socklen_t  iml_len_soa;
   class dsd_nblock_acc *adsl_nblock_acc;
   struct sockaddr_storage dsl_soa;

#ifdef TRACEHL1
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T called m_pc_acc_poll()",
                 __LINE__ );
#endif
   if ((adsp_sp1->adsc_pollfd->revents & POLLIN) == 0) {
#ifdef TRACEHL1
     m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T called m_pc_acc_poll() revents=0X%08X.",
                   __LINE__, adsp_sp1->adsc_pollfd->revents );
#endif
     return;
   }
// adsp_sp1->adsc_pollfd->revents = 0;
   /* POLLIN for accept                                                */
   adsl_nblock_acc = (class dsd_nblock_acc *) ((char *) adsp_sp1 - offsetof( class dsd_nblock_acc, dsc_sithr_poll_1 ));
   memset( &dsl_soa, 0, sizeof(struct sockaddr_storage) );
   iml_len_soa = sizeof(struct sockaddr_storage);
   iml_socket_client = accept( adsl_nblock_acc->dsc_sithr_poll_1.adsc_pollfd->fd, (struct sockaddr *) &dsl_soa, &iml_len_soa );
   if (iml_socket_client < 0) {             /* error occured           */
// to-do 04.06.10 KB call error routine
     return;
   }
   adsl_nblock_acc->adsc_callback->amc_acceptcallback( adsl_nblock_acc,
                                     adsl_nblock_acc->vpc_userfld,
                                     iml_socket_client,
                                     (struct sockaddr *) &dsl_soa,
                                     iml_len_soa );
} /* end m_pc_acc_poll()                                               */

/*+-------------------------------------------------------------------+*/
/*| TCPCOMP - non-blocking TCP connection.                            |*/
/*+-------------------------------------------------------------------+*/

/** start TCPCOMP - TCP connection management                          */
int dsd_tcpcomp::m_startco_fb( int imp_socket, struct dsd_tcpcallback *adsp_callback, void * vpp_userfld ) {
   int        iml1;                         /* working variable        */
   BOOL       bol1;                         /* working variable        */

#ifdef TRACEHL1
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T called dsd_tcpcomp::m_startco_fb()",
                 __LINE__ );
#endif
   /* set to non-blocking I/O                                          */
   iml1 = fcntl( imp_socket, F_GETFL, 0 );
   fcntl( imp_socket, F_SETFL, iml1 | O_NONBLOCK );

   this->boc_cb_active = FALSE;             /* callback routine is active */
   this->boc_do_close = FALSE;              /* do close                */
#ifdef D_INCL_UNIX_SOCKET
   this->boc_unix_socket = FALSE;           /* is not Unix socket      */
#endif
   this->adsc_callback = adsp_callback;
   this->vpc_userfld = vpp_userfld;
   this->imc_conn_no = -1;                  /* number of connect       */
   memset( &this->dsc_sithr_poll_1, 0, sizeof(struct dsd_sithr_poll_1) );  /* single thread poll structure */
   this->dsc_sithr_poll_1.amc_p_compl_poll = &m_pc_tc_poll;  /* callback event POLL */
   bol1 = m_poll_arr_add( &this->dsc_sithr_poll_1 );
   if (bol1 == FALSE) return -1;            /* return error            */
   this->dsc_sithr_poll_1.adsc_pollfd->fd = imp_socket;  /* file descriptor */
   return 0;                                /* all done                */
} /* end dsd_tcpcomp::m_startco_fb()                                   */

#ifdef D_INCL_UNIX_SOCKET
/** start TCPCOMP - Unix socket connection, no allocated memory        */
int dsd_tcpcomp::m_startco_unix_socket_fix( int imp_socket, struct dsd_tcpcallback *adsp_callback, void * vpp_userfld ) {
   int        iml1;                         /* working variable        */
   BOOL       bol1;                         /* working variable        */

#ifdef TRACEHL1
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T called dsd_tcpcomp::m_startco_unix_socket_fix()",
                 __LINE__ );
#endif
   /* set to non-blocking I/O                                          */
   iml1 = fcntl( imp_socket, F_GETFL, 0 );
   fcntl( imp_socket, F_SETFL, iml1 | O_NONBLOCK );

   this->boc_cb_active = FALSE;             /* callback routine is active */
   this->boc_do_close = FALSE;              /* do close                */
   this->boc_unix_socket = TRUE;            /* is Unix socket          */
   this->adsc_callback = adsp_callback;
   this->vpc_userfld = vpp_userfld;
   this->imc_conn_no = -1;                  /* number of connect       */
   memset( &this->dsc_sithr_poll_1, 0, sizeof(struct dsd_sithr_poll_1) );  /* single thread poll structure */
   this->dsc_sithr_poll_1.amc_p_compl_poll = &m_pc_tc_poll;  /* callback event POLL */
   bol1 = m_poll_arr_add( &this->dsc_sithr_poll_1 );
   if (bol1 == FALSE) return -1;            /* return error            */
   this->dsc_sithr_poll_1.adsc_pollfd->fd = imp_socket;  /* file descriptor */
   return 0;                                /* all done                */
} /* end dsd_tcpcomp::m_startco_unix_socket_fix()                      */
#endif

/** start TCPCOMP with connect multi-homed, multiple targets           */
int dsd_tcpcomp::m_startco_mh( struct dsd_tcpcallback *adsp_callback,
                               void * vpp_userfld,
                               const struct dsd_bind_ineta_1 *adsp_bind_ineta,
                               const struct dsd_target_ineta_1 *adsp_target_ineta,
#ifndef B130807
                               const void * ap_free_ti1,
#endif
                               unsigned short usp_port,
                               BOOL bop_round_robin ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
// int        iml_rc;
   enum ied_ret_conn iel_rcc;               /* returned from TCP connect() */

#ifdef TRACEHL1
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T dsd_tcpcomp::m_startco_mh( ... , ... , adsp_target_ineta=%p , ... , ... , ... ) called",
                 __LINE__, adsp_target_ineta );
   if (adsp_target_ineta) {
     m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T adsp_target_ineta=%p ...->imc_no_ineta=%d.",
                   __LINE__, adsp_target_ineta, adsp_target_ineta->imc_no_ineta );
   }
#endif
   this->boc_cb_active = FALSE;             /* callback routine is active */
   this->boc_do_close = FALSE;              /* do close                */
#ifdef D_INCL_UNIX_SOCKET
   this->boc_unix_socket = FALSE;           /* is not Unix socket      */
#endif
   this->adsc_callback = adsp_callback;
   this->vpc_userfld = vpp_userfld;
   this->adsc_target_ineta = (struct dsd_target_ineta_1 *) adsp_target_ineta;
#ifndef B130807
   this->ac_free_ti1 = ap_free_ti1;
#endif
   this->adsc_bind_ineta = (struct dsd_bind_ineta_1 *) adsp_bind_ineta;
   this->usc_port = usp_port;
   this->boc_round_robin = bop_round_robin;
   if (   (this->ilc_used_round_robin)
       && (   (this->adsc_callback->amc_get_random_number == NULL)
           || (this->adsc_target_ineta->imc_no_ineta > (sizeof(this->ilc_used_round_robin) * 8)))) {
// to-do 15.06.10 KB warning or error message ???
     this->ilc_used_round_robin = FALSE;
   }
   this->imc_conn_no = 0;                   /* number of connect       */
   memset( &this->dsc_sithr_poll_1, 0, sizeof(struct dsd_sithr_poll_1) );  /* single thread poll structure */
   this->dsc_sithr_poll_1.amc_p_compl_poll = &m_pc_tc_poll;  /* callback event POLL */
   bol1 = m_poll_arr_add( &this->dsc_sithr_poll_1 );
// to-do 14.06.10 KB call error routine
   if (bol1 == FALSE) return 1;
   this->dsc_sithr_poll_1.adsc_pollfd->events = POLLIN | POLLOUT;
   iml1 = 0;                                /* start first INETA       */
   if (this->boc_round_robin) {             /* connect round robin     */
     this->ilc_used_round_robin = 0;        /* used bits round robin   */
     iml1 = m_sub_conn_round_robin( this );
   }
   iel_rcc = m_sub_conn_start( this, iml1 );
   switch (iel_rcc) {                       /* returned from TCP connect() */
     case ied_rcc_ok:                       /* connect done            */
       adsc_callback->amc_conncallback( this,
                                        vpc_userfld,
#ifndef B130807
                                        this->adsc_target_ineta,
                                        (void *) this->ac_free_ti1,
#endif
                                        (struct sockaddr *) &dsc_soa_conn, imc_len_soa_conn, 0 );
       return 0;                            /* return success, no error */
     case ied_rcc_block:                    /* connect is blocking     */
       return 0;                            /* return success, no error */
   }
   bol1 = m_poll_arr_del( &this->dsc_sithr_poll_1 );
/*   if (bol1 == FALSE)
	   adsc_callback->amc_errorcallback */
// to-do 14.06.10 KB check error
   return 1;
} /* end dsd_tcpcomp::m_startco_mh()                                   */

/** start or continue receiving on TCPCOMP managed TCP connection      */
int dsd_tcpcomp::m_recv( void ) {           /* start receiving again   */
#ifdef TRACEHL1
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T called dsd_tcpcomp::m_recv()",
                 __LINE__ );
#endif
   this->dsc_sithr_poll_1.adsc_pollfd->events |= POLLIN;
   return 0;
} /* end dsd_tcpcomp::m_recv()                                         */

/** send data in gather structures                                     */
int dsd_tcpcomp::m_send_gather( struct dsd_gather_i_1 *adsp_gai1_inp,
                                struct dsd_gather_i_1 **aadsp_gai1_out, int *aimp_rc ) {
   int        iml1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   int        iml_no_iov;                   /* number of vectors       */
   int        iml_sent;                     /* count data sent         */
   struct dsd_gather_i_1 *adsl_gai1_inp;    /* input data to be sent   */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* gather input data       */
   struct iovec dsrl_iov[ DEF_SEND_WRITEV ];

   adsl_gai1_inp = adsp_gai1_inp;           /* get input data to be sent */
   iml_sent = 0;                            /* count data sent         */
   if (aimp_rc) *aimp_rc = 0;

   p_send_20:                               /* check if something to send */
   if (adsl_gai1_inp == NULL) {             /* no gather data to send */
     if (aadsp_gai1_out) *aadsp_gai1_out = NULL;
     return iml_sent;
   }
   adsl_gai1_w1 = adsl_gai1_inp;            /* get gather data to send */
   iml_no_iov = 0;                          /* number of vectors       */
   do {
     if (iml_no_iov >= DEF_SEND_WRITEV) break;  /* array already filled */
     if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
       memset( &dsrl_iov[ iml_no_iov ], 0, sizeof(struct iovec) );
       dsrl_iov[ iml_no_iov ].iov_base = adsl_gai1_w1->achc_ginp_cur;
       dsrl_iov[ iml_no_iov ].iov_len
         = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
       iml_no_iov++;                        /* increment number of vectors */
     }
     adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain     */
   } while (adsl_gai1_w1);
   if (iml_no_iov == 0) {                   /* check number of vectors */
     if (aadsp_gai1_out) *aadsp_gai1_out = NULL;
     return iml_sent;
   }
   iml_rc = writev( this->dsc_sithr_poll_1.adsc_pollfd->fd, dsrl_iov, iml_no_iov );
   if (iml_rc < 0) {                        /* error occured           */
#ifdef TRACEHL1
     iml1 = errno;                          /* save errno              */
     m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T dsd_tcpcomp::m_send_gather() writev() returned %d/%d.",
                   __LINE__, iml_rc, iml1 );
     errno = iml1;                          /* restore errno           */
#endif
     if (errno == EAGAIN) {
       if (aadsp_gai1_out) *aadsp_gai1_out = adsl_gai1_inp;
       return iml_sent;
     }
#ifdef XYZ1
// to-do 05.06.10 KB - call error routine - AGAG
     adsc_callback->amc_errorcallback(this, vpc_userfld, "Unable to send data", errno, ERRORAT_SEND); // AGAG
     printf( "nbtrdps6-%05d-W TCP send writev() failed rc=%d errno=%d\n",
             __LINE__, iml_rc, D_TCP_ERROR );
     adsl_gai1_inp = NULL;                  /* clear gather data to send */
#endif
     return iml_sent;
   }
   iml_sent += iml_rc;                      /* count data sent         */
#ifdef XYZ1
   dsrs_poll[ D_POLL_CLIENT ].events &= -1 - POLLOUT;
#endif
   while (TRUE) {
     iml1 = adsl_gai1_inp->achc_ginp_end
              - adsl_gai1_inp->achc_ginp_cur;
     if (iml1 > iml_rc) break;              /* gather not totally sent */
     adsl_gai1_inp->achc_ginp_cur = adsl_gai1_inp->achc_ginp_end;
     adsl_gai1_inp = adsl_gai1_inp->adsc_next;  /* remove from chain   */
     iml_rc -= iml1;
     if (iml_rc == 0) goto p_send_20;       /* check if something to send */
   }
   adsl_gai1_inp->achc_ginp_cur += iml_rc;  /* add part send */
   goto p_send_20;                          /* check if something to send */
} /* end dsd_tcpcomp::m_send_gather()                                  */

/** set notify when sending is possible again                          */
void dsd_tcpcomp::m_sendnotify( void ) {
   this->dsc_sithr_poll_1.adsc_pollfd->events |= POLLOUT;
} /* end dsd_tcpcomp::m_sendnotify()                                   */

/** end of TCPCOMP managed TCP session                                 */
void dsd_tcpcomp::m_end_session( void ) {
   int        iml_rc;                       /* return code             */
   BOOL       bol1;                         /* working variable        */

#ifdef TRACEHL1
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T called dsd_tcpcomp::m_end_session() this=%p.",
                 __LINE__, this );
#endif
   this->boc_do_close = TRUE;               /* do close                */
   if (this->boc_cb_active) return;         /* callback routine is active */
   iml_rc = close( this->dsc_sithr_poll_1.adsc_pollfd->fd );
// to-do 05.06.10 KB check error
   if (iml_rc != 0) {                       /* error occured           */
     adsc_callback->amc_errorcallback(this, vpc_userfld, (char*)"Error closing socket", errno, ERRORAT_ENDSESSION); // AGAG
   }
   bol1 = m_poll_arr_del( &this->dsc_sithr_poll_1 );
// to-do 05.06.10 KB check error
   this->adsc_callback->amc_cleanup( this,
                                     this->vpc_userfld );
} /* end dsd_tcpcomp::m_end_session()                                  */

/** do connect round-robin                                             */
static int m_sub_conn_round_robin( class dsd_tcpcomp *adsp_tcpcomp ) {
   int        iml1, iml2;                   /* working variables       */

   /* compute remaining number of connects to be done                  */
   iml1 = adsp_tcpcomp->adsc_target_ineta->imc_no_ineta
            - adsp_tcpcomp->imc_conn_no;
   if (iml1 <= 1) {
     iml1 = 0;                              /* take first one          */
   } else {
     iml1 = adsp_tcpcomp->adsc_callback->amc_get_random_number( iml1 );
   }
   iml2 = 0;                                /* clear index             */
   while (TRUE) {
     if ((adsp_tcpcomp->ilc_used_round_robin & (((HL_LONGLONG) 1) << iml2)) == 0) {  /* connect round robin */
       if (iml1 <= 0) {                     /* we use this entry       */
         adsp_tcpcomp->ilc_used_round_robin |= ((HL_LONGLONG) 1) << iml2;  /* set bit this entry used */
         return iml2;                       /* connect to this entry   */
       }
       iml1--;                              /* decrement index         */
     }
     iml2++;                                /* check next bit          */
   }
   /* program should never come here                                   */
   return 0;                                /* for compiler only       */
} /* m_sub_conn_round_robin()                                          */

/** start connect                                                      */
static enum ied_ret_conn m_sub_conn_start( class dsd_tcpcomp *adsp_tcpcomp, int imp_no_ineta ) {
   int        iml1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
#ifdef TRACEHL1
   int        iml_save_errno;               /* save errno              */
#endif
   int        iml_socket;
   int        iml_count;                    /* count entries           */
   int        iml_bindlen;                  /* length sockaddr bind    */
   struct sockaddr *adsl_soa_bind;          /* address information for bind */
   struct dsd_ineta_single_1 *adsl_ineta_s_w1;  /* single INETA target */

#ifdef TRACEHL1
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T called m_sub_conn_start( adsp_tcpcomp=%p , imp_no_ineta=%d )",
                 __LINE__, adsp_tcpcomp, imp_no_ineta );
   if (adsp_tcpcomp->adsc_target_ineta) {
     m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T adsp_tcpcomp->adsc_target_ineta=%p ...->imc_no_ineta=%d.",
                   __LINE__, adsp_tcpcomp->adsc_target_ineta, adsp_tcpcomp->adsc_target_ineta->imc_no_ineta );
   }
#endif
#ifdef XYZ1
   if (adsp_tcpcomp->imc_conn_no >= adsp_tcpcomp->adsc_target_ineta->imc_no_ineta) {  /* number of connect */
     return 1;
   }
#endif
   iml_count = 0;                           /* clear count entries     */
   adsl_ineta_s_w1 = (struct dsd_ineta_single_1 *) (adsp_tcpcomp->adsc_target_ineta + 1);
   while (iml_count < imp_no_ineta) {       /* overread members before */
     adsl_ineta_s_w1
       = (struct dsd_ineta_single_1 *)
           ((char *) (adsl_ineta_s_w1 + 1) + adsl_ineta_s_w1->usc_length);
     iml_count++;                           /* count entry             */
   }
#ifdef TRACEHL1
   m_console_out( (char *) adsl_ineta_s_w1,
                  sizeof(struct dsd_ineta_single_1) + adsl_ineta_s_w1->usc_length );
#endif
// memset( &adsp_tcpcomp->dsc_soa_conn, 0, sizeof(struct sockaddr) );
   memset( &adsp_tcpcomp->dsc_soa_conn, 0, sizeof(struct sockaddr_storage) );
   ((struct sockaddr *) &adsp_tcpcomp->dsc_soa_conn)->sa_family = adsl_ineta_s_w1->usc_family;
   iml_bindlen = 0;                         /* length sockaddr bind    */
   switch (adsl_ineta_s_w1->usc_family) {
     case AF_INET:
       *((UNSIG_MED *) &(((struct sockaddr_in *) &adsp_tcpcomp->dsc_soa_conn)->sin_addr))
         = *((UNSIG_MED *) (adsl_ineta_s_w1 + 1));
       adsp_tcpcomp->imc_len_soa_conn = sizeof(struct sockaddr_in);
       ((struct sockaddr_in *) &adsp_tcpcomp->dsc_soa_conn)->sin_port = htons( adsp_tcpcomp->usc_port );
       if (adsp_tcpcomp->adsc_bind_ineta == NULL) break;
       if (adsp_tcpcomp->adsc_bind_ineta->boc_bind_needed == FALSE) break;  /* flag bind() is needed */
       if (adsp_tcpcomp->adsc_bind_ineta->boc_ipv4 == FALSE) return ied_rcc_needs_bind;  /* IPV4 is not supported */
       adsl_soa_bind = (struct sockaddr *) &adsp_tcpcomp->adsc_bind_ineta->dsc_soai4;
       iml_bindlen = sizeof(struct sockaddr_in);
       break;
     case AF_INET6:
       memcpy( &((struct sockaddr_in6 *) &adsp_tcpcomp->dsc_soa_conn)->sin6_addr,
               adsl_ineta_s_w1 + 1,
               16 );
       adsp_tcpcomp->imc_len_soa_conn = sizeof(struct sockaddr_in6);
       ((struct sockaddr_in6 *) &adsp_tcpcomp->dsc_soa_conn)->sin6_port = htons( adsp_tcpcomp->usc_port );
       if (adsp_tcpcomp->adsc_bind_ineta == NULL) break;
       if (adsp_tcpcomp->adsc_bind_ineta->boc_bind_needed == FALSE) break;  /* flag bind() is needed */
       if (adsp_tcpcomp->adsc_bind_ineta->boc_ipv6 == FALSE) return ied_rcc_needs_bind;  /* IPV6 is not supported */
       adsl_soa_bind = (struct sockaddr *) &adsp_tcpcomp->adsc_bind_ineta->dsc_soai6;
       iml_bindlen = sizeof(struct sockaddr_in6);
       break;
   }
   iml_socket = socket( adsl_ineta_s_w1->usc_family, SOCK_STREAM, IPPROTO_TCP );
   if (iml_socket < 0) {
     adsp_tcpcomp->adsc_callback->amc_errorcallback(adsp_tcpcomp, adsp_tcpcomp->vpc_userfld, (char*)"Error creating socket", errno, ERRORAT_STARTCONN); // AGAG

#ifdef TRACEHL1
     m_hl1_printf( "nsl-tcpcomp-singthr-%05d-E socket() failed with code %d %d.",
                   __LINE__, iml_socket, D_TCP_ERROR );
#endif
     return ied_rcc_error_socket;           /* error from socket       */
   }
   if (iml_bindlen) {                       /* with bind               */
#ifdef TRACEHL1
     m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T m_sub_conn_start() iml_bindlen=%d.",
                   __LINE__, iml_bindlen );
     m_console_out( (char *) adsl_soa_bind, iml_bindlen );
#endif
     iml_rc = bind( iml_socket, adsl_soa_bind, iml_bindlen );
     if (iml_rc != 0) {                     /* error occured           */
// to-do 15.06.10 KB call error routine
#ifdef TRACEHL1
       m_hl1_printf( "nsl-tcpcomp-singthr-%05d-W bind GW-OUT Error %d %d",
                     __LINE__, iml_rc, D_TCP_ERROR );
#endif
       D_TCP_CLOSE( iml_socket );           /* close socket again      */
       return ied_rcc_error_bind;           /* error from bind         */
     }
   }
   adsp_tcpcomp->dsc_sithr_poll_1.adsc_pollfd->fd = iml_socket;
#ifndef TRY_BLOCKING_CONNECT
   /* set to non-blocking I/O                                          */
   iml1 = fcntl( iml_socket, F_GETFL, 0 );
   fcntl( iml_socket, F_SETFL, iml1 | O_NONBLOCK );
#endif
#ifdef TRACEHL1
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T m_sub_conn_start() adsp_tcpcomp->imc_len_soa_conn=%d.",
                 __LINE__, adsp_tcpcomp->imc_len_soa_conn );
   m_console_out( (char *) &adsp_tcpcomp->dsc_soa_conn, adsp_tcpcomp->imc_len_soa_conn );
#endif
   iml_rc = connect( iml_socket,
                     (struct sockaddr *) &adsp_tcpcomp->dsc_soa_conn, adsp_tcpcomp->imc_len_soa_conn );
#ifdef TRACEHL1
   iml_save_errno = errno;                  /* save errno              */
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T m_sub_conn_start() after connect() fd=%d iml_rc=%d errno=%d.",
                 __LINE__, iml_socket, iml_rc, iml_save_errno );
   errno = iml_save_errno;                  /* restore errno           */
#endif
   if (iml_rc == 0) return ied_rcc_ok;      /* connect done            */
   if (errno == EINPROGRESS) return ied_rcc_block;  /* connect is blocking */
#ifdef TRACEHL1
   iml_save_errno = errno;
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-W connect() Error %d %d.",
                 __LINE__, iml_rc, D_TCP_ERROR );
   errno = iml_save_errno;                  /* restore errno           */
#endif
   adsp_tcpcomp->adsc_callback->amc_connerrcallback( adsp_tcpcomp, adsp_tcpcomp->vpc_userfld,
                                                     (struct sockaddr *) &adsp_tcpcomp->dsc_soa_conn,
                                                     adsp_tcpcomp->imc_len_soa_conn,
                                                     adsp_tcpcomp->imc_conn_no, adsp_tcpcomp->adsc_target_ineta->imc_no_ineta, errno );
   D_TCP_CLOSE( iml_socket );               /* close socket again      */
   return ied_rcc_error_conn;               /* error from connect      */
} /* end m_sub_conn_start()                                            */

#ifdef D_INCL_UNIX_SOCKET
/** retrieve file-descriptor passed with last message received over Unix socket connection */
int dsd_tcpcomp::m_get_unix_socket_fd( void ) {
#ifdef MSGHDR_CONTROL_AVAILABLE
   struct cmsghdr *adsl_cmd;
#endif

#ifdef MSGHDR_CONTROL_AVAILABLE
   adsl_cmd = CMSG_FIRSTHDR( &this->dsc_msghdr );
   if (   (adsl_cmd == NULL)
       || (adsl_cmd->cmsg_len != CMSG_LEN(sizeof(int)))
       || (adsl_cmd->cmsg_level != SOL_SOCKET)
       || (adsl_cmd->cmsg_type != SCM_RIGHTS)) {
#ifdef XYZ1
     m_hlnew_printf( HLOG_WARN1, "HWSPM167W nbipgw20 l%05d listen-gateway recvmsg() no descriptor in message",
                     __LINE__ );
#endif
     return -1;                             /* return error            */
   }
   return *((int *) CMSG_DATA( adsl_cmd ));
#else
   if (this->dsc_msghdr.msg_accrightslen != sizeof(int)) {
#ifdef XYZ1
     m_hlnew_printf( HLOG_WARN1, "HWSPM167W nbipgw20 l%05d listen-gateway recvmsg() no descriptor in message",
                     __LINE__ );
#endif
     return -1;                             /* return error            */
   }
   return this->imc_msg_fd;                 /* file-descriptor received */
#endif
} /* end m_get_unix_socket_fd()                                        */
#endif

/** callback event POLL for TCPCOMP                                    */
static void m_pc_tc_poll( struct dsd_sithr_poll_1 *adsp_sp1 ) {
   void *     vpl_handle;                   /* handle to receive buffer */
   char       *achl_buffer;                 /* receive buffer          */
   int        *aiml_datalen;                /* length of data received */
   int        iml_bufferlen;                /* maximum length to receive */
   int        iml_received;                 /* number of bytes received with one recv */
   int        iml_cont;                     /* if continue receive     */
   int        iml_rc;                       /* return code             */
#ifdef XYZ1
   BOOL       bol_close;                    /* has to do close         */
   BOOL       bol1;                         /* working variable        */
#endif
   BOOL       bol1;                         /* working variable        */
#ifdef TRACEHL1
   int        iml_save_errno;               /* save errno              */
#endif
   int        iml1;                         /* working variable        */
   enum ied_ret_conn iel_rcc;               /* returned from TCP connect() */
   class dsd_tcpcomp *adsl_tcpcomp;
#ifdef D_INCL_UNIX_SOCKET
   struct iovec dsrl_iov[1];                /* vector containing send data */
#ifdef MSGHDR_CONTROL_AVAILABLE
   union {
     struct cmsghdr dsc_msg;
     char chrc_control[ CMSG_SPACE(sizeof(int)) ];
   } dsl_control_un;
   struct cmsghdr *adsl_cmd;
#endif
#endif

#ifdef TRACEHL1
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T called m_pc_tc_poll( adsp_sp1=%p )",
                 __LINE__, adsp_sp1 );
#endif
   adsl_tcpcomp = (class dsd_tcpcomp *) ((char *) adsp_sp1 - offsetof( class dsd_tcpcomp, dsc_sithr_poll_1 ));
   if ((adsp_sp1->adsc_pollfd->revents & POLLIN) == 0) {
     goto p_pollout_00;                     /* process POLLOUT         */
   }
   if (adsl_tcpcomp->imc_conn_no >= 0) {    /* number of connect valid */
     goto p_pollout_00;                     /* process POLLOUT         */
   }

   /* POLLIN is for receive                                            */
   /* get receive buffer from application                              */
   iml_bufferlen = adsl_tcpcomp->adsc_callback->amc_getrecvbuf( adsl_tcpcomp,
                                                                adsl_tcpcomp->vpc_userfld,
                                                                &vpl_handle,
                                                                &achl_buffer,
                                                                &aiml_datalen );
   if (iml_bufferlen <= 0) {                /* no buffer available     */
// to-do 04.06.10 KB error message
      adsl_tcpcomp->adsc_callback->amc_errorcallback(adsl_tcpcomp, adsl_tcpcomp->vpc_userfld, (char*)"Did not get receive buffer", 0, ERRORAT_RECV); // AGAG

     /* stop receiving more events                                     */
     adsl_tcpcomp->dsc_sithr_poll_1.adsc_pollfd->events &= -1 - POLLIN;
     return;
   }
#ifdef D_INCL_UNIX_SOCKET
   if (adsl_tcpcomp->boc_unix_socket == FALSE) {  /* is not Unix socket */
     goto p_recv_20;                        /* receive normal          */
   }
#ifdef MSGHDR_CONTROL_AVAILABLE
   adsl_tcpcomp->dsc_msghdr.msg_control = dsl_control_un.chrc_control;
   adsl_tcpcomp->dsc_msghdr.msg_controllen = sizeof(dsl_control_un.chrc_control);
#else
   adsl_tcpcomp->imc_msg_fd = -1;           /* file-descriptor received invalid */
   adsl_tcpcomp->dsc_msghdr.msg_accrights = (caddr_t) &adsl_tcpcomp->imc_msg_fd;
   adsl_tcpcomp->dsc_msghdr.msg_accrightslen = sizeof(int);
#endif
   adsl_tcpcomp->dsc_msghdr.msg_name = NULL;
   adsl_tcpcomp->dsc_msghdr.msg_namelen = 0;
   dsrl_iov[0].iov_base = achl_buffer;
   dsrl_iov[0].iov_len = iml_bufferlen;
   adsl_tcpcomp->dsc_msghdr.msg_iov = dsrl_iov;
   adsl_tcpcomp->dsc_msghdr.msg_iovlen = 1;

   iml_received = recvmsg( adsl_tcpcomp->dsc_sithr_poll_1.adsc_pollfd->fd, &adsl_tcpcomp->dsc_msghdr, 0 );
   goto p_recv_40;                          /* after receive           */

   p_recv_20:                               /* receive normal          */
#endif
   iml_received = recv( adsl_tcpcomp->dsc_sithr_poll_1.adsc_pollfd->fd,
                        achl_buffer, iml_bufferlen,
                        0 );

#ifdef D_INCL_UNIX_SOCKET
   p_recv_40:                               /* after receive           */
#endif
   *aiml_datalen = iml_received;            /* pass length received    */
   if (iml_received <= 0) {                 /* error occured           */
     adsl_tcpcomp->boc_do_close = TRUE;     /* do close                */
     if (iml_received < 0) {
       adsl_tcpcomp->adsc_callback->amc_errorcallback(adsl_tcpcomp, adsl_tcpcomp->vpc_userfld, "Error receiving data", errno, ERRORAT_RECV); // AGAG
     }
// to-do 04.06.10 KB error message
#ifdef XYZ1
     bol_close = TRUE;                      /* has to do close         */
     /* stop receiving more events                                     */
#endif
   }
   adsl_tcpcomp->dsc_sithr_poll_1.adsc_pollfd->events &= -1 - POLLIN;
   adsl_tcpcomp->boc_cb_active = TRUE;      /* callback routine is active */
   iml_cont = adsl_tcpcomp->adsc_callback->amc_recvcallback( adsl_tcpcomp,
                                                             adsl_tcpcomp->vpc_userfld,
                                                             vpl_handle );
#ifdef B110912
   if (iml_received <= 0) {                 /* connected has ended     */
     iml_rc = close( adsl_tcpcomp->dsc_sithr_poll_1.adsc_pollfd->fd );
     if (iml_rc != 0) {                     /* error occured           */
       adsl_tcpcomp->adsc_callback->amc_errorcallback( adsl_tcpcomp,
                                                       adsl_tcpcomp->vpc_userfld,
                                                       (char *) "Error closing socket",
                                                       errno,
                                                       ERRORAT_RECV ); // AGAG
     }
     bol1 = m_poll_arr_del( &adsl_tcpcomp->dsc_sithr_poll_1 );
// to-do 05.06.10 KB check error
     adsl_tcpcomp->adsc_callback->amc_cleanup( adsl_tcpcomp,
                                               adsl_tcpcomp->vpc_userfld );
     return;                                /* no more to do           */
   }
#endif
   if (adsl_tcpcomp->boc_do_close) {        /* do close                */
     iml_rc = close( adsl_tcpcomp->dsc_sithr_poll_1.adsc_pollfd->fd );
     if (iml_rc != 0) {                     /* error occured           */
       adsl_tcpcomp->adsc_callback->amc_errorcallback( adsl_tcpcomp,
                                                       adsl_tcpcomp->vpc_userfld,
                                                       (char *) "Error closing socket",
                                                       errno,
                                                       ERRORAT_RECV ); // AGAG
     }
     bol1 = m_poll_arr_del( &adsl_tcpcomp->dsc_sithr_poll_1 );
// to-do 05.06.10 KB check error
     adsl_tcpcomp->adsc_callback->amc_cleanup( adsl_tcpcomp,
                                               adsl_tcpcomp->vpc_userfld );
     return;                                /* no more to do           */
   }
   adsl_tcpcomp->boc_cb_active = FALSE;     /* callback routine is active */
   if (iml_cont) {                          /* continue receiving      */
     adsl_tcpcomp->dsc_sithr_poll_1.adsc_pollfd->events |= POLLIN;
   }
#ifdef XYZ1
   if (bol_close == FALSE) return;          /* has to do close         */
#ifdef TRACEHL1
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T m_pc_tc_pollin() close TCP connection",
                 __LINE__ );
#endif
   iml_rc = close( adsl_tcpcomp->dsc_sithr_poll_1.adsc_pollfd->fd );
   if (iml_rc != 0)
		adsl_tcpcomp->adsc_callback->amc_errorcallback(adsl_tcpcomp, adsl_tcpcomp->vpc_userfld, (char*)"Error closing socket", errno, ERRORAT_RECV); // AGAG
// to-do 05.06.10 KB check error
   bol1 = m_poll_arr_del( &adsl_tcpcomp->dsc_sithr_poll_1 );
// to-do 05.06.10 KB check error
   adsl_tcpcomp->adsc_callback->amc_cleanup( adsl_tcpcomp,
                                             adsl_tcpcomp->vpc_userfld );
#endif

   p_pollout_00:                            /* process POLLOUT         */
   if ((adsp_sp1->adsc_pollfd->revents & (POLLOUT | POLLERR)) == 0) {
     return;                                /* nothing to do           */
   }
#ifdef TRACEHL1
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T m_pc_tc_poll() p_pollout_00",
                 __LINE__ );
#endif
   if (adsl_tcpcomp->imc_conn_no < 0) {     /* number of connect not valid */
     goto p_pollout_20;                     /* POLLOUT is for send     */
   }
   iml_rc = connect( adsl_tcpcomp->dsc_sithr_poll_1.adsc_pollfd->fd,
                     (struct sockaddr *) &adsl_tcpcomp->dsc_soa_conn, adsl_tcpcomp->imc_len_soa_conn );
#ifdef TRACEHL1
   iml_save_errno = errno;                  /* save errno              */
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T after connect() iml_rc=%d errno=%d.",
                 __LINE__, iml_rc, errno );
   errno = iml_save_errno;                  /* restore errno           */
#endif
   if (iml_rc == 0) {                       /* connect succeeded       */
#ifdef B130807
     adsl_tcpcomp->adsc_callback->amc_conncallback( adsl_tcpcomp,
                                                    adsl_tcpcomp->vpc_userfld,
                                                    (struct sockaddr *) &adsl_tcpcomp->dsc_soa_conn,
                                                    adsl_tcpcomp->imc_len_soa_conn, 0 );
#else
     adsl_tcpcomp->adsc_callback->amc_conncallback( adsl_tcpcomp,
                                                    adsl_tcpcomp->vpc_userfld,
                                                    adsl_tcpcomp->adsc_target_ineta,
                                                    (void *) adsl_tcpcomp->ac_free_ti1,
                                                    (struct sockaddr *) &adsl_tcpcomp->dsc_soa_conn,
                                                    adsl_tcpcomp->imc_len_soa_conn, 0 );
#endif
     adsl_tcpcomp->imc_conn_no = -1;        /* number of connect       */
     return;                                /* all done                */
   }
p_pollout_14:	
   adsl_tcpcomp->adsc_callback->amc_connerrcallback( adsl_tcpcomp,
                                                     adsl_tcpcomp->vpc_userfld,
                                                     (struct sockaddr *) &adsl_tcpcomp->dsc_soa_conn,
                                                     adsl_tcpcomp->imc_len_soa_conn,
                                                     adsl_tcpcomp->imc_conn_no,  /* number of connect */
                                                     adsl_tcpcomp->adsc_target_ineta->imc_no_ineta,
                                                     errno );
   D_TCP_CLOSE( adsl_tcpcomp->dsc_sithr_poll_1.adsc_pollfd->fd );  /* close socket again */
   adsl_tcpcomp->imc_conn_no++;             /* number of connect       */
   if (adsl_tcpcomp->imc_conn_no >= adsl_tcpcomp->adsc_target_ineta->imc_no_ineta) {  /* was last connect */
     bol1 = m_poll_arr_del( &adsl_tcpcomp->dsc_sithr_poll_1 );
// to-do 12.07.10 KB check error
// to-do 16.08.10 KB error number 1234 to be replaced
     adsl_tcpcomp->adsc_callback->amc_conncallback( adsl_tcpcomp,
                                                    adsl_tcpcomp->vpc_userfld,
#ifndef B130807
                                                    adsl_tcpcomp->adsc_target_ineta,
                                                    (void *) adsl_tcpcomp->ac_free_ti1,
#endif
                                                    NULL, 0,
                                                    1234 );
     adsl_tcpcomp->adsc_callback->amc_cleanup( adsl_tcpcomp,
                                               adsl_tcpcomp->vpc_userfld );
     return;
   }
   iml1 = adsl_tcpcomp->imc_conn_no;        /* use next INETA          */
   if (adsl_tcpcomp->boc_round_robin) {     /* connect round robin     */
     iml1 = m_sub_conn_round_robin( adsl_tcpcomp );
   }
   iel_rcc = m_sub_conn_start( adsl_tcpcomp, iml1 );
   switch (iel_rcc) {                       /* returned from TCP connect() */
     case ied_rcc_ok:                       /* connect done            */
		adsl_tcpcomp->adsc_callback->amc_conncallback( adsl_tcpcomp,
										   adsl_tcpcomp->vpc_userfld,
#ifndef B130807
                                                 adsl_tcpcomp->adsc_target_ineta,
                                                 (void *) adsl_tcpcomp->ac_free_ti1,
#endif
										   (struct sockaddr *) &adsl_tcpcomp->dsc_soa_conn, adsl_tcpcomp->imc_len_soa_conn, 0 );

// to-do 12.07.10 KB call connect complete
       goto p_pollout_00;                   /* return success, no error */
     case ied_rcc_block:                    /* connect is blocking     */
       return;                              /* return success, no error */
   }
// to-do 12.07.10 KB what to do now? do next connect() maybe?
	goto p_pollout_14; /* go back to indicate error and to try the next ineta AGAG */

   p_pollout_20:                            /* POLLOUT is for send     */
   if ((adsp_sp1->adsc_pollfd->revents & POLLOUT) == 0) {
     return;                                /* nothing to do           */
   }
#ifdef TRACEHL1
   m_hl1_printf( "nsl-tcpcomp-singthr-%05d-T m_pc_tc_poll() p_pollout_20",
                 __LINE__ );
#endif
   adsl_tcpcomp->dsc_sithr_poll_1.adsc_pollfd->events &= -1 - POLLOUT;
   adsl_tcpcomp->adsc_callback->amc_sendcallback( adsl_tcpcomp,
                                                  adsl_tcpcomp->vpc_userfld );
   return;
} /* end m_pc_tc_poll()                                                */

#ifdef TRACEHL1
static void m_console_out( char *achp_buff, int implength ) {
   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variable */
   char       byl1;                         /* working-variable        */
   char       chrlwork1[ 76 ];              /* buffer to print         */

   iml1 = 0;
   while (iml1 < implength) {
     iml2 = iml1 + 16;
     if (iml2 > implength) iml2 = implength;
     for ( iml3 = 4; iml3 < 75; iml3++ ) {
       chrlwork1[iml3] = ' ';
     }
     chrlwork1[58] = '*';
     chrlwork1[75] = '*';
     iml3 = 4;
     do {
       iml3--;
       chrlwork1[ iml3 ] = chrstrans[ (iml1 >> ((4 - 1 - iml3) << 2)) & 0X0F ];
     } while (iml3 > 0);
     iml4 = 6;                              /* start hexa digits here  */
     iml5 = 59;                             /* start ASCII here        */
     iml6 = 4;                              /* times normal            */
     do {
       byl1 = achp_buff[ iml1++ ];
       chrlwork1[ iml4++ ] = chrstrans[ (byl1 >> 4) & 0X0F ];
       chrlwork1[ iml4++ ] = chrstrans[ byl1 & 0X0F ];
       iml4++;
       if (byl1 > 0X20) {
         chrlwork1[ iml5 ] = byl1;
       }
       iml5++;
       iml6--;
       if (iml6 == 0) {
         iml4++;
         iml6 = 4;
       }
     } while (iml1 < iml2);
     m_hl1_printf( "%.*s", sizeof(chrlwork1), chrlwork1 );
   }
} /* end m_console_out()                                            */
#endif
