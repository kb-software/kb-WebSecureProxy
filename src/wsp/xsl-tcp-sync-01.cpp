/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xsl-tcp-sync-01                                     |*/
/*| -------------                                                     |*/
/*|  HOB common library - TCPSYNC                                     |*/
/*|  Project WSP, WSPnG, HCU2 and HL-VPN V2                           |*/
/*|  KB 08.05.08                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|                                                                   |*/
/*| EXPECTED INPUT:                                                   |*/
/*| ---------------                                                   |*/
/*|                                                                   |*/
/*| EXPECTED OUTPUT:                                                  |*/
/*| ----------------                                                  |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifdef B120816
#ifndef LEN_DISP_INETA
#define LEN_DISP_INETA 56
#endif
#endif

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

#ifndef HL_UNIX
#ifndef HOB_DEF_SOCKLEN
#define HOB_DEF_SOCKLEN
typedef int socklen_t;
#endif
#endif
#ifndef HL_UNIX
#ifndef UNSIG_MED
typedef unsigned int UNSIG_MED;
#endif
#ifndef D_TCP_ERROR
#define D_TCP_ERROR WSAGetLastError()
#endif
#ifndef D_TCP_CLOSE
#define D_TCP_CLOSE closesocket
#endif
#else
#ifndef D_TCP_ERROR
#define D_TCP_ERROR errno
#endif
#ifndef D_TCP_CLOSE
#define D_TCP_CLOSE close
#endif
#endif

#ifdef HL_FREEBSD
#include <time.h>
#endif
#include <sys/timeb.h>
#ifndef HL_UNIX
#include <winsock2.h>
#include <ws2tcpip.h>
//#include <windows.h>
#endif
#ifdef HL_UNIX
#include <hob-unix01.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#ifdef HL_FREEBSD
#include <sys/uio.h>
#endif
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/time.h>
#endif
#include <hob-netw-01.h>
#include <hob-tcp-sync-01.h>

#define DEF_SEND_IOV           32           /* for WSASend() or writev() */

extern "C" int m_hl1_printf( char *aptext, ... );

#ifndef DEF_HL_STR_G_I_1
#define DEF_HL_STR_G_I_1
struct dsd_gather_i_1 {                     /* gather input data       */
   struct dsd_gather_i_1 *adsc_next;        /* next in chain           */
   char *     achc_ginp_cur;                /* current position        */
   char *     achc_ginp_end;                /* end of input data       */
};
#endif

/*+-------------------------------------------------------------------+*/
/*| Procedure Sections.                                               |*/
/*+-------------------------------------------------------------------+*/

/** TCP connect to target                                              */
extern "C" BOOL m_tcpsync_connect( int *aimp_error,
                                   struct dsd_tcpsync_1 *adsp_tcpsync_1,
                                   struct dsd_bind_ineta_1 *adsp_biineta1,
                                   struct dsd_target_ineta_1 *adsp_target_ineta,
                                   int imp_port ) {
   int        iml_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   int        iml_ind_connect;              /* index of connect        */
   socklen_t  iml_namelen;                  /* length of name          */
   socklen_t  iml_bindlen;                  /* length for bind         */
   char       *achl1;                       /* working variable        */
   struct sockaddr *adsl_soa_bind;          /* address information for bind */
   struct sockaddr_storage dsl_soa_conn;    /* address information for connect */

#ifdef TRACEHL1
   m_hl1_printf( "xsl-tcp-sync-01 l%05d m_tcpsync_connect() adsp_tcpsync_1=%p.",
                 __LINE__, adsp_tcpsync_1 );
#endif
   iml_ind_connect = 0;                     /* index of connect        */
#ifndef B120201
   adsp_tcpsync_1->boc_close_received = FALSE;  /* TCP close received  */
#endif
   while (TRUE) {                           /* loop over INETA to connect */
     if (iml_ind_connect >= adsp_target_ineta->imc_no_ineta) break;
     m_set_connect_p1( &dsl_soa_conn, &iml_namelen,
                       adsp_target_ineta, iml_ind_connect );
     adsp_tcpsync_1->imc_socket = socket( ((struct sockaddr *) &dsl_soa_conn)->sa_family, SOCK_STREAM, IPPROTO_TCP );
     if (adsp_tcpsync_1->imc_socket < 0) {  /* error occured           */
       m_hl1_printf( "xsl-tcp-sync-01-l%05d-W socket returned %d / %d",
                     __LINE__, adsp_tcpsync_1->imc_socket, D_TCP_ERROR );
       iml_ind_connect++;                   /* increment index of INETA */
       continue;
     }
     if (adsp_biineta1->boc_bind_needed) {  /* flag bind() is needed   */
       iml_bindlen = 0;                     /* set flag not valid      */
       switch (((struct sockaddr *) &dsl_soa_conn)->sa_family) {
         case AF_INET:                      /* IPV4                    */
           if (adsp_biineta1->boc_ipv4 == FALSE) break;  /* IPV4 not supported */
           adsl_soa_bind = (struct sockaddr *) &adsp_biineta1->dsc_soai4;
           iml_bindlen = sizeof(struct sockaddr_in);
           break;
         case AF_INET6:                     /* IPV6                    */
           if (adsp_biineta1->boc_ipv6 == FALSE) break;  /* IPV6 not supported */
           adsl_soa_bind = (struct sockaddr *) &adsp_biineta1->dsc_soai6;
           iml_bindlen = sizeof(struct sockaddr_in6);
           break;
       }
       if (iml_bindlen == 0) {              /* flag not valid set      */
         m_hl1_printf( "xsl-tcp-sync-01-l%05d-W bind multihomed not possible",
                       __LINE__ );
         D_TCP_CLOSE( adsp_tcpsync_1->imc_socket );       /* close socket again      */
         iml_ind_connect++;                 /* increment index of INETA */
         continue;
       }
       iml_rc = bind( adsp_tcpsync_1->imc_socket, adsl_soa_bind, iml_bindlen );
       if (iml_rc < 0) {                    /* error occured           */
         m_hl1_printf( "xsl-tcp-sync-01-l%05d-W bind returned %d / %d.",
                       __LINE__, iml_rc, D_TCP_ERROR );
         D_TCP_CLOSE( adsp_tcpsync_1->imc_socket );       /* close socket again      */
         iml_ind_connect++;                 /* increment index of INETA */
         continue;
       }
     }
     iml_rc = getnameinfo( (struct sockaddr *) &dsl_soa_conn, iml_namelen,
                           adsp_tcpsync_1->chrc_ineta_target, sizeof(adsp_tcpsync_1->chrc_ineta_target),
                           0, 0, NI_NUMERICHOST );
     if (iml_rc < 0) {                      /* error occured           */
       m_hl1_printf( "xsl-tcp-sync-01-l%05d-W getnameinfo returned %d / %d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
       strcpy( adsp_tcpsync_1->chrc_ineta_target, "???" );
     }
     ((struct sockaddr_in *) &dsl_soa_conn)->sin_port = htons( imp_port );
     iml_rc = connect( adsp_tcpsync_1->imc_socket,
                       (struct sockaddr *) &dsl_soa_conn, iml_namelen );
     if (iml_rc) {                          /* connect was not successful */
       iml_ind_connect++;                   /* increment index of INETA */
       achl1 = "";                          /* no additional text      */
       if (iml_ind_connect < adsp_target_ineta->imc_no_ineta) {
         achl1 = " - try next INETA from DNS";  /* set additional text */
       } else if (iml_ind_connect > 1) {    /* more than one INETA configured */
         achl1 = " - was last INETA from DNS";  /* set additional text */
       }
       m_hl1_printf( "xsl-tcp-sync-01-l%05d-W connect to %s returned %d / %d%s.",
                     __LINE__,
                     adsp_tcpsync_1->chrc_ineta_target,
                     iml_rc, D_TCP_ERROR, achl1 );
       D_TCP_CLOSE( adsp_tcpsync_1->imc_socket );  /* close socket again */
       continue;
     }
     /* connect was successful                                         */
#ifndef HL_UNIX
     adsp_tcpsync_1->dsc_event_1 = WSACreateEvent();  /* create event for recv */
     if (adsp_tcpsync_1->dsc_event_1 == WSA_INVALID_EVENT) {  /* error occured */
       m_hl1_printf( "xsl-tcp-sync-01-l%05d-W WSACreateEvent() Error %d.",
                     __LINE__, D_TCP_ERROR );
       if (aimp_error) *aimp_error = TCPSYNC_ERR_CREATEEVENT;  /* set error code */
       D_TCP_CLOSE( adsp_tcpsync_1->imc_socket );
       break;
     }
     iml_rc = WSAEventSelect( adsp_tcpsync_1->imc_socket,
                              adsp_tcpsync_1->dsc_event_1,
                              FD_WRITE | FD_READ | FD_CLOSE );
     if (iml_rc) {                          /* error occured           */
       m_hl1_printf( "xsl-tcp-sync-01-l%05d-W WSAEventSelect() Error %d / %d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
       if (aimp_error) *aimp_error = TCPSYNC_ERR_EVENTSELECT;  /* set error code */
       WSACloseEvent( adsp_tcpsync_1->dsc_event_1 );
       D_TCP_CLOSE( adsp_tcpsync_1->imc_socket );         /* close socket again      */
       break;
     }
#endif
#ifdef HL_UNIX
     /* set the TCP socket to non-blocking                               */
     iml1 = fcntl( adsp_tcpsync_1->imc_socket, F_GETFL, 0 );
     iml_rc = fcntl( adsp_tcpsync_1->imc_socket, F_SETFL, iml1 | O_NONBLOCK );
#ifdef TRACEHL1
     m_hl1_printf( "xsl-tcp-sync-01 l%05d m_tcpsync_connect() adsp_tcpsync_1=%p fcntl() returned %d %d.",
                   __LINE__, adsp_tcpsync_1, iml_rc, errno );
#endif
     if (iml_rc) {                            /* error occured           */
       m_hl1_printf( "xsl-tcp-sync-01-l%05d-W fcntl() failed with code %d %d.",
                     __LINE__, iml_rc, D_TCP_ERROR );
       if (aimp_error) *aimp_error = errno;  /* set error code         */
       D_TCP_CLOSE( adsp_tcpsync_1->imc_socket );  /* close socket again */
       break;
     }
#endif
     if (aimp_error) *aimp_error = 0;       /* clear error code        */
     return TRUE;                           /* all done                */
   }
   if (aimp_error) *aimp_error = TCPSYNC_ERR_CONNECT_MISC;  /* set error code */
   return FALSE;                            /* return error            */
} /* end m_tcpsync_connect()                                           */

/** send single chunk to connected server, with timeout                */
extern "C" int m_tcpsync_send_single( int *aimp_error, struct dsd_tcpsync_1 *adsp_tcpsync_1,
                                      char *achp_buffer, int imp_len_send, int imp_msec ) {
   int        iml1;                         /* working variable        */
   int        iml_offset;                   /* offset data to send     */
   int        iml_rc;                       /* return code             */
// HL_LONGLONG ill_w1;                      /* working variable        */
   HL_LONGLONG ill_time_end;                /* time to return          */
#ifndef HL_UNIX
   WSANETWORKEVENTS dsl_net_events;         /* return events           */
   struct __timeb64 dsl_timebuffer;
#endif
#ifdef HL_UNIX
   pollfd     dsrl_poll[1];                 /* for poll()              */
   struct timeval dsl_timeval;
#endif

#ifdef TRACEHL1
   m_hl1_printf( "xsl-tcp-sync-01 l%05d m_tcpsync_send_single() adsp_tcpsync_1=%p achp_buffer=%p imp_len_send=%d imp_msec=%d.",
                 __LINE__, adsp_tcpsync_1, achp_buffer, imp_len_send, imp_msec );
#endif
#ifndef HL_UNIX
   _ftime64( &dsl_timebuffer );
   ill_time_end = dsl_timebuffer.time * 1000 + dsl_timebuffer.millitm
                    + imp_msec;
#endif
#ifdef HL_UNIX
   gettimeofday( &dsl_timeval, NULL );
   ill_time_end = (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 + dsl_timeval.tv_usec / 1000)
                    + imp_msec;
#endif
   iml_offset = 0;                          /* offset where to send    */

   psend10:                                 /* send data to server     */
   iml1 = imp_len_send - iml_offset;        /* remaining length        */
   iml_rc = send( adsp_tcpsync_1->imc_socket, achp_buffer + iml_offset, iml1, 0 );
   if (iml_rc == iml1) {                    /* all data sent           */
     if (aimp_error) *aimp_error = 0;       /* clear error code        */
     return (iml_offset + iml_rc);
   }
   if (iml_rc >= 0) {                       /* did not return error    */
     iml_offset += iml_rc;                  /* add data sent           */
     goto psend10;                          /* send data to server     */
   }

#ifndef HL_UNIX
   iml1 = D_TCP_ERROR;                      /* get error code          */
   if (iml1 != WSAEWOULDBLOCK) {
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP send to INETA=%s returned error %d / %d.",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target,
                   iml_rc, iml1 );
     if (aimp_error) *aimp_error = iml1;    /* set error code          */
     return -1;                             /* return error            */
   }

   psend20:                                 /* wait till send possible */
   _ftime64( &dsl_timebuffer );
   iml1 = ill_time_end
            - (HL_LONGLONG) (dsl_timebuffer.time * 1000 + dsl_timebuffer.millitm);
   if (iml1 <= 0) {
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP send to INETA=%s timed out - milliseconds %d.",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target,
                   imp_msec );
     if (aimp_error) *aimp_error = TCPSYNC_ERR_TIMEOUT_SEND;  /* set error code */
     return -1;                             /* return error            */
   }
   iml_rc = WSAWaitForMultipleEvents( 1, &adsp_tcpsync_1->dsc_event_1,
                                      FALSE, iml1, FALSE );
   if (iml_rc != WSA_WAIT_EVENT_0) {        /* did not succeed         */
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP send to INETA=%s WSAWaitForMultipleEvents error %d / %d.",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target,
                   iml_rc, D_TCP_ERROR );
     if (aimp_error) *aimp_error = TCPSYNC_ERR_TIMEOUT_SEND;  /* set error code */
     return -1;                             /* return error            */
   }
   iml_rc = WSAEnumNetworkEvents( adsp_tcpsync_1->imc_socket,
                                  adsp_tcpsync_1->dsc_event_1,
                                  &dsl_net_events );
   if (iml_rc) {                            /* did not succeed         */
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP send to INETA=%s WSAEnumNetworkEvents error %d / %d.",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target,
                   iml_rc, D_TCP_ERROR );
     if (aimp_error) *aimp_error = TCPSYNC_ERR_WSAENUMNE;  /* set error code */
     return -1;                             /* return error            */
   }
   if (dsl_net_events.lNetworkEvents & FD_WRITE) goto psend10;
   if ((dsl_net_events.lNetworkEvents & FD_CLOSE) == 0) goto psend20;
   m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP send to INETA=%s connection closed by other side",
                 __LINE__,
                 adsp_tcpsync_1->chrc_ineta_target );
   if (aimp_error) *aimp_error = TCPSYNC_ERR_CLOSED_OTHER_SIDE;  /* set error code */
   return -1;                               /* return error            */
#endif
#ifdef HL_UNIX
   iml1 = D_TCP_ERROR;                      /* get error code          */
   if (iml1 != EAGAIN) {
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP send to INETA=%s returned error %d / %d.",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target,
                   iml_rc, iml1 );
     if (aimp_error) *aimp_error = iml1;    /* set error code          */
     return -1;                             /* return error            */
   }

   psend20:                                 /* wait till send possible */
   gettimeofday( &dsl_timeval, NULL );
   iml1 = ill_time_end
            - (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 + dsl_timeval.tv_usec / 1000);
   if (iml1 <= 0) {
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP send to INETA=%s timed out - milliseconds %d.",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target,
                   imp_msec );
     if (aimp_error) *aimp_error = TCPSYNC_ERR_TIMEOUT_SEND;  /* set error code */
     return -1;                             /* return error            */
   }
   memset ( dsrl_poll, 0, sizeof(dsrl_poll) );  /* for poll()          */
   dsrl_poll[ 0 ].fd = adsp_tcpsync_1->imc_socket;
   dsrl_poll[ 0 ].events = POLLOUT;
   iml_rc = poll( dsrl_poll, 1, iml1 );
   if (iml_rc < 0) {                        /* was error               */
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W poll() returned=%d errno=%d.",
                   __LINE__, iml_rc, errno );
   }
   if ((dsrl_poll[ 0 ].revents & POLLOUT) == 0) {
     goto psend20;                          /* wait till send possible */
   }
   goto psend10;                            /* send data to server     */
#endif
} /* end m_tcpsync_send_single()                                       */

/** send data in gather structures to connected server, with timeout   */
extern "C" int m_tcpsync_send_gather( int *aimp_error, struct dsd_tcpsync_1 *adsp_tcpsync_1,
                                      struct dsd_gather_i_1 *adsp_gai1_inp,
                                      struct dsd_gather_i_1 **aadsp_gai1_out,
                                      int imp_msec ) {
   int        iml1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   int        iml_sent;                     /* data sent               */
   int        iml_no_iov;                   /* number of WSABUF / vector */
   HL_LONGLONG ill_time_end;                /* time to return          */
   struct dsd_gather_i_1 *adsl_gai1_send;   /* send data               */
#ifndef HL_UNIX
   DWORD      dwl_sent;                     /* bytes sent              */
   WSABUF     dsrl_wsabuf[ DEF_SEND_IOV ];  /* buffer for WSASend()    */
   WSANETWORKEVENTS dsl_net_events;         /* return events           */
   struct __timeb64 dsl_timebuffer;
#endif
#ifdef HL_UNIX
   struct iovec dsrl_iov[ DEF_SEND_IOV ];   /* buffer for sendmsg()    */
   pollfd     dsrl_poll[1];                 /* for poll()              */
   struct timeval dsl_timeval;
#endif

#ifdef TRACEHL1
   m_hl1_printf( "xsl-tcp-sync-01 l%05d m_tcpsync_send_single() adsp_tcpsync_1=%p achp_buffer=%p imp_len_send=%d imp_msec=%d.",
                 __LINE__, adsp_tcpsync_1, achp_buffer, imp_len_send, imp_msec );
#endif
   iml_sent = 0;                            /* data sent               */
   adsl_gai1_send = adsp_gai1_inp;          /* input data              */
#ifndef HL_UNIX
   _ftime64( &dsl_timebuffer );
   ill_time_end = dsl_timebuffer.time * 1000 + dsl_timebuffer.millitm
                    + imp_msec;
#endif
#ifdef HL_UNIX
   gettimeofday( &dsl_timeval, NULL );
   ill_time_end = (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 + dsl_timeval.tv_usec / 1000)
                    + imp_msec;
#endif

   psend10:                                 /* send data to server     */
   iml_no_iov = 0;                          /* number of WSABUF / vector */
   while (adsl_gai1_send) {                 /* loop over input data    */
     iml1 = adsl_gai1_send->achc_ginp_end - adsl_gai1_send->achc_ginp_cur;
     if (iml1 > 0) {                        /* data to send            */
#ifndef HL_UNIX
       dsrl_wsabuf[ iml_no_iov ].buf = adsl_gai1_send->achc_ginp_cur;
       dsrl_wsabuf[ iml_no_iov ].len = iml1;
#else
       dsrl_iov[ iml_no_iov ].iov_base = adsl_gai1_send->achc_ginp_cur;
       dsrl_iov[ iml_no_iov ].iov_len = iml1;
#endif
       iml_no_iov++;                        /* vector set              */
       if (iml_no_iov >= DEF_SEND_IOV) break;  /* all vectors set      */
     }
     adsl_gai1_send = adsl_gai1_send->adsc_next;  /* get next in chain */
   }
   if (iml_no_iov <= 0) {                   /* number of WSABUF / vector */
     if (aimp_error) *aimp_error = 0;       /* clear error code        */
     if (aadsp_gai1_out) *aadsp_gai1_out = NULL;
     return iml_sent;                       /* data sent               */
   }
   adsl_gai1_send = adsp_gai1_inp;          /* input data              */
#ifndef HL_UNIX
   iml_rc = WSASend( adsp_tcpsync_1->imc_socket, dsrl_wsabuf, iml_no_iov, &dwl_sent, 0, NULL, NULL);
   if (iml_rc != 0) goto p_send_14;         /* error occured           */
   iml_sent += dwl_sent;                    /* data sent               */
#else
   iml_rc = writev( adsp_tcpsync_1->imc_socket, dsrl_iov, iml_no_iov );
   if (iml_rc < 0) goto p_send_14;          /* error occured           */
   iml_sent += iml_rc;                      /* data sent               */
#endif
   while (adsl_gai1_send) {                 /* loop over input data    */
     iml1 = adsl_gai1_send->achc_ginp_end - adsl_gai1_send->achc_ginp_cur;
#ifndef HL_UNIX
     if (iml1 > dwl_sent) iml1 = dwl_sent;
#else
     if (iml1 > iml_rc) iml1 = iml_rc;
#endif
     adsl_gai1_send->achc_ginp_cur += iml1;
#ifndef HL_UNIX
     dwl_sent -= iml1;
#else
     iml_rc -= iml1;
#endif
     if (adsl_gai1_send->achc_ginp_cur < adsl_gai1_send->achc_ginp_end) {
       goto psend10;                        /* send data to server     */
     }
     adsl_gai1_send = adsl_gai1_send->adsc_next;  /* get next in chain */
   }
   if (aimp_error) *aimp_error = 0;         /* clear error code        */
   if (aadsp_gai1_out) *aadsp_gai1_out = NULL;
   return iml_sent;                         /* data sent               */

   p_send_14:                               /* error occured           */
#ifndef HL_UNIX
   iml1 = D_TCP_ERROR;                      /* get error code          */
   if (iml1 != WSAEWOULDBLOCK) {
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP send to INETA=%s returned error %d / %d.",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target,
                   iml_rc, iml1 );
     if (aimp_error) *aimp_error = iml1;    /* set error code          */
     if (aadsp_gai1_out) *aadsp_gai1_out = adsl_gai1_send;
     return -1;                             /* return error            */
   }

   psend20:                                 /* wait till send possible */
   _ftime64( &dsl_timebuffer );
   iml1 = ill_time_end
            - (HL_LONGLONG) (dsl_timebuffer.time * 1000 + dsl_timebuffer.millitm);
   if (iml1 <= 0) {
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP send to INETA=%s timed out - milliseconds %d.",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target,
                   imp_msec );
     if (aimp_error) *aimp_error = TCPSYNC_ERR_TIMEOUT_SEND;  /* set error code */
     if (aadsp_gai1_out) *aadsp_gai1_out = adsl_gai1_send;
     return -1;                             /* return error            */
   }
   iml_rc = WSAWaitForMultipleEvents( 1, &adsp_tcpsync_1->dsc_event_1,
                                      FALSE, iml1, FALSE );
   if (iml_rc != WSA_WAIT_EVENT_0) {        /* did not succeed         */
     goto psend20;                          /* wait till send possible */
   }
   iml_rc = WSAEnumNetworkEvents( adsp_tcpsync_1->imc_socket,
                                  adsp_tcpsync_1->dsc_event_1,
                                  &dsl_net_events );
   if (iml_rc) {                            /* did not succeed         */
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP send to INETA=%s WSAEnumNetworkEvents error %d / %d.",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target,
                   iml_rc, D_TCP_ERROR );
     if (aimp_error) *aimp_error = TCPSYNC_ERR_WSAENUMNE;  /* set error code */
     if (aadsp_gai1_out) *aadsp_gai1_out = adsl_gai1_send;
     return -1;                             /* return error            */
   }
   if (dsl_net_events.lNetworkEvents & FD_WRITE) {
     goto psend10;
   }
   if ((dsl_net_events.lNetworkEvents & FD_CLOSE) == 0) goto psend20;
   m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP send to INETA=%s connection closed by other side",
                 __LINE__,
                 adsp_tcpsync_1->chrc_ineta_target );
   if (aimp_error) *aimp_error = TCPSYNC_ERR_CLOSED_OTHER_SIDE;  /* set error code */
   if (aadsp_gai1_out) *aadsp_gai1_out = adsl_gai1_send;
   return -1;                               /* return error            */
#endif
#ifdef HL_UNIX
   iml1 = D_TCP_ERROR;                      /* get error code          */
   if (iml1 != EAGAIN) {
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP send to INETA=%s returned error %d / %d.",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target,
                   iml_rc, iml1 );
     if (aimp_error) *aimp_error = iml1;    /* set error code          */
     if (aadsp_gai1_out) *aadsp_gai1_out = adsl_gai1_send;
     return -1;                             /* return error            */
   }

   psend20:                                 /* wait till send possible */
   gettimeofday( &dsl_timeval, NULL );
   iml1 = ill_time_end
            - (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 + dsl_timeval.tv_usec / 1000);
   if (iml1 <= 0) {
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP send to INETA=%s timed out - milliseconds %d.",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target,
                   imp_msec );
     if (aimp_error) *aimp_error = TCPSYNC_ERR_TIMEOUT_SEND;  /* set error code */
     if (aadsp_gai1_out) *aadsp_gai1_out = adsl_gai1_send;
     return -1;                             /* return error            */
   }
   memset ( dsrl_poll, 0, sizeof(dsrl_poll) );  /* for poll()          */
   dsrl_poll[ 0 ].fd = adsp_tcpsync_1->imc_socket;
   dsrl_poll[ 0 ].events = POLLOUT;
   iml_rc = poll( dsrl_poll, 1, iml1 );
   if (iml_rc < 0) {                        /* was error               */
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W poll() returned=%d errno=%d.",
                   __LINE__, iml_rc, errno );
   }
   if ((dsrl_poll[ 0 ].revents & POLLOUT) == 0) {
     goto psend20;                          /* wait till send possible */
   }
   goto psend10;                            /* send data to server     */
#endif
} /* end m_tcpsync_send_gather()                                       */

/** receive something from connected server, with timeout              */
extern "C" int m_tcpsync_recv( int *aimp_error, struct dsd_tcpsync_1 *adsp_tcpsync_1,
                               char *achp_buffer, int imp_len_recv, int imp_msec ) {
   int        iml1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
// HL_LONGLONG ill_w1;                      /* working variable        */
   HL_LONGLONG ill_time_end;                /* time to return          */
#ifndef HL_UNIX
   WSANETWORKEVENTS dsl_net_events;         /* return events           */
   struct __timeb64 dsl_timebuffer;
#endif
#ifdef HL_UNIX
   pollfd     dsrl_poll[1];                 /* for poll()              */
   struct timeval dsl_timeval;
#endif

#ifdef TRACEHL1
#ifndef HL_UNIX
   _ftime64( &dsl_timebuffer );
#endif
#ifdef HL_UNIX
   gettimeofday( &dsl_timeval, NULL );
#endif
   m_hl1_printf( "xsl-tcp-sync-01 l%05d m_tcpsync_recv() adsp_tcpsync_1=%p achp_buffer=%p imp_len_recv=%d imp_msec=%d time=%lld.",
                 __LINE__, adsp_tcpsync_1, achp_buffer, imp_len_recv, imp_msec,
#ifndef HL_UNIX
                 dsl_timebuffer.time * 1000 + dsl_timebuffer.millitm );
#ifdef FORKEDIT
               (
#endif
#endif
#ifdef HL_UNIX
                 (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 + dsl_timeval.tv_usec / 1000) );
#endif
#endif
#ifndef HL_UNIX
   _ftime64( &dsl_timebuffer );
   ill_time_end = dsl_timebuffer.time * 1000 + dsl_timebuffer.millitm
                    + imp_msec;
#endif
#ifdef HL_UNIX
   gettimeofday( &dsl_timeval, NULL );
   ill_time_end = (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 + dsl_timeval.tv_usec / 1000)
                    + imp_msec;
#endif

   precv10:                                 /* loop to receive data    */
#ifndef HL_UNIX
   iml1 = ill_time_end
            - (HL_LONGLONG) (dsl_timebuffer.time * 1000 + dsl_timebuffer.millitm);
#endif
#ifdef HL_UNIX
   iml1 = ill_time_end
            - (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 + dsl_timeval.tv_usec / 1000);
#endif
   if (iml1 <= 0) {
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP receive from INETA=%s timed out - milliseconds %d.",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target,
                   imp_msec );
     if (aimp_error) *aimp_error = TCPSYNC_ERR_TIMEOUT_RECV;  /* set error code */
     return -1;                             /* return error            */
   }
#ifndef HL_UNIX
   iml_rc = WSAWaitForMultipleEvents( 1, &adsp_tcpsync_1->dsc_event_1,
                                      FALSE, iml1, FALSE );
   if (iml_rc != WSA_WAIT_EVENT_0) {        /* did not succeed         */
     goto precv10;                          /* loop to receive data    */
   }
   _ftime64( &dsl_timebuffer );
   iml_rc = WSAEnumNetworkEvents( adsp_tcpsync_1->imc_socket,
                                  adsp_tcpsync_1->dsc_event_1,
                                  &dsl_net_events );
   if (iml_rc) {                            /* did not succeed         */
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP receive from INETA=%s WSAEnumNetworkEvents error %d / %d.",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target,
                   iml_rc, D_TCP_ERROR );
     if (aimp_error) *aimp_error = TCPSYNC_ERR_WSAENUMNE;  /* set error code */
     return -1;                             /* return error            */
   }
   if (dsl_net_events.lNetworkEvents & FD_CLOSE) {
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP receive from INETA=%s connection closed by other side",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target );
     adsp_tcpsync_1->boc_close_received = TRUE;  /* TCP close received */
   }
   if ((dsl_net_events.lNetworkEvents & FD_READ) == 0) {
     if (adsp_tcpsync_1->boc_close_received) {  /* TCP close received */
       if (aimp_error) *aimp_error = TCPSYNC_ERR_CLOSED_OTHER_SIDE;  /* set error code */
       return -1;                           /* return error            */
     }
     goto precv10;                          /* loop to receive data    */
   }
#endif
#ifdef HL_UNIX
   memset ( dsrl_poll, 0, sizeof(dsrl_poll) );  /* for poll()          */
   dsrl_poll[ 0 ].fd = adsp_tcpsync_1->imc_socket;
   dsrl_poll[ 0 ].events = POLLIN;
   iml_rc = poll( dsrl_poll, 1, iml1 );
   if (iml_rc < 0) {                        /* was error               */
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W poll() returned=%d errno=%d.",
                   __LINE__, iml_rc, errno );
   }
   gettimeofday( &dsl_timeval, NULL );
   if ((dsrl_poll[ 0 ].revents & POLLIN) == 0) {
     goto precv10;                          /* loop to receive data    */
   }

#endif
#ifdef TRACEHL1
#ifndef HL_UNIX
   _ftime64( &dsl_timebuffer );
#endif
#ifdef HL_UNIX
   gettimeofday( &dsl_timeval, NULL );
#endif
   m_hl1_printf( "xsl-tcp-sync-01 l%05d m_tcpsync_recv() adsp_tcpsync_1=%p before recv() time %lld.",
                 __LINE__, adsp_tcpsync_1,
#ifndef HL_UNIX
                 dsl_timebuffer.time * 1000 + dsl_timebuffer.millitm );
#ifdef FORKEDIT
               (
#endif
#endif
#ifdef HL_UNIX
                 (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 + dsl_timeval.tv_usec / 1000) );
#endif
#endif
   iml_rc = recv( adsp_tcpsync_1->imc_socket, achp_buffer, imp_len_recv, 0 );
#ifdef TRACEHL1
#ifndef HL_UNIX
   _ftime64( &dsl_timebuffer );
#endif
#ifdef HL_UNIX
   gettimeofday( &dsl_timeval, NULL );
#endif
   m_hl1_printf( "xsl-tcp-sync-01 l%05d m_tcpsync_recv() adsp_tcpsync_1=%p recv() returned %d error %d time %lld.",
                 __LINE__, adsp_tcpsync_1, iml_rc, D_TCP_ERROR,
#ifndef HL_UNIX
                 dsl_timebuffer.time * 1000 + dsl_timebuffer.millitm );
#ifdef FORKEDIT
               (
#endif
#endif
#ifdef HL_UNIX
                 (((HL_LONGLONG) dsl_timeval.tv_sec) * 1000 + dsl_timeval.tv_usec / 1000) );
#endif
#endif
#ifdef HL_UNIX
   if (iml_rc < 0) {                        /* was error               */
     adsp_tcpsync_1->boc_close_received = TRUE;  /* TCP close received */
   }
#endif
#ifdef TRACEHL1
   m_hl1_printf( "xsl-tcp-sync-01 l%05d m_tcpsync_recv() adsp_tcpsync_1=%p returning %d adsp_tcpsync_1->boc_close_received %d.",
                 __LINE__, adsp_tcpsync_1, iml_rc, adsp_tcpsync_1->boc_close_received );
#endif
   return iml_rc;
} /* end m_tcpsync_recv()                                              */

/** close TCP connection to server                                     */
extern "C" int m_tcpsync_close( int *aimp_error, struct dsd_tcpsync_1 *adsp_tcpsync_1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml_rc;                       /* return code socket      */
   int        iml_errno;                    /* TCP error code          */
   int        iml_close_rc;                 /* return code this function */

#ifdef TRACEHL1
   m_hl1_printf( "xsl-tcp-sync-01 l%05d m_tcpsync_close() adsp_tcpsync_1=%p.",
                 __LINE__, adsp_tcpsync_1 );
#endif
   iml_close_rc = 0;                        /* clear return code this function */
   if (aimp_error) *aimp_error = 0;         /* clear error code        */
#ifndef HL_UNIX
   bol1 = WSACloseEvent( adsp_tcpsync_1->dsc_event_1 );
   if (bol1 == FALSE) {                     /* error returned          */
     iml_rc = D_TCP_ERROR;                  /* get error code          */
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP close connection to INETA=%s WSACloseEvent error %d",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target,
                   iml_rc );
     if (aimp_error) *aimp_error = iml_rc;  /* set error code          */
     iml_close_rc = -1;                     /* set return code this function */
   }
#endif
   iml_rc = D_TCP_CLOSE( adsp_tcpsync_1->imc_socket );
   if (iml_rc) {                            /* error returned          */
     iml_errno = D_TCP_ERROR;                  /* get error code          */
     m_hl1_printf( "xsl-tcp-sync-01-l%05d-W TCP close connection to INETA=%s socket close error %d %d",
                   __LINE__,
                   adsp_tcpsync_1->chrc_ineta_target,
                   iml_rc, iml_errno );
#ifndef HL_UNIX
     if (iml_close_rc == 0) {               /* no error set yet        */
       if (aimp_error) *aimp_error = iml_errno;  /* set error code     */
       iml_close_rc = -1;                   /* set return code this function */
     }
#endif
#ifdef HL_UNIX
     if (aimp_error) *aimp_error = iml_errno;  /* set error code       */
     iml_close_rc = iml_rc;                 /* set return code this function */
#endif
   }
   return iml_close_rc;                     /* all done                */
} /* end m_tcpsync_close()                                             */
