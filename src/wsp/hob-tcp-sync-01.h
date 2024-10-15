/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| HEADER FILE NAME: hob-tcp-sync-01.h                               |*/
/*| -----------------                                                 |*/
/*|  HOB common library - TCPSYNC                                     |*/
/*|  Project WSP, WSPnG, HCU2 and HL-VPN V2                           |*/
/*|  KB 08.05.08                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  Unix / Linux GCC and others                                      |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

#ifndef LEN_DISP_INETA
//#define LEN_DISP_INETA 40
#define LEN_DISP_INETA 56
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

#ifndef HL_TCP_SYNC_01
#define HL_TCP_SYNC_01

#ifndef TCPSYNC_ERR_BASE
#define TCPSYNC_ERR_BASE               80000
#endif
#define TCPSYNC_ERR_CREATEEVENT        (TCPSYNC_ERR_BASE + 0)
#define TCPSYNC_ERR_EVENTSELECT        (TCPSYNC_ERR_BASE + 1)
#define TCPSYNC_ERR_WSAWAITM           (TCPSYNC_ERR_BASE + 2)
#define TCPSYNC_ERR_WSAENUMNE          (TCPSYNC_ERR_BASE + 3)
#define TCPSYNC_ERR_CONNECT_MISC       (TCPSYNC_ERR_BASE + 4)
#define TCPSYNC_ERR_TIMEOUT_SEND       (TCPSYNC_ERR_BASE + 5)
#define TCPSYNC_ERR_TIMEOUT_RECV       (TCPSYNC_ERR_BASE + 6)
#define TCPSYNC_ERR_CLOSED_OTHER_SIDE  (TCPSYNC_ERR_BASE + 7)

struct dsd_tcpsync_1 {
   int        imc_socket;                   /* TCP socket for connection */
#ifndef HL_UNIX
   WSAEVENT   dsc_event_1;                  /* WSA event for recv      */
#endif
   BOOL       boc_close_received;           /* TCP close received      */
   char       chrc_ineta_target[ LEN_DISP_INETA ];  /* for INETA target */
};

extern PTYPE BOOL m_tcpsync_connect( int *aimp_error,
                                     struct dsd_tcpsync_1 *adsp_tcpsync_1,
                                     struct dsd_bind_ineta_1 *adsp_biineta1,
                                     struct dsd_target_ineta_1 *adsp_target_ineta,
                                     int imp_port );

extern PTYPE int m_tcpsync_send_single( int *aimp_error, struct dsd_tcpsync_1 *adsp_tcpsync_1,
                                        char *achp_buffer, int imp_len_send, int imp_msec );

extern PTYPE int m_tcpsync_send_gather( int *aimp_error, struct dsd_tcpsync_1 *adsp_tcpsync_1,
                                        struct dsd_gather_i_1 *adsp_gai1_inp,
                                        struct dsd_gather_i_1 **aadsp_gai1_out,
                                        int imp_msec );

extern PTYPE int m_tcpsync_recv( int *aimp_error, struct dsd_tcpsync_1 *adsp_tcpsync_1,
                                 char *achp_buffer, int imp_len_recv, int imp_msec );

extern PTYPE int m_tcpsync_close( int *aimp_error, struct dsd_tcpsync_1 *adsp_tcpsync_1 );

#endif
