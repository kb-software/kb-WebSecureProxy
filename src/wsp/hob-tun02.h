//+-------------------------------------------------------------------+
//|                                                                   |
//| PROGRAM NAME: hob-tun02.h                                         |
//| -------------                                                     |
//|  HOB Header file for TUN component of HOB Framework               |
//|    WebSecureProxy and HOBLink VPN                                 |
//|  KB 17.03.09                                                      |
//|                                                                   |
//| COPYRIGHT:                                                        |
//| ----------                                                        |
//|  Copyright (C) HOB Germany 2009                                   |
//|  Copyright (C) HOB Germany 2010                                   |
//|  Copyright (C) HOB Germany 2011                                   |
//|                                                                   |
//| REQUIRED PROGRAMS:                                                |
//| ------------------                                                |
//|  MS Visual Studio 2005 (VC8)                                      |
//|  GCC all platforms                                                |
//|                                                                   |
//|                                                                   |
//+-------------------------------------------------------------------+

#ifndef HOBTUN_H02_INC
#define HOBTUN_H02_INC

#define KS_18_03_09

#ifdef B100702
// TUN interface control structure
struct dsd_tun_contr1
{
  ied_tunc_def            iec_tunc;         // interface type
/* to be replaced later 24.09.08 KB - start                            */
  struct dsd_ineta_conf_1 dsc_ineta_conf_1; // configured INETA
/* to be replaced later 24.09.08 KB - end                              */
   struct sockaddr_storage dsc_soa_local;   /* address information INETA to be used locally */
   /* for HTCP connect                                                 */
   struct dsd_target_ineta_1 *adsc_server_ineta;  /* server INETA      */
   int        imc_server_port;              /* TCP/IP port connect     */
#ifndef KS_18_03_09
   class dsd_htcp_session dsc_htcp_session;  /* HTCP session           */
#else
   char chrc_htcp_session[sizeof(class dsd_htcp_session)];    /* buffer for HTCP session */
#endif
};
#endif
/**
   When the HOB WebSecureProxy (WSP) starts a session using HOB-TUN
   by calling m_htun_new_sess(), two structures are passed.
   struct dsd_tun_start1 is used to pass parameters required only
   during startup. struct dsd_tun_start1 is mostly in memory located
   in the stack and is destroyed after m_htun_new_sess() returns.
   m_htun_new_sess() returns immediately, it does not call any
   blocking APIs.
   struct dsd_tun_contr1 is alive as long as the session exists,
   permanently needed data are stored there.
   struct dsd_tun_contr1 is alive as long as the INETA given in
   struct sockaddr_storage dsc_soa_local is in use.
*/
struct dsd_tun_start1 {                     /* HTUN start interface    */
   dsd_htun_h *adsc_htun_h;                 /* where to put the handle created */
   struct sockaddr_storage dsc_soa_local;   /* address information INETA to be used locally */
   /* for HTCP connect                                                 */
   struct dsd_target_ineta_1 *adsc_server_ineta;  /* server INETA      */
   int        imc_server_port;              /* TCP/IP port connect     */
   BOOL       boc_connect_round_robin;      /* do connect round-robin  */
   /* for PPP                                                          */
   struct dsd_wsptun_conf_1 *adsc_wsptun_conf_1;  /* TUN PPP INETAs    */
   UNSIG_MED  umc_s_nw_ineta;               /* server-network-ineta    */
   UNSIG_MED  umc_s_nw_mask;                /* server-network-mask     */
};

struct dsd_tun_contr1 {                     /* HOB-TUN control interface */
   enum ied_tunc_def iec_tunc;              /* HOB-TUN interface type  */
   int        imc_sno;                      /* session number          */
   int        imc_trace_level;              /* WSP trace level         */
   BOOL       boc_not_drop_tcp_packet;      /* do not drop TCP packets */
   int        imc_on_the_fly_packets_client;  /* number of packets on the fly to the client */
   union {
     char chrc_htcp_session[ sizeof(class dsd_htcp_session) ];  /* for HTCP */
     char chrc_ppp_session [ sizeof(class dsd_ppp_session ) ];  /* for PPP */
     char chrc_sstp_session[ sizeof(class dsd_sstp_session) ];  /* for SSTP */
   } achc_session_buffer;
};

#define DEF_HTCP_SESSION(tun_contr1) ((dsd_htcp_session*)&((tun_contr1)->achc_session_buffer))
#define DEF_PPP_SESSION(tun_contr1) ((dsd_ppp_session* )&((tun_contr1)->achc_session_buffer))
#define DEF_SSTP_SESSION(tun_contr1) ((dsd_sstp_session*)&((tun_contr1)->achc_session_buffer))

#ifdef KS_18_03_09
#define TUN_CONTR_HTCP_SESSION(ads_tun_contr1)  ((dsd_htcp_session*)((ads_tun_contr1)->chrc_htcp_session))
#endif

#endif
