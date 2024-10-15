//+-------------------------------------------------------------------+
//|                                                                   |
//| PROGRAM NAME: hob-tun01.h                                         |
//| -------------                                                     |
//|  HOB Header file for TUN component of HOB Framework               |
//|    WebSecureProxy and HOBLink VPN                                 |
//|  KB 17.11.07                                                      |
//|                                                                   |
//| COPYRIGHT:                                                        |
//| ----------                                                        |
//|  Copyright (C) HOB Germany 2007                                   |
//|  Copyright (C) HOB Germany 2008                                   |
//|  Copyright (C) HOB Germany 2009                                   |
//|  Copyright (C) HOB Germany 2010                                   |
//|  Copyright (C) HOB Germany 2011                                   |
//|  Copyright (C) HOB Germany 2012                                   |
//|  Copyright (C) HOB Germany 2013                                   |
//|  Copyright (C) HOB Germany 2014                                   |
//|  Copyright (C) HOB Germany 2015                                   |
//|                                                                   |
//| REQUIRED PROGRAMS:                                                |
//| ------------------                                                |
//|  MS Visual Studio 2005 (VC8)                                      |
//|  GCC all platforms                                                |
//|                                                                   |
//|  Changes:                                                         |
//|  28.11.2007  Wu  some more functions and comments                 |
//|  13.12.2007  Du  some more comments                               |
//|                                                                   |
//|                                                                   |
//+-------------------------------------------------------------------+

#ifndef HOBTUN_H_INC
#define HOBTUN_H_INC

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

#ifdef OLD01
#if defined WIN32 || WIN64
#include <windows.h>
#endif
#endif

#ifndef UNSIG_MED
#define UNSIG_MED unsigned int
#endif

#define HTCP_ERR_BASE                  60000
#define HTCP_ERR_CANCELLED            (HTCP_ERR_BASE + 0)
#define HTCP_ERR_CONN_REFUSED         (HTCP_ERR_BASE + 1)
#define HTCP_ERR_CONN_TIMEOUT         (HTCP_ERR_BASE + 2)
#define HTCP_ERR_CONN_ALL_REFUSED     (HTCP_ERR_BASE + 3)
#define HTCP_ERR_CONN_ALL_TIMEOUT     (HTCP_ERR_BASE + 4)
#define HTCP_ERR_CONN_ALL_RF_TO       (HTCP_ERR_BASE + 5)
#define HTCP_ERR_SESS_END_FIN         (HTCP_ERR_BASE + 10)
#define HTCP_ERR_SESS_END_RST         (HTCP_ERR_BASE + 11)
#define HTCP_ERR_SESS_END_TIMEOUT     (HTCP_ERR_BASE + 12)
#define HTCP_ERR_INTERNAL_ERROR       (HTCP_ERR_BASE + 13)

// TUN control type
enum ied_tunc_def
{
   ied_tunc_invalid = 0,                    /* invalid                 */
   ied_tunc_htcp,                           /* HTCP                    */
   ied_tunc_ppp,                            /* PPP - HOB-PPP-T1        */
   ied_tunc_sstp                            /* SSTP                    */
};

/* we need only one type of handle 24.09.08 KB                         */
typedef void *dsd_tun_htcp_h;                // HTCP handle
typedef void *dsd_tun_ppp_h;                 // PPP handle
typedef void *dsd_tun_sstp_h;                // SSTP handle
typedef void * dsd_htun_h;                  /* HTUN handle             */

#ifndef DEF_HL_STR_G_I_1
#define DEF_HL_STR_G_I_1

// gather input data
struct dsd_gather_i_1
{
  struct dsd_gather_i_1 *adsc_next;          // next in chain
  char *                achc_ginp_cur;       // current position
  char *                achc_ginp_end;       // end of input data
};

#endif

/* to be replaced later 24.09.08 KB - start                            */
// configured INETA IP Address
struct dsd_ineta_conf_1
{
  int  imc_family;                           // address family - IPV4 or IPV6
  char chrc_ineta[16];                       // virtual ip INETA
};
/* to be replaced later 24.09.08 KB - end                              */

#ifdef HL_UNIX
#ifdef D_INCL_TUN_CTRL
struct dsd_tun_ctrl {                       /* HOB-TUN control area    */
#ifdef HL_LINUX
   int        imc_ifindex_nic_ipv4;         /* interface number of NIC IPV4 */
   int        imc_ifindex_nic_ipv6;         /* interface number of NIC IPV6 */
#endif
   int        imc_fd_tun;                   /* file-descriptor TUN adapter */
   BOOL       boc_tun_opened;               /* TUN-adapter successful opened */
   int        imc_tun_socket;               /* socket for HOB-TUN      */
#ifdef HL_FREEBSD
   int        imc_route_socket;             /* socket for HOB-TUN ARP and route */
   int        imc_bpf_fd;                   /* file-descriptor for bpf - Berkeley Packet Filter */
#endif
   char       *achc_ta_ineta_ipv4;          /* entry <TUN-adapter-ineta> IPV4 */
   char       *achc_ta_ineta_ipv6;          /* entry <TUN-adapter-ineta> IPV6 */
#ifdef HL_LINUX
   char       chrc_tiface[ IFNAMSIZ ];      /* name of tun interface   */
   char       chrc_riface[ IFNAMSIZ ];      /* name of real interface  */
   struct sockaddr dsc_rhwaddr;             /* real interface mac addr */
#endif
#ifdef HL_FREEBSD
   struct sockaddr_dl dsc_soa_dl_r;         /* real interface mac addr */
   struct sockaddr_dl dsc_soa_dl_t;         /* tun interface mac addr  */
   char       chrc_riface[ IFNAMSIZ ];      /* name of real interface  */
#endif
};
#endif

extern "C" struct dsd_tun_ctrl dsg_tun_ctrl;
#endif

#ifndef HL_UNIX

// dsd_tun_ctrl:: boc_started is TRUE if, and only if an adapter was found,
// was opened and initialization worked.
//
// If initialization failed but the adapter was still installed and/or opened,
// dsd_tun_ctrl::boc_started is FALSE but dsd_tun_ctrl::dsc_handle and
// dsd_tun_ctrl::imc_instance_id are set in order to allow for proper cleanup!
//
// Note that the driver never assigns an InstanceId of 0!

struct dsd_tun_ctrl {                       /* HOB-TUN adapter information structure */
   BOOL       boc_started;                  /* TUN-Adapter successfully initialized  */
   HANDLE     dsc_handle;                   /* handle TUN adapter                    */
   int        imc_instance_id;              /* TUN adapter instance identifier       */
   BOOL       boc_with_nic_macaddr;         /* macaddr NIC is included */
   char       chrc_nic_macaddr[6];          /* macaddr NIC             */

};
#endif

// struct for configuration of INETAs
struct dsd_wsptun_conf_1 {
   BOOL       boc_use_ipv4;                 /* use IPV4                */
   BOOL       boc_use_ipv6;                 /* use IPV6                */
   char       chrc_ipv4_dns_pri[4];         /* primary DNS INETA IPV4  */
   char       chrc_ipv4_dns_sec[4];         /* secondary DNS INETA IPV4 */
   char       chrc_ipv4_nbns_pri[4];        /* primary wins INETA IPV4 */
   char       chrc_ipv4_nbns_sec[4];        /* secondary wins INETA IPV4 */
   char       chrc_ipv6_dns_pri[16];        /* primary DNS INETA IPV6  */
   char       chrc_ipv6_dns_sec[16];        /* secondary DNS INETA IPV6 */
   char       chrc_ipv6_nbns_pri[16];       /* primary wins INETA IPV6 */
   char       chrc_ipv6_nbns_sec[16];       /* secondary wins INETA IPV6 */
};

#ifndef HL_UNIX
enum ied_strategy_inst_win_driver {         /* strategy install - uninstall Windows TUN driver */
   ied_siwd_invalid = 0,                    /* invalid value           */
   ied_siwd_no_inst_uninst,                 /* no install or uninstall */
   ied_siwd_only_inst,                      /* only install when needed */
   ied_siwd_uninst_startup,                 /* uninstall at startup    */
   ied_siwd_uninst_all                      /* uninstall all possible  */
};
#endif

/**
  the ports adsc_appl_port_conf are sorted in ascending order
  if boc_random_appl_port is set, otherwise not.
*/
struct dsd_raw_packet_if_conf {             /* configuration raw-packet-interface */
   struct dsd_tun_ineta_1 *adsc_tun_ineta_1;  /* chain range of INETAs used by TUN */
   struct dsd_pool_ineta_1 *adsc_pool_ineta_1;  /* chain of pools of INETAs */
   struct dsd_appl_port_conf *adsc_appl_port_conf;  /* configured ports for appl */
#ifndef HL_UNIX
   WCHAR      *awcc_driver_fn;              /* filename of driver for installation */
#endif
#ifdef B130109
   UNSIG_MED  umc_ta_ineta_local;           /* <TUN-adapter-ineta>     */
#ifdef B100912
   UNSIG_MED  umc_ta_ineta_remote;          /* <TUN-adapter-ineta>     */
   UNSIG_MED  umc_ta_ineta_mask;            /* <TUN-adapter-ineta>     */
#endif
   UNSIG_MED  umc_taif_ineta;               /* <TUN-adapter-use-interface-ineta> */
#endif
/* new 06.01.13 KB - start                                             */
   int        imc_no_ta_ineta_ipv4;         /* <TUN-adapter-ineta> IPV4 */
   int        imc_no_ta_ineta_ipv6;         /* <TUN-adapter-ineta> IPV6 */
   char       *achc_ar_ta_ineta_ipv4;       /* array <TUN-adapter-ineta> IPV4 */
   char       *achc_ar_ta_ineta_ipv6;       /* array <TUN-adapter-ineta> IPV6 */
   UNSIG_MED  umc_taif_ineta_ipv4;          /* <TUN-adapter-use-interface-ineta> IPV4 */
   char       chrc_taif_ineta_ipv6[ 16 ];   /* <TUN-adapter-use-interface-ineta> IPV6 */
#ifndef HL_UNIX
   enum ied_strategy_inst_win_driver iec_siwd;  /* strategy install - uninstall Windows TUN driver */
#endif
/* new 06.01.13 KB - end                                               */
   int        imc_tcpc_to_msec;             /* <TCP-connect-timeout-millisec> */
   int        imc_tcpc_try_no;              /* <TCP-connect-number-of-try> */
   int        imc_no_ele_appl_port_conf;    /* number of elements configured ports for appl */
   BOOL       boc_random_appl_port;         /* <appl-use-random-tcp-source-port> */
   BOOL       boc_c_tun_ipv4;               /* configured TUN IPV4     */
   BOOL       boc_c_tun_ipv6;               /* configured TUN IPV6     */
   struct dsd_wsptun_conf_1 dsc_wsptun_conf_1;  /* TUN PPP INETAs      */
};

// buffer vector element
struct dsd_buf_vector_ele
{
  void *ac_handle;                          // handle of buffer
  char *achc_data;                          // address of data in this buffer
  int  imc_len_data;                        // length of data in this buffer
};

//struct for MS-CHAP-V2 user credentials
// to be removed since handled in WSP PPP module 29.11.08 KB
struct dsd_usrcredents_mschap2
{
   unsigned char  ucrc_un[256];             //null terminated username
   unsigned char  ucrc_pw_md4[16];          //md4 peer password hash
};


#ifdef B130123
enum ied_ppp_auth_rc {                      /* PPP authentication return code */
   ied_pppar_ok = 0,                        /* authentication was checked O.K. */
   ied_pppar_userid_inv,                    /* userid invalid          */
   ied_pppar_password_inv,                  /* password invalid        */
   ied_pppar_auth_failed,                   /* authentication failed   */
   ied_pppar_misc                           /* miscellaneous           */
};
#endif


/**
   in struct dsd_tun_contr_ineta it needs to be checked if
   sin_family is set to AF_INET and if sin6_family is set to AF_INETA6.
   Only when sinx_family is not equal to zero, this structure is in use.
   For HOB-TUN HTCP, either dsc_soa_local_ipv4 is valid
   or dsc_soa_local_ipv6 is valid, never both.
   For HOB-TUN PPP, there maybe one INETA IPV4 and one INETA IPV6
   at the same time. So both, dsc_soa_local_ipv4 and dsc_soa_local_ipv6
   may be vaild.

   When the HOB WebSecureProxy (WSP) starts a session using HOB-TUN HTCP
   by calling m_htun_new_sess_htcp(), three structures are passed.
   struct dsd_tun_start_htcp is used to pass parameters required only
   during startup. struct dsd_tun_start_htcp is mostly in memory located
   in the stack and is destroyed after m_htun_new_sess_htcp() returns.
   m_htun_new_sess_htcp() returns immediately, it does not call any
   blocking APIs.
   struct dsd_tun_contr_conn is alive as long as the INETA is
   bound to the WSP SSL-TCP-session to the client.
   struct dsd_tun_contr_ineta is alive as long as the INETA given in
   struct sockaddr_in dsc_soa_local_ipv4
   or struct sockaddr_in6 dsc_soa_local_ipv6 is in use.
*/

struct dsd_tun_start_htcp {                 /* HOB-TUN start interface HTCP */
   dsd_htun_h *adsc_htun_h;                 /* where to put the handle created */
   /* for HTCP connect                                                 */
   struct dsd_target_ineta_1 *adsc_server_ineta;  /* server INETA      */
   void *     ac_free_ti1;                  /* INETA to free           */
   int        imc_server_port;              /* TCP/IP port connect     */
   BOOL       boc_connect_round_robin;      /* do connect round-robin  */
   int        imc_tcpc_to_msec;             /* TCP connect timeout milliseconds */
   int        imc_tcpc_try_no;              /* TCP connect number of try */
   BOOL       boc_tcp_keepalive;            /* TCP KEEPALIVE           */
#ifdef XYZ1
   /* for PPP                                                          */
   struct dsd_wsptun_conf_1 *adsc_wsptun_conf_1;  /* TUN PPP INETAs    */
   UNSIG_MED  umc_s_nw_ineta;               /* server-network-ineta    */
   UNSIG_MED  umc_s_nw_mask;                /* server-network-mask     */
#endif
};

struct dsd_tun_start_ppp {                  /* HOB-TUN start interface PPP */
   dsd_htun_h *adsc_htun_h;                 /* where to put the handle created */
   /* for PPP                                                          */
// struct dsd_wsptun_conf_1 *adsc_wsptun_conf_1;  /* TUN PPP INETAs    */
   UNSIG_MED  umc_s_nw_ineta_ipv4;          /* server-network-ineta    */
   UNSIG_MED  umc_s_nw_mask_ipv4;           /* server-network-mask     */
};

struct dsd_tun_contr_conn {                 /* HOB-TUN control interface for connection */
   enum ied_tunc_def iec_tunc;              /* HOB-TUN interface type  */
   int        imc_sno;                      /* session number          */
   int        imc_trace_level;              /* WSP trace level         */
   BOOL       boc_not_drop_tcp_packet;      /* do not drop TCP packets */
   int        imc_on_the_fly_packets_client;  /* number of packets on the fly to the client */
#ifdef NOT_YET_120911
   union {
     char chrc_htcp_session[ sizeof(class dsd_htcp_session) ];  /* for HTCP */
     char chrc_ppp_session [ sizeof(class dsd_ppp_session ) ];  /* for PPP */
     char chrc_sstp_session[ sizeof(class dsd_sstp_session) ];  /* for SSTP */
// 12.06.12 KB HOB coding-standards - should be dsc_session_buffer
// beginning a means address = pointer, but is no address
   } achc_session_buffer;
#endif
   void *     vpc_htun_userfld;             /* userfield for HOB-TUN   */
};

struct dsd_tun_contr_ineta {                /* HOB-TUN control interface for INETA */
   struct dsd_tun_contr_conn *adsc_tun_contr_conn;  /* HOB-TUN control interface for connection */
   struct sockaddr_in dsc_soa_local_ipv4;   /* address information INETA to be used locally */
   struct sockaddr_in6 dsc_soa_local_ipv6;  /* address information INETA to be used locally */
};

#ifdef B120923
#ifdef HL_UNIX
struct dsd_tun_main_contr {                 /* HOB-TUN main control interface */
   int        imc_fd_tun;                   /* file descriptor TUN adapter */
   BOOL       boc_tun_active;               /* TUN is active and initialized */
};
#endif
#endif

/**
 * Finds & opens an existing and available TUN adapter.
 * Calling this function instructs the system to find an available and unused
 * TAP-WIN32 virtual adapter. Once found, the adapter is opened, and its status
 * is set to connected.
 *
 * @return  True if successful, False if otherwise.
 */
extern PTYPE BOOL m_htun_start( struct dsd_raw_packet_if_conf *, struct dsd_tun_ctrl * );

/**
 * Closes the opened TUN device.
 * This sub routine is called in order to close the currently opened TUN device.
 */

#ifdef B130922
#ifndef HL_UNIX
extern PTYPE BOOL m_htun_end( struct dsd_raw_packet_if_conf *adsp_raw_packet_if_conf,
                              struct dsd_tun_ctrl *adsp_tun_ctrl);
#else
extern PTYPE void m_htun_end(void);
#endif
#else
extern PTYPE BOOL m_htun_end( struct dsd_raw_packet_if_conf *adsp_raw_packet_if_conf,
                              struct dsd_tun_ctrl *adsp_tun_ctrl);
#endif

/**
 * Create new PPP, SSTP or HTCP session.
 * This function creates a new PPP, SSTP or HTCP session with the connecting
 * client. It returns a handle to the session which must be used as a key
 * whenever data needs to be transfered from the connecting client to the
 * internal network. This function should be called by the WSP when it is
 * required to set up a session between itself and a client.
 *
 * @param  adsp_tun_contr1  Struct containing information required to set up
 *                          the session.
 * @param  adsp_saddr       Only required for HTCP sessions. Pass NULL
 *                          otherwise.
 * @param  ulp_ifaddr       INETA of the internal network interface to be
 *                          used with this session.
 * @param  adsp_auth_info   User credentials for MS-CHAP-V2 PPP authentication.
 * @param  abop_ipok        After the routine returns, the value pointed to
 *                          by this pointer will be TRUE if the specified
 *                          VINETA was available for use, and FALSE if the
 *                          address was already in use.
 * @return  Returns a handle to the newly created session.
 */
extern PTYPE void m_htun_new_sess_htcp( struct dsd_tun_start_htcp *,
                                        struct dsd_tun_contr_conn *,
                                        struct dsd_tun_contr_ineta * );

extern PTYPE void m_htun_new_sess_ppp( struct dsd_tun_start_ppp *,
                                       struct dsd_tun_contr_conn * );

/**
   called from HTCP when the connect to the target failed.
   IBIPGW08 may give multiple INETAs, and so HTCP can try all INETAs.
   For each connect that fails the routine m_htun_htcp_connect_failed()
   is called, so that IBIPGW08 can give the necessary information
   to the administrator.
   02.10.08 KB
*/
extern PTYPE void m_htun_htcp_connect_failed( struct dsd_tun_contr_conn *adsp_tun_contr_conn,
   struct sockaddr *, socklen_t, int imp_current_index, int imp_total_index, int imp_errno );

/**
   called from HTCP when the connect to the target ended, either because
   the connect succeeded or all connects (multiple INETAs) have failed.
   imp_errno zero means the connect succeeded.
*/
extern PTYPE void m_htun_htcp_connect_end( struct dsd_tun_contr_conn *adsp_tun_contr_conn,
   struct dsd_target_ineta_1 *adsp_server_ineta,
   void * ap_free_ti1,                      /* INETA to free           */
   struct sockaddr *, socklen_t,
   int imp_errno );

/**
   give a warning on a session using HOB-TUN
   either adsp_tun_contr_conn or adsp_tun_contr_ineta are not NULL
*/
extern PTYPE void m_htun_warning( struct dsd_tun_contr_conn *adsp_tun_contr_conn,
                                  struct dsd_tun_contr_ineta *adsp_tun_contr_ineta,
                                  int imp_error_number,
                                  const char *achp_format, ... );
/**
 * Sends data towards the internal network over an opened session.
 * Interprets the headers within a message, and decapsulates the IP packet.
 * Then sends the decapsulated IP packet over the internal network. If the
 * message does not contain any IP packets, it might be a control message.
 * In such a case, this call might cause the session object to send other
 * control messages in response to the client.
 *
 * @param  dsp_session  Handle to the session.
 * @param  adsp_gather  Pointer to the first relevant gather structure.
 */
/**
   what will happen if IBIPGW08 gives records which are not complete
   because there is still something missing which will be received later?
   IBIPGW08 does not know about the record structure of HOB-PPP-T1 or SSTP.
   The solution is that m_htun_sess_send() just sets achc_ginp_cur in
   struct dsd_gather_i_1 only as far as m_htun_sess_send()
   could process the data. Later, when IBIPGW08 did receive more from the
   client, m_htun_sess_send() will be called again giving the remaining
   data plus the new data.
   02.10.08 KB
*/
extern PTYPE void m_htun_sess_send( struct dsd_hco_wothr *,
                                    dsd_htun_h dsp_session,
                                    struct dsd_gather_i_1* adsp_gather );

extern PTYPE void m_htun_htcp_send_complete( struct dsd_tun_contr_conn *adsp_tun_contr_conn );

extern PTYPE void m_htun_ppp_set_auth( struct dsd_tun_contr_conn *adsp_tun_contr_conn, char *achp_ppp_auth );

/**
 * Closes a PPP, SSTP or HTCP session.
 * Finds the session node pointed to by the handle passed as parameter, and
 * The session object referenced by this session node is also deleted.
 *
 * @param  dsp_husip_sess  Session handle pointing to the session to be deleted
 *                         and closed. Must be obtained by calling
 *                         m_htun_new_sess_htcp() or m_htun_new_sess_ppp().
 */
extern PTYPE void m_htun_sess_close(dsd_htun_h dsp_husip_sess);

extern PTYPE void m_htun_session_end( struct dsd_tun_contr_conn *adsp_tun_contr_conn,
                                      int imp_reason );

extern PTYPE void m_htun_htcp_free_resources( struct dsd_tun_contr_ineta *adsp_tun_contr_ineta );

extern PTYPE struct dsd_tun_contr_ineta *
     m_htun_ppp_acquire_local_ineta_ipv4( struct dsd_hco_wothr *,
                                          struct dsd_tun_contr_conn *,
                                          struct dsd_tun_contr_ineta * );

extern PTYPE void m_htun_ppp_free_resources( struct dsd_tun_contr_ineta *adsp_tun_contr_ineta );

//extern PTYPE struct dsd_targfi_1 * m_htun_ppp_get_targfi( struct dsd_tun_contr_conn * );
extern PTYPE struct dsd_targfi_1 * m_htun_ppp_get_targfi( struct dsd_tun_contr_conn * );

/**
 * Sends data traveling over an opened session towards the client.
 * Sends messages belonging to any of the opened sessions torwards the
 * session client. Session messages might be PPP, SSTP or HTCP messages
 * and might be control or data messages. In any case, the messages are
 * sent towards the client.
 *
 * @param  adsp_tctl       Handle to the session.
 * @param  adsp_vector     First in a list of elements containing the message to
 *                         be sent to the client.
 * @param  imp_ele_vector  Number of elements in the list.
 *
 * @return  Returns TRUE if it is safe to continue sending messages towards the
 *          session client. Returns FALSE if no more messages can be handled. To
 *          resume the sending of messages, call m_se_cansend().
 */
extern PTYPE BOOL m_se_htun_recvbuf(struct dsd_tun_contr_conn* adsp_tctl,
                                    struct dsd_buf_vector_ele* adsp_vector,
                                    int                        imp_ele_vector );

/**
 * Returns a buffer to store messages for transfer to a session client.
 *
 * @param  aap_handle    When the call returns, this will contain a handle to
 *                       the buffer.
 * @param  aachp_buffer  When the call returns, this will contain a pointer to
 *                       the start of the buffer.
 *
 * @return  Returns the size of the buffer in bytes.
 */
//extern PTYPE int m_tun_getrecvbuf(void** aap_handle,
//                                  char** aachp_buffer);
extern PTYPE int m_htun_getrecvbuf( void** aap_handle,
                                    char** aachp_buffer );

/**
 * Releases a buffer obtained by calling m_tun_getrecvbuf().
 *
 * @param  ap_handle  Handle to the buffer.
 */
//extern PTYPE void m_tun_relrecvbuf(void *ap_handle);
extern PTYPE void m_htun_relrecvbuf(void *ap_handle);

#ifdef B120921
/**
 * Applies a DNS and WINS configuration.
 * Sets the configuration options for DNS and WINS servers. These option values
 * will be applied to all new sessions until this function is called again with
 * a different DNS and WINS configuration. This function MUST be called once
 * before any sessions are created.
 *
 * @param  adsp_wsptun_newconfig  DNS and WINS configuration to apply.
 */
extern PTYPE void m_wsptun_reset_conf( dsd_wsptun_conf_1* adsp_wsptun_newconfig );
#endif

/**
 * Sets the 'can send' event.
 * Signals the event which indicates whether the session is allowed to send data
 * towards the client. Signalling this event indicates that it is safe to transmit
 * data towards the client.
 *
 * @param  dsp_hdl_sess  Handle to the session.
 */
extern PTYPE void m_htun_sess_canrecv(dsd_htun_h dsp_hdl_sess);

//#ifdef B120921
extern PTYPE struct dsd_wsptun_conf_1 * m_get_wsptun_conf_1();

extern PTYPE char * m_get_wsptun_ineta_ipv4_adapter();
//#endif

extern PTYPE unsigned int m_get_next_hop();

#endif
