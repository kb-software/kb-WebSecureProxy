#ifndef HOBHPPP_H_INC
#define HOBHPPP_H_INC

#include "hob-session01.h"

#define MAX_HOBPPPT1_MSGLEN 1024 * 16

class dsd_ppp_session;

struct dsd_ppp_wrap {
   dsd_ppp_session* adsc_ppp_session;
   dsd_ppp_server_1 dsc_ppp_se_1;      // Associated PPP session.
   dsd_timer_ele    dsc_timer_close;   // Timer for PPP session close.
};

struct dsd_packet{
	dsd_buf_vector_ele dsl_buf_vec;
	dsd_packet *adsc_next;
};


inline dsd_ppp_session* m_ppp_session_from_s1(dsd_ppp_server_1* adsp_ppp_se_1)
{
   dsd_ppp_wrap* adsl_ppp_wrap = (dsd_ppp_wrap*)
      ((char*)adsp_ppp_se_1 - offsetof(dsd_ppp_wrap, dsc_ppp_se_1));
   return adsl_ppp_wrap->adsc_ppp_session;
}

inline dsd_ppp_session* m_ppp_session_from_te(dsd_timer_ele* adsp_timer_ele)
{
   dsd_ppp_wrap* adsl_ppp_wrap = (dsd_ppp_wrap*)
      ((char*)adsp_timer_ele - offsetof(dsd_ppp_wrap, dsc_timer_close));
   return adsl_ppp_wrap->adsc_ppp_session;
}

// HOB-PPP-T1 session class.
struct dsd_ppp_session
{
    enum ied_hpppt1_conn_state iec_conn_state;
   // Control handle for application.
   dsd_tun_contr_conn* adsc_tun_contr_conn;
   // Client VINETA.
   dsd_tun_contr_ineta* adsc_tun_contr_ineta;
   // Location where WSP can find this.
   dsd_htun_handle dsc_htun_handle;
   // Indicates whether session has been closed.
   BOOL boc_sess_closed;
   // Signaled when data can be sent to client.
   BOOL boc_cansend;
   // Target filter for this PPP session.
   dsd_targfi_1* adsc_targ_filter;
   // Active target filter.
   struct dsd_ppp_targfi_act_1* adsc_ppp_targfi_act;
   // Index of internal network interface associated with this session.
   //uint32_t umc_if_idx;
   // Buffer for error and warning messages.
   char chrc_last_error[256];

#define TRY_140519_01
#ifdef TRY_140519_01	
   int imc_len_session_owner;
#ifndef ML150114
   char chrc_session_owner[1024];
#endif
#endif

#ifndef ML150126  // random tunnel ID
   uint32_t umc_tunnel_id;
#endif

#ifdef B150706
   char chrc_wrk[1024];
#endif
   char chrc_wrk[ 4096 ];


   dsd_ppp_wrap   dsc_ppp_wrap;
   uint32_t         umc_discard_count;     // Number of messages discarded.
   uint32_t         umc_discard_count_tf;  // Number of messages discarded because of target filter.
   uint32_t         umc_discard_count_cli; // Number of messages discarded by client.
   uint32_t         umc_s_nw_ineta;        // Server internal network ineta.
   uint32_t         umc_s_nw_mask;         // Server internal network netmask.
   // Queue for messages which are to be sent to the client over the external
   // network.
   struct dsd_packet *adsc_queue_first;
   struct dsd_packet *adsc_queue_last;
   int umc_packets_list;

   dsd_hcla_critsect_1 dsc_cs; // General critical section for session.
   BOOL boc_ppp_svr_started;

#ifdef QUICKFIX16112010
   // Workaround.
   int32   imc_i;
   BOOLEAN boc_b;
#endif

#ifdef QUICKFIX18112010
   BOOLEAN boc_ppp_svr_started;
#endif

   //
   // Default constructor.
   // Not implemented.
   //
   dsd_ppp_session();

   //
   // Constructor.
   // Initializes the HOB-PPP-T1 session object.
   //
   // @param  adsp_sess_info  Configuration for the new session.
   //
   dsd_ppp_session(dsd_tun_start_ppp* adsp_tun_start_ppp,
                   dsd_tun_contr_conn* adsp_tun_contr_conn,
                   dsd_tun_contr_ineta* adsp_tun_contr_ineta);

   //
   // Copy constructor.
   // Not implemented.
   //
   dsd_ppp_session(const dsd_ppp_session& dsp_orig);

   //
   // Assignment operator.
   // Not implemented.
   //
   const dsd_ppp_session& operator=(dsd_ppp_session& dsp_rhs);

   //
   // Destructor.
   // Performs the necessary cleanup.
   //
   ~dsd_ppp_session();

   //
   // Initializes the PPP session.
   // Must be called before any other methods are called on the object. Performs
   // any initialisation of the object which might possibly fail.
   //
   // @return  Returns a value which is < 0 on faliure.
   //
   int32_t mc_init();


   void mc_close();

   //
   // Processes the message header.
   // Reads the contents of the message header and updates the session
   // accordingly. Depending on the header contents, this can trigger a
   // response to the session client, the transfer of data over the internal
   // network, or the updating of the session object.
   //
   // @param  adsp_gather  Gather struct containing message to be interpreted.
   // @param  adsp_hco_wothr  Pointer to the calling workthread.
   //
   // @return  Returns a value which is < 0 on faliure.
   //
   int32_t mc_interpret_msg(dsd_gather_i_1* adsp_gather,
                                    dsd_hco_wothr*  adsp_hco_wothr);

   //
   // Sends the RESPONSE-START message to the HOB-PPP-T1 client.
   // Writes and sends a RESPONSE-START message to the client. This message is
   // meant to be sent upon receipt of a START message, and contains the ID of the tunnel
   // created and the network address and netmask for the server's internal network.
   //
   // @return  Returns TRUE if the call succeeded.
   //
   BOOL mc_send_responsestart();

   //
   // Called when more data can be sent.
   //
   void mc_can_send();

   //
   // Adds a PPP header to the data.
   // Encapsulates the data in a PPP header, and sends the message over to
   // the session client.
   //
   // @param  ap_handle   Handle to the buffer containing the data to
   //                     encapsulate.
   // @param  aucp_data   Pointer to the buffer containing the data to
   //                     encapsulate.
   // @param  ump_length  Length, in bytes, of the data to encapsulate.
   //
   // @return  Returns a value which is < 0 on faliure.
   //
   int32_t mc_encapsulate_msg(void*    ap_handle,
                                      byte*    abyp_data,
                                      uint32_t ump_length);

   //
   // Adds an HTUN header to the data.
   // Encapsulates the passed data in an HTUN header.
   //
   // @param  adsp_buf_vec  Buffer containing data to encapsulate.
   //
   void mc_make_htun(dsd_buf_vector_ele* adsp_buf_vec);

   int32_t mc_tunnel_to_cl(void*    ap_handle,
                           byte*    abyp_data,
                           uint32_t ump_length);

   BOOL mc_send_nop();

   BOOL mc_send_stop();

};

#endif
