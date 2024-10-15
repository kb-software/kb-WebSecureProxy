//#ifndef HOSHSSTP_H_INC
#define HOSHSSTP_H_INC

#define MAX_HSSTP_MSGLEN 1024 * 16

#define MS_CHAP_V2

class dsd_sstp_session;

struct dsd_sstp_wrap {
   dsd_sstp_session*	adsc_sstp_session;
   dsd_ppp_server_1		dsc_ppp_se_1;      // Associated PPP session.
   dsd_timer_ele		dsc_timer_close;   // Timer for PPP session close.
   dsd_hco_wothr*		adsp_hco_wothr;
};

inline dsd_sstp_session* m_sstp_session_from_s1(dsd_ppp_server_1* adsp_ppp_se_1)
{
   dsd_sstp_wrap* adsl_sstp_wrap = (dsd_sstp_wrap*)
      ((char*)adsp_ppp_se_1 - offsetof(dsd_sstp_wrap, dsc_ppp_se_1));
   return adsl_sstp_wrap->adsc_sstp_session;
}

inline dsd_sstp_session* m_sstp_session_from_te(dsd_timer_ele* adsp_timer_ele)
{
   dsd_sstp_wrap* adsl_sstp_wrap = (dsd_sstp_wrap*)
      ((char*)adsp_timer_ele - offsetof(dsd_sstp_wrap, dsc_timer_close));
   return adsl_sstp_wrap->adsc_sstp_session;
}

// Class representing an SSTP session.
class dsd_sstp_session : public dsd_session
{

private:

   // SSTP FSM states.
   enum ied_sstp_state
   {
      ied_sstp_state_waithttp,
      ied_sstp_state_waitcallconnreq,
      ied_sstp_state_waitcallconnected,
      ied_sstp_state_connected
   };

   // SSTP version
   static const char SSTP_VERSION_BYTE  = 0x10;


   // SSTP control/data byte
   static const char SSTP_CONTROL_BYTE	= 0x01;
   static const char SSTP_DATA_BYTE		= 0x00;


   // SSTP control message types.
   static const uint16_t SSTP_MSG_CALL_CONNECT_REQ    = 0x0100;
   static const uint16_t SSTP_MSG_CALL_CONNECT_ACK    = 0x0200;
   static const uint16_t SSTP_MSG_CALL_CONNECTED      = 0x0400;
   static const uint16_t SSTP_MSG_CALL_ABORT          = 0x0500;
   static const uint16_t SSTP_MSG_CALL_DISCONNECT     = 0x0600;
   static const uint16_t SSTP_MSG_CALL_DISCONNECT_ACK = 0x0700;
   static const uint16_t SSTP_MSG_ECHO_REQ            = 0x0800;
   static const uint16_t SSTP_MSG_ECHO_ACK            = 0x0900;

   // SSTP control message attribute types.
   static const byte SSTP_ATTR_ENCAPSULATED_PROTO = 0x01;
   static const byte SSTP_ATTR_CRYPTO             = 0x03;
   static const byte SSTP_ATTR_CRYPTO_REQ         = 0x04;

   // Encapsulated Protocol attribute values.
   static const uint16_t SSTP_ATTR_ENCAPSULATED_PROTO_PPP = 0x0100;

   // Certificate Hash Protocol values.
   static const byte HASH_PROTO_SHA1   = 0x01;
   static const byte HASH_PROTO_SHA256 = 0x02;

   // Current SSTP FSM state.
   ied_sstp_state   iec_sstp_state;
   dsd_ppp_client_1 dsc_ppp_cl_1;

   // Pointers to the buffer queue
   struct dsd_packet *adsc_queue_first;
   struct dsd_packet *adsc_queue_last;

   // Memory for handing over data to the PPP implementation
#ifdef B150706
   char chrc_work1[1500];
#endif
   char chrc_work1[ 4096 ];
   // TODO - chrch_work1 large enough?

   // Number of pkts queued waiting for bol_cansend
   unsigned int umc_packets_list;

   // Target filter for this PPP session.
   dsd_targfi_1* adsc_targ_filter;
   // Active target filter.
   struct dsd_ppp_targfi_act_1* adsc_ppp_targfi_act;

   // Whether LCP negotiation has been kicked off
   BOOL boc_lcp_sent;

   BOOL boc_crypto_ok;


   // 32 bytes for random Nonce
   byte byrc_nonce[32];

   // Critical section to synchronize the clean up
   dsd_hcla_critsect_1 dsc_cs;


public:

   dsd_sstp_wrap    dsc_sstp_wrap;
   uint32_t         umc_client_ineta;  // Client VINETA.
   uint32_t         umc_discard_count; // Number of messages discarded.
#ifdef ML150205
   // Queue for messages which are to be sent to the client over the external
   // network.
   std::queue<dsd_queued_msg> dsc_sendto_extnw_msgq;
#endif

private:

   //
   // Writes a Disconnect Ack SSTP control message.
   // Writes to a buffer an SSTP Disconnect Ack control message. The buffer
   // which is written to is referenced by adsp_buf_vec. The Disconnect Ack SSTP
   // control message indicates to the client that his request to terminate the
   // session has been received and accepted.
   //
   // @param  adsp_buf_vec  Pointer to the dsd_buf_vector_ele containing the
   //                       buffer to write to.
   //
   void mc_make_sstp_disconnect_ack(dsd_buf_vector_ele *adsp_buf_vec);

   //
   // Writes a Call Abort SSTP control message.
   // Writes to a buffer an SSTP Call Abort control message. The buffer which is
   // written to is referenced by adsp_buf_vec. The Call Abort SSTP control
   // message requests the client to abort the session.
   //
   // @param  adsp_buf_vec  Pointer to the dsd_buf_vector_ele containing the
   //                       buffer to write to.
   //
   void mc_make_sstp_call_abort(dsd_buf_vector_ele* adsp_buf_vec);

   //
   // Aborts the SSTP session.
   // Terminates the entire session by generating an SSTP Call Abort message and
   // sending it to the client.
   //
   void mc_abort_sstp_conn();

public:

   //
   // Default constructor.
   // Not implemented.
   //
   dsd_sstp_session();

   //
   // Constructor.
   // Initializes the SSTP session object.
   //
   // @param  adsp_sess_info  Configuration for the new session.
   //
   dsd_sstp_session(dsd_tun_start_ppp * adsp_tun_start1,
                    dsd_tun_contr_conn* adsp_sess_info,
                    dsd_tun_contr_ineta* adsp_ineta_info);

   //
   // Copy constructor.
   // Not implemented.
   //
   dsd_sstp_session(const dsd_sstp_session& dsp_orig);

   //
   // Copy assignment operator.
   // Not implemented.
   //
   const dsd_sstp_session& operator=(const dsd_sstp_session& dsp_rhs);

   //
   // Destructor.
   // Performs the necessary cleanup.
   //
   ~dsd_sstp_session();

   //
   // Initializes the SSTP session.
   // Must be called before any other methods are called on the object. Performs
   // any initialisation of the object which might possibly fail.
   //
   // @return  Returns a value which is < 0 on faliure.
   //
   virtual int32_t mc_init();

   virtual void mc_close();

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
   virtual int32_t mc_interpret_msg(dsd_gather_i_1* adsp_gather,
                                    dsd_hco_wothr*  adsp_hco_wothr);

   //
   // Adds an SSTP header to the data.
   // Encapsulates the data in an SSTP header, and sends the message over to
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
   virtual int32_t mc_encapsulate_msg(void*  ap_handle,
                                      byte*    abyp_data,
                                      uint32_t ump_length);

   virtual int32_t mc_tunnel_to_cl(void*    ap_handle,
                           byte*    abyp_data,
                           uint32_t ump_length);


   //
   // Adds an SSTP header to the data.
   // Encapsulates the data in an SSTP header, and sends the message over to
   // the session client.
   //
   // @param  adsp_vector  Buffer containing data to be encapsulates and sent.
   //
   void mc_sstp_tunnel_data(void*  ap_handle,
	                        byte*  abyp_data,
                            unsigned int ump_length);


#ifndef callback_hs_compl
   //
   // Create target_filter from CallBack function
   //
   void mc_auth_compl();
#endif



};

//#endif
