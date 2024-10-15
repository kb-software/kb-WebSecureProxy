#ifndef HOBSESSION_H_INC
#define HOBSESSION_H_INC

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

#if defined WIN32 || defined WIN64
#define THDRET unsigned int
#define DEFCRITSEC(x) CRITICAL_SECTION x
#define INITCRITSEC(x) InitializeCriticalSection(&x)
#define ENTERCRITSEC(x) EnterCriticalSection(&x)
#define LEAVECRITSEC(x) LeaveCriticalSection(&x)
#elif defined HL_UNIX
#define THDRET void*
#define DEFCRITSEC(x) pthread_mutex_t x
#ifndef HL_FREEBSD
#define INITCRITSEC(x)                                                     \
{                                                                          \
   pthread_mutexattr_t dsl_mattr;                                          \
   pthread_mutexattr_settype(&dsl_mattr, PTHREAD_MUTEX_RECURSIVE_NP);      \
   pthread_mutex_init(&x, &dsl_mattr);                                     \
   pthread_mutexattr_destroy(&dsl_mattr);                                  \
}
#endif
#ifdef HL_FREEBSD
#define INITCRITSEC(x)                                                     \
{                                                                          \
   pthread_mutexattr_t dsl_mattr;                                          \
   pthread_mutexattr_settype(&dsl_mattr, PTHREAD_MUTEX_RECURSIVE);         \
   pthread_mutex_init(&x, &dsl_mattr);                                     \
   pthread_mutexattr_destroy(&dsl_mattr);                                  \
}
#endif
#define ENTERCRITSEC(x) pthread_mutex_lock(&x)
#define LEAVECRITSEC(x) pthread_mutex_unlock(&x)
#define WINAPI
#define LPVOID void*
#endif

enum ied_hpppt1_conn_state
{
   ied_hpppt1_conn_idle = 0,
   ied_hpppt1_conn_started,
   ied_hpppt1_conn_ended
};

// Custom avl tree node struct.
struct dsd_avl_sess_entry
{
   // NODE HEADER.
   dsd_htree1_avl_entry dsc_avl_hdr;
   // NODE PAYLOAD.
   // Node KEY: Tunnel ID.
   uint32_t umc_key_ineta;
   // PPP session.
   void* adsc_ppp_sess;
};

//extern std::list<dsd_tun_contr_ineta*> dsg_tun_contr_ineta_list;

extern "C" void m_htun_critsect_enter( struct dsd_tun_contr_conn *adsp_tun_contr_conn );
extern "C" void m_htun_critsect_leave( struct dsd_tun_contr_conn *adsp_tun_contr_conn );

// Session class stub.
class dsd_session;

struct dsd_queued_msg
{
    BOOL bo_nodrop;
    dsd_buf_vector_ele ds_buf_vec_ele;
};

struct dsd_htun_handle {
    enum ied_tunc_def iec_tunc;
    void* vpc_contr;
};

// Abstract class to superclass all session classes (HOB-PPP-T1, SSTR & HTCP).
class dsd_session
{

public:

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
   // Index of internal network interface associated with this session.
   //uint32_t umc_if_idx;
   // Buffer for error and warning messages.
   char chrc_last_error[256];

public:

   //
   // Default Constructor.
   // Not implemented.
   //
   dsd_session();

   //
   // Constructor.
   // Initializes part of the session object.
   //
   dsd_session(dsd_tun_contr_conn* adsp_tun_contr_conn,
               dsd_tun_contr_ineta* adsp_tun_contr_ineta) :
   adsc_tun_contr_conn(adsp_tun_contr_conn),
   adsc_tun_contr_ineta(adsp_tun_contr_ineta),
   boc_sess_closed(false),
   boc_cansend(true)
   {
      dsc_htun_handle.iec_tunc = adsp_tun_contr_conn->iec_tunc;
      memset(chrc_last_error, 0, sizeof(chrc_last_error));
      //dsg_tun_contr_ineta_list.push_back(adsp_tun_contr_ineta);
   };

   //
   // Copy constructor.
   // Not implemented.
   //
   dsd_session(const dsd_session& dsp_orig);

   //
   // Copy assignment operator.
   // Not implemented.
   //
   const dsd_session& operator=(const dsd_session& dsp_rhs);

   //
   // Destructor.
   //
   virtual ~dsd_session()
   {
      /*std::list<dsd_tun_contr_ineta*>::iterator dsl_iter;
      for(dsl_iter = dsg_tun_contr_ineta_list.begin();
		  dsl_iter != dsg_tun_contr_ineta_list.end(); dsl_iter++)
	  {
		  if(*dsl_iter == adsc_tun_contr_ineta)
			  break;
	  }
      if(dsl_iter != dsg_tun_contr_ineta_list.end())
         dsg_tun_contr_ineta_list.erase(dsl_iter);*/
   };

   //
   // Initializes the session object.
   // Must be called before any other methods are called on the object. Performs
   // any initialisation of the object which might possibly fail.
   //
   // @return  Returns a value which is < 0 on faliure.
   //
   virtual int32_t mc_init() = 0;

   //
   // Called from m_htun_sess_close().
   // Defaults to calling the destructor, but can be changed.
   // Note that since destructor is virtual, correct destructor is called.
   //
   virtual void mc_close()
   {
       this->~dsd_session();
   }

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
                                    dsd_hco_wothr*  adsp_hco_wothr) = 0;

   //
   // Adds a message header to the data.
   // Encapsulates the data in a message header, and sends the message over to
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
                                      byte*  abyp_data,
                                      uint32_t ump_length) = 0;

   //
   // Called when more data can be sent.
   // This virtual method is optional.
   // If overrriden, remember to set boc_cansend to true.
   //
   virtual void mc_can_send()
   {
       boc_cansend = true;
   }

   //
   // Returns a description of the last error or warning of the session.
   //
   // @return  Pointer to the NULL terminated error or warning message.
   //
   inline char* mc_sess_last_err() { return chrc_last_error; };

};

//
// Creates and initializes a session object.
// Creates a session object based on the session information passed as
// parameter. The session object created might be an instance of one of any
// of the session classes which subclass the dsd_session class.
//
// @param  m_se_htun_recvbuf  New session configuration.
//
//

extern PTYPE void m_init_sess(//dsd_tun_start_htcp* adsp_tun_start_htcp,
                                      dsd_tun_start_ppp* adsp_tun_start_ppp,
                                      dsd_tun_contr_conn* adsp_tun_contr_conn,
                                      dsd_tun_contr_ineta* adsp_tun_contr_ineta);
//
// Sends data over the opened TUN adapter towards the internal network.
// This function is called when it is necessary to send some data over the
// internal network through the currently opened TUN virtual adapter. It
// makes use of the HTUN_WIN32API module in order to execute a blocking write
// to the TUN adapter.
//
// @param  achp_data   Pointer to the start of the buffer containing the data
//                     to be sent.
// @param  imp_length  Number of bytes to be sent.
//
// @return  True if successful, False if otherwise.
//
extern PTYPE BOOL m_se_husip_send(byte* abyp_data,
                                  int32_t imp_length);

//
// Sends data over the opened TUN adapter towards the internal network.
// This function is called when it is necessary to send some data over the
// internal network through the currently opened TUN virtual adapter. It
// makes use of the HTUN_WIN32API module in order to execute a blocking write
// to the TUN adapter.
//
// @param  adsp_data   Pointer to the initial struct dsd_gather_i_1 block
//                     for the data to be sent.
// @param  unp_length  Number of bytes to be sent.
//
// @return  TRUE if successful, FALSE if otherwise.
//
extern PTYPE BOOL m_se_husip_send_gather(dsd_gather_i_1* adsp_data,
                                         unsigned unp_length);
// WSP configuration struct declaration.
extern dsd_wsptun_conf_1 dss_wsptun_config;

// Critical section object for WSP configuration (defined in ishusip01.cpp).
extern DEFCRITSEC(dsg_critsec_wspconf);

#endif
