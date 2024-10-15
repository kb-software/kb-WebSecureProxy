#ifdef TRACEHL1
#define TRACE                               /* 11.08.11 KB             */
#endif
#ifndef BOOL
    #define BOOL int
#endif
#ifndef TRUE
    #define TRUE 1
#endif
#ifndef FALSE
    #define FALSE 0
#endif

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/uio.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <pthread.h>
#include <hob-netw-01.h>
#include "hob-tcpco1.hpp"

dsd_tcpthread_p dsd_tcpcomp::ads_thranc = NULL;  // anchor for tcp threads
pthread_mutex_t dsd_tcpcomp::ds_critsect; // Mutex for safe access to ressources
md_at_thr_start dsd_tcpthread_t::amc_at_thread_start;      // thread callback address

#ifdef DEF_EPOLL
dsd_etcpthread_p dsd_tcpcomp::adsc_ethranc = NULL;  // anchor for tcp threads
BOOL dsd_tcpcomp::boc_epoll = FALSE; // to do determin kernel version and set it properly
md_at_thr_start dsd_etcpthread_t::amc_at_thread_start;      // thread callback address
unsigned int dsd_tcpcomp::umsc_minreqver_2_5_66 = MAKEKERNELVERSIONNUMBER(2,5,66);
#endif



static inline void m_dummy_printf(...)
{
}

#ifndef TRACE
#define printf m_dummy_printf
#endif

#ifdef DEF_EPOLL

static const int ims_maxnum = 1024;

boundaries_t* dsd_cntstor::adsc_anchor = NULL;
chunk_t* dsd_cntstor::adsc_nextfree = NULL;
dsd_hcla_critsect_1 dsd_cntstor::dsc_storlock;

chunk_t* dsd_cntstor::mc_getnextfree()
{
	chunk_t* adsl_ret;
	dsc_storlock.m_enter();
	if (adsc_nextfree == NULL)
	{
		boundaries_t* adsl_newbound = (boundaries_t*)malloc(sizeof(boundaries_t));
		adsl_newbound->adsc_next = adsc_anchor;
		adsc_anchor = adsl_newbound;

		adsc_nextfree = adsc_anchor->adsc_chunks = (chunk_t*)malloc(sizeof(chunk_t) * ims_maxnum);

		adsc_nextfree[ims_maxnum - 1].adsc_next = NULL;
		for (int iml_ii = 0, iml_sz = ims_maxnum - 1; iml_ii < iml_sz; ++ iml_ii)
			adsc_nextfree[iml_ii].adsc_next = &adsc_nextfree[iml_ii + 1];
	}
	adsl_ret = adsc_nextfree;
	adsc_nextfree = adsc_nextfree->adsc_next;
	
	dsc_storlock.m_leave();

	adsl_ret->imc_counter = 1;
	adsl_ret->boc_valid = TRUE;
	adsl_ret->dsc_lock.m_create();
	return adsl_ret;

}

void dsd_cntstor::mc_release(chunk_t* adsp_forrel)
{
	adsp_forrel->adsc_next = adsc_nextfree;
	adsp_forrel->dsc_lock.m_close();
	adsc_nextfree = adsp_forrel;
}

void dsd_cntstor::mc_init()
{
	dsc_storlock.m_create();
}

void dsd_cntstor::mc_shutdown()
{
	boundaries_t* adsl_iter;
	while ((adsl_iter = adsc_anchor))
	{
		free(adsl_iter->adsc_chunks);
		adsc_anchor = adsl_iter->adsc_next;
		free(adsl_iter);
	}
	dsc_storlock.m_close();
}

void* dsd_refcnt::operator new(size_t dsp_size, void* avop_where)
{
	return avop_where;
}

dsd_refcnt::dsd_refcnt() {
	avoc_content = NULL;
	adsc_counter = NULL;
}

dsd_refcnt::~dsd_refcnt() {
	if (adsc_counter)
	{
		adsc_counter->dsc_lock.m_enter();
		-- adsc_counter->imc_counter;
		if (adsc_counter->imc_counter == 0) {
			adsc_counter->dsc_lock.m_leave();
			dsd_cntstor::mc_release(adsc_counter); // here the lock will be destroyed
            printf("RefCnt instance was released\n");
		}
		else
			adsc_counter->dsc_lock.m_leave();

	}
	
}

dsd_refcnt::dsd_refcnt(const dsd_refcnt& dsp_) // copy constructor
{
	if (dsp_.avoc_content)
	{
		avoc_content = dsp_.avoc_content;
		adsc_counter = dsp_.adsc_counter;
		adsc_counter->dsc_lock.m_enter();
		++ adsc_counter->imc_counter;
		adsc_counter->dsc_lock.m_leave();
	}
	else
		new (this) dsd_refcnt;
}

dsd_refcnt::dsd_refcnt(void* avop_content)
{
	avoc_content = avop_content;
	if (avop_content)
		adsc_counter = dsd_cntstor::mc_getnextfree();
	else
		adsc_counter = NULL;
}

dsd_refcnt& dsd_refcnt::operator = (dsd_refcnt& dsp_)
{
	this->~dsd_refcnt();
	new (this) dsd_refcnt(dsp_);
	return *this;
}

dsd_refcnt& dsd_refcnt::operator = (void* avop_obj)
{
	this->~dsd_refcnt();
	new (this) dsd_refcnt(avop_obj);
	return *this;
}

void* dsd_refcnt::mc_getobj()
{
	return avoc_content;
}

void dsd_refcnt::mc_invalidate()
{
	if (adsc_counter) {
		//adsc_counter->dsc_lock.m_enter();
		adsc_counter->boc_valid = FALSE;
		//adsc_counter->dsc_lock.m_leave();
	}
}

BOOL dsd_refcnt::mc_isvalid()
{
	if (adsc_counter)
		return adsc_counter->boc_valid;
	return FALSE;
}

void dsd_refcnt::mc_destruct_stackless()
{
	this->~dsd_refcnt();
}

void dsd_refcnt::mc_prevent_destruct()
{
    avoc_content = NULL;
    adsc_counter = NULL;
}

void dsd_refcnt::mc_setflags(int imp_flags)
{
	imc_flags = imp_flags;
}

int dsd_refcnt::mc_getflags()
{
	return imc_flags;
}

dsd_tcpcomp* dsd_tcpcomp::mc_estartconn(dsd_tcphandle ds_sock,
                                      dsd_tcpcallback_p ads_callback,
                                      void* ads_usrfld)
{
   dsd_tcpcomp* ads_newcon;               // new connection object

   printf("%s\n", __FUNCTION__);

   if(ds_sock == -1 || ads_callback == NULL || ads_usrfld == NULL ||
      ads_callback->am_getrecvbuf == NULL || ads_callback->am_recvcallback == NULL)
   {
      printf("Parameter is null\n");
      return NULL;
   }

   ads_newcon = new dsd_tcpcomp();
   if(!ads_newcon)
   {
      printf("Unable to allocate memory for new connection object\n");
      return NULL;
   }
   // Init connection object
   ads_newcon->boc_storage = TRUE;          /* storage has been acquired */
   ads_newcon->boc_end = FALSE;             /* end has not been set    */
   ads_newcon->bo_sendnot = FALSE;
   ads_newcon->bo_data = FALSE;
   ads_newcon->bo_sendok = FALSE; //TRUE;
   ads_newcon->bo_recv = FALSE;
   if (ads_callback->am_conncallback != NULL)
    ads_newcon->bo_connot = TRUE;
   else
    ads_newcon->bo_connot = FALSE;
   ads_newcon->ds_sock = ds_sock;
   ads_newcon->ads_callback = ads_callback;
   ads_newcon->ads_usrfld = ads_usrfld;
   ads_newcon->im_error = 0;
   ads_newcon->ads_findsock = 0;
   ads_newcon->ads_findcur = 0;

   if (fcntl(ds_sock, F_SETFL, O_NONBLOCK) != 0) //Set socket to non-blocking mode
   {
      printf("Unable to set socket for non-blocking operation: %d\n", errno);
      delete ads_newcon;
      return NULL;
   }

   ads_newcon->adsc_ethread = adsc_ethranc;
   ads_newcon->dsc_refcnt = (void*)ads_newcon;
   ads_newcon->mc_esend_notification(DEF_TCPC_ADDNEW);
   printf("pipe event fired in m_startconn()\n");
   return ads_newcon;
} // dsd_tcpcomp* dsd_tcpcomp::mc_estartconn(dsd_tcphandle, dsd_tcpcallback_p, void*)

int dsd_tcpcomp::mc_estartup(md_at_thr_start amp_at_thread_start)
{
   printf("%s\n", __FUNCTION__);
   if(adsc_ethranc != NULL)
   {
      return TCPCOMP_ERROR_ALREADYRUNNING;
   }
   adsc_ethranc = mc_ecreatenewthread();
   if(adsc_ethranc == NULL)
   {
      return TCPCOMP_ERROR_NOTHREAD;
   }
   dsd_cntstor::mc_init();
   pthread_mutex_init(&ds_critsect, NULL);
   dsd_tcpthread_t::amc_at_thread_start = amp_at_thread_start;
   return TCPCOMP_ERROR_NONE;
} // int class dsd_tcpcomp::mc_estartup()

int dsd_tcpcomp::mc_estartco_fb( int imp_socket, dsd_tcpcallback_p adsp_callback, void * vpp_userfld ) {

   printf( "%s l%05d %s this=%p\n", __FILE__, __LINE__, __FUNCTION__, this );
   if (imp_socket == -1 ||
      !adsp_callback ||
      !adsp_callback->am_getrecvbuf ||
      !adsp_callback->am_recvcallback) {
      printf("Parameter is null\n");
      return 1;
   }

   // Init connection object
   this->boc_storage = FALSE;               /* storage has not been acquired */
   this->boc_end = FALSE;                   /* end has not been set    */
   this->bo_sendnot = FALSE;
   this->bo_data = FALSE;
   this->bo_sendok = FALSE;//TRUE;
   this->bo_recv = FALSE;
   if (adsp_callback->am_conncallback != NULL)
      bo_connot = TRUE;
   else
      bo_connot = FALSE;
   this->ds_sock = imp_socket;
   this->ads_callback = adsp_callback;
   this->ads_usrfld = vpp_userfld;
   this->im_error = 0;
   this->ads_findsock = NULL;
   this->ads_findcur = NULL;
   if (fcntl(ds_sock, F_SETFL, O_NONBLOCK) != 0) //Set socket to non-blocking mode
   {
      printf("Unable to set socket to non-blocking operation: %d\n", errno);
      return 3;
   }

   adsc_ethread = adsc_ethranc;
   dsc_refcnt = (void*)this;
   mc_esend_notification(DEF_TCPC_ADDNEW);
   return 0;
} /* end dsd_tcpcomp::mc_estartco_fb()                                   */

int dsd_tcpcomp::mc_eshutdown()
{
   printf("%s\n", __FUNCTION__);

   adsc_ethranc->bo_cleanup = TRUE;
   write(adsc_ethranc->imr_pipefd[1], &adsc_ethranc, sizeof(adsc_ethranc)); // Tell thread to cleanup.
   return TRUE;
} // int class dsd_tcpcomp::m_shutdown()

void dsd_tcpcomp::mc_estopconn(BOOL bo_close, BOOL bo_thread)
{
   printf("%s\n", __FUNCTION__);
   bo_recv = false;
   bo_sendnot = false;
   if(ads_findsock)
   {
      freeaddrinfo(ads_findsock);
      ads_findsock = 0;
   }
   mc_esend_notification(DEF_TCPC_DEL);

} // void dsd_tcpcomp::m_stopconn(BOOL bo_close, BOOL bo_thread)

void dsd_tcpcomp::mc_eend_session( void ) {
   dsd_tcpcallback_p adsl_callback;

   printf( "l%05d %s\n", __LINE__, __FUNCTION__);
   adsl_callback = this->ads_callback;
   if (adsl_callback == NULL) return;
    boc_end = TRUE;                          /* end has been set        */
   mc_esend_notification(DEF_TCPC_DEL);
} /* end dsd_tcpcomp::mc_eend_session()                                  */

int dsd_tcpcomp::mc_econnect(char* str_ip, char* str_port) // to do
{
   int im_error;                      // error code
   struct addrinfo ds_sohint;         // input for getaddressinfo
   printf("%s\n", __FUNCTION__);
   if(ads_findsock != NULL)  // check next address
   {
      ads_findcur = ads_findcur->ai_next;
      if(ads_findcur == NULL)
      {
         freeaddrinfo(ads_findsock);
         ads_findsock = NULL;
         printf("No more addresses\n");
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
   else                      // find first address
   {
      memset((void*)&ds_sohint, 0, sizeof(struct addrinfo));
      ds_sohint.ai_family = PF_INET;
      ds_sohint.ai_socktype = SOCK_STREAM;
      ds_sohint.ai_protocol = IPPROTO_TCP;
      im_error = getaddrinfo(str_ip, str_port,&ds_sohint, &ads_findsock);
      if( im_error )
      {
         printf("getaddrinfo failed for %s: %d.\n\n", str_ip, im_error);
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
   if(im_error == 0)
   {
      printf("Connect doesn't return with EWOULDBLOCK. Strange\n");
   }
   else
   {
      im_error = errno;
      if(im_error != EWOULDBLOCK && im_error != EINPROGRESS)
      {
         printf("Connect failed: %d.\n\n", im_error );
         bo_connot = FALSE;
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
   printf("Connect OK\n");
   return TRUE;
}  // int dsd_tcpcomp::m_connect(char* str_ip, char* str_port)

int dsd_tcpcomp::mc_erecv()
{
   printf("%s\n", __FUNCTION__);
   bo_recv = TRUE;
   mc_esend_notification(DEF_TCPC_RECV);
   printf("pipe event fired in m_recv()\n");
   return TRUE;
} // int dsd_tcpcomp::m_recv();

int dsd_tcpcomp::mc_esend(char *ach_data, int im_len)
{
   printf("%s\n", __FUNCTION__);
   int iml_error;                        // error code
   int im_sendcnt;                      // number of bytes sent with one send
   int im_send;                         // total number of bytes
   dsd_tcpcallback_p adsl_callback;

   printf("%s to %d: %d bytes. bo_data = %d\n", __FUNCTION__, ds_sock, im_len, bo_data);
   im_send = 0;                         // nothing send yet
   do
   {
      bo_sendok = FALSE;
      im_sendcnt = send(ds_sock, ach_data, im_len - im_send, 0);
      if(im_sendcnt < 0)
      {
         iml_error = errno;
         printf("Send failed: %d.\n", iml_error );
         if(iml_error != EWOULDBLOCK &&
         iml_error != ENOTCONN && iml_error != EPIPE)
         {
            adsl_callback = ads_callback;
            if(adsl_callback && ads_callback->am_errorcallback != NULL)
            {
               this->im_error = iml_error;
               adsl_callback->am_errorcallback(this,
                                              ads_usrfld,
                                              "Send failed",
                                              iml_error,
                                              ERRORAT_SEND);
            }
            im_send = -1;
         }
         break;
      }
      bo_sendok = TRUE;
      im_send += im_sendcnt;
      ach_data += im_sendcnt;
   }while(im_send < im_len);
   printf("m_send OK. Len: %d\n", im_send);
   return im_send;
} // int dsd_tcpcomp::m_send(char *ach_data, int im_len)

void dsd_tcpcomp::mc_esendnotify()
{
   printf("%s\n", __FUNCTION__);
   bo_sendnot = TRUE;
   if(bo_sendok)
   {
      printf("Set Event\n");
      mc_esend_notification(DEF_TCPC_SENDNOTIFY);
   }
} // void dsd_tcpcomp::m_sendnotify()

dsd_etcpthread_p dsd_tcpcomp::mc_ecreatenewthread()
{
   printf("%s\n", __FUNCTION__);
   dsd_etcpthread_p ads_newthread;
   ads_newthread = new dsd_etcpthread_t;
   if(!ads_newthread)
   {
      printf("Unable to allocate memory for new TCP/IP thread structure\n");
      return 0;
   }

   if(pipe(ads_newthread->imr_pipefd) < 0)
   {
      printf("Unable to create pipes for new TCP/IP thread\n");
      delete ads_newthread;
      return 0;
   }
   ads_newthread->dsr_waitevent[0].events = EPOLLIN;
   if(pthread_create(&(ads_newthread->ds_threadhandle),
                     NULL,
                     m_estarttcpthread,
                     (void*)ads_newthread))
   {
      printf("Unable to start new TCP/IP thread.\n");
      close(ads_newthread->imr_pipefd[0]);
      close(ads_newthread->imr_pipefd[1]);
      delete ads_newthread;
      return 0;
   }
   printf("New thread started.\n");
   return ads_newthread;
} // dsd_tcpthread_p dsd_tcpcomp::m_createnewthread()

BOOL dsd_tcpcomp::mc_econnect_notify(int imp_events)
{
    printf("%s\n", __FUNCTION__);
    BOOL bol_connected;
    BOOL bol_remove_entry;
    bol_connected = FALSE;
    bol_remove_entry = FALSE;

    int iml_error;
    iml_error = 0;
    if ((imp_events & (EPOLLERR)) != 0)
    {
        if (boc_mhconnect == FALSE)
            iml_error = 1;
    }

    switch (boc_mhconnect)
    {
        case FALSE:
            if (iml_error) {        /* reported error          */
                bol_remove_entry = TRUE;  /* set has to remove entry */
                if (ads_callback->am_errorcallback != NULL) {
                    this->im_error = iml_error;
                    ads_callback->am_connerrcallback(this, ads_usrfld, NULL, 0, 0, 0, iml_error);
                }
            }
            else if (ads_callback->am_conncallback != NULL) {
                ads_callback->am_conncallback( this, ads_usrfld, NULL, 0, 0 );
            }
            if (ads_findsock) {
                freeaddrinfo(ads_findsock);
                ads_findsock = NULL;
            }
            if (bol_remove_entry == FALSE)
                bol_connected = TRUE;
            break;
        case TRUE:
            {
                sockaddr_storage dsl_sockaddr;
                socklen_t dsl_len;
                int iml_ineta_curno;
                iml_ineta_curno = imc_ineta_curno - 1;
                m_set_connect_p1(&dsl_sockaddr, (socklen_t*)&dsl_len,
                                    (dsd_target_ineta_1*)adsc_target_ineta, iml_ineta_curno);
                if (iml_error == 0)
                {
                    int iml_errno;
                    int iml_reconnerr;
                    iml_reconnerr = connect(ds_sock, (sockaddr*)&dsl_sockaddr, (socklen_t)dsl_len);
                    iml_errno = errno;
                    printf("connect returned %d errno %d: %s\n", iml_reconnerr, iml_errno, strerror(iml_errno));
                    if (iml_reconnerr != -1)
                        break;
                    else if (iml_errno == EINPROGRESS || iml_errno == EALREADY)
                        break;
                    else if (iml_errno != EISCONN)
                        iml_error = iml_errno;
                }
                this->im_error = iml_error;
                if (iml_error) {        /* reported error          */
                    if (ads_callback->am_connerrcallback != NULL) {
                        ads_callback->am_connerrcallback(this, ads_usrfld,
                                (struct sockaddr *) &dsl_sockaddr, dsl_len,
                                iml_ineta_curno, adsc_target_ineta->imc_no_ineta, iml_error);
                    }
                    if (imc_ineta_curno == adsc_target_ineta->imc_no_ineta) {
                        bol_remove_entry = TRUE;  /* set has to remove entry */
                        break;
                    }
                    else {
                        SOCKET dsl_save_sock;
                        dsl_save_sock = ds_sock; // save the current socket
                        ds_sock = INVALID_SOCKET;
                        if (mc_estartco_mh( NULL, NULL, NULL, NULL, 0, FALSE ) != 0) {
                            bol_remove_entry = TRUE;  /* set has to remove entry */
                            // it was the last attemt to connect, restore the socket to be closed by m_eremove_entry
                            ds_sock = dsl_save_sock;
                        }
                        else
                        {
                            // close the saved socket it's going to do next non-blocking connect
                            struct epoll_event dsl_ee_dummy; // bug kernel version 2.6.9 needs it
                            printf("EPOLL_CTL_DEL %p sock %d\n", this, dsl_save_sock);
                            if (epoll_ctl(adsc_ethread->imc_epoll_fd, EPOLL_CTL_DEL, dsl_save_sock, &dsl_ee_dummy) !=0) {
                                printf("ERROR EPOLL_CTL_DEL on sock %d errno %d %s\n", dsl_save_sock, errno, strerror(errno));
                            }

                            close(dsl_save_sock); // to do
                        }
                        break;
                    }

                }
                if (ads_callback->am_conncallback != NULL) {
                    ads_callback->am_conncallback( this, ads_usrfld,
                            (struct sockaddr *) &dsl_sockaddr, dsl_len, 0 );
                }
                bol_connected = TRUE;
            }
            break;
    }
    if (bol_connected == TRUE)
        bo_connot = FALSE;
    return bol_remove_entry;
}

void dsd_tcpcomp::mc_eremove_entry(int imp_epoll_fd, int imp_cur, int imp_size)
{
    printf("%s\n", __FUNCTION__);
    BOOL bol_save_1;
    dsd_tcpcallback_p adsl_callback;
    adsl_callback = ads_callback;
    ads_callback = NULL;
    struct epoll_event dsl_ee_dummy; // bug - kernel version 2.6.9 needs it

    for (++ imp_cur; imp_cur < imp_size; ++ imp_cur) // invalidate event cache
    {
        if (adsc_ethread->dsr_waitevent[imp_cur].data.ptr == this)
            adsc_ethread->dsr_waitevent[imp_cur].data.ptr = NULL;
    }
    printf("EPOLL_CTL_DEL %p sock %d\n", this, ds_sock);
    if (epoll_ctl(imp_epoll_fd, EPOLL_CTL_DEL, ds_sock, &dsl_ee_dummy) != 0) {
        printf("ERROR EPOLL_CTL_DEL on sock %d errno %d %s\n", ds_sock, errno, strerror(errno));
    }

    close(ds_sock);
    bol_save_1 = boc_storage;  /* save value */
    if (adsl_callback->amc_cleanup)
        adsl_callback->amc_cleanup(this, ads_usrfld);

    dsc_refcnt.mc_invalidate();
    if (bol_save_1)
        delete this;
    else
        dsc_refcnt = NULL;

}


void* m_estarttcpthread(void* adsp_param)
{
    printf("%s\n", __FUNCTION__);
    dsd_tcpcomp::mc_etcpthread(adsp_param);
    return NULL;
}
/**
 * TCP/IP wait thread.
 * @param ads_parm pointer to corresponding thread structure.
 */
void dsd_tcpcomp::mc_etcpthread(void* ads_parm)
{
    printf("%s\n", __FUNCTION__);
    BOOL       bol_remove_entry;             /* has to remove entry     */
    BOOL       bol_ret;                      /* return code             */
    int im_waitret;    // return code from wait
    dsd_etcpthread_p ads_thread; // thread structure
    dsd_refcnt dsl_refcnt; //the incomming notification is a ref counter object with a an action index
    dsd_tcpcallback_p adsl_callback;


    dsd_tcpcomp* adsl_curconn;
    int iml_epoll_fd;   // epoll descriptor
    int iml_msg_fd;     // control event descriptor
    epoll_event dsl_epoll_event;


    ads_thread = (dsd_etcpthread_p)ads_parm;
    if (dsd_etcpthread_t::amc_at_thread_start)
        dsd_etcpthread_t::amc_at_thread_start(0);

    printf("TCP/IP epoll thread started\n");


    ads_thread->imc_epoll_fd = iml_epoll_fd = epoll_create(TCPCOMP_MAXCONN + 1);

    // add the notification pipe descriptor to the epoll set
    iml_msg_fd = ads_thread->imr_pipefd[0];
    ads_thread->dsr_waitevent[0].data.ptr = &iml_msg_fd; // set user field for ident later
    epoll_ctl(iml_epoll_fd, EPOLL_CTL_ADD, iml_msg_fd, &ads_thread->dsr_waitevent[0]);

    do
    {
        bol_remove_entry = FALSE;             /* reset has to remove entry */
        im_waitret = epoll_wait(iml_epoll_fd, &ads_thread->dsr_waitevent[0], TCPCOMP_MAXCONN + 1, -1);
        if(ads_thread->bo_cleanup)
        {
            printf("Cleanup requested\n");
            break;
        }
#ifdef TRACE
        printf("epoll returned with %d\n", im_waitret);
        printf("list events:\n");
        for (int iml_ii = 0; iml_ii < im_waitret; ++ iml_ii) {
            if (ads_thread->dsr_waitevent[iml_ii].data.ptr == &iml_msg_fd)
                printf("index %d revents 0x%x - control event\n", iml_ii, ads_thread->dsr_waitevent[iml_ii].events);
            else
                printf("index %d revents 0x%x %p %d\n", iml_ii, ads_thread->dsr_waitevent[iml_ii].events,
                             ads_thread->dsr_waitevent[iml_ii].data.ptr, ((dsd_tcpcomp*)ads_thread->dsr_waitevent[iml_ii].data.ptr)->ds_sock);
        }
        printf("end of list events\n");
#endif
        if(im_waitret <= 0)
        {
            printf("Epoll error %d or nothing received? %d %s\n", errno, im_waitret, strerror(errno));
            sleep(1);
            continue;
        }
        for (int iml_conn = 0; iml_conn < im_waitret; ++ iml_conn)
        {
            if (ads_thread->dsr_waitevent[iml_conn].data.ptr == &iml_msg_fd)
            { // control event fired
                read(iml_msg_fd, &dsl_refcnt, sizeof(dsd_refcnt));
                if (dsl_refcnt.mc_isvalid())
                {
                    adsl_curconn = (dsd_tcpcomp*)dsl_refcnt.mc_getobj();
                    switch (dsl_refcnt.mc_getflags())
                    {
                        case DEF_TCPC_ADDNEW:
                            dsl_epoll_event.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLET;
                            dsl_epoll_event.data.ptr = adsl_curconn;
                            printf("EPOLL_CTL_ADD %p sock %d\n", adsl_curconn, adsl_curconn->ds_sock);
                            if (epoll_ctl(iml_epoll_fd, EPOLL_CTL_ADD, adsl_curconn->ds_sock, &dsl_epoll_event) < 0) {
                                printf("ERROR EPOLL_CTL_ADD on sock %d errno %d %s\n", adsl_curconn->ds_sock, errno, strerror(errno));
                                printf( "%s l%05d remove entry\n", __FILE__, __LINE__ );
                                adsl_curconn->mc_eremove_entry(iml_epoll_fd, iml_conn, im_waitret);
                            }

                            break;
                        case DEF_TCPC_DEL:
                            printf( "%s l%05d remove entry\n", __FILE__, __LINE__ );
                            adsl_curconn->mc_eremove_entry(iml_epoll_fd, iml_conn, im_waitret);
                            break;
                        case DEF_TCPC_RECV:
                        case DEF_TCPC_SENDNOTIFY:
                            bol_remove_entry = FALSE;
                            if (adsl_curconn->bo_connot == TRUE)
                                break;
                            adsl_callback = adsl_curconn->ads_callback;
                            if (adsl_curconn->boc_end)   /* end has been set */
                                bol_remove_entry = TRUE;   /* set has to remove entry */

                            if(adsl_curconn->bo_sendnot && adsl_curconn->bo_sendok)
                            {
                                adsl_curconn->bo_sendnot = FALSE;
                                adsl_curconn->ads_callback->am_sendcallback(adsl_curconn, adsl_curconn->ads_usrfld);
                            }
                            if(adsl_curconn->bo_recv && adsl_curconn->bo_data)
                            {
                                bol_ret = adsl_curconn->m_recvdata();
                                if (bol_ret)
                                    bol_remove_entry = TRUE;  /* set has to remove entry */
                            }
                            if (bol_remove_entry) {   /* set has to remove entry */
                                printf( "%s l%05d remove entry\n", __FILE__, __LINE__);
                                adsl_curconn->mc_eremove_entry(iml_epoll_fd, iml_conn, im_waitret);
                            }
                            break;
                        default:
                            printf("UNKNOWN EVENT CONTROL NOTIFICATION!!!\n");
                            break;
                    }
                }
                else {
                    printf("INVALID EVENT ARRIVED!!! %p\n", dsl_refcnt.mc_getobj());
                }
                dsl_refcnt = NULL; //adsl_refcnt->mc_destruct_stackless();
            }
            else // do receive send ... on sockets
            {
                adsl_curconn = (dsd_tcpcomp*)ads_thread->dsr_waitevent[iml_conn].data.ptr;
                if (adsl_curconn == NULL) // allready deleted connection
                {
                    printf("INVALID CONNECTION ARRIVED PROBABLY FROM EVENT CACHE!!!\n");
                    continue;
                }
                adsl_callback = adsl_curconn->ads_callback;
                if ((ads_thread->dsr_waitevent[iml_conn].events & (EPOLLERR | EPOLLIN)) != 0)
                { // receive data
                    bol_remove_entry = FALSE;
                    if (adsl_curconn->bo_connot == TRUE)
                        bol_remove_entry = adsl_curconn->mc_econnect_notify(ads_thread->dsr_waitevent[iml_conn].events);
                    if (adsl_curconn->bo_connot == FALSE)
                    {
                        if(adsl_curconn->bo_recv)
                        {
                            bol_ret = adsl_curconn->m_recvdata();
                            if (bol_ret)
                                bol_remove_entry = TRUE;  /* set has to remove entry */
                        }
                        else
                            adsl_curconn->bo_data = TRUE;
                    }
                    if (bol_remove_entry) {   /* set has to remove entry */
                        printf( "%s l%05d remove entry\n", __FILE__, __LINE__ );
                        adsl_curconn->mc_eremove_entry(iml_epoll_fd, iml_conn, im_waitret);
                        continue;
                    }
                }
                if((ads_thread->dsr_waitevent[iml_conn].events & (EPOLLOUT | EPOLLHUP)) == EPOLLOUT)
                {
                    if(adsl_curconn->bo_connot) // connect notify
                    {
                        printf("CONNECT NOTIFY EPOLLOUT\n");
                        adsl_curconn->bo_connot = FALSE;
                        switch (adsl_curconn->boc_mhconnect)
                        {
                            case FALSE:
                                if (adsl_callback->am_conncallback != NULL) {
                                    adsl_callback->am_conncallback( adsl_curconn, adsl_curconn->ads_usrfld, NULL, 0, 0 );
                                }
                                if (adsl_curconn->ads_findsock) {
                                    freeaddrinfo(adsl_curconn->ads_findsock);
                                    adsl_curconn->ads_findsock = NULL;
                                }
                                break;
                            case TRUE:
                                {
                                    sockaddr_storage dsl_sockaddr;
                                    socklen_t dsl_len;
                                    int iml_ineta_curno;
                                    iml_ineta_curno = adsl_curconn->imc_ineta_curno - 1;
                                    adsl_curconn->im_error = 1;
                                    m_set_connect_p1(&dsl_sockaddr, (socklen_t*)&dsl_len,
                                            (dsd_target_ineta_1*)adsl_curconn->adsc_target_ineta, iml_ineta_curno);
                                    if (adsl_callback->am_conncallback != NULL) {
                                        adsl_callback->am_conncallback( adsl_curconn,
                                                adsl_curconn->ads_usrfld,
                                                (struct sockaddr *) &dsl_sockaddr, dsl_len, 0 );
                                    }
                                }
                                break;
                        }
                    }


                    adsl_curconn->bo_sendok = TRUE;
                    if(adsl_curconn->bo_sendnot)
                    {
                        adsl_curconn->bo_sendnot = FALSE;
                        adsl_curconn->ads_callback->am_sendcallback(adsl_curconn,
                                                                        adsl_curconn->ads_usrfld);
                        printf("return from send.\n");
                    }
                }
            }
        }

    } while(TRUE);
#ifdef TRACE
    printf("TCPthread ended. clean up.\n");
#endif
// clean up
    /* for(im_index = 0; im_index < ads_thread->im_concount; im_index++)
    {
        if(ads_thread->dsr_tcpconn[im_index] != NULL)
        {
            ads_thread->dsr_tcpconn[im_index]->m_stopconn(FALSE, FALSE);
            delete ads_thread->dsr_tcpconn[im_index];
        }
    } */
    close(ads_thread->imr_pipefd[0]);
    close(ads_thread->imr_pipefd[1]);
    close(iml_epoll_fd);
    delete ads_thread;
    dsd_cntstor::mc_shutdown();
    return;
} // void m_etcpthread(void*)

int dsd_tcpcomp::mc_estartco_mh( dsd_tcpcallback_p adsp_callback, void * vpp_userfld,
                              const dsd_target_ineta_1* adsp_target_ineta, const dsd_bind_ineta_1* adsp_bind_ineta,
                              unsigned short usp_port, BOOL bop_round_robin )
{
    printf("%s\n", __FUNCTION__);

    int iml_ret;
    const dsd_bind_ineta_1* adsl_bind;
    sockaddr_storage dsl_sockaddr;
    socklen_t dsl_len;

#ifdef TRACE
    printf( "%s l%05d m_startco_mh this=%p\n", __FILE__, __LINE__, this );
#endif
    if (ads_callback == NULL) // the tcpcomp instanse is not on tcpcomp thread
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
        this->boc_storage = FALSE;               /* storage has not been acquired */
        this->boc_end = FALSE;                   /* end has not been set    */
        this->bo_sendnot = FALSE;
        this->bo_data = FALSE;
        this->bo_sendok = FALSE;
        this->bo_recv = FALSE;
        //this->bo_fd_close = FALSE; // AG 14.04.2008
        if (adsp_callback->am_conncallback != NULL)
            this->bo_connot = TRUE;
        else
            this->bo_connot = FALSE;
        this->ads_callback = adsp_callback;
        this->ads_usrfld = vpp_userfld;
        this->im_error = 0;
        this->ads_findsock = NULL;
        this->ads_findcur = NULL;

        imc_ineta_curno = 0;
        usc_port = usp_port;
        boc_mhconnect = TRUE;
        adsc_target_ineta = adsp_target_ineta;

    }
    while (true) {
        while (imc_ineta_curno < adsc_target_ineta->imc_no_ineta) {

            memset(&dsl_sockaddr, 0, sizeof(sockaddr_storage));
            m_set_connect_p1(&dsl_sockaddr, (socklen_t*)&dsl_len, (dsd_target_ineta_1*)adsc_target_ineta, imc_ineta_curno ++);

            adsl_bind = NULL;
            if (adsp_bind_ineta && adsp_bind_ineta->boc_bind_needed) {
                if (dsl_sockaddr.ss_family == AF_INET && adsp_bind_ineta->boc_ipv4)
                    adsl_bind = adsp_bind_ineta;
                else if (dsl_sockaddr.ss_family == AF_INET6 && adsp_bind_ineta->boc_ipv6)
                    adsl_bind = adsp_bind_ineta;
            }

            if ((this->ds_sock = ms_socket(dsl_sockaddr.ss_family, adsl_bind)) != INVALID_SOCKET) {
                printf("new sock created %d\n", ds_sock);
                break;
            }

        }
        if (this->ds_sock == INVALID_SOCKET) {
#ifdef TRACE
            printf("Unable to create socket for new connection object\n");
#endif
            return 2;
        }
        if (fcntl(ds_sock, F_SETFL, O_NONBLOCK) != 0) //Set socket to non-blocking mode
        {
#ifdef TRACE
            printf("Unable to set socket to non-blocking operation: %d\n", errno);
#endif
            close(this->ds_sock);
            this->ds_sock = INVALID_SOCKET;
            return 3;
        }
        break;

    }

    if ((iml_ret = mc_econnect_mh(&dsl_sockaddr, dsl_len)) == TRUE)
    {
        if (adsc_ethread == NULL) // the tcpcomp instanse is not on tcpcomp thread
        {
           adsc_ethread = adsc_ethranc;
           dsc_refcnt = (void*)this;
           mc_esend_notification(DEF_TCPC_ADDNEW);
           printf("DEF_TCPC_ADDNEW event fired\n");

    #ifdef TRACE
           printf( "%s l%05d %s\n", __FILE__, __LINE__, __FUNCTION__);
    #endif

        }
        else
        {
            epoll_event dsl_epoll_event;
            dsl_epoll_event.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLET;
            dsl_epoll_event.data.ptr = this;
            printf("EPOLL_CTL_ADD %p sock %d\n", this, ds_sock);
            if (epoll_ctl(adsc_ethread->imc_epoll_fd, EPOLL_CTL_ADD, ds_sock, &dsl_epoll_event) < 0)
            {
                printf("ERROR EPOLL_CTL_ADD on sock %d errno %d %s\n", ds_sock, errno, strerror(errno));
            }

        }
        return 0;
    }



#ifdef TRACE
    printf("Error connect() on the new connection object %d\n", im_error);
#endif
    if (imc_ineta_curno < adsc_target_ineta->imc_no_ineta)
    {
        printf("close sock %d\n", ds_sock);
        if (close(ds_sock) != 0) {
            printf("error close on sock %d\n", ds_sock);
        }

        iml_ret = mc_estartco_mh(NULL, NULL, NULL, NULL, usc_port, FALSE );
    }
    else
        iml_ret = -1;

    if (iml_ret != 0 && adsp_callback != NULL) {  // only if first call
        BOOL bol_save_1;
        bol_save_1 = boc_storage;
        if (ads_callback->amc_cleanup)
            ads_callback->amc_cleanup(this, ads_usrfld);
        if (bol_save_1)
            delete this;
    }
    return iml_ret;

} /* end int dsd_tcpcomp::mc_estartco_mh()                                            */


int dsd_tcpcomp::mc_econnect_mh(sockaddr_storage* adsp_sockaddr, socklen_t dsp_len)
{
    printf("%s\n", __FUNCTION__);
    int iml_error;
    if (adsp_sockaddr->ss_family == AF_INET)
        ((sockaddr_in*)adsp_sockaddr)->sin_port = htons(usc_port);
    else
        ((sockaddr_in6*)adsp_sockaddr)->sin6_port = htons(usc_port);

    iml_error = connect(ds_sock, (const sockaddr*) adsp_sockaddr, dsp_len);
    if( !iml_error ) {
#ifdef TRACE
        printf("Connect doesn't return with WSAEWOULDBLOCK. Strange\n");
#endif
    }
    else {
        iml_error = errno;
        if( iml_error != EWOULDBLOCK && iml_error != EINPROGRESS)
        {
#ifdef TRACE
            printf("Connect failed: %d.\n\n", iml_error );
#endif
            if (ads_callback->am_connerrcallback != NULL) {
                sockaddr_storage dsl_sockaddr;
                socklen_t dsl_len;
                int iml_ineta_curno;
                im_error = iml_error;
                iml_ineta_curno = imc_ineta_curno - 1;
                m_set_connect_p1(   &dsl_sockaddr, (socklen_t*)&dsl_len,
                                    (dsd_target_ineta_1*)adsc_target_ineta,
                                    iml_ineta_curno);
                ads_callback->am_connerrcallback(   this, ads_usrfld,
                                                    (struct sockaddr *) &dsl_sockaddr, dsl_len,
                                                    iml_ineta_curno, adsc_target_ineta->imc_no_ineta,
                                                    iml_error);
            }
            return FALSE;
        }
    }
    return TRUE;
}

int dsd_tcpcomp::mc_esend_notification(int imp_cmd) // to do
{
    int iml_errorplace;
    dsd_refcnt dsl_objrefcnt(dsc_refcnt); // increment ref count
    dsl_objrefcnt.mc_setflags(imp_cmd);
    if (write(adsc_ethread->imr_pipefd[1], &dsl_objrefcnt, sizeof(dsd_refcnt)) < 0)
    {
        if(ads_callback->am_errorcallback != NULL)
        {
            im_error = errno;
            switch (imp_cmd)
            {
                case DEF_TCPC_ADDNEW:
                    iml_errorplace = ERRORAT_STARTCONN;
                    break;
                case DEF_TCPC_DEL:
                    iml_errorplace = ERRORAT_STOPCONN;
                    break;
                case DEF_TCPC_RECV:
                    iml_errorplace = ERRORAT_RECV;
                    break;
                case DEF_TCPC_SENDNOTIFY:
                    iml_errorplace = ERRORAT_SEND;
                    break;
            }
            ads_callback->am_errorcallback(this, ads_usrfld,
                  "Unable to set event for receive", im_error, iml_errorplace);
        }
        printf("Unable to set event for receive.\n");
        return -1;
    }
    else
        dsl_objrefcnt.mc_prevent_destruct();  // the object will not be destructed after
    return 0;
}

#endif // #ifdef DEF_EPOLL

#ifndef TRACE
#undef printf
#endif


