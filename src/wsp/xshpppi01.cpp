// #define TRY_FORCE_TRACE
#define HPPPT1_V21
//#define HL_DEBUG
//+-------------------------------------------------------------------+
//|                                                                   |
//| PROGRAM NAME: HPPP.cpp                                            |
//| -------------                                                     |
//|  HOB Point to Point Protocol module for use with HUSIP and WSP    |
//|    modules                                                        |
//|                                                                   |
//| COPYRIGHT:                                                        |
//| ----------                                                        |
//|  Copyright (C) HOB Germany 2008                                   |
//|  Copyright (C) HOB Germany 2009                                   |
//|  Copyright (C) HOB Germany 2014                                   |
//|  Copyright (C) HOB Germany 2015                                   |
//|  Copyright (C) HOB Germany 2017                                   |
//|                                                                   |
//+-------------------------------------------------------------------+

#ifndef HL_UNIX
#ifdef HL_LINUX
#define HL_UNIX
#endif
#ifdef HL_FREEBSD
#define HL_UNIX
#endif
#endif
#ifndef HL_UNIX
#define HL_THRID GetCurrentThreadId()
#else
#ifndef HL_LINUX
#define HL_THRID m_gettid()
#include <sys/thr.h>
extern "C" pid_t m_gettid( void );
#else
#define HL_THRID syscall( __NR_gettid )
#endif
#endif
#ifdef HL_DEBUG
extern "C" int m_hl1_printf( char *aptext, ... );
#endif
#ifndef D_INCL_TUN_CTRL
#define D_INCL_TUN_CTRL
#endif

#define D_ARRAY_PACKET 8

#ifndef HL_UNIX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <setupapi.h>
#else
#include "hob-unix01.h"
#endif
#ifndef HL_UNIX
#include <hob-avl03.h>
#else
#include "hob-avl03.h"
#endif
#ifndef HL_UNIX
typedef int socklen_t;
#endif
#ifdef HL_UNIX
#ifndef HOB_CONTR_TIMER
#define HOB_CONTR_TIMER
#endif
#ifdef HL_LINUX
#include <sys/syscall.h>
#endif
#ifdef HL_FREEBSD
#define TRY_150625
#ifdef TRY_150625
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#include <net/if_tun.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <netinet/if_ether.h>
//#include <sys/types.h>
#include <sys/sysctl.h>
#ifndef TRY_150625
#include <sys/socket.h>
#endif
#endif
#ifndef TRY_150625
#include <netinet/in.h>
#endif
#include <net/if.h>
#include <time.h>
#include <string.h>

//#include "types_defines.h"
#ifndef byte
#define byte unsigned char
#endif

#endif
#include <hob-xslhcla1.hpp>
#include <hob-netw-01.h>
#include <string>
#include <map>
#include <sstream>
#include <list>
#include <stddef.h>
#include <iostream>
#include <queue>
#include <math.h>
#include "hob-xslcontr.h"
#include "hob-tun01.h"
#include "hob-htcp-int-01.h"
//#include "hob-htcp-int-types.h"
//#include "hob-htcp.h"
//#include "hob-htcp-bit-reference.h"
//#include "hob-htcp-tcpip-hdr.h"
//#include "hob-htcp-misc.h"
//#include "hob-htcp-connection.h"
#include "hob-session01.h"
//#include "hob-htcp-session.h"
#include "hob-gw-ppp-1.h"
#include "hob-hppp01.h"
#include "hob-hsstp01.h"
#include "hob-tuntapif01.h"
#include <stdio.h>
#include <vector>
#include "hob-xslcontr.h"
#include "hob-sessutil01.h"
#define DOMNode void
#define DEF_HL_INCL_DOM
#include "hob-wsppriv.h"
#include "hob-xsclib01.h"
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"



#define BASE_ERR_NUMBER 100
#define D_POS_IPV4_H_PROT 9 /* position protocol in IPV4 header */
#define D_POS_IPV6_H_PROT 6 /* next header in IPV6 header */

// Callback for new PPP implementation to do authentication.
extern PTYPE void m_ppp_auth_1(struct dsd_ppp_server_1*);

// New function implemented to get address of INETA configured for htun.
static char* m_ppp_se_get_ineta_client(struct dsd_ppp_server_1 *adsp_ppp_se_1);

// Called to inform WPS that a session has terminated.
extern PTYPE void m_htun_session_end( struct dsd_tun_contr_conn *adsp_tun_contr_conn,
                                      int imp_reason );

extern PTYPE struct dsd_ppp_targfi_act_1 * m_create_ppp_targfi( struct dsd_targfi_1 *, int, int );

extern PTYPE enum ied_ret_cf m_proc_ppp_targfi_ipv4( struct dsd_hco_wothr *, struct dsd_ppp_targfi_act_1 *, struct dsd_gather_i_1 *, int );

extern PTYPE enum ied_ret_cf m_proc_ppp_targfi_ipv6( struct dsd_hco_wothr *, struct dsd_ppp_targfi_act_1 *, struct dsd_gather_i_1 *, int );

// Callback for PPP implementation to send HOB-PPP-T1 message back to client.
static void m_ppp_send_callback_se(dsd_ppp_server_1*   adsp_ppp_server,
                                   dsd_buf_vector_ele* adsp_buf_vec);

// Callback for session close timer.
static void m_cb_timer_close(dsd_timer_ele* adsp_timer_close);

// Closes a PPP session and releases all related resources.
static void mc_ppp_close_and_release(dsd_ppp_session* adsp_ppp_sess, bool bop_end_sess = true);

// Callback when auth ready in order to create target filter
static void m_ppp_se_hs_compl(dsd_ppp_server_1*);

// Prints a PPP server related message.
static void m_log_ppp_warning(dsd_ppp_server_1* adsp_ppp_svr, char* achp_message);

bool bo_pppsess_avl_initd = false;
dsd_htree1_avl_cntl ds_pppsess_avl_cntl;
dsd_htree1_avl_work ds_pppsess_avl_wrk;
dsd_hcla_critsect_1 ds_pppsess_avl_cs;

// AVL tree node comparison function.
int m_cmp_pppsess_nodes(void*, dsd_htree1_avl_entry* adsp_a, dsd_htree1_avl_entry* adsp_b)
{
    // Get tunnel IDs
    unsigned int uml_a = *(unsigned int*)(adsp_a + 1);
    unsigned int uml_b = *(unsigned int*)(adsp_b + 1);
    // Compare.
    return uml_a - uml_b;
}

dsd_ppp_session::dsd_ppp_session(dsd_tun_start_ppp* adsp_tun_start_ppp,
                                 dsd_tun_contr_conn* adsp_tun_contr_conn,
                                 dsd_tun_contr_ineta* adsp_tun_contr_ineta)
   : iec_conn_state(ied_hpppt1_conn_idle),
     adsc_tun_contr_conn(adsp_tun_contr_conn),
     adsc_tun_contr_ineta(adsp_tun_contr_ineta),
     boc_sess_closed(false),
     boc_cansend(true),
     adsc_targ_filter(NULL),
     adsc_ppp_targfi_act(NULL),
     umc_discard_count(0),
     umc_discard_count_tf(0),
	 umc_tunnel_id(0)
{
#ifdef TRY_FORCE_TRACE
   adsc_tun_contr_conn->imc_trace_level = HL_WT_SESS_NETW | HL_WT_SESS_DATA2;
#endif

   dsc_htun_handle.iec_tunc = adsp_tun_contr_conn->iec_tunc;
   memset(chrc_last_error, 0, sizeof(chrc_last_error));
   //dsg_tun_contr_ineta_list.push_back(adsp_tun_contr_ineta);

   dsc_ppp_wrap.adsc_ppp_session = this;
   dsc_htun_handle.vpc_contr = this;
   // Init AVL tree, if necessary.
   if(!bo_pppsess_avl_initd)
   {
      m_htree1_avl_init(NULL, &ds_pppsess_avl_cntl, m_cmp_pppsess_nodes);
      ds_pppsess_avl_cs.m_create();
      bo_pppsess_avl_initd = true;
   }

   // Initialize PPP server instance for this HOB-PPP-T1 session.
   memset(&dsc_ppp_wrap.dsc_ppp_se_1, 0, sizeof(dsd_ppp_server_1));
   dsc_ppp_wrap.dsc_ppp_se_1.amc_ppp_se_send = m_ppp_send_callback_se;
   dsc_ppp_wrap.dsc_ppp_se_1.amc_ppp_se_auth = m_ppp_auth_1;
//#ifdef B150702
   dsc_ppp_wrap.dsc_ppp_se_1.amc_ppp_se_abend = m_log_ppp_warning;
   dsc_ppp_wrap.dsc_ppp_se_1.amc_ppp_se_get_ineta_client = m_ppp_se_get_ineta_client; // obtain from sockaddr_storage
   dsc_ppp_wrap.dsc_ppp_se_1.amc_ppp_se_hs_compl = m_ppp_se_hs_compl;
//#endif
#ifndef B150701
   m_htun_ppp_set_auth( adsc_tun_contr_conn, (char *) &(dsc_ppp_wrap.dsc_ppp_se_1.chrc_ppp_auth) );
#endif

   int iml1, iml2;
   do {                                     /* compute magic number    */
     iml1 = iml2 = sizeof(dsc_ppp_wrap.dsc_ppp_se_1.chrc_magic_number_se);
     do {
       iml1--;                              /* decrement index         */
       dsc_ppp_wrap.dsc_ppp_se_1.chrc_magic_number_se[ iml1 ]
         = (unsigned char) m_get_random_number( 0X0100 );
       if (dsc_ppp_wrap.dsc_ppp_se_1.chrc_magic_number_se[ iml1 ] == 0) {
         iml2--;                            /* count character zero    */
       }
     } while (iml1 > 0);
   } while (iml2 == 0);                     /* magic number zero not allowed */
   adsc_queue_first = NULL;
   adsc_queue_last = NULL;
   umc_packets_list = 0;

   dsc_ppp_wrap.dsc_ppp_se_1.isc_recv_ident_lcp_conf = -1;
#ifdef B150702
   dsc_ppp_wrap.dsc_ppp_se_1.vpc_handle = &dsc_htun_handle;
#endif
   dsc_ppp_wrap.dsc_ppp_se_1.vpc_handle = adsc_tun_contr_conn;

   // Obtain server's internal network INETA and netmask.
   umc_s_nw_ineta = adsp_tun_start_ppp->umc_s_nw_ineta_ipv4;
   umc_s_nw_mask = adsp_tun_start_ppp->umc_s_nw_mask_ipv4;

   // Init general CS.
   dsc_cs.m_create();

   boc_ppp_svr_started = false;

#ifdef QUICKFIX16112010
   // Workaround.
   imc_i = 1;
   boc_b = TRUE;
#endif

#ifdef QUICKFIX18112010
   boc_ppp_svr_started = false;
#endif

};

const dsd_ppp_session& dsd_ppp_session::operator=(dsd_ppp_session& dsp_rhs)
{
	if(this != &dsp_rhs)
    {
		adsc_tun_contr_ineta = dsp_rhs.adsc_tun_contr_ineta;
		dsc_ppp_wrap.dsc_ppp_se_1 = dsp_rhs.dsc_ppp_wrap.dsc_ppp_se_1;

#ifndef TJ_B170914
		umc_tunnel_id = dsp_rhs.umc_tunnel_id;
#endif
		umc_discard_count = dsp_rhs.umc_discard_count;
		umc_discard_count_tf = dsp_rhs.umc_discard_count_tf;
		umc_s_nw_ineta = dsp_rhs.umc_s_nw_ineta;
		umc_s_nw_mask = dsp_rhs.umc_s_nw_mask;
		//dsc_sendto_extnw_msgq = dsp_rhs.dsc_sendto_extnw_msgq;
		//boc_ppp_svr_started = dsp_rhs.boc_ppp_svr_started;
		boc_ppp_svr_started = TRUE;
		dsp_rhs.iec_conn_state = ied_hpppt1_conn_ended;
		dsp_rhs.boc_ppp_svr_started = FALSE;

		// Get the target-filter from the previous session
		// and set it to NULL so that the struct is not freed
		// later when the session gets destroyed
		adsc_ppp_targfi_act = dsp_rhs.adsc_ppp_targfi_act;
		dsp_rhs.adsc_ppp_targfi_act = NULL;


	}
    return *this;
}


dsd_ppp_session::~dsd_ppp_session()
{
    // Close PPP server.
    if(boc_ppp_svr_started)
		m_close_ppp_server_cs(&dsc_ppp_wrap.dsc_ppp_se_1);

    // Release target filter resources.
    if (adsc_ppp_targfi_act)
        free(adsc_ppp_targfi_act);



    // Release general CS.
    dsc_cs.m_close();
}

int dsd_ppp_session::mc_init()
{

   // Return OK.
   return 0;

}


void dsd_ppp_session::mc_close()
{

	dsc_cs.m_enter();

	if(adsc_tun_contr_conn){
		if((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
		{
			m_do_wsp_trace("SNEPPPCL", 0, adsc_tun_contr_conn->imc_sno,
				adsc_tun_contr_conn->imc_trace_level, NULL, 0, 0,
				"HOB-PPP-T1 session being closed. Reconnect timer launching for %d seconds.",
				1000 * 60 * 4);
		}

		// Inform WSP about session termination.
		m_htun_session_end(adsc_tun_contr_conn, 0);
	}
	adsc_tun_contr_conn = NULL;

#ifdef TJ_B170922
	// Free messages queue
	while (adsc_queue_first)
	{
		adsc_queue_last = adsc_queue_first->adsc_next;
		m_htun_relrecvbuf( adsc_queue_first->dsl_buf_vec.ac_handle );
		adsc_queue_first = adsc_queue_last;
	}
#endif

	// END message was recv
	if(iec_conn_state == ied_hpppt1_conn_ended){
		//dsc_cs.m_leave();
		if(adsc_tun_contr_ineta){
			m_htun_ppp_free_resources(adsc_tun_contr_ineta);
			adsc_tun_contr_ineta = NULL;
		}

		dsc_cs.m_leave();

		// Call class dtor.
		delete this;

	}else{


		//#ifdef HPPPT1_RECONNECT
		// Create and set timer to release resources (Route, PARP, INETA etc...).
		memset(&dsc_ppp_wrap.dsc_timer_close, 0, sizeof(dsc_ppp_wrap.dsc_timer_close));
		dsc_ppp_wrap.dsc_timer_close.amc_compl = m_cb_timer_close;
		dsc_ppp_wrap.dsc_timer_close.ilcwaitmsec = 1000 * 60 * 4; // 4 min timeout.
		m_time_set(&dsc_ppp_wrap.dsc_timer_close, false);

		boc_sess_closed = TRUE;
		dsc_cs.m_leave();
	}


	return;

}

void m_reconnect_workaround(struct dsd_tun_contr_ineta* adsp_tun_contr_ineta, struct dsd_tun_contr_conn* adsp_tun_contr_conn);


enum ied_hpppt1_ctrl_tag
{
	ied_hpppt1_ctrl_none = 0,
	ied_hpppt1_ctrl_start,
	ied_hpppt1_ctrl_reconnect,
	ied_hpppt1_ctrl_end
};


int m_get_hpppt1_ctrl(char* abyl_data, dsd_gather_i_1* adsl_curr_link){

	static const char chrg_start[] = { 'S', 'T', 'A', 'R', 'T' };
	static const char chrg_reconnect[] = { 'R', 'E', 'C', 'O', 'N', 'N', 'E', 'C', 'T' };
	static const char chrg_end[] = { 'E', 'N', 'D' };

	int iml_offset = abyl_data - adsl_curr_link->achc_ginp_end;
	if (iml_offset < 0)
		iml_offset = 0;
	int iml1 = 0;
	if (abyl_data < adsl_curr_link->achc_ginp_end)
		iml1 = adsl_curr_link->achc_ginp_end - abyl_data;
	// Checking start tag
	if((abyl_data+5)<=adsl_curr_link->achc_ginp_end){
		if(memcmp(abyl_data, chrg_start, 5) == 0)
			return ied_hpppt1_ctrl_start;
	}

	else if((memcmp(adsl_curr_link->achc_ginp_cur, chrg_start, iml1) == 0)&&
		(memcmp(adsl_curr_link->adsc_next->achc_ginp_cur, chrg_start + iml1, 5-(adsl_curr_link->achc_ginp_end-abyl_data)) == 0))
		return ied_hpppt1_ctrl_start;


	// Checking reconnect tag
	if((abyl_data+9)<=adsl_curr_link->achc_ginp_end){
		if(memcmp(abyl_data, chrg_reconnect, 9) == 0)
			return ied_hpppt1_ctrl_reconnect;
	}
	else if(memcmp(adsl_curr_link->achc_ginp_cur, chrg_reconnect, iml1) == 0){
		if (memcmp(adsl_curr_link->adsc_next->achc_ginp_cur, chrg_reconnect + iml1, 9 - iml1) == 0)
			return ied_hpppt1_ctrl_reconnect;
	}


	// Checking end tag
	if((abyl_data+3)<=adsl_curr_link->achc_ginp_end){
		if(memcmp(abyl_data, chrg_end, 3) == 0)
			return ied_hpppt1_ctrl_end;
	}
	else if((memcmp(adsl_curr_link->achc_ginp_cur, chrg_end, iml1) == 0)&&
		(memcmp(adsl_curr_link->adsc_next->achc_ginp_cur + iml_offset, chrg_end + iml1, 3-(iml1)) == 0))
		return ied_hpppt1_ctrl_end;

	return ied_hpppt1_ctrl_none;
}




int dsd_ppp_session::mc_interpret_msg(dsd_gather_i_1* adsp_gather,
                                          dsd_hco_wothr*  adsp_hco_wothr)
{
   //int iml_len                = 0; // Length value of hob-tun length field.
   int iml_lenlen             = 0; // Length of hob-tun length field.
   int iml_tot_ht_pkt_len     = 0; // Tot length of hob-tun pkt.
   dsd_gather_i_1* adsl_curr_link = adsp_gather;
   dsd_gather_i_1 dsl_curr_record; //= adsp_gather;



   // -- TEMPORARY FIX --
   // Skip to link where cur != end.
   while(adsl_curr_link->achc_ginp_cur == adsl_curr_link->achc_ginp_end)
   {
	   if(adsl_curr_link->adsc_next == NULL)
		   return 0;
	   else adsl_curr_link = adsl_curr_link->adsc_next;

   }

   enum ied_hpppt1_tag
   {
      ied_hpppt1_none = 0x00,
      ied_hpppt1_ctrl = 0x30,
      ied_hpppt1_ppp  = 0x31,
      ied_hpppt1_ipv4 = 0x40,
      ied_hpppt1_ipv6 = 0x60
   };

   // While more links are available...
   while(adsl_curr_link != NULL)
   {
      // -- TEMPORARY FIX --
      // Skip to link where cur != end.
      while(adsl_curr_link->achc_ginp_cur == adsl_curr_link->achc_ginp_end)
      {
         if(adsl_curr_link->adsc_next == NULL)
            return 0;
         else adsl_curr_link = adsl_curr_link->adsc_next;

      }
	  memcpy(&dsl_curr_record, adsl_curr_link, sizeof(dsd_gather_i_1));

      int iml_hpppt1_length = 0;
      int iml_lenlen = 0;  // Length of length field and auxiliary length value later

      char* achl_cur_pos = adsl_curr_link->achc_ginp_cur;

      ied_hpppt1_tag iel_hpppt1_tag = ied_hpppt1_none;

	  // If HOB-PPP-T1 connection not started yet...
	  switch (iec_conn_state)
	  {
	  case ied_hpppt1_conn_idle:
		  // Look for Start HOB-PPP-T1 command...
		  iec_conn_state = m_check_hpppt1_cmd(adsl_curr_link);
		  // If Start HOB-PPP-T1 command found...
		  if(iec_conn_state == ied_hpppt1_conn_started)
			  iml_hpppt1_length = 20;
		  else return 0;
		  break;


	  case ied_hpppt1_conn_ended:
		  /*// consume all gathers?????
		  do{
			  adsp_gather->achc_ginp_cur = adsp_gather->achc_ginp_end;
			  adsp_gather = adsp_gather->adsc_next;
		  }while(adsp_gather);
		  return 0;
		  //break;*/

		  break;



	  case ied_hpppt1_conn_started:
#ifdef HPPPT1_V21
         // --TAG--
         // Find link with at least one unconsumed byte...
         while(adsl_curr_link->achc_ginp_cur == adsl_curr_link->achc_ginp_end)
         {
            adsl_curr_link = adsl_curr_link->adsc_next;
            // No unconsumed links found...
            if(adsl_curr_link == NULL)
               return 0;
         }
         // Read tag byte.
         achl_cur_pos = adsl_curr_link->achc_ginp_cur;
         iel_hpppt1_tag = (ied_hpppt1_tag)*achl_cur_pos;
         // Truncate type if IPv4 or IPv6...
         if((iel_hpppt1_tag & 0xF0) == ied_hpppt1_ipv4 ||
            (iel_hpppt1_tag & 0xF0) == ied_hpppt1_ipv6)
         {
            iel_hpppt1_tag = (ied_hpppt1_tag)(iel_hpppt1_tag & 0xF0);
         }
         // Move one byte forward.
         achl_cur_pos++;
         adsl_curr_link->achc_ginp_cur++;


         // --LENGTH--
         switch(iel_hpppt1_tag)
         {
            case ied_hpppt1_ctrl:
            {
               // Read NHASN length.
				if(!m_getlen_nhasn(adsl_curr_link, iml_hpppt1_length, iml_lenlen))
				{
					adsl_curr_link->achc_ginp_cur--;
					return 0;
				}
               iml_hpppt1_length += 1 + iml_lenlen;
               // Move back one byte.
               adsl_curr_link->achc_ginp_cur--;
            } break;
            case ied_hpppt1_ppp:
            {
               // Read NHASN length.
               if(!m_getlen_nhasn(adsl_curr_link, iml_hpppt1_length, iml_lenlen))
			   {
				   adsl_curr_link->achc_ginp_cur--;
				   return 0;
			   }
               iml_hpppt1_length += 1 + iml_lenlen;
               // Move back one byte.
               adsl_curr_link->achc_ginp_cur--;
            } break;
            case ied_hpppt1_ipv4:
            {
               // Move back one byte.
               adsl_curr_link->achc_ginp_cur--;
               achl_cur_pos = adsl_curr_link->achc_ginp_cur;
               // Try to skip to length field.
               if(!m_skip(&adsl_curr_link, &achl_cur_pos, 2))
                  return 0;
               // Read lenght value.
               unsigned short usl_len = 0;
               if(!m_get_ushort(&adsl_curr_link, &achl_cur_pos, &usl_len))
                  return 0;
               usl_len = ntohs(usl_len);
               iml_hpppt1_length = (int32_t)usl_len;
            } break;
            case ied_hpppt1_ipv6:
            {
               // Move back one byte.
               adsl_curr_link->achc_ginp_cur--;
               achl_cur_pos = adsl_curr_link->achc_ginp_cur;
               // Try to skip to length field.
               if(!m_skip(&adsl_curr_link, &achl_cur_pos, 4))
                  return 0;
               // Read lenght value.
               unsigned short usl_len = 0;
               if(!m_get_ushort(&adsl_curr_link, &achl_cur_pos, &usl_len))
                  return 0;
               usl_len = ntohs(usl_len);
               iml_hpppt1_length = (int32_t)usl_len + 40;
            } break;
            default:
            {
               return 0;
            } break;
         }

         // Peek forward to end of message.
		 adsl_curr_link = &dsl_curr_record;
         dsd_gather_i_1* adsl_peek_link = adsl_curr_link;
         char* achl_peek_pos = adsl_curr_link->achc_ginp_cur;
         if(!m_skip(&adsl_peek_link, &achl_peek_pos, iml_hpppt1_length))
            return 0;
#else
         // Read NHASN length.
         if(!m_getlen_nhasn(adsl_curr_link, iml_hpppt1_length, iml_lenlen))
            return 0;
         achl_cur_pos = adsl_curr_link->achc_ginp_cur;
         if(!m_skip(&adsl_curr_link, &achl_cur_pos, iml_lenlen))
            return 0;
         iml_hpppt1_length += iml_lenlen;

         // --TAG--
         // Find link with at least one unconsumed byte...
         dsd_gather_i_1* adsl_temp_gath = adsl_curr_link;
         while(achl_cur_pos == adsl_temp_gath->achc_ginp_end)
         {
            adsl_temp_gath = adsl_temp_gath->adsc_next;
            achl_cur_pos = adsl_temp_gath->achc_ginp_cur;
            // No unconsumed links found...
            if(adsl_temp_gath == NULL)
               return 0;
         }

         // Read tag byte.
		 if(*achl_cur_pos == '4')
			 iel_hpppt1_tag = ied_hpppt1_ipv4;
		 else if(*achl_cur_pos == '6')
			 iel_hpppt1_tag = ied_hpppt1_ipv6;
		 else
			 iel_hpppt1_tag = (ied_hpppt1_tag)*achl_cur_pos;

		 // Peek forward to end of message.
		 dsd_gather_i_1* adsl_peek_link = adsl_curr_link;
		 char* achl_peek_pos = adsl_curr_link->achc_ginp_cur;
		 if(!m_skip(&adsl_peek_link, &achl_peek_pos, iml_hpppt1_length - iml_lenlen))
			 return 0;
#endif


		 // Avoid copying memory
		 unsigned char* abyl_data = (unsigned char*)adsl_curr_link->achc_ginp_cur;


		 if( (iec_conn_state==ied_hpppt1_conn_ended) && (iel_hpppt1_tag!=ied_hpppt1_ctrl_end))
			 break;


		 // --VALUE--
		 switch(iel_hpppt1_tag)
		 {
		 case ied_hpppt1_ctrl:
			 {
				 int iml_hpppt1_ctrl_tag = m_get_hpppt1_ctrl((char*)(abyl_data  + 1 + iml_lenlen), adsl_curr_link);
				 // Match following sequence against "START"...
				 if (iml_hpppt1_ctrl_tag == ied_hpppt1_ctrl_start)
				 {
					 if((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
					 {
						 m_do_wsp_trace("SNEPPPST", 0, adsc_tun_contr_conn->imc_sno,
							 adsc_tun_contr_conn->imc_trace_level, NULL, 0, 0,
							 "HOB-PPP-T1 START received from client.");
					 }
#ifndef NEW_HOB_TUN_1103
					 // Try to obtain a VINETA for the connecting client.
					 if((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
					 {
						 m_do_wsp_trace("SNEPPPIA", 0, adsc_tun_contr_conn->imc_sno,
							 adsc_tun_contr_conn->imc_trace_level, NULL, 0, 0,
							 "Attempting to acquire VINETA for connecting client.");
					 }
					 adsc_tun_contr_ineta = m_htun_ppp_acquire_local_ineta_ipv4(adsp_hco_wothr,
						 adsc_tun_contr_conn, NULL);
#endif
					 if(adsc_tun_contr_ineta == NULL)
					 {
						 if((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
						 {
							 m_do_wsp_trace("SNEPPPIF", 0, adsc_tun_contr_conn->imc_sno,
								 adsc_tun_contr_conn->imc_trace_level, NULL, 0, 0,
								 "Could not acquire VINETA for connecting client. Closing session.");
						 }
						 // Send STOP control message.
						 mc_send_stop();
						 // Close PPP session immediately, without timer.
						 mc_ppp_close_and_release(this);
						 return 0;
					 }

#ifndef GRATUITOUSARP
					 //m_send_garp(adsc_tun_contr_ineta->dsc_soa_local_ipv4);
#endif

					 // Add new node to AVL tree.
#ifdef TJ_B170922
#ifdef B140304
					 ds_pppsess_avl_cs.m_enter();
#endif
					 dsd_avl_sess_entry* ads_new_pppsess_node = new dsd_avl_sess_entry;
#ifdef ML150126  // random tunnel ID
					 ads_new_pppsess_node->umc_key_ineta = adsc_tun_contr_ineta->dsc_soa_local_ipv4.
						 sin_addr.s_addr;
#else
	                 //TODO: check if tunnel ID is already in use
					 while (!umc_tunnel_id)
						 umc_tunnel_id = (uint32_t) m_get_random_number( INT_MAX );
					 ads_new_pppsess_node->umc_key_ineta = umc_tunnel_id;

#endif
					 ads_new_pppsess_node->adsc_ppp_sess = this;
#ifndef B140304
					 memset( &this->dsc_ppp_wrap.dsc_timer_close, 0, sizeof(struct dsd_timer_ele) );
					 ds_pppsess_avl_cs.m_enter();
#endif
					 m_htree1_avl_search(NULL, &ds_pppsess_avl_cntl, &ds_pppsess_avl_wrk,
						 &ads_new_pppsess_node->dsc_avl_hdr);
					 m_htree1_avl_insert(NULL, &ds_pppsess_avl_cntl, &ds_pppsess_avl_wrk, &ads_new_pppsess_node->dsc_avl_hdr);
					 ds_pppsess_avl_cs.m_leave();
#endif // TJ_B170922
#ifndef TJ_B170922
					dsd_avl_sess_entry* ads_new_pppsess_node = new dsd_avl_sess_entry;
					memset( &this->dsc_ppp_wrap.dsc_timer_close, 0, sizeof(struct dsd_timer_ele) );
					ads_new_pppsess_node->adsc_ppp_sess = this;
					do {
						// obtain random tunnel ID
						ads_new_pppsess_node->umc_key_ineta =  1 + (uint32_t) m_get_random_number( INT_MAX - 1 );
						ds_pppsess_avl_cs.m_enter();					
						m_htree1_avl_search(NULL, &ds_pppsess_avl_cntl, &ds_pppsess_avl_wrk,
							&ads_new_pppsess_node->dsc_avl_hdr);
						if ( ds_pppsess_avl_wrk.adsc_found ) {   // check if tunnel ID already in use?
							ds_pppsess_avl_cs.m_leave();
							continue;
						}
						// insert PPP session in AVL tree
						m_htree1_avl_insert(NULL, &ds_pppsess_avl_cntl, &ds_pppsess_avl_wrk, &ads_new_pppsess_node->dsc_avl_hdr);
					    ds_pppsess_avl_cs.m_leave();
						umc_tunnel_id = ads_new_pppsess_node->umc_key_ineta;
						break;
					} while ( TRUE );
#endif  // not defined TJ_B170922

#ifdef callback_hs_compl
					 // Create target filter, if necessary.
					 adsc_targ_filter = m_htun_ppp_get_targfi(adsc_tun_contr_conn);
					 adsc_ppp_targfi_act = NULL;
					 if(adsc_targ_filter != NULL)
					 {
						 if((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
						 {
							 m_do_wsp_trace("SNEPPPTC", 0, adsc_tun_contr_conn->imc_sno,
								 adsc_tun_contr_conn->imc_trace_level, NULL, 0, 0,
								 "Creating PPP target filter.");
						 }
//						 adsc_ppp_targfi_act = m_create_ppp_targfi(adsc_targ_filter);
         adsc_ppp_targfi_act = m_create_ppp_targfi( adsc_targ_filter,
                                                    adsc_tun_contr_conn->imc_trace_level,
                                                    adsc_tun_contr_conn->imc_sno );
					 }
#endif

					 mc_send_responsestart();
				 }
				 // Match following sequence against "RECONNECT"...
				 if (iml_hpppt1_ctrl_tag == ied_hpppt1_ctrl_reconnect)
				 {
					 //dsc_cs.m_enter();
					 if((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
					 {
						 m_do_wsp_trace("SNEPPPRC", 0, adsc_tun_contr_conn->imc_sno,
							 adsc_tun_contr_conn->imc_trace_level, NULL, 0, 0,
							 "HOB-PPP-T1 RECONNECT received from client.");
						 ds_pppsess_avl_wrk.adsc_curr_node = ds_pppsess_avl_wrk.adsc_curr_node->adsc_parent;
					 }

					 // Obtain old VINETA from RECONNECT message.
#ifdef ML150126  // random tunnel ID
					 char chrl_vineta[9] = { 0 };
					 memcpy(chrl_vineta, abyl_data + 1 + iml_lenlen + 20, 8);
					 std::stringstream dsl_ss;
					 dsl_ss << std::hex << chrl_vineta;
					 unsigned int uml_vineta = 0;
					 dsl_ss >> uml_vineta;
					 uml_vineta = htonl(uml_vineta);
#else
					 char chrl_tunnel_id[9] = { 0 };
					 memcpy(chrl_tunnel_id, abyl_data + 1 + iml_lenlen + 20, 8);
					 std::stringstream dsl_ss;
					 dsl_ss << std::hex << chrl_tunnel_id;
					 unsigned int umc_tunnel_id = 0;
					 dsl_ss >> umc_tunnel_id;
					 umc_tunnel_id = htonl(umc_tunnel_id);
#endif


					 // Look up VINETA in AVL tree.
					 ds_pppsess_avl_cs.m_enter();
					 dsd_avl_sess_entry dsl_pppsess_search_node;
#ifdef ML150126  // random tunnel ID
					 dsl_pppsess_search_node.umc_key_ineta = uml_vineta;
#else
					 dsl_pppsess_search_node.umc_key_ineta = umc_tunnel_id;
#endif
					 m_htree1_avl_search(NULL, &ds_pppsess_avl_cntl, &ds_pppsess_avl_wrk,
						 (dsd_htree1_avl_entry*)&dsl_pppsess_search_node);


					 // If original session found...
					 dsd_ppp_session* adsl_orig_ppp_sess = NULL;
					 if(ds_pppsess_avl_wrk.adsc_found)
					 {
						 // Copy original session.
						 dsd_avl_sess_entry* adsl_found_node =
							 (dsd_avl_sess_entry*)ds_pppsess_avl_wrk.adsc_found;
						 adsl_orig_ppp_sess = (dsd_ppp_session*)adsl_found_node->adsc_ppp_sess;

						 // Check session owner
						 if ((imc_len_session_owner != adsl_orig_ppp_sess->imc_len_session_owner)
							 || memcmp(chrc_session_owner, adsl_orig_ppp_sess->chrc_session_owner, imc_len_session_owner))
						 {
							 if((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
							 {
								 m_do_wsp_trace("SNEPPPRF", 0, adsc_tun_contr_conn->imc_sno,
									 adsc_tun_contr_conn->imc_trace_level, NULL, 0, 0,
									 "RECONNECT failed. Wrong session owner.");
							 }
							 // Send STOP control message.
							 mc_send_stop();
							 //dsc_cs.m_leave();
							 // Terminate session.
							 ds_pppsess_avl_cs.m_leave();
							 mc_ppp_close_and_release(this);
							 m_consume_hpppt1_msg(&adsl_curr_link, iml_hpppt1_length);
							 return 0;
						 }



						 // If first ppp session still active
						 if(!adsl_orig_ppp_sess->boc_sess_closed){
							 adsl_orig_ppp_sess->dsc_cs.m_enter();
							 //adsl_orig_ppp_sess->adsc_tun_contr_ineta = NULL;
							 if(adsl_orig_ppp_sess->adsc_tun_contr_conn){
								 // Inform WSP about session termination.
								 m_htun_session_end(adsl_orig_ppp_sess->adsc_tun_contr_conn, -1);
							 }
							 adsl_orig_ppp_sess->adsc_tun_contr_conn = NULL;
							 adsl_orig_ppp_sess->dsc_cs.m_leave();
						 }

                         //TODO: should be done in a different way (not by overloading operators)
						 *this = *adsl_orig_ppp_sess;
						 // Release close timer on original session.
						 m_time_rel(&adsl_orig_ppp_sess->dsc_ppp_wrap.dsc_timer_close);

						 adsl_found_node->adsc_ppp_sess = this;
						 /*if(!adsl_orig_ppp_sess->boc_sess_closed){
						 //mc_send_stop(adsl_orig_ppp_sess->adsc_tun_contr_conn);
						 //adsl_orig_ppp_sess->mc_close();
						 adsl_orig_ppp_sess->boc_sess_closed = TRUE;
						 m_htun_session_end(adsl_orig_ppp_sess->adsc_tun_contr_conn, 0);
						 }*/

						 ds_pppsess_avl_cs.m_leave();
#ifndef B140304
						 memset( &dsc_ppp_wrap.dsc_timer_close, 0, sizeof(struct dsd_timer_ele) );
#endif
						 //dsc_ppp_wrap.dsc_ppp_se_1.vpc_handle = this;
#ifdef B150702
						 dsc_ppp_wrap.dsc_ppp_se_1.vpc_handle = (void*) &dsc_htun_handle;
#endif
       dsc_ppp_wrap.dsc_ppp_se_1.vpc_handle = adsc_tun_contr_conn;

						 ////////////////////////////
						 m_reconnect_workaround(adsc_tun_contr_ineta, adsc_tun_contr_conn);
						 ////////////////////////////

#ifdef HPPPT1_V21
						 // Send NOP HOB-PPP-T1 control message to client.
						 mc_send_nop();
#endif

						 boc_sess_closed = FALSE;
						 //dsc_cs.m_leave();

						 delete adsl_orig_ppp_sess;
						
					 }
					 else
					 {
						 if((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
						 {
							 m_do_wsp_trace("SNEPPPRF", 0, adsc_tun_contr_conn->imc_sno,
								 adsc_tun_contr_conn->imc_trace_level, NULL, 0, 0,
								 "RECONNECT failed. Could not find original session.");
						 }
						 // Send STOP control message.
						 mc_send_stop();

						 adsl_curr_link = adsp_gather;
						 m_consume_hpppt1_msg(&adsl_curr_link, iml_hpppt1_length);

						 // Terminate session.
						 mc_ppp_close_and_release(this);
						 ds_pppsess_avl_cs.m_leave();

						 return -1;
					 }

				 }
				 // Match following sequence against "END"...
				 if (iml_hpppt1_ctrl_tag == ied_hpppt1_ctrl_end)
				 {
#ifdef ML150114
					 // Get number of messages discarded by the client.
					 if (((char*)(abyl_data + 1 + iml_lenlen + 20)) < adsl_curr_link->achc_ginp_end){
						 umc_discard_count_cli = (int) strtol( (char*)(abyl_data) + 1 + iml_lenlen + 20, &adsl_curr_link->achc_ginp_end, 10);
					 }else{
						 umc_discard_count_cli = 0;
						 iml_lenlen -= adsl_curr_link->achc_ginp_end - adsl_curr_link->achc_ginp_cur;
					 }
					 if (((char*)(adsl_curr_link->achc_ginp_cur + iml_hpppt1_length)) > adsl_curr_link->achc_ginp_end)
					 {
						 umc_discard_count_cli *= (int) pow(10, (float)(adsl_curr_link->adsc_next->achc_ginp_end - (adsl_curr_link->adsc_next->achc_ginp_cur + 1 + iml_lenlen + 20)));
						 umc_discard_count_cli += (int) strtol( adsl_curr_link->adsc_next->achc_ginp_cur + 1 + iml_lenlen + 20, &adsl_curr_link->adsc_next->achc_ginp_end, 10);
					 }
#else
					 // Parse the number of discarded pkts on client
					 unsigned int uml_bytestocheck = iml_hpppt1_length - (1 + iml_lenlen + 20);
					 adsl_peek_link = adsl_curr_link;
					 while (((unsigned char*)(abyl_data + 1 + iml_lenlen + 20)) > (unsigned char*)adsl_peek_link->achc_ginp_end){  // Get pointer
						 iml_lenlen -= adsl_peek_link->achc_ginp_end - adsl_peek_link->achc_ginp_cur;                              // to
						 adsl_peek_link = adsl_peek_link->adsc_next;                                                               // the
						 abyl_data = (unsigned char*) adsl_peek_link->achc_ginp_cur;                                               // beginning
					 }                                                                                                             // of the
					 abyl_data = (unsigned char*)(abyl_data + 1 + iml_lenlen + 20);                                                // number
					 umc_discard_count_cli = 0;
					 while(uml_bytestocheck){
						 umc_discard_count_cli *= 10;
						 if(abyl_data > (unsigned char*)adsl_peek_link->achc_ginp_end){
							 adsl_curr_link = adsl_curr_link->adsc_next;
							 abyl_data = (unsigned char*)adsl_peek_link->achc_ginp_cur;
						 }
						 umc_discard_count_cli += ((unsigned int) *abyl_data) - 48;
						 abyl_data++;
						 uml_bytestocheck--;
					 }
#endif
					 if((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
					 {
						 m_do_wsp_trace("SNEPPPEN", 0, adsc_tun_contr_conn->imc_sno,
							 adsc_tun_contr_conn->imc_trace_level, NULL, 0, 0,
							 "HOB-PPP-T1 END received from client. Packets dropped: Server %d, Target Filter %d - Client %d - Target filter %d.",
							 umc_discard_count,
							 umc_discard_count_tf,
							 umc_discard_count_cli,
							 adsc_targ_filter);
					 }


					 // No more messages after END
					 // Send STOP control message.
					 // mc_send_stop();

					 // Look up VINETA in AVL tree.
					 ds_pppsess_avl_cs.m_enter();
					 dsd_avl_sess_entry dsl_pppsess_search_node;
#ifdef ML150126  // random tunnel ID
					 dsl_pppsess_search_node.umc_key_ineta = adsc_tun_contr_ineta->dsc_soa_local_ipv4.
						 sin_addr.s_addr;
#else
					 dsl_pppsess_search_node.umc_key_ineta = umc_tunnel_id;
#endif
					 m_htree1_avl_search(NULL, &ds_pppsess_avl_cntl, &ds_pppsess_avl_wrk,
						 (dsd_htree1_avl_entry*)&dsl_pppsess_search_node);

					 if(ds_pppsess_avl_wrk.adsc_found){

						 dsd_avl_sess_entry* adsl_found_node =
							 (dsd_avl_sess_entry*)ds_pppsess_avl_wrk.adsc_found;

						 m_htree1_avl_delete(NULL, &ds_pppsess_avl_cntl, &ds_pppsess_avl_wrk);
						 ds_pppsess_avl_cs.m_leave();

						 delete adsl_found_node;
#ifdef TJ_B170913    // fix possible deadlock - see HT ticket 51059
					 }
#else
					 } else {
#ifdef HL_DEBUG						 
						 m_hl1_printf("l%05d mc_interpret_msg() -  TUNNEL-ID=%08X not found." , __LINE__, dsl_pppsess_search_node.umc_key_ineta );
#endif
						 ds_pppsess_avl_cs.m_leave();
					 }
#endif

#ifndef TJ_B171010
                     if ( adsc_tun_contr_conn ) {
                         m_htun_warning ( adsc_tun_contr_conn, NULL, 0, "Tunnel ended ID=%08X. Packets dropped: server=%u client=%u target-filter=%u.",
                             umc_tunnel_id,
                             umc_discard_count,
                             umc_discard_count_cli,
                             umc_discard_count_tf );
				     }
#endif

					 if (iec_conn_state==ied_hpppt1_conn_ended){
						 dsc_cs.m_enter();

						 // Release timer for Reconnect
						 m_time_rel(&dsc_ppp_wrap.dsc_timer_close);

						 if(adsc_tun_contr_conn){
							 // Inform WSP about session termination.
							 m_htun_session_end(adsc_tun_contr_conn, 0);
						 }
						 adsc_tun_contr_conn = NULL;

#ifdef TJ_B170922
						 // Free messages queue
						 while (adsc_queue_first)
						 {
							 adsc_queue_last = adsc_queue_first->adsc_next;
							 m_htun_relrecvbuf( adsc_queue_first->dsl_buf_vec.ac_handle );
							 adsc_queue_first = adsc_queue_last;
						 }
#endif

						 if(adsc_tun_contr_ineta){
							 m_htun_ppp_free_resources(adsc_tun_contr_ineta);
							 adsc_tun_contr_ineta = NULL;
						 }

						 do{
							 adsp_gather->achc_ginp_cur = adsp_gather->achc_ginp_end;
							 adsp_gather = adsp_gather->adsc_next;
						 }while(adsp_gather);


						 dsc_cs.m_leave();
						 // Call class dtor.
						 delete this;
						 return 0;
					 }

					 iec_conn_state = ied_hpppt1_conn_ended;

					 // Empty gathers and close the session
					 while(adsp_gather){
						 adsp_gather->achc_ginp_cur = adsp_gather->achc_ginp_end;
						 adsp_gather = adsp_gather->adsc_next;
					 }
					
					 mc_close();

					 return 0;

				 }
			 } break;
		 case ied_hpppt1_ppp:
			 {
				 if(iml_hpppt1_length > 1024)								// Check if the record fits in chrc_work
					 break;
				 int iml_ppp_size = iml_hpppt1_length;
				 char* achrl_ppp_msg = chrc_wrk;
				 int iml1 = 0;
				 dsd_gather_i_1* adsl_gather_ppp = adsl_curr_link;

				 do{
					 if((adsl_gather_ppp->achc_ginp_end - adsl_gather_ppp->achc_ginp_cur) < iml_ppp_size){
						 memcpy(achrl_ppp_msg + iml1, adsl_gather_ppp->achc_ginp_cur, adsl_gather_ppp->achc_ginp_end - adsl_gather_ppp->achc_ginp_cur);
						 iml_ppp_size -= adsl_gather_ppp->achc_ginp_end - adsl_gather_ppp->achc_ginp_cur;
						 iml1 += (unsigned int) (adsl_gather_ppp->achc_ginp_end - adsl_gather_ppp->achc_ginp_cur);
						 adsl_gather_ppp = adsl_gather_ppp->adsc_next;
						 continue;
					 }
					 memcpy( achrl_ppp_msg + iml1, adsl_gather_ppp->achc_ginp_cur, iml_ppp_size);
					 break;
				 }while(1);
#ifndef B150703
       if (adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
         int iml_w1, iml_w2, iml_w3, iml_w4;
         BOOL bol_w1;
         char *achl_w1, *achl_w2, *achl_w3, *achl_w4;
         struct dsd_wsp_trace_1 *adsl_wt1_w1;  /* WSP trace control record */
         struct dsd_wsp_trace_1 *adsl_wt1_w2;  /* WSP trace control record */
         struct dsd_wsp_trace_1 *adsl_wt1_w3;  /* WSP trace control record */
         struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record */

         iml_w1 = iml_hpppt1_length - 1 - iml_lenlen;
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "SNEHPPP1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_sno = adsc_tun_contr_conn->imc_sno;  /* WSP session number */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
         iml_w2 = sprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                           "l%05d HOB-PPP-T1 data passed to PPP module - length %d/0X%X.",
                           __LINE__, iml_w1, iml_w1 );
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
         ADSL_WTR_G1->imc_length = iml_w2;  /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
         if (adsc_tun_contr_conn->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2)) {  /* generate WSP trace record */
           achl_w1 = (char *) (((size_t) ((char *) (ADSL_WTR_G1 + 1) + iml_w2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
           iml_w2 = 0;                      /* in this buffer          */
           achl_w3 = achrl_ppp_msg + 1 + iml_lenlen;  /* start of data */
           adsl_wt1_w2 = adsl_wt1_w1;       /* in this piece of memory */
           adsl_wtr_w1 = ADSL_WTR_G1;       /* set last in chain       */
           bol_w1 = FALSE;                  /* reset more flag         */
           do {                             /* loop always with new struct dsd_wsp_trace_record */
             achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
             if ((achl_w1 + sizeof(struct dsd_wsp_trace_record)) >= achl_w2) {
               adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
               memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
               adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
               adsl_wt1_w2 = adsl_wt1_w3;  /* this is current network */
               achl_w1 = (char *) (adsl_wt1_w2 + 1);
               achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
             }
             memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
             ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
             achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
             ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
             adsl_wtr_w1->boc_more = bol_w1;  /* more data to follow   */
             bol_w1 = TRUE;                 /* set more flag           */
             adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
             adsl_wtr_w1 = ADSL_WTR_G2;     /* this is last in chain now */
             while (TRUE) {                 /* loop over data sent     */
               iml_w3 = (achrl_ppp_msg + 1 + iml_lenlen) + (iml_hpppt1_length - 1 - iml_lenlen) - achl_w3;
               if (iml_w3 > iml_w1) iml_w3 = iml_w1;
               iml_w4 = achl_w2 - achl_w4;
               if (iml_w4 > iml_w3) iml_w4 = iml_w3;
               memcpy( achl_w4, achl_w3, iml_w4 );
               achl_w4 += iml_w4;
               achl_w3 += iml_w4;
               ADSL_WTR_G2->imc_length += iml_w4;  /* length of text / data */
               iml_w1 -= iml_w4;            /* length to be copied     */
               if (iml_w1 <= 0) break;
               if (achl_w4 >= achl_w2) break;
             }
             achl_w1 = achl_w2;             /* set end of this area    */
           } while (iml_w1 > 0);
         }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
#endif
				 // Send Data field to PPP implementation for processing.
				 m_recv_ppp_server_cs(&dsc_ppp_wrap.dsc_ppp_se_1, achrl_ppp_msg + 1 + iml_lenlen, iml_hpppt1_length - 1 - iml_lenlen);

				 // Initiate PPP server LCP negotiation after first PPP message is received from client.
				 if(boc_ppp_svr_started == false)
				 {
					 m_start_ppp_server_cs(&dsc_ppp_wrap.dsc_ppp_se_1);
					 boc_ppp_svr_started = true;
				 }
			 } break;
		 case ied_hpppt1_ipv4:
			 {
				 // Pass through target filter, if available...
				 ied_ret_cf iel_ret_cf = ied_rcf_ok;
				 if(adsc_ppp_targfi_act != NULL)
				 {
#ifdef HPPPT1_V21
					 iel_ret_cf = m_proc_ppp_targfi_ipv4(adsp_hco_wothr,
						 adsc_ppp_targfi_act,
						 adsl_curr_link,
						 iml_hpppt1_length);
#else
					 iel_ret_cf = m_proc_ppp_targfi_ipv4(adsp_hco_wothr,
						 adsc_ppp_targfi_act,
						 adsl_curr_link,
						 iml_hpppt1_length - iml_lenlen - 1);
#endif
				 }
				 // If packet can be passed...
				 if(iel_ret_cf == ied_rcf_ok)
				 {
#ifdef HPPPT1_V21
					 // Send IPv4 packet over internal network.
					 if(iml_hpppt1_length <= (adsl_curr_link->achc_ginp_end-adsl_curr_link->achc_ginp_cur))
						 m_se_husip_send((byte*)adsl_curr_link->achc_ginp_cur, iml_hpppt1_length);
					 else
						 m_se_husip_send_gather(adsl_curr_link, iml_hpppt1_length);

#else
					 // Send IPv4 packet over internal network.
					 m_se_husip_send(abyl_data + iml_lenlen + 1, iml_hpppt1_length - iml_lenlen - 1);
#endif

				 }
				 else
					 umc_discard_count_tf++;
			 } break;
		 case ied_hpppt1_ipv6:
			 {
				 // Pass through target filter, if available...
				 ied_ret_cf iel_ret_cf = ied_rcf_ok;
				 if(adsc_ppp_targfi_act != NULL)
				 {
#ifdef HPPPT1_V21
					 iel_ret_cf = m_proc_ppp_targfi_ipv6(adsp_hco_wothr,
						 adsc_ppp_targfi_act,
						 adsl_curr_link,
						 iml_hpppt1_length);
#else
					 iel_ret_cf = m_proc_ppp_targfi_ipv6(adsp_hco_wothr,
						 adsc_ppp_targfi_act,
						 adsl_curr_link,
						 iml_hpppt1_length - iml_lenlen - 1);
#endif
				 }
				 // If packet can be passed...
				 if(iel_ret_cf == ied_rcf_ok)
				 {
#ifdef HPPPT1_V21
					 // Send IPv6 packet over internal network.
					 if(iml_hpppt1_length <= (adsl_curr_link->achc_ginp_end-adsl_curr_link->achc_ginp_cur))
						 m_se_husip_send((byte*)adsl_curr_link->achc_ginp_cur, iml_hpppt1_length);
					 else
						 m_se_husip_send_gather(adsl_curr_link, iml_hpppt1_length);

#else
					 // Send IPv4 packet over internal network.
					 m_se_husip_send(abyl_data + iml_lenlen + 1, iml_hpppt1_length - iml_lenlen - 1);
#endif

				 }
				 else
					 umc_discard_count_tf++;
			 } break;
		 }

		 break;
	  }
	  adsl_curr_link = adsp_gather;
      m_consume_hpppt1_msg(&adsl_curr_link, iml_hpppt1_length);
   }

   return 0;
}

BOOL dsd_ppp_session::mc_send_responsestart()
{
    // Obtain a buffer to use for sending.
    void* apl_handle = NULL;
    byte* abyl_data = NULL;
    int iml_data_len = 0;
    iml_data_len = m_htun_getrecvbuf(&apl_handle, (char**)&abyl_data);

    // Do a basic length check on the buffer obtained.
    if(iml_data_len < 266)
        return FALSE;
#ifdef TJ_B171010 // see ML150126
    // Obtain VINETA from AVL node.
    unsigned int uml_tunnel_id = htonl(adsc_tun_contr_ineta->
                          dsc_soa_local_ipv4.sin_addr.s_addr);
#endif
    // Obtain server network (internal) INETA.
    in_addr dsl_s_net_ineta;
    dsl_s_net_ineta.s_addr = umc_s_nw_ineta;
    char chrl_s_net_ineta[16];
    memcpy(chrl_s_net_ineta, inet_ntoa(dsl_s_net_ineta), 16);

    // Obtain server network (internal) mask.
    in_addr dsl_s_net_mask;
    dsl_s_net_mask.s_addr = umc_s_nw_mask;
    char chrl_s_net_mask[16];
    memcpy(chrl_s_net_mask, inet_ntoa(dsl_s_net_mask), 16);

    // Build RESPONSE-START message.
    char chrl_buf[256] = { 0 };
#ifdef ML150126
    sprintf(chrl_buf, "RESPONSE-START TUNNEL-ID=%08X SERVER-NETWORK-INETA=%s SERVER-NETWORK-MASK=%s", uml_tunnel_id, chrl_s_net_ineta, chrl_s_net_mask);
#else
	sprintf(chrl_buf, "RESPONSE-START TUNNEL-ID=%08X SERVER-NETWORK-INETA=%s SERVER-NETWORK-MASK=%s", htonl(umc_tunnel_id), chrl_s_net_ineta, chrl_s_net_mask);
#endif
    unsigned int uml_msglen = strlen(chrl_buf);
    memcpy(abyl_data + 10, chrl_buf, uml_msglen);

    // Create buf vec ele.
    dsd_buf_vector_ele dsl_buf_vec;
    dsl_buf_vec.ac_handle = apl_handle;
    dsl_buf_vec.achc_data = (char*)(abyl_data + 10);
    dsl_buf_vec.imc_len_data = uml_msglen;

#ifndef HPPPT1_V21
    // Add HOB-TUN control byte (ASCII "0").
    dsl_buf_vec.achc_data -= 1;
    *((byte*)(dsl_buf_vec.achc_data)) = 0x30;
    dsl_buf_vec.imc_len_data += 1;
#endif

    // Calculate HOB-TUN length field val.
    int iml_1 = dsl_buf_vec.imc_len_data;
    // Write HOB-TUN length value to pkt.
    char chl_more = 0;
    while(true)
    {
       dsl_buf_vec.achc_data -= 1;
       *((byte*)(dsl_buf_vec.achc_data))
          = (byte)(iml_1 & 0x7F) | chl_more;
       dsl_buf_vec.imc_len_data += 1;
       iml_1 >>= 7;
       if(iml_1 == 0) break;
       chl_more = (char)0x80;
    }

#ifdef HPPPT1_V21
    // Add HOB-TUN control byte (ASCII "0").
    dsl_buf_vec.achc_data -= 1;
    *((byte*)(dsl_buf_vec.achc_data)) = 0x30;
    dsl_buf_vec.imc_len_data += 1;
#endif

    // Check whether it is OK to send message towards client...
    if(boc_cansend)
    {
    // Send pkt to client.
    if(!(m_se_htun_recvbuf(adsc_tun_contr_conn, &dsl_buf_vec, 1)))
    {
          // Indicate that it is not OK to send more messages towards client.
          boc_cansend = false;
       }
    }
    else
    {
       // Increment number of messages discarded.
       umc_discard_count++;
    }

    // Return success.
    return TRUE;
}

BOOL dsd_ppp_session::mc_send_nop()
{
    // Obtain a buffer to use for sending.
    void* apl_handle = NULL;
    byte* abyl_data = NULL;
    int iml_data_len = 0;
    iml_data_len = m_htun_getrecvbuf(&apl_handle, (char**)&abyl_data);

    // Do a basic length check on the buffer obtained.
    if(iml_data_len < 266)
        return FALSE;

    // Build NOP message.
    char chrl_buf[256] = { 0 };
    sprintf(chrl_buf, "NOP");
    unsigned int uml_msglen = strlen(chrl_buf);
    memcpy(abyl_data + 10, chrl_buf, uml_msglen);

    // Create buf vec ele.
    dsd_buf_vector_ele dsl_buf_vec;
    dsl_buf_vec.ac_handle = apl_handle;
    dsl_buf_vec.achc_data = (char*)(abyl_data + 10);
    dsl_buf_vec.imc_len_data = uml_msglen;

#ifndef HPPPT1_V21
    // Add HOB-TUN control byte (ASCII "0").
    dsl_buf_vec.achc_data -= 1;
    *((byte*)(dsl_buf_vec.achc_data)) = 0x30;
    dsl_buf_vec.imc_len_data += 1;
#endif

    // Calculate HOB-TUN length field val.
    int iml_1 = dsl_buf_vec.imc_len_data;
    // Write HOB-TUN length value to pkt.
    char chl_more = 0;
    while(true)
    {
       dsl_buf_vec.achc_data -= 1;
       *((byte*)(dsl_buf_vec.achc_data))
          = (byte)(iml_1 & 0x7F) | chl_more;
       dsl_buf_vec.imc_len_data += 1;
       iml_1 >>= 7;
       if(iml_1 == 0) break;
       chl_more = (char)0x80;
    }

#ifdef HPPPT1_V21
    // Add HOB-TUN control byte (ASCII "0").
    dsl_buf_vec.achc_data -= 1;
    *((byte*)(dsl_buf_vec.achc_data)) = 0x30;
    dsl_buf_vec.imc_len_data += 1;
#endif

    // Check whether it is OK to send message towards client...
    if(boc_cansend)
    {
    // Send pkt to client.
    if(!(m_se_htun_recvbuf(adsc_tun_contr_conn, &dsl_buf_vec, 1)))
    {
          // Indicate that it is not OK to send more messages towards client.
          boc_cansend = false;
       }
    }
    else
    {
       // Increment number of messages discarded.
       umc_discard_count++;
    }

    // Return success.
    return TRUE;
}

BOOL dsd_ppp_session::mc_send_stop()
{
    // Obtain a buffer to use for sending.
    void* apl_handle = NULL;
    byte* abyl_data = NULL;
    int iml_data_len = 0;
    iml_data_len = m_htun_getrecvbuf(&apl_handle, (char**)&abyl_data);

    // Do a basic length check on the buffer obtained.
    if(iml_data_len < 266)
        return FALSE;

    // Build STOP message.
    char chrl_buf[256] = { 0 };
    sprintf(chrl_buf, "STOP");
    unsigned int uml_msglen = strlen(chrl_buf);
    memcpy(abyl_data + 10, chrl_buf, uml_msglen);

    // Create buf vec ele.
    dsd_buf_vector_ele dsl_buf_vec;
    dsl_buf_vec.ac_handle = apl_handle;
    dsl_buf_vec.achc_data = (char*)(abyl_data + 10);
    dsl_buf_vec.imc_len_data = uml_msglen;

#ifndef HPPPT1_V21
    // Add HOB-TUN control byte (ASCII "0").
    dsl_buf_vec.achc_data -= 1;
    *((byte*)(dsl_buf_vec.achc_data)) = 0x30;
    dsl_buf_vec.imc_len_data += 1;
#endif

    // Calculate HOB-TUN length field val.
    int iml_1 = dsl_buf_vec.imc_len_data;
    // Write HOB-TUN length value to pkt.
    char chl_more = 0;
    while(true)
    {
       dsl_buf_vec.achc_data -= 1;
       *((byte*)(dsl_buf_vec.achc_data))
          = (byte)(iml_1 & 0x7F) | chl_more;
       dsl_buf_vec.imc_len_data += 1;
       iml_1 >>= 7;
       if(iml_1 == 0) break;
       chl_more = (char)0x80;
    }

#ifdef HPPPT1_V21
    // Add HOB-TUN control byte (ASCII "0").
    dsl_buf_vec.achc_data -= 1;
    *((byte*)(dsl_buf_vec.achc_data)) = 0x30;
    dsl_buf_vec.imc_len_data += 1;
#endif

    // Check whether it is OK to send message towards client...
    if(boc_cansend)
    {
    // Send pkt to client.
    if(!(m_se_htun_recvbuf(adsc_tun_contr_conn, &dsl_buf_vec, 1)))
    {
          // Indicate that it is not OK to send more messages towards client.
          boc_cansend = false;
       }
    }
    else
    {
       // Increment number of messages discarded.
       umc_discard_count++;
    }

    // Return success.
    return TRUE;
}


#ifdef TJ_B170922
void dsd_ppp_session::mc_can_send()
{
    // Enter general CS.
    dsc_cs.m_enter();

    boc_cansend = true;

	while(boc_cansend && adsc_queue_first)
	{
		// Create buf vec ele.
		struct dsd_buf_vector_ele dsl_buf_vec[ D_ARRAY_PACKET ];
		int iml_array_len;
		for (iml_array_len = 0; iml_array_len < D_ARRAY_PACKET; iml_array_len++)
		{
			if (adsc_queue_first == NULL) break;
			dsl_buf_vec[ iml_array_len ].ac_handle = adsc_queue_first->dsl_buf_vec.ac_handle;
			dsl_buf_vec[ iml_array_len ].achc_data = (char*)adsc_queue_first->dsl_buf_vec.achc_data;
			dsl_buf_vec[ iml_array_len ].imc_len_data = adsc_queue_first->dsl_buf_vec.imc_len_data;
			adsc_queue_first = adsc_queue_first->adsc_next;
			umc_packets_list--;
			iml_array_len++;                        /* entry filled            */
		}
		if (adsc_queue_first == NULL)
			adsc_queue_last = NULL;
			// Send queued message to client.
		if((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
		{
			for (int iml1 = 0; iml1 < iml_array_len; iml1++)
			{
				// Create gather struct for tracing.
				dsd_gather_i_1 dsl_gath;
				dsl_gath.achc_ginp_cur = dsl_buf_vec[iml_array_len].achc_data;
				dsl_gath.achc_ginp_end =
					dsl_buf_vec[iml_array_len].achc_data + dsl_buf_vec[iml_array_len].imc_len_data;
				dsl_gath.adsc_next = NULL;

				m_do_wsp_trace("SNETUNSE", 0, adsc_tun_contr_conn->imc_sno,
					adsc_tun_contr_conn->imc_trace_level, &dsl_gath,
					dsl_buf_vec[iml_array_len].imc_len_data, 20,
					"HOB-PPP-T1 send %d bytes to client.",
					dsl_buf_vec[iml_array_len].imc_len_data);
			}
		}
		adsc_tun_contr_conn->imc_on_the_fly_packets_client += iml_array_len;
		if(!(m_se_htun_recvbuf(adsc_tun_contr_conn, dsl_buf_vec, iml_array_len)))
		{
			// Indicate that it is not OK to send more messages towards client.
			boc_cansend = false;
		}
	}
	

    // Leave general CS.
    dsc_cs.m_leave();
}
#endif // TJ_B170922

#ifndef TJ_B170922
void dsd_ppp_session::mc_can_send()
{
	boc_cansend = TRUE;
}
#endif // not TJ_B170922

#ifdef TJ_B170922
int dsd_ppp_session::mc_encapsulate_msg(void*  ap_handle,
                                        byte*  abyp_data,
                                        unsigned int ump_length)
{
	bool bol_rc;
    // Enter general CS.
    dsc_cs.m_enter();


	if(adsc_tun_contr_conn == NULL){
		boc_cansend = FALSE;
		dsc_cs.m_leave();
		m_htun_relrecvbuf(ap_handle);
		return 0;
	}



#define UMC_ON_THE_FLY_CURRENT (adsc_tun_contr_conn->imc_on_the_fly_packets_client + umc_packets_list)

	if (boc_cansend == FALSE) {
p_cannot_send_00:
		if( (UMC_ON_THE_FLY_CURRENT < MAX_PPP_ON_THE_FLY_PACKETS_CLIENT)
			|| ((adsc_tun_contr_conn->boc_not_drop_tcp_packet != FALSE)
			&& (*(abyp_data + D_POS_IPV4_H_PROT) == IPPROTO_TCP)))
		{
			umc_packets_list++;
			if (adsc_queue_last != NULL){
				adsc_queue_last->adsc_next = (struct dsd_packet *) ap_handle;
				adsc_queue_last = adsc_queue_last->adsc_next;
			}
			adsc_queue_last = (struct dsd_packet *) ap_handle;
			adsc_queue_last->dsl_buf_vec.ac_handle = ap_handle;
			adsc_queue_last->dsl_buf_vec.achc_data = (char*) abyp_data;
			adsc_queue_last->dsl_buf_vec.imc_len_data = ump_length;
			adsc_queue_last->adsc_next = NULL;
			if (adsc_queue_first == NULL)
				adsc_queue_first = adsc_queue_last;
#ifndef HPPPT1_V21
			// Add HOB-TUN control byte (ASCII "4").
			adsc_queue_last->dsl_buf_vec.achc_data -= 1;
			*((byte*)(adsc_queue_last->dsl_buf_vec.achc_data)) = 0x34;
			adsc_queue_last->dsl_buf_vec.imc_len_data += 1;

			// Calculate HOB-TUN length field val.
			int iml_1 = adsc_queue_last->dsl_buf_vec.imc_len_data;
			// Write HOB-TUN length value to pkt.
			char chl_more = 0;
			while(true)
			{
				adsc_queue_last->dsl_buf_vec.achc_data -= 1;
				*((byte*)(adsc_queue_last->dsl_buf_vec.achc_data)) =
					(byte)(iml_1 & 0x7F) | chl_more;
				adsc_queue_last->dsl_buf_vec.imc_len_data += 1;
				iml_1 >>= 7;
				if(iml_1 == 0) break;
				chl_more = (byte)0x80;
			}
#endif
			goto p_return_00;
		}

		goto p_backlog_00;
	}
	// Create buf vec ele.
	struct dsd_buf_vector_ele dsl_buf_vec[ D_ARRAY_PACKET ];
	int iml_array_len;

p_from_queue_00:
	// check if queued entries, if yes, fill array
	// when array full, jump to p_send_00:                                /* send packets to the WSP */
	iml_array_len = 0;

	// If number of queued messages is still below limit OR no drop flag is
	// set ...
	if (   (UMC_ON_THE_FLY_CURRENT >= MAX_PPP_ON_THE_FLY_PACKETS_CLIENT)
		&& (   (adsc_tun_contr_conn->boc_not_drop_tcp_packet == FALSE)
		|| (*(abyp_data + D_POS_IPV4_H_PROT) != IPPROTO_TCP))
		&& (ap_handle!=0)) {
			// free memory of received packet
			m_htun_relrecvbuf(ap_handle);
			// Increment number of messages discarded.
			umc_discard_count++;
	} else {
		// Fill the vector
		for (int iml1 = 0; iml1 < D_ARRAY_PACKET; iml1++){
			if (adsc_queue_first == NULL) break;
			dsl_buf_vec[ iml_array_len ].ac_handle = adsc_queue_first->dsl_buf_vec.ac_handle;
			dsl_buf_vec[ iml_array_len ].achc_data = (char*)adsc_queue_first->dsl_buf_vec.achc_data;
			dsl_buf_vec[ iml_array_len ].imc_len_data = adsc_queue_first->dsl_buf_vec.imc_len_data;
			adsc_queue_first = adsc_queue_first->adsc_next;
			umc_packets_list--;
			iml_array_len++;                        /* entry filled            */
		}
		if(adsc_queue_first == NULL)
			adsc_queue_last = NULL;
		if (ap_handle == NULL){
			if (iml_array_len > 0){
				goto p_send_00;
			}
			goto p_return_00;
		}
		// Add new packet either to the vector or the list
		if (iml_array_len < D_ARRAY_PACKET){
			dsl_buf_vec[ iml_array_len ].ac_handle = ap_handle;
			dsl_buf_vec[ iml_array_len ].achc_data = (char*)abyp_data;
			dsl_buf_vec[ iml_array_len ].imc_len_data = ump_length;
			ap_handle = NULL;
#ifndef HPPPT1_V21
			// Add HOB-TUN control byte (ASCII "4").
			dsl_buf_vec[ iml_array_len ].achc_data -= 1;
			*((byte*)(dsl_buf_vec[ iml_array_len ].achc_data)) = 0x34;
			dsl_buf_vec[ iml_array_len ].imc_len_data += 1;

			// Calculate HOB-TUN length field val.
			int iml_1 = dsl_buf_vec[ iml_array_len ].imc_len_data;
			// Write HOB-TUN length value to pkt.
			char chl_more = 0;
			while(true)
			{
				dsl_buf_vec[ iml_array_len ].achc_data -= 1;
				*((byte*)(dsl_buf_vec[ iml_array_len ].achc_data)) =
					(byte)(iml_1 & 0x7F) | chl_more;
				dsl_buf_vec[ iml_array_len ].imc_len_data += 1;
				iml_1 >>= 7;
				if(iml_1 == 0) break;
				chl_more = (byte)0x80;
			}
#endif
			iml_array_len++;
			//adsc_tun_contr_conn->imc_on_the_fly_packets_client++;
			//goto p_send_00;
		}
		else if (   (adsc_tun_contr_conn->boc_not_drop_tcp_packet != FALSE)
			&& (*(abyp_data + D_POS_IPV4_H_PROT) == IPPROTO_TCP)) {
				//adsc_tun_contr_conn->imc_on_the_fly_packets_client++;
				umc_packets_list++;
				if (adsc_queue_last != NULL){
					adsc_queue_last->adsc_next = (struct dsd_packet *) ap_handle;
					adsc_queue_last = adsc_queue_last->adsc_next;
				}
				adsc_queue_last = (struct dsd_packet *) ap_handle;
				adsc_queue_last->dsl_buf_vec.ac_handle = ap_handle;
				adsc_queue_last->dsl_buf_vec.achc_data = (char*) abyp_data;
				adsc_queue_last->dsl_buf_vec.imc_len_data = ump_length;
				adsc_queue_last->adsc_next = NULL;
				if (adsc_queue_first == NULL)
					adsc_queue_first = adsc_queue_last;
				ap_handle = NULL;
#ifndef HPPPT1_V21
				// Add HOB-TUN control byte (ASCII "4").
				adsc_queue_last->dsl_buf_vec.achc_data -= 1;
				*((byte*)(adsc_queue_last->dsl_buf_vec.achc_data)) = 0x34;
				adsc_queue_last->dsl_buf_vec.imc_len_data += 1;

				// Calculate HOB-TUN length field val.
				int iml_1 = adsc_queue_last->dsl_buf_vec.imc_len_data;
				// Write HOB-TUN length value to pkt.
				char chl_more = 0;
				while(true)
				{
					adsc_queue_last->dsl_buf_vec.achc_data -= 1;
					*((byte*)(adsc_queue_last->dsl_buf_vec.achc_data)) =
						(byte)(iml_1 & 0x7F) | chl_more;
					adsc_queue_last->dsl_buf_vec.imc_len_data += 1;
					iml_1 >>= 7;
					if(iml_1 == 0) break;
					chl_more = (byte)0x80;
				}
#endif
		}
		else {
			// free memory of received packet
			m_htun_relrecvbuf(ap_handle);
			// Increment number of messages discarded.
			umc_discard_count++;
			ap_handle = NULL;
		}
	}

	if(iml_array_len == 0){
		goto p_return_00;
	}

  p_send_00:                                /* send packets to the WSP */
  /* pass all iml_array_len records in one set of vectors */
  if ((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
  {
	  /* all packets go into the WSP-trace */
	  // Prepare gather structure for tracing.
	  for(int iml1 = 0; iml1 < iml_array_len; iml1++){
	  dsd_gather_i_1 dsl_gath;
	  dsl_gath.achc_ginp_cur = dsl_buf_vec[iml1].achc_data;
	  dsl_gath.achc_ginp_end = dsl_gath.achc_ginp_cur + dsl_buf_vec[iml1].imc_len_data;
	  dsl_gath.adsc_next = NULL;

	  m_do_wsp_trace("SNETUNSE", 0, adsc_tun_contr_conn->imc_sno,
		  adsc_tun_contr_conn->imc_trace_level, &dsl_gath,
		  dsl_buf_vec[iml1].imc_len_data, 20,
		  "HOB-PPP-T1 send %d bytes to client.",
		  dsl_buf_vec[iml1].imc_len_data);
	  }
  }

  adsc_tun_contr_conn->imc_on_the_fly_packets_client += iml_array_len;
  // Send message to client.
  bol_rc = m_se_htun_recvbuf(adsc_tun_contr_conn, dsl_buf_vec, iml_array_len);
  if(!bol_rc)
  {
	  // Indicate that it is not OK to send more messages towards client.
	  boc_cansend = false;
  }
  /*if (ap_handle == NULL) {
	  goto p_return_00;
  }*/
  if (boc_cansend == false) {
	  goto p_cannot_send_00;
  }
  goto p_from_queue_00;

p_backlog_00:
  /* check again if we can discard the packet */
  if (   (UMC_ON_THE_FLY_CURRENT >= MAX_PPP_ON_THE_FLY_PACKETS_CLIENT)
	  && (   (adsc_tun_contr_conn->boc_not_drop_tcp_packet == FALSE)
	  || (*(abyp_data + D_POS_IPV4_H_PROT) != IPPROTO_TCP))
	  && (ap_handle != NULL)) {
		  // free memory of received packet
		  m_htun_relrecvbuf(ap_handle);
		  // Increment number of messages discarded.
		  umc_discard_count++;
		  goto p_return_00;
  }

/* if not, append to chain - backlog */

p_return_00:
  // Leave general CS.
  dsc_cs.m_leave();


  return 0;
#undef UMC_ON_THE_FLIGHT
}
#endif //TJ_B170922

#ifndef TJ_B170922
/** int dsd_ppp_session::mc_encapsulate_msg() called in xshusip.cpp
    received data are assumed to be properly sized IPv4/IPv6 packets */
int dsd_ppp_session::mc_encapsulate_msg(void*  ap_handle,
                                        byte*  abyp_data,
                                        unsigned int ump_length)
{
	BOOL bol_not_count_packet;                    /* do not count packet     */
	struct dsd_buf_vector_ele dsl_buf_vec;
    int iml_1;
	char chl_more;
	char chl_ip_ver;                              /* IP version 0x04 / 0x06  */

    // Enter general CS.
    dsc_cs.m_enter();

	if (adsc_tun_contr_conn == NULL){
		boc_cansend = FALSE;
		dsc_cs.m_leave();
		m_htun_relrecvbuf(ap_handle);
#ifdef HL_DEBUG
		m_hl1_printf( "l%05d mc_encapsulate_msg() - packet dropped. adsc_tun_contr_conn=NULL!",  __LINE__); 
#endif	
		return 0;
	}

	if ( !boc_cansend ) goto p_drop_00; // drop packet
	
	chl_ip_ver = ( *abyp_data ) >> 4;
	
	bol_not_count_packet = FALSE;                 /* do not count packet     */
	if ( !adsc_tun_contr_conn->boc_not_drop_tcp_packet ) {  // drop TCP packets
		// check if packet needs to be discarded
		if ( adsc_tun_contr_conn->imc_on_the_fly_packets_client >= MAX_PPP_ON_THE_FLY_PACKETS_CLIENT ) {
			goto p_drop_00; // drop packet
		}
	} else { // do not count/drop TCP packets
		// check IPv4 / IPv6 packet
		if ( chl_ip_ver == 4 ) { // IPv4
			bol_not_count_packet = (*(abyp_data + D_POS_IPV4_H_PROT) == IPPROTO_TCP);
		} else { // IPv6
		    //TODO: header extensions
			bol_not_count_packet = (*(abyp_data + D_POS_IPV6_H_PROT) == IPPROTO_TCP);
		}
		if ( ( !bol_not_count_packet ) 
			&& ( adsc_tun_contr_conn->imc_on_the_fly_packets_client >= MAX_PPP_ON_THE_FLY_PACKETS_CLIENT ) ) {
			goto p_drop_00; // drop packet
		}
	}
	
	// prepare packet for sending
	dsl_buf_vec.ac_handle = ap_handle;
	dsl_buf_vec.achc_data = (char*) abyp_data;
	dsl_buf_vec.imc_len_data = ump_length;
#ifndef HPPPT1_V21
	// Add HOB-TUN control byte (ASCII "4" or "6").
	dsl_buf_vec.achc_data -= 1;
	*((byte*)(dsl_buf_vec.achc_data)) = 0x30 + chl_ip_ver;
	dsl_buf_vec.imc_len_data += 1;

	// Calculate HOB-TUN length field val.
	iml_1 = dsl_buf_vec.imc_len_data;
	// Write HOB-TUN length value to pkt.
	chl_more = 0;
	while (true)
	{
		dsl_buf_vec.achc_data -= 1;
		*((byte*)(dsl_buf_vec.achc_data)) =
			(byte)(iml_1 & 0x7F) | chl_more;
		dsl_buf_vec.imc_len_data += 1;
		iml_1 >>= 7;
		if (iml_1 == 0) break;
		chl_more = (byte)0x80;
	}
#endif
    if ((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
    {
	  /* show packet in WSP-trace */
	  // Prepare gather structure for tracing.
	  dsd_gather_i_1 dsl_gath;
	  dsl_gath.achc_ginp_cur = dsl_buf_vec.achc_data;
	  dsl_gath.achc_ginp_end = dsl_gath.achc_ginp_cur + dsl_buf_vec.imc_len_data;
	  dsl_gath.adsc_next = NULL;

	  m_do_wsp_trace("SNETUNSE", 0, adsc_tun_contr_conn->imc_sno,
		  adsc_tun_contr_conn->imc_trace_level, &dsl_gath,
		  dsl_buf_vec.imc_len_data, 20,
		  "HOB-PPP-T1 send %d bytes to client.",
		  dsl_buf_vec.imc_len_data);
    }
	// increase imc_on_the_fly_packets_client when counting is not disabled
	if ( !bol_not_count_packet ) adsc_tun_contr_conn->imc_on_the_fly_packets_client++;
	// send packet
	boc_cansend = m_se_htun_recvbuf( adsc_tun_contr_conn, &dsl_buf_vec, 1  );
	dsc_cs.m_leave();
	return 0;
	
	p_drop_00:  // drop packet
	// free memory of received packet
	m_htun_relrecvbuf(ap_handle);
	// Increment number of messages discarded.
#ifdef HL_DEBUG
    m_hl1_printf( "l%05d mc_encapsulate_msg() - packet dropped. boc_cansend=%d boc_not_drop_tcp_packet=%d imc_on_the_fly_packets_client=%d bol_not_count_packet=%d", 
	    __LINE__, 
		boc_cansend,
		adsc_tun_contr_conn->boc_not_drop_tcp_packet, 
		adsc_tun_contr_conn->imc_on_the_fly_packets_client,
		bol_not_count_packet );
#endif	
	umc_discard_count++;
    dsc_cs.m_leave();
	return 0;
}
#endif // not TJ_B170922


/*
void dsd_ppp_session::mc_make_htun(dsd_buf_vector_ele* adsp_buf_vec)
{
   adsp_buf_vec->achc_data -= 1;
   *((byte*)(adsp_buf_vec->achc_data)) = 0x31;
   adsp_buf_vec->imc_len_data += 1;

   // Calculate HOB-TUN length field val.
   int32_t iml_1 = adsp_buf_vec->imc_len_data;
   // Write HOB-TUN length value to pkt.
   char chl_more = 0;
   while(true)
   {
      adsp_buf_vec->achc_data -= 1;
      *((byte*)(adsp_buf_vec->achc_data))
         = (byte)(iml_1 & 0x7F) | chl_more;
      adsp_buf_vec->imc_len_data += 1;
      iml_1 >>= 7;
      if(iml_1 == 0) break;
      chl_more = (byte)0x80;
   }
}
*/


#ifdef TJ_B171010
int dsd_ppp_session::mc_tunnel_to_cl(void*    ap_handle,
                                     byte*    abyp_data,
                                     unsigned int ump_length)
{
	BOOL bol_rc;
    // Enter general CS.
    dsc_cs.m_enter();

	if(adsc_tun_contr_conn == NULL){
		boc_cansend = FALSE;
		dsc_cs.m_leave();
		return 0;
	}

#define UMC_ON_THE_FLY_CURRENT (adsc_tun_contr_conn->imc_on_the_fly_packets_client + umc_packets_list)

	if (boc_cansend == FALSE) {
p_cannot_send_00:
		if( (UMC_ON_THE_FLY_CURRENT < MAX_PPP_ON_THE_FLY_PACKETS_CLIENT)
			|| ((adsc_tun_contr_conn->boc_not_drop_tcp_packet != FALSE)
			&& (*(abyp_data + D_POS_IPV4_H_PROT) == IPPROTO_TCP)))
		{
			umc_packets_list++;
			if (adsc_queue_last != NULL){
				adsc_queue_last->adsc_next = (struct dsd_packet *) ap_handle;
				adsc_queue_last = adsc_queue_last->adsc_next;
			}
			adsc_queue_last = (struct dsd_packet *) ap_handle;
			adsc_queue_last->dsl_buf_vec.ac_handle = ap_handle;
			adsc_queue_last->dsl_buf_vec.achc_data = (char*) abyp_data;
			adsc_queue_last->dsl_buf_vec.imc_len_data = ump_length;
			adsc_queue_last->adsc_next = NULL;
			if (adsc_queue_first == NULL)
				adsc_queue_first = adsc_queue_last;
			goto p_return_00;
		}

		goto p_backlog_00;
	}
	// Create buf vec ele.
	struct dsd_buf_vector_ele dsl_buf_vec[ D_ARRAY_PACKET ];
	int iml_array_len;

p_from_queue_00:
	// check if queued entries, if yes, fill array
	// when array full, jump to p_send_00:                                /* send packets to the WSP */
	iml_array_len = 0;

	// If number of queued messages is still below limit OR no drop flag is
	// set ...
	if (   (UMC_ON_THE_FLY_CURRENT >= MAX_PPP_ON_THE_FLY_PACKETS_CLIENT)
		&& (   (adsc_tun_contr_conn->boc_not_drop_tcp_packet == FALSE)
		|| (*(abyp_data + D_POS_IPV4_H_PROT) != IPPROTO_TCP))
		&& (ap_handle!=0)) {
			// free memory of received packet
			m_htun_relrecvbuf(ap_handle);
			// Increment number of messages discarded.
			umc_discard_count++;
	} else {
		// Fill the vector
		for (int iml1 = 0; iml1 < D_ARRAY_PACKET; iml1++){
			if (adsc_queue_first == NULL) break;
			dsl_buf_vec[ iml_array_len ].ac_handle = adsc_queue_first->dsl_buf_vec.ac_handle;
			dsl_buf_vec[ iml_array_len ].achc_data = (char*)adsc_queue_first->dsl_buf_vec.achc_data;
			dsl_buf_vec[ iml_array_len ].imc_len_data = adsc_queue_first->dsl_buf_vec.imc_len_data;
			adsc_queue_first = adsc_queue_first->adsc_next;
			umc_packets_list--;
			iml_array_len++;                        /* entry filled            */
		}
		if(adsc_queue_first == NULL)
			adsc_queue_last = NULL;
		if (ap_handle == NULL){
			if (iml_array_len > 0){
				goto p_send_00;
			}
			goto p_return_00;
		}

#ifndef HPPPT1_V21
		// Add HOB-TUN control byte (ASCII "1").
		abyp_data -= 1;
		*((byte*)(abyp_data)) = 0x31;
		ump_length += 1;
#endif

		// Calculate HOB-TUN length field val.
		int iml_1 = ump_length;
		// Write HOB-TUN length value to pkt.
		char chl_more = 0;
		while(true)
		{
			abyp_data -= 1;
			*((byte*)(abyp_data)) =
				(byte)(iml_1 & 0x7F) | chl_more;
			ump_length += 1;
			iml_1 >>= 7;
			if(iml_1 == 0) break;
			chl_more = (byte)0x80;
		}

#ifdef HPPPT1_V21
		// Add HOB-TUN control byte (ASCII "1").
		abyp_data -= 1;
		*((byte*)(abyp_data)) = 0x31;
		ump_length += 1;
#endif

		// Add new packet either to the vector or the list
		if (iml_array_len < D_ARRAY_PACKET){
			dsl_buf_vec[ iml_array_len ].ac_handle = ap_handle;
			dsl_buf_vec[ iml_array_len ].achc_data = (char*)abyp_data;
			dsl_buf_vec[ iml_array_len ].imc_len_data = ump_length;
			ap_handle = NULL;
			iml_array_len++;
			//adsc_tun_contr_conn->imc_on_the_fly_packets_client++;
			//goto p_send_00;
		}
		else if (   (adsc_tun_contr_conn->boc_not_drop_tcp_packet != FALSE)
			&& (*(abyp_data + D_POS_IPV4_H_PROT) == IPPROTO_TCP)) {
				//adsc_tun_contr_conn->imc_on_the_fly_packets_client++;
				umc_packets_list++;
				if (adsc_queue_last != NULL){
					adsc_queue_last->adsc_next = (struct dsd_packet *) ap_handle;
					adsc_queue_last = adsc_queue_last->adsc_next;
				}
				adsc_queue_last = (struct dsd_packet *) ap_handle;
				adsc_queue_last->dsl_buf_vec.ac_handle = ap_handle;
				adsc_queue_last->dsl_buf_vec.achc_data = (char*) abyp_data;
				adsc_queue_last->dsl_buf_vec.imc_len_data = ump_length;
				adsc_queue_last->adsc_next = NULL;
				if (adsc_queue_first == NULL)
					adsc_queue_first = adsc_queue_last;
				ap_handle = NULL;
		}
		else {
			// free memory of received packet
			m_htun_relrecvbuf(ap_handle);
			// Increment number of messages discarded.
			umc_discard_count++;
			ap_handle = NULL;
		}
	}

	if(iml_array_len == 0){
		goto p_return_00;
	}

p_send_00:                                /* send packets to the WSP */
	/* pass all iml_array_len records in one set of vectors */
	if ((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
	{
		/* all packets go into the WSP-trace */
		// Prepare gather structure for tracing.
		for(int iml1 = 0; iml1 < iml_array_len; iml1++){
			dsd_gather_i_1 dsl_gath;
			dsl_gath.achc_ginp_cur = dsl_buf_vec[iml1].achc_data;
			dsl_gath.achc_ginp_end = dsl_gath.achc_ginp_cur + dsl_buf_vec[iml1].imc_len_data;
			dsl_gath.adsc_next = NULL;

			m_do_wsp_trace("SNETUNSE", 0, adsc_tun_contr_conn->imc_sno,
				adsc_tun_contr_conn->imc_trace_level, &dsl_gath,
				dsl_buf_vec[iml1].imc_len_data, 20,
				"HOB-PPP-T1 send %d bytes to client.",
				dsl_buf_vec[iml1].imc_len_data);
		}
	}

	adsc_tun_contr_conn->imc_on_the_fly_packets_client += iml_array_len;
	// Send message to client.
	bol_rc = m_se_htun_recvbuf(adsc_tun_contr_conn, dsl_buf_vec, iml_array_len);
	if(!bol_rc)
	{
		// Indicate that it is not OK to send more messages towards client.
		boc_cansend = false;
	}
	/*if (ap_handle == NULL) {
	goto p_return_00;
	}*/
	if (boc_cansend == false) {
		goto p_cannot_send_00;
	}
	goto p_from_queue_00;

p_backlog_00:
	/* check again if we can discard the packet */
	if (   (UMC_ON_THE_FLY_CURRENT >= MAX_PPP_ON_THE_FLY_PACKETS_CLIENT)
		&& (   (adsc_tun_contr_conn->boc_not_drop_tcp_packet == FALSE)
		|| (*(abyp_data + D_POS_IPV4_H_PROT) != IPPROTO_TCP))
		&& (ap_handle != NULL)) {
			// free memory of received packet
			m_htun_relrecvbuf(ap_handle);
			// Increment number of messages discarded.
			umc_discard_count++;
			goto p_return_00;
	}

	/* if not, append to chain - backlog */

p_return_00:
	// Leave general CS.
	dsc_cs.m_leave();


	return 0;
#undef UMC_ON_THE_FLIGHT


    // Leave general CS.
    dsc_cs.m_leave();

    return 0;
} // TJ_B170922
#endif // TJ_B171010

#ifndef TJ_B171010
int dsd_ppp_session::mc_tunnel_to_cl(void*    ap_handle,
                                     byte*    abyp_data,
                                     unsigned int ump_length)
{
	struct dsd_buf_vector_ele dsl_buf_vec;
    int iml_1;
	char chl_more;
	
    // Enter general CS.
    dsc_cs.m_enter();

	if (adsc_tun_contr_conn == NULL){
		boc_cansend = FALSE;
		dsc_cs.m_leave();
		m_htun_relrecvbuf(ap_handle);
		return 0;
	}
//#ifdef XYZ1 // only drop packets received from TUN-Adapter
	if ( !boc_cansend ) goto p_drop_00; // drop packet
//#endif
		
	// prepare packet for sending
#ifndef HPPPT1_V21
	// Add HOB-TUN control byte (ASCII "1").
	abyp_data -= 1;
	*((byte*)(abyp_data)) = 0x31;
	ump_length += 1;
#endif

	// Calculate HOB-TUN length field val.
	iml_1 = ump_length;
	// Write HOB-TUN length value to pkt.
	chl_more = 0;
	while(true)
	{
		abyp_data -= 1;
		*((byte*)(abyp_data)) =
			(byte)(iml_1 & 0x7F) | chl_more;
		ump_length += 1;
		iml_1 >>= 7;
		if(iml_1 == 0) break;
		chl_more = (byte)0x80;
	}

#ifdef HPPPT1_V21
	// Add HOB-TUN control byte (ASCII "1").
	abyp_data -= 1;
	*((byte*)(abyp_data)) = 0x31;
	ump_length += 1;
#endif
	dsl_buf_vec.ac_handle = ap_handle;
	dsl_buf_vec.achc_data = (char*) abyp_data;
	dsl_buf_vec.imc_len_data = ump_length;

    if ((adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
    {
	  /* show packet in WSP-trace */
	  // Prepare gather structure for tracing.
	  dsd_gather_i_1 dsl_gath;
	  dsl_gath.achc_ginp_cur = dsl_buf_vec.achc_data;
	  dsl_gath.achc_ginp_end = dsl_gath.achc_ginp_cur + dsl_buf_vec.imc_len_data;
	  dsl_gath.adsc_next = NULL;

	  m_do_wsp_trace("SNETUNSE", 0, adsc_tun_contr_conn->imc_sno,
		  adsc_tun_contr_conn->imc_trace_level, &dsl_gath,
		  dsl_buf_vec.imc_len_data, 20,
		  "HOB-PPP-T1 send %d bytes to client.",
		  dsl_buf_vec.imc_len_data);
    }
	// send packet
	boc_cansend = m_se_htun_recvbuf( adsc_tun_contr_conn, &dsl_buf_vec, 1  );
	dsc_cs.m_leave();
	return 0;

//#ifdef XYZ1	
	p_drop_00:  // drop packet
	// free memory of received packet
#ifdef HL_DEBUG
    m_hl1_printf( "l%05d mc_tunnel_to_cl() - packet dropped. boc_cansend=%d boc_not_drop_tcp_packet=%d imc_on_the_fly_packets_client=%d", 
	    __LINE__, 
		boc_cansend,
		adsc_tun_contr_conn->boc_not_drop_tcp_packet, 
		adsc_tun_contr_conn->imc_on_the_fly_packets_client );
#endif	
	m_htun_relrecvbuf(ap_handle);
	// Increment number of messages discarded.
	umc_discard_count++;
    dsc_cs.m_leave();
	return 0;
//#endif
}
#endif // not TJ_B171010



// New routine implemented in order to get address of INETA configured for htun.
static char* m_ppp_se_get_ineta_client(struct dsd_ppp_server_1 *adsp_ppp_se_1)
{
#ifdef B150702
   //dsd_tun_contr_ineta* adsl_tun_contr_ineta = DEF_PPP_SESSION((dsd_tun_contr_conn*)adsp_ppp_se_1->
   //    vpc_handle)->adsc_tun_contr_ineta;
    dsd_tun_contr_ineta* adsl_tun_contr_ineta = ((dsd_ppp_session*)(((dsd_htun_handle*)(adsp_ppp_se_1->vpc_handle))->vpc_contr))->adsc_tun_contr_ineta;
#endif
#ifndef B150702
   dsd_ppp_session* adsl_sess = m_ppp_session_from_s1( adsp_ppp_se_1 );
   dsd_tun_contr_ineta* adsl_tun_contr_ineta = adsl_sess->adsc_tun_contr_ineta;
#endif

   if(adsl_tun_contr_ineta == NULL)
      return NULL;

   unsigned int* auml_client_ineta =
       (unsigned int*)&(adsl_tun_contr_ineta->dsc_soa_local_ipv4.sin_addr.s_addr);

   if(*auml_client_ineta > 0)
       return (char*)(auml_client_ineta);
   else
       return NULL;
} // End m_ppp_se_get_ineta_client().

// Callback for PPP implementation to send HOB-PPP-T1 message back to client.
static void m_ppp_send_callback_se(dsd_ppp_server_1* adsp_ppp_server,
                                   dsd_buf_vector_ele* adsp_buf_vec)
{

   // dsd_ppp_session* adsl_sess =
   //    (dsd_ppp_session*)((char*)adsp_ppp_server -
   //    offsetof(dsd_ppp_session, dsc_ppp_se_1));
   dsd_ppp_session* adsl_sess = m_ppp_session_from_s1(adsp_ppp_server);
   adsl_sess->mc_tunnel_to_cl(adsp_buf_vec->ac_handle,
                              (byte*)adsp_buf_vec->achc_data,
                              adsp_buf_vec->imc_len_data);
   return;

}

static void m_cb_timer_close(dsd_timer_ele* adsp_timer_close)
{
    // Obtain ptr to ppp session.
    // int iml_offset = offsetof(dsd_ppp_session, dsc_timer_close);
    // dsd_ppp_session* adsl_ppp_sess =
    //     (dsd_ppp_session*)((char*)adsp_timer_close - iml_offset);
   dsd_ppp_session* adsl_ppp_sess = m_ppp_session_from_te(adsp_timer_close);


   if(adsl_ppp_sess->adsc_tun_contr_conn)
   	if((adsl_ppp_sess->adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
    {
        m_do_wsp_trace("SNEPPPRE", 0, adsl_ppp_sess->adsc_tun_contr_conn->imc_sno,
            adsl_ppp_sess->adsc_tun_contr_conn->imc_trace_level, NULL, 0, 0,
            "HOB-PPP-T1 reconnect timer expired.");
    }

    // Remove PPP session node from AVL tree.
    ds_pppsess_avl_cs.m_enter();
    dsd_avl_sess_entry dsl_pppsess_search;
#ifdef TJ_B170915
    dsl_pppsess_search.umc_key_ineta = adsl_ppp_sess->adsc_tun_contr_ineta->dsc_soa_local_ipv4.
        sin_addr.s_addr;
#else
	dsl_pppsess_search.umc_key_ineta = adsl_ppp_sess->umc_tunnel_id;
#endif

    m_htree1_avl_search(NULL, &ds_pppsess_avl_cntl, &ds_pppsess_avl_wrk,
        (dsd_htree1_avl_entry*)&dsl_pppsess_search);
    if(ds_pppsess_avl_wrk.adsc_found)
    {
        dsd_avl_sess_entry* ads_pppsess_found = (dsd_avl_sess_entry*)ds_pppsess_avl_wrk.adsc_found;
        m_htree1_avl_delete(NULL, &ds_pppsess_avl_cntl, &ds_pppsess_avl_wrk);
        delete ads_pppsess_found;
#ifdef HL_DEBUG
    } else {
		m_hl1_printf("l%05d m_cb_timer_close() -  TUNNEL-ID=%08X not found." , __LINE__, dsl_pppsess_search.umc_key_ineta );
#endif
    } 

    ds_pppsess_avl_cs.m_leave();

    // Close PPP tunnel and release resources.
    mc_ppp_close_and_release(adsl_ppp_sess, false);


	delete adsl_ppp_sess;

    return;
}

static void mc_ppp_close_and_release(dsd_ppp_session* adsp_ppp_sess, bool bop_end_sess)
{

	adsp_ppp_sess->dsc_cs.m_enter();

    dsd_tun_contr_conn* adsl_tc = adsp_ppp_sess->adsc_tun_contr_conn;

	if(adsp_ppp_sess->adsc_tun_contr_conn)
   	if((adsp_ppp_sess->adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
    {
        m_do_wsp_trace("SNEPPPCR", 0, adsp_ppp_sess->adsc_tun_contr_conn->imc_sno,
            adsp_ppp_sess->adsc_tun_contr_conn->imc_trace_level, NULL, 0, 0,
            "HOB-PPP-T1 session being closed and released.");
#ifdef TJ_B171010
        unsigned int uml_tunnel_id = htonl(adsp_ppp_sess->adsc_tun_contr_ineta->dsc_soa_local_ipv4.sin_addr.s_addr);
#endif
        m_do_wsp_trace("SNEPPPRP", 0, adsp_ppp_sess->adsc_tun_contr_conn->imc_sno,
            adsp_ppp_sess->adsc_tun_contr_conn->imc_trace_level, NULL, 0, 0,
            "Tunnel-id %08X ended. Packets dropped: Server %d - Client %d - Target filter %d.",
#ifdef TJ_B171010
            uml_tunnel_id,
#else
            adsp_ppp_sess->umc_tunnel_id,
#endif
            adsp_ppp_sess->umc_discard_count,
            adsp_ppp_sess->umc_discard_count_cli,
            adsp_ppp_sess->umc_discard_count_tf);
    }



    if(bop_end_sess)
    {
       // Inform WSP about session termination.
       m_htun_session_end(adsl_tc, -1);
	   adsp_ppp_sess->adsc_tun_contr_conn = NULL;
    }


	adsp_ppp_sess->dsc_cs.m_leave();

    // Release tun_contr_ineta of session.
	if(adsp_ppp_sess->adsc_tun_contr_ineta){
        m_htun_ppp_free_resources(adsp_ppp_sess->adsc_tun_contr_ineta);
		adsp_ppp_sess->adsc_tun_contr_ineta = NULL;
	}


    // Call class dtor.
	adsp_ppp_sess->adsc_tun_contr_ineta = NULL;


    return;
}

static void m_log_ppp_warning(dsd_ppp_server_1* adsp_ppp_svr, char* achp_message)
{
    // Report PPP server warning.
#ifdef B150702
    dsd_ppp_session* ads_ppp_se = ((dsd_ppp_session*)(((dsd_htun_handle*)(adsp_ppp_svr->vpc_handle))->vpc_contr));
    m_htun_warning(ads_ppp_se->adsc_tun_contr_conn, ads_ppp_se->adsc_tun_contr_ineta,
       BASE_ERR_NUMBER + 0, achp_message); //TODO
#endif
#ifndef B150702
   dsd_ppp_session* adsl_sess = m_ppp_session_from_s1( adsp_ppp_svr );
   m_htun_warning( adsl_sess->adsc_tun_contr_conn, adsl_sess->adsc_tun_contr_ineta,
                   BASE_ERR_NUMBER + 0, achp_message ); //TODO
#endif
    return;
}



// Call back function to create the target filter
static void m_ppp_se_hs_compl(dsd_ppp_server_1* adsp_ppp_svr)
{
#ifndef callback_hs_compl
	dsd_ppp_session* adsl_sess = m_ppp_session_from_s1(adsp_ppp_svr);
	if(adsl_sess->adsc_targ_filter)
		return;
	adsl_sess->adsc_targ_filter = m_htun_ppp_get_targfi(adsl_sess->adsc_tun_contr_conn);
	if(adsl_sess->adsc_targ_filter != NULL)
	{
		if((adsl_sess->adsc_tun_contr_conn->imc_trace_level & HL_WT_SESS_NETW) != 0)
		{
			// TODO - trace - correct?
			m_do_wsp_trace("SNEPPPTC", 0, adsl_sess->adsc_tun_contr_conn->imc_sno,
				adsl_sess->adsc_tun_contr_conn->imc_trace_level, NULL, 0, 0,
				"Creating PPP target filter - SSTP.");
		}
//		adsl_sess->adsc_ppp_targfi_act = m_create_ppp_targfi(adsl_sess->adsc_targ_filter);
    adsl_sess->adsc_ppp_targfi_act = m_create_ppp_targfi( adsl_sess->adsc_targ_filter,
                                                          adsl_sess->adsc_tun_contr_conn->imc_trace_level,
                                                          adsl_sess->adsc_tun_contr_conn->imc_sno );
	}
#endif
    return;
}


