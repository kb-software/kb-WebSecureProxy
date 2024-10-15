#define TRACEHL1
//+-------------------------------------------------------------------+
//|                                                                   |
//| PROGRAM NAME: HUSIP.cpp                                           |
//| -------------                                                     |
//|  HOB User Space IP module for use with HOB PPP and HOB TCP        |
//|    modules                                                        |
//|  Alan Duca 27.02.08                                               |
//|                                                                   |
//| COPYRIGHT:                                                        |
//| ----------                                                        |
//|  Copyright (C) HOB Germany 2008                                   |
//|  Copyright (C) HOB Germany 2009                                   |
//|                                                                   |
//+-------------------------------------------------------------------+

#ifndef D_INCL_TUN_CTRL
#define D_INCL_TUN_CTRL
#endif

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
#ifdef HL_FREEBSD
//#include <sys/socket.h>
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
#include <net/if.h>
#ifndef TRY_150625
#include <netinet/in.h>
#endif
#include <sys/select.h>
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
#include <list>
#include <queue>
#include <stddef.h>
#include <iostream>
#include "hob-xslcontr.h"
#include "hob-tun01.h"
#include "hob-htcp-int-01.h"
#include "hob-htcp-hdr-01.h"
#include "hob-htcp-01.h"
//#include "hob-htcp-int-types.h"
//#include "hob-htcp.h"
//#include "hob-htcp-bit-reference.h"
//#include "hob-htcp-tcpip-hdr.h"
//#include "hob-htcp-misc.h"
//#include "hob-htcp-connection.h"
#include "hob-session01.h"
//#include "hob-htcp-session.h"
#include "hob-htcp-htun-01.h"
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
#include "hob-tun01.h"

#if defined WIN32 || WIN64
#include <Iphlpapi.h>
#endif

extern PTYPE void m_htun_session_end( struct dsd_tun_contr_conn *adsp_tun_contr_conn,
                                      int imp_reason );

extern "C" int img_wsp_trace_core_flags1;

#ifndef NEW_HOB_TUN_1103
dsd_vnic dsg_vnic;
#endif

//-------------------
//FUNCTION PROTOTYPES
//-------------------
THDRET WINAPI m_htun_read_loop(LPVOID ap_param);
extern "C" int m_hl1_printf(char * aptext, ... );

/**
 * Send packet from TUN adapter to HTUN.
 *
 * @param  ap_handle   Handle to the buffer.
 * @param  inp_offset  Empty space available just before data.
 * @param  achp_data   Pointer to the start of the packet data.
 * @param  inp_len     Length of the packet.
 */
extern "C" void m_htun_recv( void * ap_handle, int inp_offset,
                             char *achp_data, int inp_len );

//static void m_del_next_node(struct dsd_timer_ele* dsl_timer_ele_w1);

//-----------
//GLOBAL VARS
//-----------
// Critical section object for WSP configuration.
DEFCRITSEC(dsg_critsec_wspconf);
// WSP configuration struct.
dsd_wsptun_conf_1 dss_wsptun_config;

//----------------
//DEFINES
//----------------

#define DSG_KEY_PATH       HKEY_LOCAL_MACHINE
#define WCG_KEY_ROOT       "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define WCG_SEARCHED_VALUE "IPEnableRouter"

//----------------
//FILE STATIC VARS
//----------------
// TUN DEVICE RELATED VARS.
// TUN interface.
static struct dsd_tun_intf_1 dss_tun_intf_1;
static char chrs_htun_name[ 1024 ];
// Thread object for read thread.
static dsd_hcthread dsl_thd_read;
// BOOL indicating whether WSP config crit section has been initialized.
static BOOL bos_wspconf_init = false;

#ifndef HL_UNIX

static BOOL m_is_user_an_admin()
{
    BOOL bol_ret;
    PSID a_admin_group;
    SID_IDENTIFIER_AUTHORITY ds_nt_authority = SECURITY_NT_AUTHORITY;

    bol_ret = AllocateAndInitializeSid(&ds_nt_authority,
                                       2,
                                       SECURITY_BUILTIN_DOMAIN_RID,
                                       DOMAIN_ALIAS_RID_ADMINS,
                                       0, 0, 0, 0, 0, 0,
                                       &a_admin_group);

    if (bol_ret)
    {
        if (!CheckTokenMembership(NULL, a_admin_group, &bol_ret))
            bol_ret = FALSE;

        FreeSid(a_admin_group);
    }

    return bol_ret;
} // m_is_user_an_admin

#endif // HL_UNIX

/* Check IP Forwarding for Windows */
#ifndef HL_UNIX

static BOOL m_check_ipforwarding_status()
{
    BOOL bo_ret = TRUE;
    DWORD ildl_result;
    DWORD ildl_ip_fwd_value=0;
    DWORD ildl_ip_fwd_size;
    HKEY dsl_reg_searched_key;

    ildl_result = RegOpenKeyEx(DSG_KEY_PATH, WCG_KEY_ROOT, 0, KEY_READ, &dsl_reg_searched_key);
    if (ildl_result != ERROR_SUCCESS)
    {
        m_hlnew_printf(HLOG_WARN1, "HWSPTUN-l%05d-W Failed to check the status of IPForwarding: "
           "failed to open registry key %s with error %d.", __LINE__, WCG_KEY_ROOT, ildl_result);
        return FALSE;
    }

    /* If we had success reading the key, we need to check the value of the variable related to the IPForwarding */
    ildl_ip_fwd_size = sizeof(DWORD);

    ildl_result = RegQueryValueEx(dsl_reg_searched_key, WCG_SEARCHED_VALUE, 0, NULL,
        (LPBYTE)&ildl_ip_fwd_value, &ildl_ip_fwd_size);

    if (ildl_result != ERROR_SUCCESS)
    {
        m_hlnew_printf(HLOG_WARN1, "HWSPTUN-l%05d-W Failed to check the status of IPForwarding: "
           "failed to open registry value %s with error %d.", __LINE__, WCG_SEARCHED_VALUE, ildl_result);
        bo_ret = FALSE;
    }

    if (bo_ret)
    {
        if (ildl_ip_fwd_value == 0)
            bo_ret = FALSE;
        else
            bo_ret = TRUE;
    }

    RegCloseKey(dsl_reg_searched_key);

    return bo_ret;
} // m_check_ipforwarding_status

#endif // HL_UNIX

extern "C" BOOL m_htun_start( struct dsd_raw_packet_if_conf *adsp_raw_packet_if_conf,
                              struct dsd_tun_ctrl *adsp_tun_ctrl )
{
   BOOL bol_retval = FALSE;
   int iml_retval;

#ifdef NEW_HOB_TUN_1103
   char str_htun_name[1024] = "";

// to-do 02.08.10 KB - reload configuration
   if (bos_htun_started) return TRUE;
   if (m_open_tun(&dss_tun_intf_1.dsc_tunhandle,
                  chrs_htun_name,
                  sizeof(chrs_htun_name) ) != 0)
   {  // Get handle FAILED.
      m_hl1_printf(m_tun_last_err());
      return FALSE;
   }
   dss_tun_intf_1.achc_adapter_name = chrs_htun_name;  // Adapter name.
   *((unsigned int *) dss_tun_intf_1.chrc_ineta_locale)
     = adsp_raw_packet_if_conf->umc_ta_ineta_local;  /* <TUN-adapter-ineta>     */

   *((unsigned int *) dss_tun_intf_1.chrc_ineta_remote) = adsp_raw_packet_if_conf->umc_ta_ineta_local;
   *((unsigned char *) &dss_tun_intf_1.chrc_ineta_remote + sizeof(int) - 1) ^= 0X03; /* <TUN-adapter-ineta> */
   *((unsigned int *) dss_tun_intf_1.chrc_netmask_1)
     = inet_addr( "255.255.255.252" );      /* Network mask.           */
   if (m_init_tun( &dss_tun_intf_1 ) != 0)
   {  // Tun config FAILED.
      m_hl1_printf(m_tun_last_err());
      return FALSE;
   }

   // Try to set tun to "connected".
// if(m_connect_tun(as_htun) != 0)
   if(m_connect_tun(dss_tun_intf_1.dsc_tunhandle) != 0)
   {  // Tun status "connected" FAILED.
      m_hl1_printf(m_tun_last_err());
      return FALSE;
   }

   // All OK.
   bos_htun_started = TRUE;
   bol_retval = TRUE;

#else

#ifndef HL_UNIX

   // Administrator rights are required for adapter installation and handle opening.

   if (!m_is_user_an_admin())
   {
       m_hlnew_printf(HLOG_WARN1, "HWSPTUN-l%05d-W Initialising HOB-TUN adapter failed: "
                      "administrator rights are required in order to use the HOB-TUN adapter.",
                      __LINE__);
       adsp_tun_ctrl->boc_started = FALSE;
       return FALSE;
   }

   // IP Forwarding needs to be enabled in the registry for the TUN to work.
   // Failure to check the status of IP Forwarding is assumed to be the same as
   // IP Forwarding being disabled since we can't make sure that it is enabled!

   if (!m_check_ipforwarding_status())
   {
       m_hlnew_printf(HLOG_WARN1, "HWSPTUN-l%05d-W IP forwarding switched off - TUN cannot work",
                      __LINE__);
       adsp_tun_ctrl->boc_started = FALSE;
       return FALSE;
   }

   // Do not install the adapter multiple times!

   if (adsp_raw_packet_if_conf && adsp_tun_ctrl && adsp_tun_ctrl->imc_instance_id == 0)
   {
      bol_retval = m_proc_adapter(adsp_tun_ctrl, FALSE, adsp_raw_packet_if_conf->awcc_driver_fn,
                                  adsp_raw_packet_if_conf->iec_siwd);

      // Adapter found/installed?

      adsp_tun_ctrl->boc_started = bol_retval;

      // We still keep track of the InstanceId and the handle in order to be able to clean-up
      // properly.

      if (!bol_retval)
      {
         m_hlnew_printf(HLOG_WARN1, "HWSPTUN-l%05d-W Opening a TUN adapter failed.", __LINE__);
         return FALSE;
      }
   }
   else if (!adsp_raw_packet_if_conf)
   {
      return FALSE;
   }
#endif // HL_UNIX

   // dss_tun_intf_1.achc_adapter_name = chrs_htun_name;  // Adapter name.
   // *((unsigned int *) dss_tun_intf_1.chrc_ineta_locale)
   //   = adsp_raw_packet_if_conf->umc_taif_ineta_ipv4;  /* <TUN-adapter-ineta>     */
   // *((unsigned int *) dss_tun_intf_1.chrc_ineta_remote)
   //   = adsp_raw_packet_if_conf->umc_taif_ineta_ipv4 ^ htonl(0X03);  // KS /* <TUN-adapter-ineta> */
   // *((unsigned int *) dss_tun_intf_1.chrc_netmask_1)
   //   = inet_addr( "255.255.255.252" );      /* Network mask.           */

   char* adsl_ineta = m_get_wsptun_ineta_ipv4_adapter();
   if (!adsl_ineta)
   {
      m_hlnew_printf(HLOG_WARN1, "HWSPTUN-l%05d-W TUN adapter ip not valid.", __LINE__);

#ifndef HL_UNIX

      // adsp_tun_ctrl->boc_started needs to show that the adapter is not usable
      // therefore it has to be set to FALSE but we still want to be able to
      // close the handle and uninstall (if configured to do so) when closing
      // so adsp_tun_ctrl->dsc_handle and adsp_tun_ctrl->imc_instance_id
      // are not reset.

      adsp_tun_ctrl->boc_started = FALSE;

#endif // HL_UNIX

      return FALSE;
   }
   in_addr dsl_ineta;
   dsl_ineta.s_addr = *(ULONG*)adsl_ineta;
   char chrl_ineta[17];
   strcpy(chrl_ineta, inet_ntoa(dsl_ineta));

   bol_retval = dsg_vnic.m_init_ipv4(chrl_ineta, "255.255.255.0", adsp_tun_ctrl);
   if (!bol_retval)
   {
      m_hlnew_printf(HLOG_WARN1, "HWSPTUN-l%05d-W Initialize TUN failed.", __LINE__);

#ifndef HL_UNIX

      // adsp_tun_ctrl->boc_started needs to show that the adapter is not usable
      // therefore it has to be set to FALSE but we still want to be able to
      // close the handle and uninstall (if configured to do so) when closing
      // so adsp_tun_ctrl->dsc_handle and adsp_tun_ctrl->imc_instance_id
      // are not reset.

      adsp_tun_ctrl->boc_started = FALSE;

#endif // HL_UNIX

      return FALSE;
   }


#ifndef HL_UNIX
   adsp_tun_ctrl->boc_started = TRUE;                     // TUN can be used
#endif

#ifdef HL_UNIX
   dsg_tun_hdl = adsp_tun_ctrl->imc_fd_tun;
#endif

   iml_retval = dsl_thd_read.mc_create(m_htun_read_loop);
   if(iml_retval < 0)
   {
      m_hlnew_printf(HLOG_WARN1, "HWSPTUN-l%05d-W Create TUN read thread failed with code %d.",
                     iml_retval, __LINE__);
      return FALSE;
   }

   return TRUE;

#endif
#ifdef B130110
   if(!bol_retval)
   {
#ifndef NEW_HOB_TUN_1103
      m_hlnew_printf(HLOG_WARN1, "HWSPTUN1012W Starting TUN adapter failed with error '%s'.", dsg_vnic.m_get_last_error());
#else
       m_hlnew_printf(HLOG_WARN1, "HWSPTUN1013W Starting TUN adapter failed.");
#endif
      return false;
   }

   m_hlnew_printf(HLOG_INFO1, "HWSPTUN1000I TUN adapter successfully started.");

   // Launch thread to read packets coming over TUN adapter & dispatch
   // them to HPPP or HTCP modules as required.
   iml_retval = dsl_thd_read.mc_create(m_htun_read_loop);
   if(iml_retval < 0)
   {
      m_hlnew_printf(HLOG_WARN1, "HWSPTUN1014W Create TUN read thread failed with code %d.", iml_retval);
      return FALSE;
   }

   adsp_tun_ctrl->boc_tun_opened = TRUE;
   return bol_retval;
#endif
}// ~m_htun_start.




extern PTYPE BOOL m_htun_end(struct dsd_raw_packet_if_conf *adsp_raw_packet_if_conf,
                             struct dsd_tun_ctrl *adsp_tun_ctrl)
{
    BOOL bol_retval = TRUE;

#ifndef HL_UNIX

    if (adsp_raw_packet_if_conf && adsp_tun_ctrl->imc_instance_id)
{
       bol_retval = m_proc_adapter(adsp_tun_ctrl, TRUE,
                                   adsp_raw_packet_if_conf->awcc_driver_fn,
                                   adsp_raw_packet_if_conf->iec_siwd );

       memset(adsp_tun_ctrl, 0, sizeof(dsd_tun_ctrl));

       if (!bol_retval)
           m_hlnew_printf(HLOG_WARN1, "HWSPTUN-l%05d-W Uninstall TUN failed.", __LINE__);
    }

#endif // HL_UNIX

#ifdef NEW_HOB_TUN_1103
   // Try to close tun device.
// if(m_close_tun(as_htun) != 0)
   if(m_close_tun(dss_tun_intf_1.dsc_tunhandle) != 0)
   {
      m_hl1_printf(m_tun_last_err());
//    as_htun = NULL;
      dss_tun_intf_1.dsc_tunhandle = NULL;
   }

#else
#if defined _WIN32
    dsg_vnic.m_terminating();
#endif
#endif

    return bol_retval;
}// ~m_htun_end.

extern PTYPE void m_htun_new_sess_ppp(struct dsd_tun_start_ppp* adsp_tun_start_ppp,
                                      struct dsd_tun_contr_conn* adsp_tun_contr_conn)
{
#ifdef NEW_HOB_TUN_1103
   if(adsp_tun_start1->dsc_soa_local.ss_family != 2) //AF_INET
   {
      m_hl1_printf("Current version of TAP-Win32 only supports IPv4 when in TUN mode.");
      return;
   }
#endif
   //create session
   m_init_sess(/*NULL,*/ adsp_tun_start_ppp, adsp_tun_contr_conn, NULL);
} /* m_htun_new_sess()                                                 */

extern PTYPE void m_htun_sess_close(dsd_htun_h dsp_husip_sess)
{
   dsd_htun_handle* adsl_hth = (dsd_htun_handle*)dsp_husip_sess;

   if (adsl_hth->iec_tunc == ied_tunc_htcp)
   {
      struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)adsl_hth->vpc_contr;
      m_htcp_sess_close(adsl_hh);
      return;
   }
   else if (adsl_hth->iec_tunc == ied_tunc_ppp)
   {
	  struct dsd_ppp_session* adsl_ppp = (struct dsd_ppp_session*)adsl_hth->vpc_contr;
      adsl_ppp->mc_close();
      return;
   }

   dsd_session* adsl_session = (dsd_session*)adsl_hth->vpc_contr;
   // NOTE: adsl_session can be ppp or pppt session
   adsl_session->mc_close();
}

extern PTYPE BOOL m_se_husip_send(unsigned char *aucp_data,
                                  int imp_length)
{
// if(m_writeone_blk(as_htun,
//                   aucp_data,
//                   imp_length,
//                   NULL,
//                   &iml_bytes_written) < 0)

#ifdef NEW_HOB_TUN_1103
   int iml_bytes_written;

   if(m_writeone_blk(dss_tun_intf_1.dsc_tunhandle,
                     aucp_data,
                     imp_length,
                     NULL,
                     &iml_bytes_written) < 0)
      return false;
   else
      return true;

#else
   unsigned int iml_bytes_written;
   BOOL bol_ret;
   const char* achl_message;
   dsd_gather_i_1 dsl_gath;

   bol_ret = dsg_vnic.m_write(aucp_data,
                              imp_length,
                              iml_bytes_written) >= 0;

   if ((img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) != 0) {
       if (bol_ret) {
           achl_message = "TUN adapter write %d bytes over internal network.";
       } else {
           achl_message = "TUN adapter failed to write %d bytes over internal network.";
       }

      dsl_gath.achc_ginp_cur = (char*)aucp_data;
      dsl_gath.achc_ginp_end = dsl_gath.achc_ginp_cur + imp_length;
      dsl_gath.adsc_next = NULL;
      m_do_wsp_trace("CTUNSEND", HL_WT_CORE_HOB_TUN, 0, 0, &dsl_gath,
                     imp_length, 48, achl_message, imp_length);
   }

   return bol_ret;
#endif
}

extern PTYPE BOOL m_se_husip_send_gather(dsd_gather_i_1* adsp_data,
                                         unsigned unp_length)
{
#ifdef NEW_HOB_TUN_1103

    if (adsp_data->achc_ginp_cur + unp_length <= adsp_data->achc_ginp_end) {
        return m_se_husip_send((unsigned char*)adsp_data->achc_ginp_cur,
                               unp_length);
    } else {
        const unsigned unl_buf_len = 16384;
        char chrl_buffer[unl_buf_len];
        char* achl_buffer;
        struct dsd_gather_i_1* adsl_g = adsp_data;
        unsigned unl_cur_ofs;
        unsigned unl_l;
        BOOL bol_ret;

        if (unp_length <= unl_buf_len) {
            achl_buffer = chrl_buffer;
        } else {
            achl_buffer = (char*)malloc(unp_length);
            if (achl_buffer == NULL) {
                // TODO: warning message
                return FALSE;
            }
        }

        unl_cur_ofs = 0;
        while (unl_cur_ofs < unp_length) {
            while (adsl_g != NULL &&
                   adsl_g->achc_ginp_cur == adsl_g->achc_ginp_end) {

                adsl_g = adsl_g->adsc_next;
            }
            if (adsl_g == NULL) {
                // TODO: warning message
                if (achl_buffer != chrl_buffer)
                    free(achl_buffer);
                return FALSE;
            }
            unl_l = adsl_g->achc_ginp_end - adsl_g->achc_ginp_cur;
            if (unl_cur_ofs + unl_l > unp_length)
                unl_l = unp_length - unl_cur_ofs;
            memcpy(achl_buffer + unl_cur_ofs, adsl_g->achc_ginp_cur, unl_l);
            unl_cur_ofs += unl_l;
            adsl_g = adsl_g->adsc_next;
        }

        bol_ret = m_se_husip_send((unsigned char*)achl_buffer, unp_length);

        if (achl_buffer != chrl_buffer)
            free(achl_buffer);

        return bol_ret;
    }

#else // !defined NEW_HOB_TUN_1103

    const int inl_vect_len = 16;
    struct dsd_gather_i_1* adsl_data = adsp_data;
    unsigned unl_length = unp_length;
    struct dsd_vector dsrl_vect[inl_vect_len];
    struct dsd_vector* adsl_vect = NULL;
    int inl_vect_count = 0;
    BOOL bol_ret = TRUE;
    const char* achl_message;

    if (unp_length == 0)
        return TRUE;

    for (inl_vect_count = 0; inl_vect_count < inl_vect_len; ++inl_vect_count) {
        while (adsl_data != NULL &&
               adsl_data->achc_ginp_cur == adsl_data->achc_ginp_end) {

            adsl_data = adsl_data->adsc_next;
        }
        if (adsl_data == NULL) {
            // TODO: warning message
            bol_ret = FALSE;
            break;
        }

        dsrl_vect[inl_vect_count].ach_buf = adsl_data->achc_ginp_cur;
        dsrl_vect[inl_vect_count].ul_size =
            adsl_data->achc_ginp_end - adsl_data->achc_ginp_cur;

        if (dsrl_vect[inl_vect_count].ul_size >= unl_length) {
            dsrl_vect[inl_vect_count].ul_size = unl_length;
            ++inl_vect_count;
            adsl_vect = dsrl_vect;
            break;
            // if (dsg_vnic.m_write(dsrl_vect, inl_vect_count + 1) < 0) {
            //     // TODO: warning message
            //     bol_ret = FALSE;
            //     break;
            // }
        }

        adsl_data = adsl_data->adsc_next;
        unl_length -= dsrl_vect[inl_vect_count].ul_size;
    }

    // packet does not fit in inl_vect_len blocks

    if (bol_ret && adsl_vect == NULL) {
        struct dsd_gather_i_1* adsl_search = adsl_data;
        for (unsigned unl_rem = unl_length; unl_rem > 0; ) {
            while (adsl_search != NULL &&
                   adsl_search->achc_ginp_cur == adsl_search->achc_ginp_end) {

                adsl_search = adsl_search->adsc_next;
            }
            if (adsl_search == NULL) {
                // TODO: warning message
                bol_ret = FALSE;
                break;
            }

            ++inl_vect_count;
            if (adsl_search->achc_ginp_cur + unl_rem <=
                adsl_search->achc_ginp_end) {

                unl_rem = 0;
            } else {
                unl_rem -=
                    adsl_search->achc_ginp_end - adsl_search->achc_ginp_cur;
				adsl_search = adsl_search->adsc_next;
            }
        }

        if (bol_ret) {
            adsl_vect = (struct dsd_vector*)
                malloc(inl_vect_count * sizeof(struct dsd_vector));
            if (adsl_vect == NULL) {
                // TODO: warning message
                bol_ret = FALSE;
            }
        }

        if (bol_ret) {
            memcpy(adsl_vect, dsrl_vect,
                   inl_vect_len * sizeof(struct dsd_vector));
            inl_vect_count = inl_vect_len;

            while (unl_length > 0) {
                while (adsl_data->achc_ginp_cur == adsl_data->achc_ginp_end)
                    adsl_data = adsl_data->adsc_next;

                adsl_vect[inl_vect_count].ach_buf = adsl_data->achc_ginp_cur;
                adsl_vect[inl_vect_count].ul_size =
                    adsl_data->achc_ginp_end - adsl_data->achc_ginp_cur;

                if (adsl_vect[inl_vect_count].ul_size > unl_length)
                    adsl_vect[inl_vect_count].ul_size = unl_length;

                unl_length -= adsl_vect[inl_vect_count].ul_size;

                ++inl_vect_count;
				adsl_data = adsl_data->adsc_next;
            }
        }
    }

    if (bol_ret) {
        bol_ret = dsg_vnic.m_write(adsl_vect, inl_vect_count) >= 0;
    }

    if ((img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) != 0) {
        if (bol_ret) {
            achl_message = "TUN adapter gather write %u bytes "
                "over internal network.";
        } else {
            achl_message = "TUN adapter failed to gather write %u bytes "
                "over internal network.";
        }

        // m_do_wsp_trace can handle adsp_data being NULL or having less
        // data than unp_length.
        m_do_wsp_trace("CTUNSEND", HL_WT_CORE_HOB_TUN, 0, 0, adsp_data,
                       unp_length, 48, achl_message, unp_length);
    }

    if (adsl_vect != NULL && adsl_vect != dsrl_vect) {
        free(adsl_vect);
    }

    return bol_ret;

#endif // !defined NEW_HOB_TUN_1103
}

extern "C" void* m_find_htun_ineta(struct sockaddr_storage*);

#ifndef B121024 // KS

extern "C" void m_htun_recv( void * ap_handle, int inp_offset,
                             char *achp_data, int inp_len )
{
    bool bol_ipv4 = false;
    bool bol_ipv6 = false;
    unsigned unl_prot = 0;
    int inl_hlen = 0;

    if (inp_len > 0) {
        switch (((unsigned char)(*achp_data) >> 4) & 0x0f) {
        case 4: // IPv4
            if (inp_len >= 20) {
                inl_hlen = m_get_calc_ip_hlen(achp_data);
                if (inl_hlen >= 20 && inp_len >= inl_hlen &&
                    (int)m_get_ip_tlen(achp_data) == inp_len) {

                    bol_ipv4 = true;
                    unl_prot = m_get_ip_prot(achp_data);
                }
            }
            break;

        case 6: // IPv6
            if (inp_len >= 40 &&
                inp_len >= 40 + (int)m_get_ip6_plen(achp_data)) {

                inl_hlen = 40;
                bol_ipv6 = true;
                unl_prot = m_get_ip6_nh(achp_data);
            }
            break;
        }
    }

    if (!bol_ipv4 && !bol_ipv6) {
        m_hlnew_printf(HLOG_WARN1, "HWSPTUN-l%05d-W Received malformed packet on TUN interface.",
                       __LINE__);
        m_htun_relrecvbuf(ap_handle);
        return;
    }

    bool bol_tcp = unl_prot == 6 && inp_len >= inl_hlen + 20;

    // TODO: handle ICMP for HTCP (currenlty useless since HTCP does not yet support ICMP)

    struct sockaddr_storage dsl_address;
    memset(&dsl_address, 0, sizeof(dsl_address));
    if (bol_ipv4) {
        sockaddr_in* adsl_sa = (sockaddr_in*)&dsl_address;
        adsl_sa->sin_family = AF_INET;
        memcpy(&adsl_sa->sin_addr.s_addr, m_get_ip_dst_addr_buf(achp_data), 4);
        if (bol_tcp)
            memcpy(&adsl_sa->sin_port, achp_data + inl_hlen + 2, 2);
    } else { // here bol_ipv6 is true
        sockaddr_in6* adsl_sa6 = (sockaddr_in6*)&dsl_address;
        adsl_sa6->sin6_family = AF_INET6;
        memcpy(&adsl_sa6->sin6_addr.s6_addr, m_get_ip6_dst_addr(achp_data), 16);
        if (bol_tcp)
            memcpy(&adsl_sa6->sin6_port, achp_data + inl_hlen + 2, 2);
    }

    dsd_htun_h vp_handle = m_find_htun_ineta(&dsl_address);
    if (vp_handle != NULL) {
        dsd_htun_handle* adsl_hth = (dsd_htun_handle*)vp_handle;
        if (adsl_hth->iec_tunc == ied_tunc_htcp) {
            struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)adsl_hth->vpc_contr;
            m_htcp_packet_from_network(adsl_hh, ap_handle, inp_offset, achp_data, inp_len);
        }
        else if(adsl_hth->iec_tunc == ied_tunc_ppp) {
            struct dsd_ppp_session* adsl_ppp_sess = (struct dsd_ppp_session*)adsl_hth->vpc_contr;
            adsl_ppp_sess->mc_encapsulate_msg(ap_handle, (byte*)achp_data, inp_len);
        } else {
            dsd_session* adsl_session = (dsd_session*)adsl_hth->vpc_contr;
            // NOTE: adsl_session can be ppp or pppt session
            //the IP packet is encapsulated in a session header, and sent to the WSP module
            adsl_session->mc_encapsulate_msg(ap_handle, (byte*)achp_data, inp_len);
        }
    } else { // vp_handle == NULL
        if (bol_tcp) {
            // if TCP packet received, send RST
            // uses some utilities from HTCP
            char chrl_rst[60];
            uint32_t uml_rlen = sizeof(chrl_rst);
            if (bol_ipv4) {
                uml_rlen = m_ip_tcp_answer_reset(chrl_rst, uml_rlen, achp_data, inp_len, 0);
            } else { // bol_ipv6
                uml_rlen = m_ip6_tcp_answer_reset(chrl_rst, uml_rlen, achp_data, inp_len);
            }
            if (uml_rlen > 0) {
                m_hlnew_printf(HLOG_WARN1, "HWSPTUN1018 Received unexpected TCP segment on TUN interface, replying with RST.");
                m_se_husip_send((unsigned char*)chrl_rst, uml_rlen);
            } else {
                m_hlnew_printf(HLOG_WARN1, "HWSPTUN1019 Received unexpected TCP segment on TUN interface, ignoring.");
            }
        } else {
            m_hlnew_printf(HLOG_WARN1, "HWSPTUN1020 Received unexpected IP packet (protocol %u) on TUN interface, ignoring.", unl_prot);
        }
        m_htun_relrecvbuf(ap_handle);
    } // vp_handle == NULL
}

//
// Executes a loop to read data incoming over the TUN adapter.
// This function is called in a seperate thread, as soon as a TUN adapter is
// activated. It constantly reads IP packets going over the virtual
// TUN adapter, reads their destination IPs, determines the session
// they belong to, and calls upon the respective session object for further
// processing. Once processed by the session object these packets are
// forwarded to the WSP module, in order to be sent to the client machine.
//
// @param  ap_param  Not used.
//
// @return  Always returns 0.
//

THDRET WINAPI m_htun_read_loop(LPVOID ap_param)
{
   // Number of bytes reserved for PPP Header, HOB-TUN Header & SSTP Header.
    // This is also used by HTCP for packet control information.
   const int iml_OFFSET = 32;
   int iml1 = 0;

   void* al_handle;  // Handle to buffer obtained from WSP module.
   char* achl_data;  // Ptr to the start of data field in the obtained buffer.
   int iml_data_len; // Length of data field in the obtained buffer.

   // Read IP pkt from intranet.
   unsigned int uml_bytes_read;           // Int to hold number of bytes read.
   while(true)
   {
      // Get new buffer from WSP module.
      iml_data_len = m_htun_getrecvbuf(&al_handle, &achl_data);

      // Block until a single incoming IP packet is read on the TUN adapter.

#ifdef NEW_HOB_TUN_1103
      iml1 = m_readone_blk(dss_tun_intf_1.dsc_tunhandle,
                           (unsigned char*)(achl_data + iml_OFFSET),
                           iml_data_len - iml_OFFSET,
                           NULL,
                           (int*)&uml_bytes_read);

#else

      fd_set dsl_fd_read;
      FD_ZERO(&dsl_fd_read);
#ifdef HL_UNIX
      FD_SET(dsg_tun_ctrl.imc_fd_tun, &dsl_fd_read);
      iml1 = select(dsg_tun_ctrl.imc_fd_tun + 1, &dsl_fd_read, NULL, NULL, NULL);
#endif

      if (iml1 >= 0)
      {
         iml1 = dsg_vnic.m_read((unsigned char*)(achl_data + iml_OFFSET),
                                iml_data_len - iml_OFFSET,
                                uml_bytes_read);
      }
#endif

      if(iml1 < 0)
      {
         // Read operation failed.
         // Release buffer obtained from WSP module.
         m_htun_relrecvbuf(al_handle);
         m_hlnew_printf(HLOG_WARN1, "HWSPTUN???? TUN read operation failed.");
         break;
      }

      if ((img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) != 0) {
          dsd_gather_i_1 dsl_gath;
          dsl_gath.achc_ginp_cur = (achl_data + iml_OFFSET);
          dsl_gath.achc_ginp_end = dsl_gath.achc_ginp_cur + uml_bytes_read;
          dsl_gath.adsc_next = NULL;
          m_do_wsp_trace("CTUNRECV", HL_WT_CORE_HOB_TUN, 0, 0, &dsl_gath,
                         uml_bytes_read, 48,
                         "TUN adapter read %d bytes over internal network.", uml_bytes_read);
      }

      m_htun_recv(al_handle, iml_OFFSET, achl_data + iml_OFFSET, uml_bytes_read);

   } // loop forever

   // only arrive here in case of error reading from TUN
   return NULL;
}

#else // B121024 KS

THDRET WINAPI m_htun_read_loop(LPVOID ap_param)
{
   // Number of bytes reserved for PPP Header, HOB-TUN Header & SSTP Header.
   const int iml_OFFSET = 20;
   int iml1; // Working var.

   void* al_handle;  // Handle to buffer obtained from WSP module.
   char* achl_data;  // Ptr to the start of data field in the obtained buffer.
   int iml_data_len; // Length of data field in the obtained buffer.

   // Read IP pkt from intranet.
   unsigned int uml_dest_addr;   // Destination address of IP packet read.
   unsigned short usl_dest_port; // Destination port of packet read if TCP.
   unsigned int uml_bytes_read;           // Int to hold number of bytes read.
   while(true)
   {
      // Get new buffer from WSP module.
      iml_data_len = m_htun_getrecvbuf(&al_handle, &achl_data);

      // Block until a single incoming IP packet is read on the TUN adapter.
//    iml1 = m_readone_blk(as_htun,
//                         (unsigned char*)(achl_data + iml_OFFSET),
//                         iml_data_len - iml_OFFSET,
//                         NULL,
//                         &iml_bytes_read);

#ifdef NEW_HOB_TUN_1103
      iml1 = m_readone_blk(dss_tun_intf_1.dsc_tunhandle,
                           (unsigned char*)(achl_data + iml_OFFSET),
                           iml_data_len - iml_OFFSET,
                           NULL,
                           (int*)&uml_bytes_read);

#else
      iml1 = dsg_vnic.m_read((unsigned char*)(achl_data + iml_OFFSET), iml_data_len - iml_OFFSET, uml_bytes_read);
#endif
      if(iml1 < 0)
      {  // Read operation failed.
         // Release buffer obtained from WSP module.
         m_htun_relrecvbuf(al_handle);
         break;
      }

      dsd_gather_i_1 dsl_gath;
      dsl_gath.achc_ginp_cur = (achl_data + iml_OFFSET);
      dsl_gath.achc_ginp_end = dsl_gath.achc_ginp_cur + uml_bytes_read;
      dsl_gath.adsc_next = NULL;
      m_do_wsp_trace("CTUNRECV", HL_WT_CORE_HOB_TUN, 0, 0, &dsl_gath,
                     uml_bytes_read, 20,
                     "TUN adapter read %d bytes over internal network.", uml_bytes_read);

      // Get dest ip from pkt read.
      uml_dest_addr = *(unsigned long*)(achl_data + iml_OFFSET + 16);
      usl_dest_port = *(unsigned short*)(achl_data + iml_OFFSET + 22);

#ifdef B100706
      // Create node struct to find.
      dsd_avl_sess_entry dsl_search_node;
      dsl_search_node.umc_key_ineta = uml_dest_addr;

      // Enter critical section.
      ENTERCRITSEC(dsg_critsec_avl);

      // Search for node struct.
      if(!m_htree1_avl_search(NULL,
                              &dss_control,
                              &dss_workspace,
                              &(dsl_search_node.dsc_avl_hdr)))
      {  // Search failed.
         m_hl1_printf("AVL ERROR!");

         // Leave critical section.
         LEAVECRITSEC(dsg_critsec_avl);
         m_htun_relrecvbuf(al_handle);
         continue;
      }
      if(dss_workspace.adsc_found == NULL)
      {  // Matching node not found.
         m_hl1_printf("AVL ERROR: SPECIFIED NODE DOES NOT EXIST!");

         // Leave critical section.
         LEAVECRITSEC(dsg_critsec_avl);

         // If TCP packet received, send RST - KS.
         goto send_rst;
      }

      // Get matching node found in AVL tree.
      dsl_search_node = *((dsd_avl_sess_entry*)dss_workspace.adsc_found);

      // Get session object from node.
      dsd_session* adsl_session = (dsd_session*)(dsl_search_node.a_extend);
//    dsd_session* adsl_session = ((dsd_avl_session*)((char*)&dsl_search_node - offsetof(dsd_avl_session, ds_entry)))->ds_info.ads_sess;
#endif // B100706

      if (uml_bytes_read < 20 ||
          achl_data[iml_OFFSET] != 0x45 /* IPv4, IP header 20 bytes */) {
          m_hlnew_printf(HLOG_WARN1, "HWSPTUN1015W Received malformed packet on TUN interface!");
          m_htun_relrecvbuf(al_handle);
          continue;
      }

      struct sockaddr_storage dsl_address;
      memset(&dsl_address, 0, sizeof(dsl_address));
      sockaddr_in* adsl_sa = (sockaddr_in*)&dsl_address;
      adsl_sa->sin_family = 2; // IPv4 - currently only IPv4 is supported
      adsl_sa->sin_addr.s_addr = uml_dest_addr; // already network byte order
      if (uml_bytes_read >= 40 &&
          achl_data[iml_OFFSET + 9] == 6 /* IP protocol TCP */) {
          adsl_sa->sin_port = usl_dest_port; // already network byte order
      }
      dsd_htun_h vp_handle = m_find_htun_ineta(&dsl_address);
      if (vp_handle != NULL) {
#ifdef B100706
          //leave critical section
          LEAVECRITSEC(dsg_critsec_avl);
#endif
          dsd_tun_contr_conn* adsl_tun_contr_conn = (dsd_tun_contr_conn*)vp_handle;
          dsd_session* adsl_session = (dsd_session*)&adsl_tun_contr_conn->dsc_session_buffer;
          // NOTE: adsl_session can be htcp, ppp or pppt session
          //the IP packet is encapsulated in a session header, and sent to the WSP module
          adsl_session->mc_encapsulate_msg(al_handle, (byte*)achl_data + iml_OFFSET, uml_bytes_read);
      } else { // vp_handle == NULL
#ifdef B100706
          LEAVECRITSEC(dsg_critsec_avl);
#endif
         if (achl_data[iml_OFFSET + 9] == 1) {
             // ICMP - check if it belongs to an HTCP session
            if (uml_bytes_read >= 52 /* enough to identify session */ &&
                achl_data[iml_OFFSET + 28] == 0x45 /* IPv4, IP header 20 bytes */ &&
                achl_data[iml_OFFSET + 37] == 6 /* TCP embedded */ &&
                *(uint32*)(achl_data + iml_OFFSET + 16) == *(uint32*)(achl_data + iml_OFFSET + 40)) {
                // get address from inside ICMP
                // IP address already set
                adsl_sa->sin_port = *(unsigned short*)(achl_data + iml_OFFSET + 48); // already network byte order
                dsd_htun_h vp_handle = m_find_htun_ineta(&dsl_address);

                if (vp_handle != NULL) {
                    dsd_tun_contr_conn* adsl_tun_contr_conn = (dsd_tun_contr_conn*)vp_handle;
                    dsd_session* adsl_session = (dsd_session*)&adsl_tun_contr_conn->dsc_session_buffer;
                    adsl_session->mc_encapsulate_msg(al_handle, (byte*)achl_data + iml_OFFSET, uml_bytes_read);
                } else {
                    m_hlnew_printf(HLOG_WARN1, "HWSPTUN1016W Received unexpected ICMP packet on TUN interface, ignoring.");
                    m_htun_relrecvbuf(al_handle);
                }
            } else {
                m_hlnew_printf(HLOG_WARN1, "HWSPTUN1017 Received unexpected ICMP packet on TUN interface, ignoring.");
                m_htun_relrecvbuf(al_handle);
            }
         } else if (uml_bytes_read >= 40 &&
             achl_data[iml_OFFSET + 9] == 6 /* IP protocol TCP */) {
             if ((achl_data[iml_OFFSET + 33] & 0x04) == 0 /* TCP RST flag off */) {
                // if TCP packet received, send RST
                // uses some utilities from HTCP
                m_hlnew_printf(HLOG_WARN1, "HWSPTUN1018 Received unexpected TCP segment on TUN interface, replying with RST.");
                uint8* aut_rst_buf = m_allocate_header();
                memset(aut_rst_buf, 0, 40);
                tcp_segment ds_rst_segment(aut_rst_buf);
                tcp_segment ds_rcv_segment((uint8*)achl_data + iml_OFFSET);
                aut_rst_buf[0] = 0x45;
                aut_rst_buf[3] = 40;  // total length
                aut_rst_buf[8] = 128; // TTL
                aut_rst_buf[9] = 6; // protocol
                *(uint32*)(aut_rst_buf + 12) = *(uint32*)(achl_data + iml_OFFSET + 16); // src address
                *(uint32*)(aut_rst_buf + 16) = *(uint32*)(achl_data + iml_OFFSET + 12); // dst address
                *(uint16*)(aut_rst_buf + 20) = *(uint16*)(achl_data + iml_OFFSET + 22); // src port
                *(uint16*)(aut_rst_buf + 22) = *(uint16*)(achl_data + iml_OFFSET + 20); // dst port
                if (ds_rcv_segment.ack()) {
                   *(uint32*)(aut_rst_buf + 24) = *(uint32*)(achl_data + iml_OFFSET + 28); // seq no
                }
                *(uint32*)(aut_rst_buf + 28) = *(uint32*)(achl_data + iml_OFFSET + 24); // ack no
                ds_rst_segment.tcp_header_length() = 5;
                ds_rst_segment.ack() = 1;
                ds_rst_segment.rst() = 1;
                ds_rst_segment.update_checksum();
                ds_rst_segment.update_tcp_checksum();
                dsd_send_packet_info dsl_send_packet_info(aut_rst_buf, 40, 0, 0, 40);
                m_send_packet(0, dsl_send_packet_info);
                m_htun_relrecvbuf(al_handle);
             } else {
                m_hlnew_printf(HLOG_WARN1, "HWSPTUN1019 Received unexpected TCP RST segment on TUN interface, ignoring.");
                m_htun_relrecvbuf(al_handle);
             }
         } else {
             m_hlnew_printf(HLOG_WARN1, "HWSPTUN1020 Received unexpected IP packet (protocol %d) on TUN interface, ignoring.", achl_data[iml_OFFSET + 9]);
             m_htun_relrecvbuf(al_handle);
         }
      } // vp_handle == NULL

   } // loop forever

   // should not arrive here
   return NULL;
}

#endif // B121024 KS

#if defined WIN32 || WIN64

static int m_getindex_if(unsigned long ulp_ifaddr)
{
    unsigned long ull_index_if;            // Holds index of compatible IF.
    unsigned long ull_retval;              // Holds return values.
    unsigned long ull_buf_len = 0;         // Length of buffer for adapter info.
    unsigned char* aucl_info_buf;          // Buffer for adapter info.
    PIP_ADAPTER_INFO dsl_adap_info = NULL; // Points to first adapter info.
   DWORD      dwl1;
   char       chrl_work1[ 512 ];

    // 1st call to get required buff size.
    ull_retval = GetAdaptersInfo(dsl_adap_info, &ull_buf_len);
    // Check if overflow error returned.
    if(ull_retval != ERROR_BUFFER_OVERFLOW)
    {    // Overflow error NOT returned.
        return -1;
    }
    else
    {   // Overflow error returned.
        // Create buffer with correct size.
        aucl_info_buf = new unsigned char[ull_buf_len];
        dsl_adap_info = (PIP_ADAPTER_INFO)aucl_info_buf;
        // 2nd call with proper buffer.
        ull_retval = GetAdaptersInfo(dsl_adap_info, &ull_buf_len);
        if(ull_retval != ERROR_SUCCESS)
        {   // GetAdapterInfo call failed.
          dwl1 = FormatMessageA( FORMAT_MESSAGE_IGNORE_INSERTS |
                                  FORMAT_MESSAGE_FROM_SYSTEM,
                                 NULL,
                                 ull_retval,
                                 0,             // Default language.
                                 chrl_work1,
                                 sizeof(chrl_work1),
                                 NULL );
            m_hl1_printf( "xshusip01-l%05d-W GetAdaptersInfo() failed 0X%08X \"%s\"",
                          __LINE__, ull_retval, chrl_work1 );
            delete []aucl_info_buf;
            return -2;
        }
    }

    // Start checking configuration of interfaces on local system.
    IP_ADDR_STRING* adsl_curr_addr;
    while(dsl_adap_info != NULL)
    {   // More interfaces remain.
        // Get list of addresses associated to current interface.
        adsl_curr_addr = &(dsl_adap_info->IpAddressList);
        // Check all addresses.
        while(adsl_curr_addr != NULL)
        {
#ifdef TRACEHL1
            m_hl1_printf( "xshusip01-l%05d-T m_getindex_if() found INETA \"%s\" Index=%d 0X%08X.",
                          __LINE__,
                          adsl_curr_addr->IpAddress.String,
                          dsl_adap_info->Index,
                          inet_addr( adsl_curr_addr->IpAddress.String ) );
#endif
            if(inet_addr(adsl_curr_addr->IpAddress.String) == ulp_ifaddr)
            {
                // Return index of current adapter.
                ull_index_if = dsl_adap_info->Index;
                delete []aucl_info_buf;
                return ull_index_if;
            }
            // Move to next address.
            adsl_curr_addr = adsl_curr_addr->Next;
        }
        // Move to next interface.
        dsl_adap_info = dsl_adap_info->Next;
    }

    delete []aucl_info_buf;
    m_hl1_printf( "xshusip01-l%05d-W m_getindex_if() did not find INETA %08X",
                  __LINE__, ulp_ifaddr );
    return -4;
} // m_getindex_if().

#endif


extern PTYPE void m_wsptun_reset_conf(dsd_wsptun_conf_1* adsp_wsptun_newconfig)
{

  // Check if WSP conf crit section not yet initialized.
  if(!bos_wspconf_init)
  {
    // Init critical section object for WSP configuration access.
    INITCRITSEC(dsg_critsec_wspconf);
    bos_wspconf_init = true;
  }

  // Enter WSP conf access critical section.
  ENTERCRITSEC(dsg_critsec_wspconf);
  // Set WSP conf pointer to new value.
  dss_wsptun_config = *adsp_wsptun_newconfig;
  // Leave critical section.
  LEAVECRITSEC(dsg_critsec_wspconf);
}

// Defined m_htun_sess_canrecv, since this was being called by WSP,
// and was apparently not implemented anywhere.
extern PTYPE void m_htun_sess_canrecv(dsd_htun_h dsp_hdl_sess)
{
   dsd_htun_handle* adsl_hth = (dsd_htun_handle*)dsp_hdl_sess;

   if (adsl_hth->iec_tunc == ied_tunc_htcp) {
      struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)adsl_hth->vpc_contr;
      m_htcp_sess_canrecv(adsl_hh);
      return;
   }
   else if (adsl_hth->iec_tunc == ied_tunc_ppp) {
      struct dsd_ppp_session* adsl_ppp_sess = (struct dsd_ppp_session*)adsl_hth->vpc_contr;
      adsl_ppp_sess->mc_can_send();
      return;
   }

   dsd_session* adsl_session = (dsd_session*)adsl_hth->vpc_contr;

   // Indicate that it is OK to resume data transmission to client.
   // should be inside mc_can_send: adsl_session->boc_cansend = true;
   adsl_session->mc_can_send();
}

extern PTYPE void m_htun_sess_send( struct dsd_hco_wothr *adsp_hco_wothr,
								    dsd_htun_h dsp_session,
                                    struct dsd_gather_i_1* adsp_gather )
{
	dsd_htun_handle* adsl_hth = (dsd_htun_handle*)dsp_session;

	if (adsl_hth->iec_tunc == ied_tunc_htcp) {
		struct dsd_htcp_htun* adsl_hh = (struct dsd_htcp_htun*)adsl_hth->vpc_contr;
		m_htcp_sess_send(adsl_hh, adsp_gather);
		return;
	}
	else if (adsl_hth->iec_tunc == ied_tunc_ppp) {
		struct dsd_ppp_session* adsl_ppp_sess = (struct dsd_ppp_session*)adsl_hth->vpc_contr;
		dsd_tun_contr_conn* adsl_tun_contr_conn = adsl_ppp_sess->adsc_tun_contr_conn;
		adsl_ppp_sess->mc_interpret_msg(adsp_gather, adsp_hco_wothr);
		return;
	}

	dsd_session* adsl_session = (dsd_session*)adsl_hth->vpc_contr;
	dsd_tun_contr_conn* adsl_tun_contr_conn = adsl_session->adsc_tun_contr_conn;

	adsl_session->mc_interpret_msg(adsp_gather, adsp_hco_wothr);
	// Check if session has been closed.
	if(adsl_session->boc_sess_closed)
	{
		// Delete session instance.
		//////////dsd_tun_contr_conn* adsl_tun_contr_conn = (dsd_tun_contr_conn*)dsp_session;

		//dsd_session* adsl_session =
		//   (dsd_session*)&adsl_tun_contr_conn->dsc_session_buffer;
		// NOTE: adsl_session can be htcp, ppp or pppt session
		adsl_session->mc_close();
		// NOTE: not really - cannot be htcp which uses different mechanism KS 2012-02-13

		// Inform WSP re session close.
		//m_htun_session_end(adsl_tun_contr_conn, -1);
	}
}

extern PTYPE unsigned int m_get_next_hop()
{
   return dsg_vnic.m_get_hook_ip();
}
