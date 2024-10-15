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



#ifdef B090317
#ifndef HL_UNIX
#include <winsock2.h>
#include <windows.h>
#endif
#ifndef HL_UNIX
#include <hob-avl03.h>
#else
#include "hob-avl03.h"
#endif
#ifndef HL_UNIX
typedef int socklen_t;
#endif
#include "hob-tun01.h"
#include "hmd4.h"
#include "hsha.h"
#include <stdio.h>
#include "hob-sessutil01.h"
#include "hob-session01.h"
#include "hob-hppp01.h"
#include "hob-gw-ppp-1.h"
#include "hob-hsstp01.h"
#include "HTCP/htcp_session.h" // KS
#endif
#ifndef HL_UNIX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <hob-avl03.h>
#include <setupapi.h>
#else
#define HOB_CONTR_TIMER
#include <time.h>

//#include "types_defines.h"
#ifndef byte
#define byte unsigned char
#endif

#include "hob-unix01.h"
#include "hob-avl03.h"
#include <string.h>
#include <stdarg.h>
#ifdef HL_FREEBSD
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include <netdb.h>
#include <net/if.h>
#endif
#ifndef HL_UNIX
typedef int socklen_t;
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
#ifdef HL_FREEBSD
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#include "hob-tun01.h"
#include "hob-htcp-int-01.h"
//#include "hob-htcp-int-types.h"
//#include "hob-htcp.h"
//#include "hob-htcp-bit-reference.h"
//#include "hob-htcp-tcpip-hdr.h"
//#include "hob-htcp-misc.h"
//#include "hob-htcp-connection.h"
#define TRY_140519_01
#ifdef TRY_140519_01	
extern "C" int m_tun_pass_session_owner( struct dsd_tun_contr_conn *, char *, int );
#endif

#include "hob-session01.h"
//#include "hob-htcp-session.h"
#include "hob-gw-ppp-1.h"
#include "hob-hppp01.h"
#include "hob-hsstp01.h"
#include "hob-tuntapif01.h"
#include <stdio.h>
#include <vector>
#include "hob-xslcontr.h"
#include "hob-session01.h"
#include "hob-sessutil01.h"
#ifdef KB_ORG
#include "hmd4.h"
#include "hsha.h"
#else
#include <hob-encry-1.h>
#endif


#ifdef HL_LINUX
#include <sys/syscall.h>
#endif


//std::list<dsd_tun_contr_ineta*> dsg_tun_contr_ineta_list;

void m_init_sess(//dsd_tun_start_htcp* adsp_tun_start_htcp,
                         dsd_tun_start_ppp* adsp_tun_start_ppp,
                         dsd_tun_contr_conn* adsp_tun_contr_conn,
                         dsd_tun_contr_ineta* adsp_tun_contr_ineta)
{
   dsd_session* adsl_new_sess = 0; // Return value.

   // Create the session object based on the session configuration info.
   switch(adsp_tun_contr_conn->iec_tunc)
   {
      case ied_tunc_ppp:
      {  // PPP session.

		 class dsd_ppp_session * adsl_new_ppp_sess = new dsd_ppp_session(adsp_tun_start_ppp, adsp_tun_contr_conn, adsp_tun_contr_ineta);

		 // Get the session owner so that later it can be checked
	     // during a Reconnect and nobody can steal it
		 adsl_new_ppp_sess->imc_len_session_owner = m_tun_pass_session_owner( adsp_tun_contr_conn, adsl_new_ppp_sess->chrc_session_owner, 1024 );
         *(adsp_tun_start_ppp->adsc_htun_h) = (void*)&adsl_new_ppp_sess->dsc_htun_handle; //adsp_tun_contr_conn;
		 // Initialize the session object properly.
		 adsl_new_ppp_sess->mc_init();
	     return;
      }; break;
      case ied_tunc_sstp:
      {  // SSTP session.
         adsl_new_sess = new dsd_sstp_session(adsp_tun_start_ppp, adsp_tun_contr_conn,
            adsp_tun_contr_ineta);
         *(adsp_tun_start_ppp->adsc_htun_h) = (void*)&adsl_new_sess->dsc_htun_handle; //adsp_tun_contr_conn;
      }; break;
//      case ied_tunc_htcp:
//      {  // HTCP session.
//         adsl_new_sess = new dsd_htcp_session(adsp_tun_start_htcp, adsp_tun_contr_conn,
//            adsp_tun_contr_ineta);
//         *(adsp_tun_start_htcp->adsc_htun_h) = (void*)adsp_tun_contr_conn;
//	  }; break;
   }

   // Initialize the session object properly.
   adsl_new_sess->mc_init();
}

void m_free_gath_chain(dsd_gather_i_1* adsp_chain_root)
{
   dsd_gather_i_1* adsl_link_to_del;
   while(adsp_chain_root != NULL)
   {
      adsl_link_to_del = adsp_chain_root;
      adsp_chain_root = adsp_chain_root->adsc_next;
      delete adsl_link_to_del;
   }
}

#ifdef B101123
BOOL m_getlen_nhasn(dsd_gather_i_1* adsp_root_gather,
              int32_t& imp_length,
              int32_t& imp_lenlen)
{
   imp_length = 0; // Value of length field.
   imp_lenlen = 1; // Length of length field.

   // Set start ptr to curr ptr of the passed gather struct.
   byte* abyl_len_start = (byte*)adsp_root_gather->achc_ginp_cur;
   // Check ASN encoding.
   while(((*((byte*)abyl_len_start)) & 0x80) > 0)
   {  // More bytes to come.
      // Increment length of length field.
      imp_lenlen++;
      // Update length value.
      imp_length = imp_length << 7;
      imp_length |= (*abyl_len_start) & 0x7F;
      // Update opsition of start ptr.
      abyl_len_start++;
      // Check if start ptr is at end of this gather struct.
      if(abyl_len_start == (byte*)adsp_root_gather->achc_ginp_end)
      {  // IS at end.
         // Check if there is another link in the chain.
         if(adsp_root_gather->adsc_next != NULL)
         {  // YES.
            // Update start ptr to point to start of next link in chain.
            abyl_len_start = (byte*)adsp_root_gather->adsc_next->achc_ginp_cur;
         }
         else
         {  // NO.
            return false;
         }
      }
   }
   // NO more bytes in length field.
   // Update length value.
   imp_length = imp_length << 7;
   imp_length |= (*abyl_len_start) & 0x7F;
   return true;
}
#endif

BOOL m_getlen_nhasn(dsd_gather_i_1* adsp_root_gather,
              int& imp_length,
              int& imp_lenlen)
{
    imp_length = 0; // Value of length field.
    imp_lenlen = 0; // Length of length field.

    dsd_gather_i_1* adsl_gath = adsp_root_gather;
    while (adsl_gath) {
        char* achl_cur = adsl_gath->achc_ginp_cur;
        while (achl_cur < adsl_gath->achc_ginp_end) {
            imp_length <<= 7;
            imp_length |= *achl_cur & 0x7f;
            ++imp_lenlen;
            if (!(*achl_cur & 0x80)) {
                // the length is complete
                return TRUE;
            }
            ++achl_cur;
        }
        // we used all bytes in current gather
        adsl_gath = adsl_gath->adsc_next;
    }
    // only arrives here if we ran out of bytes
    return FALSE;
}

BOOL m_check_pkt_complete(dsd_gather_i_1* adsp_root_link,
                          int imp_tot_pkt_len,
                          byte** aabyp_pkt_end)
{
   // Set ptr to pass back to NULL.
   *aabyp_pkt_end = NULL;
   // Set current link to root link.
   dsd_gather_i_1* adsl_cur_link = adsp_root_link;
   // Set pkt length found to be available to 0.
   int iml_tot_avail_len = 0;
   // While more links are available in chain.
   while(adsl_cur_link != NULL)
   {
      // Check if pkt len found to be available + length available in this chain
      // is less than total pkt len.
      if(iml_tot_avail_len +
         (adsl_cur_link->achc_ginp_end - adsl_cur_link->achc_ginp_cur)<
         imp_tot_pkt_len)
      {  // IS less.
         // Add length available in this chain to pkt len found to be available.
         iml_tot_avail_len
            += adsl_cur_link->achc_ginp_end - adsl_cur_link->achc_ginp_cur;
         // Set current link to next link in chain, and repeat loop.
         adsl_cur_link = adsl_cur_link->adsc_next;
      }
      else
      {  // NOT less
         // Update end of pkt ptr.
         *aabyp_pkt_end =
            ((byte*)adsl_cur_link->achc_ginp_cur) +
            (imp_tot_pkt_len - iml_tot_avail_len);
         // Return true: complete pkt available.
         return true;
      }
   }
   // Return false: complete pkt NOT available.
   return false;
}

byte* m_search_nlnl(byte* abyp_pos_start, byte* abyp_pos_end)
{
  unsigned int uml_nlnl = 0x0A0D0A0D; // Value to find.
  // Set current position to start of buffer.
  byte* ubyl_pos_cur = abyp_pos_start;
  // Iterate through buffer, searching for value.

  while(ubyl_pos_cur < abyp_pos_end - 3)
  {
    if(*((unsigned int*)(ubyl_pos_cur)) == uml_nlnl)
      // Value found!
      return ubyl_pos_cur + 4;
    // Move to next position in buffer.
    ubyl_pos_cur += 1;
  }
  // Value not found.
  return NULL;
}


int m_get_sstp_lengthpacket(dsd_gather_i_1* adsp_link_cur)
{
  int iml1 = 2;

  dsd_gather_i_1* adsl_link_cur = adsp_link_cur;
  while((adsl_link_cur != NULL) &&
     (adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur) <= iml1)
  {
    iml1 -= ((adsl_link_cur->achc_ginp_end) - (adsl_link_cur->achc_ginp_cur));
    adsl_link_cur = adsl_link_cur->adsc_next;
  }

  if(adsl_link_cur == NULL)
    return -1;

  int iml_lengthpacket = -1;

  if((adsl_link_cur->achc_ginp_cur + iml1 + 2) <= adsl_link_cur->achc_ginp_end)
  { // Entire LengthPacket value in current link.
    // Get SSTP length value.
    iml_lengthpacket =
       ntohs(0xFF0F & *((unsigned short*)(adsl_link_cur->achc_ginp_cur + iml1)));
  }
  // Entire length value not available.
  else if(adsl_link_cur->adsc_next != NULL)
  { // LengthPacket value divided across two links, and next link is available.
    // Get SSTP length value.
    iml_lengthpacket =
       0x0FFF & ((*(adsl_link_cur->achc_ginp_cur + iml1) << 8) |
       (*adsl_link_cur->adsc_next->achc_ginp_cur));
  }
  return iml_lengthpacket;
}


char* m_check_sstp_complete(dsd_gather_i_1* adsp_link_cur,
                            unsigned short usp_lengthpacket)
{
  // Get ptr to start of chain.
  dsd_gather_i_1* adsl_link_cur = adsp_link_cur;
  int iml1 = usp_lengthpacket;
  // Loop through links in chain, looking for end of message.
  // Stop when end of message found, or no more links in chain.
  while(adsl_link_cur != NULL)
  {
    iml1 -= adsl_link_cur->achc_ginp_end - adsl_link_cur->achc_ginp_cur;
    if(iml1 <= 0) // End of SSTP message found: create ptr to end of message.
      return (adsl_link_cur->achc_ginp_end + iml1);
    // Move to next link.
    adsl_link_cur = adsl_link_cur->adsc_next;
  }
  // No more links in chain.
  // Indicate that not entire message is available in this chain.
  return NULL;
}


byte* GenerateAuthenticatorResponse
   (byte*    abyp_peer_pw,    // Peer password.
    unsigned int ump_peer_pw_len, // Peer password length.
    byte*    abyp_peer_un,    // Peer username.
    unsigned int ump_peer_un_len, // Peer username length.
    byte*    abyp_peer_resp,  // Peer NT-Response value (24 byte).
    byte*    abyp_peer_chal,  // Peer challenge value (16 byte).
    byte*    abyp_own_chal,   // Own challenge value (16 byte).
    byte*    abyp_result_buf) // Buffer to place result.
{
  // MD4 hash of peer password.
  byte byrl_pw_hash[16]     = { 0 };
  // MD4 hash of peer password hash.
  byte byrl_pw_hashhash[16] = { 0 };
  // SHA1 hash to hold result.
  byte byrl_digest_1[20]    = { 0 };
  // SHA1 hash to be used as temp buffer.
  byte byrl_digest_2[20]    = { 0 };
  // SHA1 hash to be used as temp buffer.
  //unsigned char ucrl_digest_3[20]    = { 0 };
  // SHA1 hash to be used as temp buffer.
  byte byrl_digest_chal[8]  = { 0 };

  // "Magic" constants used in response generation.
  static byte byrl_magic1[39] =
   { 0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
     0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
     0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
     0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74 };

  static byte byrl_magic2[41] =
   { 0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
     0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
     0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
     0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
     0x6E };

  
  // Hash the password with MD4.
  unsigned int umrl_md4_state[24] = { 0 };
  MD4_Init((int*)umrl_md4_state);
  MD4_Update((int*)umrl_md4_state, (char*)abyp_peer_pw, 0, ump_peer_pw_len);
  MD4_Final((int*)umrl_md4_state, (char*)byrl_pw_hash, 0);

  // Now hash the hash with MD4.
  MD4_Init((int*)umrl_md4_state);
  MD4_Update((int*)umrl_md4_state, (char*)byrl_pw_hash, 0, 16);
  MD4_Final((int*)umrl_md4_state, (char*)byrl_pw_hashhash, 0);

  // Hash a combination of the MD4 password digest, NT-Response
  // and the first Magic constant with SHA1.
  unsigned int umrl_sha_state[24] = { 0 };
  SHA1_Init((int*)umrl_sha_state);
  SHA1_Update((int*)umrl_sha_state, (char*)byrl_pw_hashhash, 0, 16);
  SHA1_Update((int*)umrl_sha_state, (char*)abyp_peer_resp, 0, 24);
  SHA1_Update((int*)umrl_sha_state, (char*)byrl_magic1, 0, 39);
  SHA1_Final((int*)umrl_sha_state, (char*)byrl_digest_1, 0);

  // Hash a combination of the original challenge, peer challenge
  // and the peer username with SHA1.

  SHA1_Init((int*)umrl_sha_state);
  SHA1_Update((int*)umrl_sha_state, (char*)abyp_peer_chal, 0, 16);
  SHA1_Update((int*)umrl_sha_state, (char*)abyp_own_chal, 0, 16);
  SHA1_Update((int*)umrl_sha_state, (char*)abyp_peer_un, 0, ump_peer_un_len);
  SHA1_Final((int*)umrl_sha_state, (char*)byrl_digest_2, 0);
  memcpy(byrl_digest_chal, byrl_digest_2, 8);

  // Hash a combination of the first SHA1 digest, Challenge SHA1 digest
  // and the second magic number with SHA1.

  SHA1_Init((int*)umrl_sha_state);
  SHA1_Update((int*)umrl_sha_state, (char*)byrl_digest_1, 0, 20);
  SHA1_Update((int*)umrl_sha_state, (char*)byrl_digest_chal, 0, 8);
  SHA1_Update((int*)umrl_sha_state, (char*)byrl_magic2, 0, 41);
  SHA1_Final((int*)umrl_sha_state, (char*)byrl_digest_1, 0);

  sprintf((char*)abyp_result_buf,
          "S=%08X%08X%08X%08X%08X",
          htonl(*((unsigned int*)(byrl_digest_1) + 0)),
          htonl(*((unsigned int*)(byrl_digest_1) + 1)),
          htonl(*((unsigned int*)(byrl_digest_1) + 2)),
          htonl(*((unsigned int*)(byrl_digest_1) + 3)),
          htonl(*((unsigned int*)(byrl_digest_1) + 4)));

  return NULL;

}

BOOL m_skip(dsd_gather_i_1** aadsp_gather, char** aachp_pos, unsigned int ump_skip_len)
{
   if(*aadsp_gather == NULL)
      return FALSE;
   else if(*aachp_pos + ump_skip_len <= (*aadsp_gather)->achc_ginp_end)
   {
      *aachp_pos += ump_skip_len;
      return TRUE;
   }
   else
   {
      ump_skip_len -= (*aadsp_gather)->achc_ginp_end - *aachp_pos;
      *aadsp_gather = (*aadsp_gather)->adsc_next;
      if(*aadsp_gather == NULL)
         return FALSE;
      *aachp_pos = (*aadsp_gather)->achc_ginp_cur;
      return m_skip(aadsp_gather, aachp_pos, ump_skip_len);
   }
}

BOOL m_get_ushort(dsd_gather_i_1** aadsp_gather, char** aachp_pos, unsigned short* aisp_short, unsigned int ump_left)
{
   if(*aadsp_gather == NULL)
      return FALSE;
   else if(*aachp_pos + ump_left <= (*aadsp_gather)->achc_ginp_end)
   {
      memcpy(aisp_short + (sizeof(unsigned short) - ump_left), *aachp_pos, ump_left);
      *aachp_pos += ump_left;
      return TRUE;
   }
   else
   {
      unsigned int uml_copyable = (*aadsp_gather)->achc_ginp_end - *aachp_pos;
      memcpy(aisp_short + (sizeof(unsigned short) - ump_left), *aachp_pos, uml_copyable);
      *aadsp_gather = (*aadsp_gather)->adsc_next;
      if(*aadsp_gather == NULL)
         return FALSE;
      *aachp_pos = (*aadsp_gather)->achc_ginp_cur;
      return m_get_ushort(aadsp_gather, aachp_pos, aisp_short, ump_left - uml_copyable);
   }     
}

void m_get_hpppt1_msg_rec(unsigned char** aachp_data, dsd_gather_i_1* adsp_gather, unsigned int ump_length, unsigned int ump_left)
{
   if(adsp_gather == NULL)
      return;
   else if(adsp_gather->achc_ginp_cur + ump_left <= adsp_gather->achc_ginp_end)
   {
      memcpy(*aachp_data + ump_length - ump_left, adsp_gather->achc_ginp_cur, ump_left);
      return;
   }
   else
   {
      unsigned int uml_copyable = adsp_gather->achc_ginp_end - adsp_gather->achc_ginp_cur;
      memcpy(*aachp_data + ump_length - ump_left, adsp_gather->achc_ginp_cur, uml_copyable);
      return m_get_hpppt1_msg_rec(aachp_data, adsp_gather->adsc_next, ump_length, ump_left - uml_copyable);
   } 
}

void m_get_hpppt1_msg(unsigned char** aachp_data, dsd_gather_i_1* adsp_gather, unsigned int ump_length)
{
   if(adsp_gather->achc_ginp_cur + ump_length <= adsp_gather->achc_ginp_end)
      *aachp_data = (unsigned char*)(adsp_gather->achc_ginp_cur);
   else
      m_get_hpppt1_msg_rec(aachp_data, adsp_gather, ump_length, ump_length);

   return;
}

void m_consume_hpppt1_msg(dsd_gather_i_1** aadsp_gather, unsigned int ump_length)
{
   if(*aadsp_gather == NULL)
      return;
   else if((*aadsp_gather)->achc_ginp_cur + ump_length <= (*aadsp_gather)->achc_ginp_end)
   {
      (*aadsp_gather)->achc_ginp_cur += ump_length;
   }
   else
   {
      ump_length -= (*aadsp_gather)->achc_ginp_end - (*aadsp_gather)->achc_ginp_cur;
      (*aadsp_gather)->achc_ginp_cur = (*aadsp_gather)->achc_ginp_end;
      *aadsp_gather = (*aadsp_gather)->adsc_next;
      m_consume_hpppt1_msg(aadsp_gather, ump_length);
   }
}

unsigned int m_seek_comm(dsd_gather_i_1* adsp_gather, char* achp_cmp_buf, unsigned int ump_pos)
{
    // Length of current link.
    unsigned int uml_link_len = adsp_gather->achc_ginp_end - adsp_gather->achc_ginp_cur;
    // Command length remaining.
    unsigned int uml_remaining_len = 20 - ump_pos;

    // If length of current link is >= than remaining command length...
    if(uml_link_len >= uml_remaining_len)
    {
        // Copy all of remaining command and return number of bytes copied.
        memcpy(achp_cmp_buf + ump_pos, adsp_gather->achc_ginp_cur, uml_remaining_len);
        return uml_remaining_len;
    }
    else // Length of current link is < than remaining command length...
    {
        // If another link is available...
        unsigned int uml_bytes_read = 0;
        if(adsp_gather->adsc_next != NULL)
        {
            // Call function recursively.
            uml_bytes_read =
                m_seek_comm(adsp_gather->adsc_next, achp_cmp_buf, ump_pos + uml_link_len);
        }

        // Copy contents of current link and return.
        memcpy(achp_cmp_buf + ump_pos, adsp_gather->achc_ginp_cur, uml_link_len);

        // Return number of bytes copied at this point
        return uml_bytes_read + uml_link_len;
    }
}

ied_hpppt1_conn_state m_check_hpppt1_cmd(dsd_gather_i_1* adsp_root_link)
{

    // String to match to.
    char chrl_ppp_vers_01[] =
        { 'H', 'O', 'B', ' ', 'P', 'P', 'P', ' ', 'T', 'U', 'N', 'N', 'E', 'L',
          ' ', 'V', '0', '1', 0x0D, 0x0A };

    // Buffer to read command into.
    char chrl_cmp_buf[20] = { 0 };

    // Seek the HOB-PPP-T1 command.
    unsigned int uml_bytes_found = m_seek_comm(adsp_root_link, chrl_cmp_buf, 0);

    // Compare the fetched command...
    if(memcmp(chrl_cmp_buf, chrl_ppp_vers_01, uml_bytes_found) == 0)
    {
        // If command matched completely...
        if(uml_bytes_found == 20)
        {
            return ied_hpppt1_conn_started;
        }
    }

    // No (or partial) match.
    return ied_hpppt1_conn_idle;
}

#ifdef _MSC_VER
static int vsnprintf(char* achp_str, size_t upp_size,
                     const char* achp_format, va_list ap)
{
    va_list ap_copy;
    int inl_ret;

    if (achp_str != NULL && upp_size > 0) {
        ap_copy = ap; // _MSC_VER does not yet support va_copy(ap_copy, ap)
        inl_ret = _vsnprintf(achp_str, upp_size, achp_format, ap);

        if (inl_ret == -1 || inl_ret == (int)upp_size) {
            achp_str[upp_size - 1] = '\0';
            inl_ret = _vscprintf(achp_format, ap_copy);
        }

        return inl_ret;
    } else {
        return _vscprintf(achp_format, ap);
    }
}
#endif // _MSC_VER

#define DEF_HL_INCL_DOM
#define DOMNode void
#include "hob-wsppriv.h"
#include "hob-xslcontr.h"
#include "hob-xsclib01.h"
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"

extern "C" int img_wsp_trace_core_flags1;

/* core traces:
 * set inp_core_id to HL_WT_CORE_?
 * inp_session_wtrt_sno and inp_session_trace_level will be ignored
 *
 * session traces:
 * set inp_core_id to 0
 * set inp_sesssion_wtrt_sno to session number
 * set inp_session_trace_level to trace level
 */
void m_do_wsp_trace(const char* achp_wtrt_id, int inp_core_id,
                    int inp_session_wtrt_sno, int inp_session_trace_level,
                    struct dsd_gather_i_1* adsp_data, int inp_data_len,
                    int inp_short_len,
                    const char* achp_message, ...)
{
    char* achl_wa_front;
    char* achl_wa_back;
    struct dsd_gather_i_1 dsl_gath;
    struct dsd_gather_i_1* adsl_gath_next;
    struct dsd_wsp_trace_1* adsl_wt_first;
    struct dsd_wsp_trace_1* adsl_wt;
    struct dsd_wsp_trace_1* adsl_wt_prev;
    struct dsd_wsp_trace_record* adsl_wtr;
    struct dsd_wsp_trace_record* adsl_wtr_cur;
    int inl_len;
    va_list ap;

    if (inp_core_id != 0) {
        // core
        inp_session_wtrt_sno = 0;

#ifdef B130115
        if ((img_wsp_trace_core_flags1 & inp_core_id) == 0)
            return;
#endif

        if (adsp_data == NULL || inp_data_len < 0) {
            inp_data_len = 0;
        } else if ((img_wsp_trace_core_flags1 & HL_WT_CORE_DATA2) == 0) {
            if ((img_wsp_trace_core_flags1 & HL_WT_CORE_DATA1) == 0 ||
                inp_short_len <= 0) {

                inp_data_len = 0;
            } else if (inp_data_len > inp_short_len) {
                inp_data_len = inp_short_len;
            }
        }
    } else {
        // session

#ifdef B130115
#ifndef B120710
        if (!(inp_session_trace_level & HL_WT_SESS_NETW))
#else
        if (inp_session_trace_level == 0)
#endif
            return;
#endif

        if (adsp_data == NULL || inp_data_len < 0) {
            inp_data_len = 0;
        } else if ((inp_session_trace_level & HL_WT_SESS_DATA2) == 0) {
            if ((inp_session_trace_level & HL_WT_SESS_DATA1) == 0 ||
                inp_short_len <= 0) {

                inp_data_len = 0;
            } else if (inp_data_len > inp_short_len) {
                inp_data_len = inp_short_len;
            }
        }
    }

    if (inp_data_len == 0 && achp_message == NULL)
        return;

    achl_wa_front = (char*)m_proc_alloc();
    achl_wa_back = achl_wa_front + LEN_TCP_RECV;

    memset(achl_wa_front, 0,
           sizeof(struct dsd_wsp_trace_1) +
           sizeof(struct dsd_wsp_trace_record));
    adsl_wt_first = (struct dsd_wsp_trace_1*)achl_wa_front;
    achl_wa_front += sizeof(struct dsd_wsp_trace_1);
    adsl_wtr = (struct dsd_wsp_trace_record*)achl_wa_front;
    achl_wa_front += sizeof(struct dsd_wsp_trace_record);

    adsl_wt_first->iec_wtrt = ied_wtrt_trace_data;

	adsl_wt_first->ilc_epoch = m_get_epoch_microsec();
	adsl_wt_first->imc_wtrt_tid = HL_THRID;  /* thread-id             */

    memcpy(adsl_wt_first->chrc_wtrt_id, achp_wtrt_id,
           sizeof(adsl_wt_first->chrc_wtrt_id));
    adsl_wt_first->imc_wtrt_sno = inp_session_wtrt_sno;
    adsl_wt_first->adsc_wsp_trace_record = adsl_wtr;
    adsl_wt = adsl_wt_first;

    adsl_wtr_cur = NULL;
    if (achp_message != NULL) {
        va_start(ap, achp_message);
        inl_len = vsnprintf(achl_wa_front, achl_wa_back - achl_wa_front,
                            achp_message, ap);
        va_end(ap);

        if (inl_len > 0) {
            if (achl_wa_front + inl_len >= achl_wa_back) {
                inl_len = achl_wa_back - achl_wa_front;
                --inl_len;
                achl_wa_front[inl_len - 3] = '.';
                achl_wa_front[inl_len - 2] = '.';
                achl_wa_front[inl_len - 1] = '.';
            }

            adsl_wtr->iec_wtrt = ied_wtrt_text;
            adsl_wtr->achc_content = achl_wa_front;
            adsl_wtr->imc_length = inl_len;

            achl_wa_front += inl_len;
            adsl_wtr_cur = adsl_wtr;
        }
    }

    while (inp_data_len) {
        while (adsp_data != NULL &&
               adsp_data->achc_ginp_cur >= adsp_data->achc_ginp_end) {

            adsp_data = adsp_data->adsc_next;
        }
        if (adsp_data == NULL)
            break;

        if (adsl_wtr_cur == NULL) {
            // no message - we should have enough space for some data

            adsl_wtr_cur = adsl_wtr;
            adsl_wtr_cur->iec_wtrt = ied_wtrt_data;
            adsl_wtr_cur->achc_content = achl_wa_front;
        } else {
            if (achl_wa_front +
                (adsl_wtr_cur->iec_wtrt == ied_wtrt_data ?
                 0 : sizeof(struct dsd_wsp_trace_record)) >=
                achl_wa_back) {
                // we need to get new work area

                adsl_wt_prev = adsl_wt;

                achl_wa_front = (char*)m_proc_alloc();
                achl_wa_back = achl_wa_front + LEN_TCP_RECV;

                memset(achl_wa_front, 0,
                       sizeof(struct dsd_wsp_trace_1) +
                       sizeof(struct dsd_wsp_trace_record));
                adsl_wt = (struct dsd_wsp_trace_1*)achl_wa_front;
                achl_wa_front += sizeof(struct dsd_wsp_trace_1);
                adsl_wtr = (struct dsd_wsp_trace_record*)achl_wa_front;
                achl_wa_front += sizeof(struct dsd_wsp_trace_record);

                adsl_wt_prev->adsc_cont = adsl_wt;

                adsl_wtr_cur->adsc_next = adsl_wtr;
                if (adsl_wtr_cur->iec_wtrt == ied_wtrt_data)
                    adsl_wtr_cur->boc_more = TRUE;
                adsl_wtr_cur = adsl_wtr;

                adsl_wtr_cur->iec_wtrt = ied_wtrt_data;
                adsl_wtr_cur->achc_content = achl_wa_front;

            } else if (adsl_wtr_cur->iec_wtrt != ied_wtrt_data) {
                // transition from text to data
                achl_wa_back -= sizeof(struct dsd_wsp_trace_record);
                adsl_wtr = (struct dsd_wsp_trace_record*) achl_wa_back;
                memset(achl_wa_back, 0, sizeof(struct dsd_wsp_trace_record));

                adsl_wtr_cur->adsc_next = adsl_wtr;
                adsl_wtr_cur = adsl_wtr;

                adsl_wtr_cur->iec_wtrt = ied_wtrt_data;
                adsl_wtr_cur->achc_content = achl_wa_front;
            }
        }

        adsl_gath_next = adsp_data->adsc_next;

        inl_len = adsp_data->achc_ginp_end - adsp_data->achc_ginp_cur;
        if (inl_len > inp_data_len)
            inl_len = inp_data_len;
        if (achl_wa_front + inl_len > achl_wa_back) {
            inl_len = achl_wa_back - achl_wa_front;
            dsl_gath.achc_ginp_cur = adsp_data->achc_ginp_cur + inl_len;
            dsl_gath.achc_ginp_end = adsp_data->achc_ginp_end;
            dsl_gath.adsc_next = adsp_data->adsc_next;
            adsl_gath_next = &dsl_gath;
        }

        memcpy(achl_wa_front, adsp_data->achc_ginp_cur, inl_len);
        adsl_wtr_cur->imc_length += inl_len;
        achl_wa_front += inl_len;
        inp_data_len -= inl_len;

        adsp_data = adsl_gath_next;
    }

    if (adsl_wtr_cur == NULL) {
        // nothing to trace
        m_proc_free(adsl_wt_first);
        return;
    }

    m_wsp_trace_out(adsl_wt_first);
}