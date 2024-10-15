#ifndef HOB_SESSUTIL_H_INC
#define HOB_SESSUTIL_H_INC

//
// Frees a chain of gather structures.
// Frees the memory allocated by a chain of gather structures, starting from
// the root link, and finishing at the last link.
//
// @param adsp_chain_root  First link in the chain of gather structures.
//
extern inline void m_free_gath_chain(dsd_gather_i_1* adsp_chain_root);

//
// Reads and returns the message length value from the HOB-TUN header.
// Attempts to read the message length value of the variable length 'length'
// field of the HOB-TUN header.
//
// @param  adsp_root_gather  Pointer to the first relevant link in the gather
//                           chain.
// @param  imp_length        After the call returns, holds the length value
//                           read.
// @param  imp_lenlen        After the call returns, holds the length of the
//                           header's 'length' field.
//
// @return  Returns TRUE if the gather chain contained the entire lenght field
//          and FALSE otherwise.
//
extern BOOL m_getlen_nhasn(dsd_gather_i_1* adsp_root_gather,
                     int32_t&        imp_length,
                     int32_t&        imp_lenlen);

//
// Determines whether a gather structure chain contains an entire SSTP message.
// Given a chain of gather structures and the length of a HOB-TUN message,
// finds out if the chain of gather structures stores the entire HOB-TUN
// message within it.
//
// @param  adsp_root_link   Pointer to the first relevant link in the gather
//                          chain.
// @param  imp_tot_pkt_len  Length of the HOB-TUN relevant message.
// @param  aabyp_pkt_end    After the call returns, holds a pointer to the end
//                          of the HOB-TUN message in the gather chain.
//
// @return  If the entire HOB-TUN message is found, returns TRUE. Otherwise
//          returns FALSE.
//
extern BOOL m_check_pkt_complete(dsd_gather_i_1* adsp_root_link,
                                 int32_t         imp_tot_pkt_len,
                                 byte**          aabyp_pkt_end);

//
// Finds a sequence of two newline characters.
// Searches a string of characters looking for a sequence of two consecutive
// newline characters.
//
// @param  aucp_pos_start  Pointer to the beginning of the character string.
// @param  aucp_pos_end    Pointer to the end of the character string.
//
// @return  If the sequence is found, the call returns a pointer to the end of
//          the sequence. If it is not found, the call returns NULL.
//
extern byte* m_search_nlnl(byte* abyp_pos_start,
                           byte* abyp_pos_end);

//
// Gets the SSTP message length.
// Attempts to read the SSTP LengthValue field in order to determine the length
// of an SSTP message in a gather chain.
//
// @param  adsp_link_cur  Pointer to the first relevant link in the gather chain.
//
// @return  If the length value was successfully read, the call returns the
//          length of the SSTP message. If the length value could not be read
//          the call returns a value of -1.
//
extern int32_t m_get_sstp_lengthpacket(dsd_gather_i_1* adsp_link_cur);

//
// Determines whether a gather structure chain contains an entire SSTP message.
// Given a chain of gather structures and the length of an SSTP message,
// finds out if the chain of gather structures stores the entire SSTP message
// within it.
//
// @param  adsp_link_cur     Pointer to the first relevant link in the gather
//                           chain.
// @param  usp_lengthpacket  Length of the SSTP relevant message.
//
// @return  If the entire SSTP message is found, returns a pointer to the end
//          of the message in the gather chain. Returns NULL if only part of the
//          SSTP message was found.
//
extern char* m_check_sstp_complete(dsd_gather_i_1* adsp_link_cur,
                                   uint16_t        usp_lengthpacket);

//
// Copies an SSTP message from a gather chain to a single contiguous buffer.
//
// @param  adsp_link_cur      Pointer to the first relevant link in the gather
//                            chain.
// @param  usp_lengthpacket   Length of the SSTP message being copied.
// @param  abyp_sstp_msg_end  Pointer to the position in the gather chain where
//                            the SSTP message ends.
//
// @return  Returns a pointer to the new buffer.
//
extern byte* m_copy_sstp_message(dsd_gather_i_1* adsp_link_cur,
                                 uint16_t        usp_lengthpacket,
                                 byte*           abyp_sstp_msg_end);

//
// Generates a valid MS-CHAP challenge response.
//
// @return  Returns the valid response for the given challenge.
//
extern byte* GenerateAuthenticatorResponse(byte*    abyp_peer_pw,
                                           uint32_t ump_peer_pw_len,
                                           byte*    abyp_peer_un,
                                           uint32_t ump_peer_un_len,
                                           byte*    abyp_peer_resp,
                                           byte*    abyp_peer_chal,
                                           byte*    abyp_own_chal,
                                           byte*    abyp_result_buf);

#endif

BOOL m_skip(dsd_gather_i_1** aadsp_gather, char** aachp_pos, uint32_t ump_skip_len);

BOOL m_get_ushort(dsd_gather_i_1** aadsp_gather, char** aachp_pos, unsigned short* aisp_short, uint32_t ump_left = 2);

void m_get_hpppt1_msg(unsigned char** aachp_data, dsd_gather_i_1* adsp_gather, uint32_t ump_length);

void m_consume_hpppt1_msg(dsd_gather_i_1** aadsp_gather, uint32_t ump_length);

unsigned int m_seek_comm(dsd_gather_i_1* adsp_gather, char* achp_cmp_buf, uint32_t ump_pos);

ied_hpppt1_conn_state m_check_hpppt1_cmd(dsd_gather_i_1* adsp_root_link);

void m_do_wsp_trace(const char* achp_wtrt_id, int inp_core_id,
                    int inp_session_wtrt_sno, int inp_session_trace_level,
                    struct dsd_gather_i_1* adsp_data, int inp_data_len,
                    int inp_short_len,
                    const char* achp_message, ...);