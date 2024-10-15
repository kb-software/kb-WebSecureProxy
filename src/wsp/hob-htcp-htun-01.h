/******************************************************************************
 * File name: hob-htcp-htun-01.h
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2012
 ******************************************************************************/

#ifndef HOB_HTCP_HTUN_01_H
#define HOB_HTCP_HTUN_01_H

void m_htcp_sess_close(struct dsd_htcp_htun* adsp_hh);

void m_htcp_sess_send(struct dsd_htcp_htun* adsp_hh,
                      struct dsd_gather_i_1* adsp_gai1);

void m_htcp_sess_canrecv(struct dsd_htcp_htun* adsp_hh);


void m_htcp_packet_from_network(struct dsd_htcp_htun* adsp_hh,
                                void* ap_handle, unsigned unp_offset,
                                char* achp_data, unsigned unp_dlen);

#endif /* !HOB_HTCP_HTUN_01_H */
