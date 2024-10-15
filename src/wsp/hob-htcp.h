/******************************************************************************
 * File name: htcp.h
 *
 * HTCP connection interface.
 *
 * Can be used in C and C++.
 *
 * Author: Kevin Spiteri
 * Copyright: Copyright (c) HOB Software 2009
 ******************************************************************************/

#ifndef HTCP_HTCP_H
#define HTCP_HTCP_H

#ifdef DOES_INCL_HEADERS
#include "int_types.h"
#include "hob-tun01.h" /* for dsd_gather_i_1 */
#endif

#ifdef __cplusplus
extern "C" {
#endif
#if 0
} /* so as not to confuse auto-indentation */
#endif


struct dsd_htcp_conn_callbacks;

struct dsd_htcp_conn {
    void* vp_internal;  /* internal class - see connection.h */
    void* vp_user_data; /* user field                        */

    /* TODO: IPv6 friendliness */
    uint32 um_local_addr;
    uint16 us_local_port;
    uint32 um_remote_addr;
    uint16 us_remote_port;

    uint32 um_send_pend;  /* unacknowledged data sent by m_htcp_conn_send()  */
    uint32 um_recv_avail; /* received data not yet read by m_htcp_conn_recv()*/

    struct dsd_htcp_conn_callbacks* ads_callbacks;
};

typedef void (*amd_htcp_conn_callback)(struct dsd_htcp_conn*, int);

/*
 * dsd_htcp_conn_callbacks:
 *
 * am_connected:
 * The connection is established.
 *
 * am_connection_failed:
 * The connection could not be established.
 *
 * am_recv_data:
 * New data was received from the remote host, as indicated in um_recv_avail.
 *
 * am_data_acked:
 * Some data sent was acknowledged by the remote host, as indicated in
 * um_send_pend.
 *
 * am_recv_eof:
 * A FIN was received from the remote host, so no further data will be received.
 * See "Connection closing" comment below.
 *
 * am_conn_reset:
 * A RST was received from the remote host, or the connection is corrupted.
 * No further data will be received, and no further data can be sent.
 * See "Connection closing" comment below.
 *
 * am_conn_closed:
 * The following are all true:
 * 1. A FIN was received from the remote host.
 * 2. A FIN was sent to the remote host and was acknowledged.
 * 3. The TIME-WAIT delay (if applicable) is over.
 * See "Connection closing" comment below.
 */

struct dsd_htcp_conn_callbacks {
    amd_htcp_conn_callback am_connected;
    amd_htcp_conn_callback am_connection_failed;
    amd_htcp_conn_callback am_recv_data;
    amd_htcp_conn_callback am_data_acked;
    amd_htcp_conn_callback am_recv_eof;
    amd_htcp_conn_callback am_conn_reset;
    amd_htcp_conn_callback am_conn_closed;
};

/**
 * First fill in addresses/ports and ads_callbacks, then call m_htcp_connect().
 * m_htcp_connect() fills in vp_internal, um_send_pend and um_recv_avail.
 * The first SYN packet is sent.
 * An internal connection structure is created in memory.
 * Eventually, exactly one of the am_connected() and am_connection_failed()
 * callbacks is invoked.
 *
 * @param ads_conn the connection
 */
void m_htcp_connect(struct dsd_htcp_conn* ads_conn);

/**
 * Accept a connection when SYN packet is received. Send SYNACK.
 * An internal connection structure is created in memory.
 *
 * @param ads_conn the connection
 */
void m_htcp_conn_accept(dsd_htcp_conn* ads_conn);

/**
 * Refuse a connection when SYN packet is received. Send RST.
 *
 * @param ads_conn the connection
 */
void m_htcp_conn_refuse(dsd_htcp_conn* ads_conn);

/**
 * Send data on connection.
 *
 * @param ads_conn the connection
 * @param ads_data the root node of the gather structure of the data to send
 * @return the number of new bytes HTCP has received
 */
uint32 m_htcp_conn_send(dsd_htcp_conn* ads_conn, dsd_gather_i_1* ads_data);

/**
 * Receive data from connection.
 *
 * @param ads_conn the connection
 * @param ads_vec a pointer to an array o f vector elements
 * @param ads_count Before calling, *aun_count should be set to the number of
 *   vector elements that may be received. On return, *aun_count is set to the
 *   number of vector elements passed.
 * @return the number of bytes given in the vector elements
 */
uint32 m_htcp_conn_recv(dsd_htcp_conn* ads_conn,
                        dsd_buf_vector_ele* ads_vec,
                        unsigned* aun_count);

/**
 * Indicates that no further data will be sent using m_htcp_conn_send().
 * A FIN is eventually sent (possibly immediately).
 *
 * @param ads_conn the connection
 */
void m_htcp_conn_close(dsd_htcp_conn* ads_conn);

/**
 * Terminates the connection.
 * A RST is sent immediately.
 * Data received before the call may still be read using m_htcp_conn_recv().
 *
 * @param ads_conn the connection
 */
void m_htcp_conn_reset(dsd_htcp_conn* ads_conn);

/**
 * The internal connection structure is removed from memory.
 * After this call, any pending data (in either direction) is lost,
 * no further packets are sent, and no callbacks are called.
 *
 * @param ads_conn the connection
 */
void m_htcp_conn_cleanup(dsd_htcp_conn* ads_conn);


/*
 * Connection closing:
 *
 * The local application may call m_htcp_conn_reset() to send a RST. After
 * m_htcp_conn_reset() returns, HTCP will call no further callbacks, no
 * further data will be received and no further data can be sent. Any unsent
 * data remains unsent. Any received data which has not yet been read by the
 * application may still be read.
 *
 * If HTCP recieves a RST or a segment which is considered to corrupt the
 * connection, e.g. SYN segment with correct sequence and acknowledgement
 * numers in an established connection, the am_conn_reset() callback is called.
 * After am_conn_reset() is called, HTCP will call no further callbacks, no
 * further data will be received and no further data can be sent. Any unsent
 * data remains unsent. Any received data which has not yet been read by the
 * application may still be read.
 *
 * The local application calls m_htcp_conn_close() to send a FIN. Any data that
 * is queued when m_htcp_conn_close() is called will still be sent, but any
 * later calls to m_htcp_conn_send() will not be successful.
 *
 * When a FIN is received the am_recv_eof() callback is called. Any received
 * data which has not yet been read by the application may still be read.
 *
 * When the application has called m_htcp_conn_close() and received the
 * am_recv_eof() callback, the application will also receive the
 * am_conn_closed() callback. After am_conn_reset() is called, HTCP will call
 * no further callbacks, no further data will be received and no further data
 * can be sent. Any unsent data remains unsent. Any received data which has
 * not yet been read by the application may still be read.
 *
 * The application must call m_htcp_conn_cleanup() once for every connection.
 * This removes the connection and frees all internal memory relevant to the
 * connection. Although m_htcp_conn_cleanup() is usually called after the
 * m_htcp_conn_reset() call or after the am_conn_closed() or am_conn_reset()
 * callback, m_htcp_conn_cleanup() can be called at any time.
 */



#if 0
{ /* so as not to confuse auto-indentation */
#endif
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* HTCP_HTCP_H */
