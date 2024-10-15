#ifndef DS_TRANSACTION_H
#define DS_TRANSACTION_H

#define SM_USE_PLACEHOLDER_V2	0

#if defined WIN32 || defined WIN64
#include <windows.h>
#else
#include <sys/types.h>
#include <errno.h>
#include <hob-unix01.h>
#endif

#include <ds_hstring.h>
#include "ds_datablock.h"
#include "sdh_web_server.h"
#include "ds_http_header.h"

class ds_session; //forward-definition!!  #include "ds_session.h"


/*! \brief Transaction class
 *
 * @ingroup webserver
 *
 * Transaction class, which reads incoming data out of our internal memory structures
 * from the WSP
 */
class ds_transaction
{
	enum ied_states {
	   ien_st_read_chunked_size,                // read until length-info of chunked is complete
       ien_st_read_chunked_data,                // read until chunked data is complete
       ien_st_read_chunked_datablock_end,        // read trailing CRLF after data
       ien_st_wait_chunked_end,                    // receive terminating CRLF of chunked
	};
public:
    ds_transaction(void);
    ~ds_transaction(void);

    void m_init(dsd_hl_clib_1 * ads_trans_in, ds_session* ads_session);
    ds_datablock m_get_next_block(void);

    dsd_hl_clib_1 *ads_trans;  // public, because CONFIGURATION
    // len of data, which must be delivered to html-interpreter
    int in_len_data_to_deliver;
    // true: webserver delivered data in chunked format, which we must resolve, when preparing data for interpreter-classes
    bool bo_resolve_from_chunked_format;
    bool bo_send_chunked;
    bool bo_placeholder_written;
#if SM_USE_PLACEHOLDER_V2
    char* ach_placeholder_wa;
    struct dsd_gather_i_1* ads_gather_data;
#else
	 // position of placeholder for length-info of chunked format
    int in_pos_placeholder_chunked;
#endif
	 int in_len_chunked_out;
    ied_states in_chunked_state;
    int in_chunked_expected_len;
    int in_chunked_received_data_len;
    //char* ach_start_pos;
    int in_len_current;
    // set, when 0x30 0x0d 0x0a 0x0d 0x0a was read
    bool bo_read_chunked_data_done;
    bool bo_radius_must_be_released; // variable is used to avoid superfluous releasing of RADIUS

    int m_get_next_block(char** ach_start_ret);
    int m_get_gather_by_index(int in_idx, char** ach_start_ret);
    int m_get_next_unprocessed_data(char** ach_start_ret, bool bo_change_gather_counter=true);
    int m_get_next_unprocessed_data_off( char **aachp_start, const char *achp_offset );
    // loop over all gather-items and count the unprocessed gather-items
    int m_count_unprocessed_gather_items();
    // loop over all gather-items and count the unprocessed data
    int m_count_unprocessed_data();

	bool m_has_unprocessed_data();

    // pass data unchanged to browser
    int m_pass_data(int in_len_data, bool bo_send = true, ds_hstring* ahstr_data=NULL);
    // get next available data block; returns true if this data are complete
    int m_get_data(const char** ach_data_out, int* in_len_data_out, bool bo_do_decompression = true);
    // // pass all data, which are in input
    int m_pass_all_available_data(bool bo_send = true);
    ds_datablock m_get_next_unprocessed_block(void);

    bool m_check_setting( int in_setting );

    //-----------------------------
    // Callback-functions WSP
    //-----------------------------
    bool m_tcp_connect(bool bo_https, const dsd_const_string& rhstr_host, int in_port, ds_hstring& ahstr_err_msg, dsd_const_string& adsp_error_key );

    // returns the calling mode (e.g. DEF_IFUNC_START or DEF_IFUNC_FROMSERVER; defined in hob-xsclib01.h)
    int m_get_callmode(void);
    // set the flag ; returns the updated flag
    bool m_set_callagain(bool bo_new);
    // returns true, when the flag is set
    bool m_is_callagain(void);
    bool m_set_callrevdir(bool bo_new);
    // // returns true, when the flag boc_callrevdir is set
    bool m_is_callrevdir(void);
    // mark how far the received blocks are processed
    bool m_mark_as_processed(const char* ach_processed_til_here);
    // set a flag, which tells WSP to close the TCP-connection
    int m_close_connection(void);
    // collect data of several gather-items to a contiguous memory
    int m_get_linear_data(char* ach_memory, int in_len_memory, bool bol_mark_as_processed = true);

    int m_send_header(enum ied_sdh_data_direction ienp_direction);
    int m_send_complete_file(const ds_hstring* ahstr_file, enum ied_sdh_data_direction ienp_direction);
    int m_send_complete_file(const char* ach_file_to_send, int in_len_file_to_send, bool bop_copy_data, enum ied_sdh_data_direction ienp_direction);

	int m_send_data(const dsd_const_string& rdsp_data, enum ied_sdh_data_direction ienp_direction);
private:
	bool m_must_compress() const;
	//int m_send(const char* ach_to_send_zero, enum ied_sdh_data_direction ienp_direction);
    int m_send(const char* ach_to_send, int in_len_to_send, bool bop_copy_data, enum ied_sdh_data_direction ienp_direction);
    //int m_send(const ds_hstring* ahstr_to_send, bool bo_allow_chunked, enum ied_sdh_data_direction ienp_direction);
public:

    void m_begin_chunked(); 
	 int m_write_as_chunked(const char* ach_to_send, int in_len_to_send, bool bop_copy_data, enum ied_sdh_data_direction ienp_direction, bool bo_allow_compress, bool bop_eof);
    int m_send_chunked_flush(enum ied_sdh_data_direction ienp_direction);
    int m_send_chunked_end(enum ied_sdh_data_direction ienp_direction);
    
private:
    ds_session* ads_session;

    int m_write_chunked(const char* ach_to_send, int in_len_to_send, bool bop_copy_data, enum ied_sdh_data_direction ienp_direction);
    
#ifdef __HOB_ALIGN__ // MJ 29.01.08
    static const int in_len_chunked_placeholder = 16;
#else
    static const int in_len_chunked_placeholder = 10;
#endif //__HOB_ALIGN__
    
    // update chunked data len info
    bool m_update_chunked_len(int in_len_to_add);
    // get next available data block; returns true if this data are complete
    bool m_get_data_intern(const char** ach_data_out, int* in_len_data_out);

    // index of the gather-item, which was not yet delivered
    int in_idx_first_not_delivered;
    // count of occupied bytes in workarea
    int in_occupied_wa;
    // the last gather-structure, which was written into WA; (needed to find the previous gather-item)
    dsd_gather_i_1* ads_last_gather_in_wa;
};

#endif // DS_TRANSACTION_H
