#include <sys/timeb.h>
#include <time.h>

#include "ds_session.h"
#include "ds_transaction.h"

ds_transaction::ds_transaction(void)
: ads_trans(NULL)
, in_len_data_to_deliver(-1)
, bo_resolve_from_chunked_format(false)
, bo_send_chunked(false)
, bo_placeholder_written(false)
#if SM_USE_PLACEHOLDER_V2
, ach_placeholder_wa(NULL)
, ads_gather_data(NULL)
#else
, in_pos_placeholder_chunked(0)
#endif
, in_len_chunked_out(0)
, in_chunked_state(ien_st_read_chunked_size)
, in_chunked_expected_len(0)
, in_chunked_received_data_len(0)
//, ach_start_pos(NULL)
, in_len_current(-1)
, bo_read_chunked_data_done(false)
, bo_radius_must_be_released(false)

// private members
, ads_session(NULL)
, in_idx_first_not_delivered(0)
, in_occupied_wa(0)
, ads_last_gather_in_wa(NULL)
{
}

ds_transaction::~ds_transaction(void)
{
}


/*! \brief Class Initializer
 *
 * @ingroup webserver
 *
 * Sets up some variables
 */
void ds_transaction::m_init(dsd_hl_clib_1 * ads_trans_in, ds_session* ads_session_in)
{
    ads_trans = ads_trans_in;
    ads_session = ads_session_in;
    in_idx_first_not_delivered = 0;
    in_occupied_wa = 0;
    ads_last_gather_in_wa = NULL;
	 //bo_send_chunked = false;
}


/*! \brief Gets a datablock
 *
 * @ingroup webserver
 */
ds_datablock ds_transaction::m_get_next_block(void)
{
    ds_datablock ds_ret;
    char* ach_start = NULL;
    int in_len = m_get_next_block(&ach_start);
    if ( (ach_start != NULL) && (in_len > -1) ) {
        ds_ret.m_set_start(ach_start);
        ds_ret.m_set_end(ach_start + in_len);
    }

    return ds_ret;
}


/*! \brief Get the next gather
 *
 * @ingroup webserver
 *
 * get the next available gather-item
 * returns the length of this data (negative if no data are available) and a pointer to this data (NULL, if no data available)
 */
int ds_transaction::m_get_next_block(char** ach_start_ret)
{
    // loop over all available gather-items
    // return the next not yet delivered item
    struct dsd_gather_i_1 * adsl_gath = ads_trans->adsc_gather_i_1_in;
    *ach_start_ret = (char*)ads_trans->adsc_gather_i_1_in; // may be NULL here
    int in_counter_items = 0;
    while (( adsl_gath != NULL) && (in_counter_items <= in_idx_first_not_delivered) ) {
        if (in_counter_items == in_idx_first_not_delivered) { // this is the first item, which was not delivered -> return it
            *ach_start_ret = adsl_gath->achc_ginp_cur;
            in_idx_first_not_delivered++;
            return (int)(adsl_gath->achc_ginp_end - adsl_gath->achc_ginp_cur);
        }
        adsl_gath = adsl_gath->adsc_next;
        in_counter_items++;
    } // while (( adsl_gath != NULL) && (in_counter_items <= in_idx_first_not_delivered) )

    return -1;
}


/*! \brief Get the next data
 *
 * @ingroup webserver
 *
 * get next available data block; returns true if this data are complete
 */
int ds_transaction::m_get_data(const char** ach_data_out, int* in_len_data_out, bool bo_do_decompression) {
	do {
		bool bo_ret = m_get_data_intern(ach_data_out, in_len_data_out);
		// reset variables
		//ach_start_pos = NULL;
		in_len_current = -1;

		// decompression
		// JF 22.06.10 Ticket[20167]: ALWAYS check the header 'Content-Encoding'. If there is an encoding, the data must be decoded. Therefore
		// the if ((ads_session->ads_config->in_settings & SETTING_ENABLE_COMPRESSION) != 0) was deleted
		if ( bo_do_decompression
			&& ((ads_session->dsc_http_hdr_in.in_content_encoding == ds_http_header::ien_ce_gzip)
			   || (ads_session->dsc_http_hdr_in.in_content_encoding == ds_http_header::ien_ce_deflate))
			&& (*in_len_data_out > 0) && (*ach_data_out != NULL) ) {

			ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
													"HIWSI763I: start decompression with encoding %d.",
													ads_session->dsc_http_hdr_in.in_content_encoding );
			int in = *in_len_data_out;
			const char* ach = *ach_data_out;
			// pass thru zlib
			int in_len = ads_session->dsg_zlib_decomp.m_do_work(ach, ach + in, false, false, true);
			if (in_len < 0) { // error during decompression
				ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
														"HIWSI762E: decompression failed with error %d.",
														in_len );
				*in_len_data_out = -1;
				*ach_data_out = NULL;
				return in_len;
			} 
			*in_len_data_out = ads_session->dsg_zlib_decomp.m_get_output_data(ach_data_out);
			if(*in_len_data_out <= 0)
				continue;
		}
		return bo_ret ? 1 : 0;
	} while(true);
}


/*! \brief Get internal data
 *
 * @ingroup webserver
 *
 * private
 * get next available data block; returns true if this data are complete
 */
bool ds_transaction::m_get_data_intern(const char** ach_data_out, int* in_len_data_out)
{
    if (ads_session->dsc_control.bo_data_until_close) { // all data until server closes the connection must be passed to client
        char* ach_start = NULL;
        int in_len_this_block = m_get_next_unprocessed_data(&ach_start, false);
        if ( (ach_start != NULL) && (in_len_this_block > -1) ) {
            *ach_data_out = ach_start;    
            m_mark_as_processed((char*)(ach_start + in_len_this_block));
            *in_len_data_out = in_len_this_block;
        }
        else { // no data available
            *ach_data_out = NULL;
            *in_len_data_out = -1;
        }

        if (ads_trans->boc_eof_server) { // webserver closed connection -> all data are processed now
            return true;
        }

        return false;
    }

	*ach_data_out = NULL;
	*in_len_data_out = -1;
    if (bo_resolve_from_chunked_format) { // chunked data from server
        int in_count_gathers = m_count_unprocessed_gather_items();

        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                             "HIWSI693I: bo_resolve_from_chunked_format; state: %d     in_count_gathers: %d",
                                             in_chunked_state, in_count_gathers );

        // we only return data if a chunked block (containing len-info / data / trailing CRLF) is complete
        // if there are more complete chunked blocks available in one gather-item, we only return the first one
        // because the blocks are seperated by (CRLF and len-info), so we cannot return contiguous blocks!!
        // get next unprocessed gather data
        char* ach_start = NULL;
        int in_len = m_get_next_unprocessed_data(&ach_start, false);
        if ( (ach_start == NULL) || (in_len < 0) ) {
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI458I: no more data...go back..." );
            return false; // wait for more data
        }

        const char * ach_current; // current reading position
        char ch_curr = 0x00; // current char
        char ch_prev; // previous char
		const char* ach_start_pos = NULL;
        ds_hstring hstr_chunked_len(ads_session->ads_wsp_helper, "");
        int in_current_gather = 0;
        while (in_len > -1) {
            in_current_gather++;
            ach_current = ach_start;
			const char* ach_end = (ach_start + in_len);
            while (ach_current < ach_end) {
                switch (in_chunked_state) {
                    case ien_st_read_chunked_size:    { // RFC 2616-3.6.1
                        // collect the length-info of chunked data; is terminated by CRLF
                        ch_prev = ch_curr;
                        ch_curr = *ach_current;
                        ach_current++;

                        if (ch_curr != 0x0a && ch_curr != 0x0d) { // 0x0D0x0A are terminators
                            hstr_chunked_len += ch_curr;
                        }

                        if (ch_curr == 0x0a && ch_prev == 0x0d) { // the chunked-len-info is detected
                            m_mark_as_processed(ach_current);

                            ads_session->ads_wsp_helper->m_logf( ied_sdh_log_info,
                                                                 "HIWSI559I: chunked-data size string (hex!): %.*s",
                                                                 hstr_chunked_len.m_get_len(), hstr_chunked_len.m_get_ptr() );
                            // get int of len-info
                            if (!hstr_chunked_len.m_to_int(&in_chunked_expected_len, 0, 16)) {
                                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                                                     "HIWSE568E: Invalid chunked-length-value: %.*s",
                                                                     hstr_chunked_len.m_get_len(), hstr_chunked_len.m_get_ptr() );
                                ads_trans->inc_return = DEF_IRET_END;  // close connection
                                return false;
                            }
                            
                            // reset variables, because we begin a new read
                            hstr_chunked_len.m_set("");
                            in_chunked_received_data_len = 0;
                            if (in_chunked_expected_len > 0) { // data will follow
                                ach_start_pos = ach_current;
                                in_len_current = 0;
                                in_chunked_state = ien_st_read_chunked_data;
                            }
                            else { // len is 0 -> 0x30 0x0d 0x0a 0x0d 0x0a signals end of chunked data
                                // Attention: we assume trailer to be empty (trailer is not supported!!
                                in_chunked_state = ien_st_wait_chunked_end;
                            }
                        }
                        break;
                    }
                    case ien_st_read_chunked_data:    { // RFC 2616-3.6.1
                        if (in_len_current == -1) {
                            ach_start_pos = ach_current;
                            in_len_current = 0;
                        }
                        // collect data
						int inl_read = in_chunked_expected_len - in_chunked_received_data_len;
						int inl_available = ach_end - ach_current;
						if(inl_read > inl_available)
							inl_read = inl_available;
						in_len_current += inl_read;
                        in_chunked_received_data_len += inl_read;
                        ach_current += inl_read;

                        if (in_chunked_received_data_len == in_chunked_expected_len) { // all announced data are read in
                            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI549I: all announced data are read in" );
                            m_mark_as_processed(ach_current);
                            *ach_data_out = ach_start_pos;
                            *in_len_data_out = in_len_current;
                            in_chunked_state = ien_st_read_chunked_datablock_end;
                        }
                        break;
                    }
				    case ien_st_read_chunked_datablock_end:    {
                        // we expect CRLF
                        ch_prev = ch_curr;
                        ch_curr = *ach_current;
                        ach_current++;

                        if (ch_curr == 0x0a && ch_prev == 0x0d) { // chunked datablock completly (with terminating CRLF) received
                            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                                                "HIWSI547I: chunked datablock completly (with terminating CRLF) received" );
                            m_mark_as_processed(ach_current);
                            in_chunked_state = ien_st_read_chunked_size;
							return false;
                        }
                        // JF 23.10.08 Ticket[16316]: CRLF, which closes one chunked block, is split to two gather items.
                        if ( (in_len == 1) // 0x0D at the end of the first gather (previous data are processed)
                            &&  (in_current_gather < in_count_gathers) ) { // more gathers are available -> we assume, that there are data inside the next gather (first byte must be 0x0A!)
                            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info,
                                                                "HIWSI548I: closing CRLF of chunked datablock is split to two gather-items" );
                            m_mark_as_processed(ach_current);
                        }                        
                        break;
                    }
                    case ien_st_wait_chunked_end:    { // receive terminating CRLF of chunked (we don't support TRAILER !!!)
                        // we expect another CRLF
                        ch_prev = ch_curr;
                        ch_curr = *ach_current;
                        ach_current++;

                        if (ch_curr == 0x0a && ch_prev == 0x0d) { // chunked data done
                            ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, "HIWSI546I: chunked data done" );

                            // mark gathers as processed (until the current position)
                            m_mark_as_processed(ach_current);
                            in_len_data_to_deliver = 0; // signals that all data are processed
                            bo_read_chunked_data_done = true; // signals that all data are processed

                            in_chunked_state = ien_st_read_chunked_size;

                            return true;
                        }
                        break;
                    }
                    default:
						break;
                } // switch (in_chunked_state)
            } //while (ach_current < (ach_start + in_len)) {

            //---------------------------
            // shall we read the next gather item ???
            //---------------------------

            if (in_current_gather < in_count_gathers) { // more gathers are available

                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_details,
                                                     "----new gather---  state: %d.",
                                                     in_chunked_state );

                // chunked data are only partly read -> put to output
                if (in_chunked_state == ien_st_read_chunked_data) { // we read data, which are continued ot terminated in the next gather-item -> return
                    if (in_len_current > 0) {
                        // JF 22.10.07 we must return the already read data
                        m_mark_as_processed(ach_current);
                        *ach_data_out = ach_start_pos;
                        *in_len_data_out = in_len_current;

                        return false; // it is senseless to read the next data (if they are available), because these data are not contiguous with the processed ones
                    }

                    // JF 22.10.07: when there are more input-gathers, which we read one after the other, we must reset here
                    if (in_len_current == 0) {
                        in_len_current = -1;
                    }
                }

                // read next gather
                ads_session->ads_wsp_helper->m_log( ied_sdh_log_details, "----read next gather---" );
                ////// JF 22.10.07: in case of more input gathers the counter incorrectly works  in_len = m_get_gather_by_index(in_current_gather+1, &ach_start);
                ////in_len = m_get_next_unprocessed_data(&ach_start, false);
                // JF 05.12.07: no attempt to solve following problem
                // len-info-string in first gather and according CRLF in next gather -> problem: the len-info-string-data are here not marked as processed
                // so that m_get_next_unprocessed_data() will process the len-info-string again
                // Attention: don't mark data as processed here, because the data can end here -> information then will be lost !!

// JF 31.03.11 Ticket[21758]
//                if (in_chunked_state == ds_control::ien_st_read_chunked_size) {
//                    in_len = m_get_gather_by_index(in_current_gather+1, &ach_start);
//                }
//                else {
                    // MJ org JF in_len = m_get_next_unprocessed_data(&ach_start, false);
                  in_len = m_get_next_unprocessed_data_off( &ach_start, ach_current );
//                }
            }
            else  { // no more data available
                if (in_chunked_state == ien_st_read_chunked_size) { // len-info not complete
                    ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                                        "HIWSE545E: len-info not complete in consecutive chunked blocks" );
                    return false;
                }

                // chunked data are only partly read -> put to output
                if (in_chunked_state == ien_st_read_chunked_data) { // we read data, which are continued ot terminated in the next gather-item -> return
                    // mark gathers as processed (until the current position)
                    m_mark_as_processed(ach_current);
                    *ach_data_out = ach_start_pos;
                    if (in_len_current == 0) { // len-info is complete, but up to now no data are available
                        *ach_data_out = NULL;
                        in_len_current = -1; // signal that no data-byte was available
                    }
                    *in_len_data_out = in_len_current;
                    return false; // it is senseless to read the next data (if they are available), because these data are not contiguous with the processed ones
                }

                return false;
            }
        } // in_len > -1

        return false;
    }
    
    // content-length-data from server
    if (in_len_data_to_deliver <= 0) { // no data shall be delivered
        *ach_data_out = NULL;
        *in_len_data_out = -1;
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                            "HIWSE692E: No data to be delivered are announced." );
        return true;
    }

    char* ach_start = NULL;
    int in_len_this_block = m_get_next_unprocessed_data(&ach_start, false);
    if ( (ach_start != NULL) && (in_len_this_block > -1) ) {
        *ach_data_out = ach_start;    
        if (in_len_this_block >= in_len_data_to_deliver) { // this data-block contains all (or more than the) requested data
            m_mark_as_processed((char*)(ach_start + in_len_data_to_deliver));
            *in_len_data_out = in_len_data_to_deliver;
            in_len_data_to_deliver = 0;
            return true;
        }
        // this data-block contains not all requested data
        m_mark_as_processed((char*)(ach_start + in_len_this_block));
        *in_len_data_out = in_len_this_block;
        in_len_data_to_deliver -= in_len_this_block;
    }
    else { // no data available
        *ach_data_out = NULL;
        *in_len_data_out = -1;
    }
    return false;
}


/*! \brief Get a specific data item
 *
 * @ingroup webserver
 *
 * loop over all available gather-items
 * return the item (which contains an active pointer achc_ginp_cur) at the specified index-position in chain
 */
int ds_transaction::m_get_gather_by_index(int in_idx, char** ach_start_ret)
{ 
    struct dsd_gather_i_1 * adsl_gath = ads_trans->adsc_gather_i_1_in;
    *ach_start_ret = (char*)ads_trans->adsc_gather_i_1_in; // may be NULL here
    int in_counter_items = 0;
    while (adsl_gath != NULL) {
        if (adsl_gath->achc_ginp_cur < adsl_gath->achc_ginp_end) { // this is the first gather item, which is (at least partly) unprocessed -> return it
            in_counter_items++;
            if (in_counter_items == in_idx) {
                *ach_start_ret = adsl_gath->achc_ginp_cur;
                return (int)(adsl_gath->achc_ginp_end - adsl_gath->achc_ginp_cur);
            }
        }
        adsl_gath = adsl_gath->adsc_next;
    } // while (adsl_gath != NULL) {

    return -1;
}


/*! \brief Get the next unprocessed data from a chain
 *
 * @ingroup webserver
 *
 * loop over all available gather-items
 * return the first item, which contains an active pointer achc_ginp_cur
 */
int ds_transaction::m_get_next_unprocessed_data(char** ach_start_ret, bool bo_change_gather_counter)
{ 
    struct dsd_gather_i_1 * adsl_gath = ads_trans->adsc_gather_i_1_in;
    *ach_start_ret = NULL;
    int in_counter_items = 0;
    while (adsl_gath != NULL) {
        if (adsl_gath->achc_ginp_cur < adsl_gath->achc_ginp_end) { // this is the first gather item, which is (at least partly) unprocessed -> return it
            *ach_start_ret = adsl_gath->achc_ginp_cur;
            if (bo_change_gather_counter) {
                in_idx_first_not_delivered = in_counter_items + 1;
            }
            return (int)(adsl_gath->achc_ginp_end - adsl_gath->achc_ginp_cur);
        }
        adsl_gath = adsl_gath->adsc_next;
        in_counter_items++;
    } // while (adsl_gath != NULL) {

    return -1;
}


/*! \brief Reads chunked information
 *
 * @ingroup webserver
 *
 * public function ds_transaction::m_get_next_unprocessed_data_off
 *  this function tries to fix problems in webserver while reading
 *  chunked length information, which is splited in multiple gathers
 *
 * @param[out]  char    **aachp_start           start of next data block
 * @param[in]   char    *achp_offset            go over this data if there is some
 * @return      int                             length of found data block
 *                                              -1 if nothing found
*/
int ds_transaction::m_get_next_unprocessed_data_off( char **aachp_start, const char *achp_offset )
{
    struct dsd_gather_i_1 *adsl_gather;
    
    adsl_gather = ads_trans->adsc_gather_i_1_in;
    while ( adsl_gather != NULL ) {
        if ( adsl_gather->achc_ginp_cur < adsl_gather->achc_ginp_end ) {
            if ( achp_offset == adsl_gather->achc_ginp_end ) {
                if ( adsl_gather->adsc_next != NULL ) {
                    adsl_gather = adsl_gather->adsc_next;
                } else {
                    *aachp_start = NULL;
                    return -1;
                }
            }
            *aachp_start = adsl_gather->achc_ginp_cur;
            return (int)(adsl_gather->achc_ginp_end - adsl_gather->achc_ginp_cur);
        }
        adsl_gather = adsl_gather->adsc_next;
    }
    *aachp_start = NULL;
    return -1;
} // end of ds_transaction::m_get_next_unprocessed_data_off


/*! \brief Counts remaining data chunks
 *
 * @ingroup webserver
 *
 * loop over all gather-items and count the unprocessed gather-items
 */
int ds_transaction::m_count_unprocessed_gather_items()
{
    struct dsd_gather_i_1 * adsl_gath = ads_trans->adsc_gather_i_1_in;
    int in_count = 0;
    while (adsl_gath != NULL) {
        if (adsl_gath->achc_ginp_cur < adsl_gath->achc_ginp_end) { // JF 04.09.07
            in_count++;
        }
        adsl_gath = adsl_gath->adsc_next;
    } // while (adsl_gath != NULL) {

    return in_count;
}


/*! \brief Counts unprocessed data
 *
 * @ingroup webserver
 *
 * loop over all gather-items and count the unprocessed data
 */
int ds_transaction::m_count_unprocessed_data()
{
    struct dsd_gather_i_1 * adsl_gath = ads_trans->adsc_gather_i_1_in;
    int in_count = 0;
    while (adsl_gath != NULL) {
        if (adsl_gath->achc_ginp_cur < adsl_gath->achc_ginp_end) { // this is the first gather item, which is (at least partly) unprocessed -> return it
            in_count = in_count + (int)(adsl_gath->achc_ginp_end - adsl_gath->achc_ginp_cur);
        }
        adsl_gath = adsl_gath->adsc_next;
    } // while (adsl_gath != NULL) {

    return in_count;
}

bool ds_transaction::m_has_unprocessed_data() {
	struct dsd_gather_i_1 * adsl_gath = ads_trans->adsc_gather_i_1_in;
	while (adsl_gath != NULL) {
		if (adsl_gath->achc_ginp_cur < adsl_gath->achc_ginp_end) { // this is the first gather item, which is (at least partly) unprocessed -> return it
			return true;
		}
		adsl_gath = adsl_gath->adsc_next;
	}
	return false;	
}

/*! \brief Get working mode
 *
 * @ingroup webserver
 *
 * returns the calling mode (e.g. DEF_IFUNC_START or DEF_IFUNC_FROMSERVER; defined in hob-xsclib01.h)
 */
int ds_transaction::m_get_callmode(void)
{
    return ads_trans->inc_func;
}


/*! \brief Tell WSP that we want to be called again
 *
 * @ingroup webserver
 *
 * set the flag boc_callagain; returns the updated flag
 */
bool ds_transaction::m_set_callagain(bool bo_new)
{
    ads_trans->boc_callagain = bo_new;
    return m_is_callagain();
}


/*! \brief Check if we will be called again
 *
 * @ingroup webserver
 *
 * returns true, when the flag boc_callagain is set
 */
bool ds_transaction::m_is_callagain(void)
{
    return (ads_trans->boc_callagain == TRUE);
}


/*! \brief Sets that we want to be called again, in reverse direction
 *
 * @ingroup webserver
 *
 * set the flag boc_callrevdir; returns the updated flag
 */
bool ds_transaction::m_set_callrevdir(bool bo_new)
{
    ads_trans->boc_callrevdir = bo_new;
    return m_is_callrevdir();
}


/*! \brief Checks if we get called again in reverted direction
 *
 * @ingroup webserver
 *
 * returns true, when the flag boc_callrevdir is set
 */
bool ds_transaction::m_is_callrevdir(void)
{
    return (ads_trans->boc_callrevdir==1?true:false); // JF: 04.05.09 false; we must not always return 'false'. This bug had no consequences, because the return value was not evaluated.
}


/*! \brief Check a setting
 *
 * @ingroup webserver
 *
 * function ds_transaction::m_check_setting
 * check if requested setting is set in our config
 *
 * @return  bool                true = setting is set
 *                              false otherwise
*/
bool ds_transaction::m_check_setting( int in_setting )
{
    if ((ads_session->ads_config->in_settings & in_setting) == in_setting ) {
        return true;
    }
    return false;
} // end of ds_transaction::m_check_setting



/*! \brief Open a TCP connection
 *
 * @ingroup wspcallback
 *
 * Asks the WSP to connect via TCP to another machine
 */
bool ds_transaction::m_tcp_connect(bool bo_https, const dsd_const_string& rhstr_host, int in_port, ds_hstring& ahstr_err_msg, dsd_const_string& rdsp_error_key)
{
    struct dsd_aux_tcp_conn_1 ds_tcp;
    memset(&ds_tcp, 0, sizeof(struct dsd_aux_tcp_conn_1));
#if 0
    ds_tcp.achc_server_ineta = ahstr_host->m_get_ptr();
#endif
    ds_tcp.dsc_target_ineta.ac_str      = const_cast<char*>(rhstr_host.m_get_ptr());
    ds_tcp.dsc_target_ineta.imc_len_str = rhstr_host.m_get_len();

	// TODO: change to ied_chs_uri because of umlaut-encoding
    ds_tcp.dsc_target_ineta.iec_chs_str = ied_chs_utf_8;

    ds_tcp.imc_server_port = in_port;
    if (bo_https) { // for https to the webserver
        ds_tcp.dsc_aux_tcp_def.ibc_ssl_client = 1;
    }

    ds_hstring hstr(ads_session->ads_wsp_helper, "HIWSI410I: Connecting to ");
    hstr.m_write(rhstr_host);
    hstr.m_write(":");
    hstr += in_port;
    if (bo_https) {
        hstr.m_write(" (with SSL)");
    }
#ifdef _DEBUG
    ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, hstr.m_const_str() );
#else
    ads_session->ads_wsp_helper->m_log( ied_sdh_log_info, hstr.m_const_str() );
#endif

    bool bol1 = ads_session->ads_wsp_helper->m_cb_tcp_connect( &ds_tcp );
#if 0
    ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                            "m_cb_tcp_connect: host=%.*s ads_session=%p",
                                            rhstr_host.m_get_len(), rhstr_host.m_get_ptr(),
											ads_session);
	if(rhstr_host.m_equals("aep.emea.mxptint.net"))
		ads_session->boc_watch_session = true;
#endif
    if ( bol1 == false )
	{
        ahstr_err_msg.m_set("HIWSE410E: ");
        const char* ach_msg;
        int   in_len_msg;
        rdsp_error_key = MSG_SERVER_UNREACHABLE;
        GET_RES( MSG_SERVER_UNREACHABLE, ach_msg, in_len_msg );
        ahstr_err_msg.m_write( ach_msg, in_len_msg );
        ahstr_err_msg.m_write(" ");
        ahstr_err_msg.m_write((bo_https ? dsd_const_string("https://") : dsd_const_string("http://")));
        ahstr_err_msg.m_write(rhstr_host);
        ahstr_err_msg.m_write(":");
        ahstr_err_msg.m_write_int(in_port);
        if (ds_tcp.iec_tcpconn_ret != (ied_tcpconn_ret)ied_tcr_ok) {
            ahstr_err_msg.m_write(" (");
            GET_RES( MSG_ERROR, ach_msg, in_len_msg );
            ahstr_err_msg.m_write( ach_msg, in_len_msg );
            ahstr_err_msg.m_writef(" %d): ", ds_tcp.iec_tcpconn_ret);
            if (ds_tcp.iec_tcpconn_ret == ied_tcr_no_ocos) { // no option connect-other-server configured
                ahstr_err_msg.m_write("No option connect-other-server configured.");
            }
            else if (ds_tcp.iec_tcpconn_ret == ied_tcr_no_cs_ssl) { // no CS_SSL defined
                rdsp_error_key = MSG_NO_CS_SSL;
                
                GET_RES( MSG_NO_CS_SSL, ach_msg, in_len_msg );
                ahstr_err_msg.m_write( ach_msg, in_len_msg );
            }
            // Ticket[12029]: the access was denied by target filtering (WSP-output: 'thru target filter INETA' or 'thru target filter DNS')
            else if (ds_tcp.iec_tcpconn_ret == ied_tcr_denied_tf) { 
                rdsp_error_key = MSG_TARGET_FILTER;
                GET_RES( MSG_TARGET_FILTER, ach_msg, in_len_msg );
                ahstr_err_msg.m_write( ach_msg, in_len_msg );
            }
			else if (ds_tcp.iec_tcpconn_ret == ied_tcr_hostname) { // JF 06.08.10 
				ahstr_err_msg.m_write("Host name not in DNS.");
			}
			else if (ds_tcp.iec_tcpconn_ret == ied_tcr_no_route) { // JF 06.08.10
				ahstr_err_msg.m_write("No route to host.");
			}
            else if (ds_tcp.iec_tcpconn_ret == ied_tcr_refused) { // JF 06.08.10
				ahstr_err_msg.m_write("Connection refused.");
			}
            else if (ds_tcp.iec_tcpconn_ret == ied_tcr_timeout) { // JF 06.08.10
				ahstr_err_msg.m_write("Connection timed out.");
			}
            // this error can also be returned, when target filter denied the access! comment of KB: 'other error';
            else if (ds_tcp.iec_tcpconn_ret == ied_tcr_error) {
                ahstr_err_msg.m_write("Connection failed with 'other error'.");
            }
        }
        ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                             "%.*s (Attention: sending-direction in this case is  'TO CLIENT')",
                                             ahstr_err_msg.m_get_len(), ahstr_err_msg.m_get_ptr() );
        return false;
    }
    return true;
}


/*! \brief Marks data as processed
 *
 * @ingroup webserver
 *
 * mark how far the received data are processed
 * ach_processed_til_here = NULL means: "clear the whole input"
 */
bool ds_transaction::m_mark_as_processed(const char* ach_processed_til_here)
{
    if (ach_processed_til_here == NULL) {
        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                            "HIWSE013E: Clear all outstanding input gathers." ); // JF 23.03.11 HIWSE13E -> HIWSE013E
    }

    struct dsd_gather_i_1* adsl_gather_tmp = ads_trans->adsc_gather_i_1_in;
    // loop over all gathers and check, whether the pointer is inside one of those gather-items
    struct dsd_gather_i_1* adsl_gather_found = NULL;
    if (ach_processed_til_here != NULL) {
        while (adsl_gather_tmp) {
            if ( (ach_processed_til_here >= adsl_gather_tmp->achc_ginp_cur) &&
                 (ach_processed_til_here <= adsl_gather_tmp->achc_ginp_end) ) {
                     adsl_gather_found = adsl_gather_tmp;
                     break;
            }
            adsl_gather_tmp = adsl_gather_tmp->adsc_next;
        }

        if (adsl_gather_found == NULL) {
            ads_session->ads_wsp_helper->m_log( ied_sdh_log_error,
                                                "HIWSE221E: m_mark_as_processed cannot find position\n" );
            return false;
        }
    }
    
    adsl_gather_tmp = ads_trans->adsc_gather_i_1_in;
    while (adsl_gather_tmp) { // loop over all gathers
        if (ach_processed_til_here != NULL) {
            if (adsl_gather_tmp == adsl_gather_found) { // item found, which contains ach_processed_til_here -> mark as processed until there
                if ( (ach_processed_til_here >= adsl_gather_tmp->achc_ginp_cur) &&
                     (ach_processed_til_here <= adsl_gather_tmp->achc_ginp_end) ) { // ensure, that we are at correct position
                         adsl_gather_tmp->achc_ginp_cur = (char*)ach_processed_til_here;  // processed till here
                         break;
                }
            }
        }
        adsl_gather_tmp->achc_ginp_cur = adsl_gather_tmp->achc_ginp_end; // mark whole item as processed
        adsl_gather_tmp = adsl_gather_tmp->adsc_next;
    }

    return true;
}


/*! \brief Close connection
 *
 * @ingroup webserver
 *
 * set a flag, which tells WSP to close the TCP-connection
 */
int ds_transaction::m_close_connection(void)
{
    ads_trans->inc_return = DEF_IRET_END;
    return ads_trans->inc_return;
}


/*! \brief Collect data
 *
 * @ingroup webserver
 *
 * collect data of several gather-items to a contiguous memory
 * return 0 means not an error; we must wait for more data
 */
int ds_transaction::m_get_linear_data(char* ach_memory, int in_len_memory, bool bol_mark_as_processed )
{
    char* ach_start = NULL;
    int in_len_this_block = m_get_next_unprocessed_data(&ach_start);
    int in_copied = 0;
    if ( (ach_start != NULL) && (in_len_this_block > -1) ) {
        if (in_len_this_block >= in_len_memory) { // this data-block contains all (or more than the) requested data -> copy requested len of data
            memmove(ach_memory, ach_start, in_len_memory);
            if ( bol_mark_as_processed == true ) {
                m_mark_as_processed((char*)(ach_start + in_len_memory));
            }
            return in_len_memory;
        }

        // this data-block contains NOT ALL requested data -> we must collect more
        memmove(ach_memory, ach_start, in_len_this_block);
        in_copied += in_len_this_block;

        char* ach_temp = ach_memory + in_len_this_block;
        int in_expected = in_len_memory - in_len_this_block;
        while (in_expected > 0) { 
            ds_datablock ds_data = m_get_next_block();
            if (ds_data.m_get_length() == -1) { // no input-data...
                return 0; // not an error; we must wait for more data
            }
            else if (ds_data.m_get_length() < in_expected) { // data are not complete
                memmove(ach_temp, ds_data.m_get_start(), ds_data.m_get_length());
                in_copied += ds_data.m_get_length();
                ach_temp += ds_data.m_get_length();
                in_expected = in_expected - ds_data.m_get_length();
            }
            else if (ds_data.m_get_length() >= in_expected) { // data are complete
                memmove(ach_temp, ds_data.m_get_start(), in_expected);
                in_copied += in_expected;
                if ( bol_mark_as_processed == true ) {
                    m_mark_as_processed((char*)(ds_data.m_get_start() + in_expected));
                }
                return in_copied;
            }
        }
    }

    return 0;
}

static bool m_gatherpos_skip(ds_wsp_helper::dsd_gather_pos& rdsp_pos, int inp_nbytes) {
	if(inp_nbytes <= 0)
		return true;
	dsd_gather_i_1* adsl_cur = rdsp_pos.adsc_gai1;
	char* achl_pos = rdsp_pos.achl_ptr;
	while(adsl_cur != NULL) {
		int inl_rest = adsl_cur->achc_ginp_end - achl_pos;
		if(inl_rest >= inp_nbytes) {
			rdsp_pos.adsc_gai1 = adsl_cur;
			rdsp_pos.achl_ptr = achl_pos + inp_nbytes;
			return true;
		}
		inp_nbytes -= inl_rest;
		adsl_cur = adsl_cur->adsc_next;
		if(adsl_cur == NULL)
			return false;
		achl_pos = adsl_cur->achc_ginp_cur;
	}
	return false;
}

static bool m_gatherpos_copy(ds_wsp_helper::dsd_gather_pos& rdsp_pos, const char* achp_src, int inp_nbytes) {
	if(inp_nbytes <= 0)
		return true;
	dsd_gather_i_1* adsl_cur = rdsp_pos.adsc_gai1;
	char* achl_pos = rdsp_pos.achl_ptr;
	while(adsl_cur != NULL) {
		int inl_rest = adsl_cur->achc_ginp_end - achl_pos;
		if(inl_rest >= inp_nbytes) {
			memcpy(achl_pos, achp_src, inp_nbytes);
			rdsp_pos.adsc_gai1 = adsl_cur;
			rdsp_pos.achl_ptr = achl_pos + inp_nbytes;
			return true;
		}
		memcpy(achl_pos, achp_src, inl_rest);
		achp_src += inl_rest;
		inp_nbytes -= inl_rest;
		adsl_cur = adsl_cur->adsc_next;
		if(adsl_cur == NULL)
			return false;
		achl_pos = adsl_cur->achc_ginp_cur;
	}
	return false;
}

/*! \brief update chunked
 *
 * @ingroup webserver
 *
 * private
 * update chunked data len info
 */
bool ds_transaction::m_update_chunked_len(int in_len_to_add)
{
    in_len_chunked_out += in_len_to_add; // current length of chunked data

    char ach_hex[in_len_chunked_placeholder];
    memset(ach_hex, 0, in_len_chunked_placeholder);
#if defined WIN32 || defined WIN64
    itoa(in_len_chunked_out, ach_hex, 16);
    int in_len_hex = strlen(ach_hex);
#else
    int in_len_hex = snprintf(ach_hex, sizeof(ach_hex), "%x", in_len_chunked_out);
#endif // defined WIN32 || defined WIN64

	 int inl_offset = in_len_chunked_placeholder-3-in_len_hex+1;
#if SM_USE_PLACEHOLDER_V2
	 ds_wsp_helper::dsd_gather_pos dsl_pos;
	 dsl_pos.adsc_gai1 = this->ads_gather_data;
	 dsl_pos.achl_ptr = this->ach_placeholder_wa;
	 if(!m_gatherpos_skip(dsl_pos, inl_offset))
		 return false;
	 if(!m_gatherpos_copy(dsl_pos, ach_hex, in_len_hex))
		 return false;
#else
    ads_session->ads_wsp_helper->m_send_replace(in_pos_placeholder_chunked+inl_offset, ach_hex, in_len_hex);
#endif
    return true;
}

bool ds_transaction::m_must_compress() const {
	// compression
    if ((ads_session->ads_config->in_settings & SETTING_ENABLE_COMPRESSION) != 0
        && ads_session->dsc_http_hdr_out.bo_hdr_gzip_set
        && ((ads_session->dsg_state.in_accept_encoding & ds_http_header::ien_ce_gzip) == ds_http_header::ien_ce_gzip))
		return true;
	return false;
}

void ds_transaction::m_begin_chunked()
{
	this->bo_send_chunked = true;
}

/*! \brief Writes data to workarea
 *
 * @ingroup webserver
 *
 * public method; envelops resetting of variables
 * the data will be put to workarea; if workarea is full the data will be queued
 */
int ds_transaction::m_write_as_chunked(const char* ach_to_send, int in_len_to_send,
    bool bop_copy_data, enum ied_sdh_data_direction ienp_direction, bool bo_allow_compress, bool bop_eof)
{
	 if(!this->bo_send_chunked)
		 return -1;

    // compression
    if (bo_allow_compress && this->m_must_compress())
    {
        // don't write to log, because this will be called very often during processing a file by interpreter-classes
        const char* ach_to_send_end = (ach_to_send + in_len_to_send);
        do {
            // pass thru zlib
            //bool bol_eof = bop_eof && ach_to_send >= ach_to_send_end;
            int in_len_compr_in = ads_session->dsg_zlib_comp.m_do_work(ach_to_send, ach_to_send_end, true, bop_eof, false);
            if (in_len_compr_in < 0) { // error during compression
                ads_session->ads_wsp_helper->m_logf( ied_sdh_log_error,
                                                     "HIWSI587E: compression failed with error %d",
                                                     in_len_compr_in );
                return -1;
            }
            const char* strl_zlib_out;
            int in_len_compr_out = ads_session->dsg_zlib_comp.m_get_output_data(&strl_zlib_out);
            if(in_len_compr_out == 0)
                break;
            int in_ret = m_write_chunked(strl_zlib_out, in_len_compr_out, true, ienp_direction);
            // reset variables
            //ach_start_pos = NULL;
            in_len_current = -1;
            if(in_ret < 0)
                return -1;

            ach_to_send += in_len_compr_in;
            if(!bop_eof && ach_to_send >= ach_to_send_end)
                break;
        } while(!ads_session->dsg_zlib_comp.m_finished(true));

        if(bop_eof)
            ads_session->dsg_zlib_comp.m_reset();
        return 1;
    }

    int in_ret = m_write_chunked(ach_to_send, in_len_to_send, bop_copy_data, ienp_direction);
    // reset variables
    //ach_start_pos = NULL;
    in_len_current = -1;
    if(in_ret < 0)
        return -1;
    
    return in_ret;
}


/*! \brief Write chunked
 *
 * @ingroup webserver
 *
 * private
 * working function
 * the data will be put to workarea; if workarea is full the data will be queued
 */

int ds_transaction::m_write_chunked(const char* ach_to_send, int in_len_to_send, bool bop_copy_data, enum ied_sdh_data_direction ienp_direction)
{
    if ( (ach_to_send == NULL) || (in_len_to_send <= 0) ) {
        return -1;
    }

    // write placeholder for chunked-length-info
    if (!bo_placeholder_written) {
#if !SM_USE_PLACEHOLDER_V2
        // determine the end of the http-header (is the end of the first gather)
        struct dsd_gather_i_1 *adsl_out;
        adsl_out = (ads_trans->adsc_gai1_out_to_client != NULL) ? ads_trans->adsc_gai1_out_to_client
                                                                : ads_trans->adsc_gai1_out_to_server;
        if ( adsl_out != NULL ) {
            in_pos_placeholder_chunked = ads_session->ads_wsp_helper->m_get_gather_len(adsl_out);
        }
        else {
            in_pos_placeholder_chunked = 0;
        }
#endif
        // prepare placeholder for hex-string-representation of len-info
        char ach_hex_placeholder[in_len_chunked_placeholder];
        memset(ach_hex_placeholder, 0x30, in_len_chunked_placeholder);
        memmove(ach_hex_placeholder+in_len_chunked_placeholder-strlen(CRLF), CRLF, strlen(CRLF));

		  ds_wsp_helper::dsd_gather_pos dsl_pos;
		  if (!ads_session->ads_wsp_helper->m_send_data(ach_hex_placeholder, in_len_chunked_placeholder, true, ienp_direction, dsl_pos)) {
			  return -2;
		  }
#if SM_USE_PLACEHOLDER_V2
		  this->ach_placeholder_wa = dsl_pos.achl_ptr;
		  this->ads_gather_data = dsl_pos.adsc_gai1;
#endif
	     // write placeholder into wa
        //m_send(ach_hex_placeholder, in_len_chunked_placeholder, true, ied_sdh_dd_auto);
        bo_placeholder_written = true;
    }
    //------------------------
    // write the real data
    //------------------------
    m_update_chunked_len(in_len_to_send); // update len-info
    m_send(ach_to_send, in_len_to_send, bop_copy_data, ienp_direction);
    return 1;
} // m_write_as_chunked

#if 0
/*! \brief Send data
 *
 * @ingroup webserver
 */
int ds_transaction::m_send(const char* ach_to_send_zero, enum ied_sdh_data_direction ienp_direction) {
    return m_send(ach_to_send_zero, strlen(ach_to_send_zero), true, false, ienp_direction);
}
#endif

#if 0
/*! \brief Send data
 *
 * @ingroup webserver
 *
 * the data will be put to workarea; if workarea is full the data will be queued
 */
int ds_transaction::m_send(const ds_hstring* ahstr_to_send, bool bo_allow_chunked, enum ied_sdh_data_direction ienp_direction)
{
    return m_send(ahstr_to_send->m_get_ptr(), ahstr_to_send->m_get_len(), true, bo_allow_chunked, ienp_direction);
}
#endif

/*! \brief Send file
 *
 * @ingroup webserver
 */
int ds_transaction::m_send_complete_file(const ds_hstring* ahstr_file, enum ied_sdh_data_direction ienp_direction) {
    return m_send_complete_file(ahstr_file->m_get_ptr(), ahstr_file->m_get_len(), true, ienp_direction);
}


/*! \brief Sends a whole file
 *
 * @ingroup webserver
 *
 * function ds_transaction::m_send_complete_file
 * Write a complete file into workarea. The according http-header is already written to workarea.
 * If defined in http-header the data can get chunked. In case of chunk, the data can additionally be compressed.
 * If workarea is too small, a new workarea will be setup. The data will be sent by WSP, when we return to WSP.
 *
 * @param[in]   char*   ach_file_to_send      data to send
 * @param[in]   int     in_len_to_send        length of data
 * @return      int                           negative = error; 0 = success
*/
int ds_transaction::m_send_complete_file(const char* ach_file_to_send, int in_len_file_to_send, bool bop_copy_data, enum ied_sdh_data_direction ienp_direction) {
    if ( (ach_file_to_send == NULL) || (in_len_file_to_send <= 0) ) {
        return -1;
    }

    if (ads_session->dsc_http_hdr_out.bo_hdr_chunked_set) {
        // terminate chunked format
		int in_ret = this->m_write_as_chunked(ach_file_to_send, in_len_file_to_send, bop_copy_data, ienp_direction, true, true);
		if(in_ret < 0)
			return in_ret;
        in_ret = this->m_send_chunked_end(ienp_direction);
        //ads_session->dsg_zlib_comp.m_reset();
        return in_ret;
    }

#if 0
    const char* ach_file_to_send_cur = ach_file_to_send;
    const char* ach_file_to_send_end = ach_file_to_send + in_len_file_to_send;
    bool bol_copy = bop_copy_data;
    while(ach_file_to_send_cur < ach_file_to_send_end) {
        int inl_len = ach_file_to_send_end - ach_file_to_send_cur;
        if(inl_len > 256)
            inl_len = 256;
        if (!ads_session->ads_wsp_helper->m_send_data(ach_file_to_send_cur, inl_len, !bop_copy_data ? bol_copy : true, ienp_direction)) {
            return -2;
        }
        ach_file_to_send_cur += inl_len;
        bol_copy = !bol_copy;
    }
#else
    ds_wsp_helper::dsd_gather_pos dsl_pos;
	 if (!ads_session->ads_wsp_helper->m_send_data(ach_file_to_send, in_len_file_to_send, bop_copy_data, ienp_direction, dsl_pos)) {
        return -2;
    }
#endif
    return 0;
}

int ds_transaction::m_send_data(const dsd_const_string& rdsp_data, enum ied_sdh_data_direction ienp_direction) {
	if ( rdsp_data.m_get_len() <= 0 ) {
        return -1;
    }

    if ( ads_session->dsc_http_hdr_out.bo_hdr_chunked_set ) {  // chunked format is announced in http header
		int in_ret = m_write_as_chunked(rdsp_data.m_get_ptr(), rdsp_data.m_get_len(), true, ienp_direction, true, false);
        return in_ret;
    }

    ds_wsp_helper::dsd_gather_pos dsl_pos;
	 if (!ads_session->ads_wsp_helper->m_send_data(rdsp_data.m_get_ptr(), rdsp_data.m_get_len(), true, ienp_direction, dsl_pos)) {
        return -2;
    }
    return 0;
}

/*! \brief Sends data
 *
 * @ingroup webserver
 *
 * function ds_transaction::m_send
 * Write out data into workarea. If workarea is too small, a new workarea will be setup. The data will be sent by WSP, when we return to WSP.
 *
 * @param[in]   char*   ach_to_send           data to send
 * @param[in]   int     in_len_to_send        length of data
 * @return      int                           negative = error; 0 = success
*/
int ds_transaction::m_send(const char* ach_to_send, int in_len_to_send, bool bop_copy_data, enum ied_sdh_data_direction ienp_direction)
{
    if ( (ach_to_send == NULL) || (in_len_to_send <= 0) ) {
        return -1;
    }

	 ds_wsp_helper::dsd_gather_pos dsl_pos;
    if (!ads_session->ads_wsp_helper->m_send_data(ach_to_send, in_len_to_send, bop_copy_data, ienp_direction, dsl_pos)) {
        return -2;
    }
    return 0;
}


/*! \brief Send a header
 *
 * @ingroup webserver
 */
int ds_transaction::m_send_header(enum ied_sdh_data_direction ienp_direction)
{
    //ads_session->dsg_zlib_decomp.m_reset();
    //ads_session->dsg_zlib_comp.m_reset();
    return m_send(ads_session->dsc_http_hdr_out.hstr_hdr_out.m_get_ptr(), ads_session->dsc_http_hdr_out.hstr_hdr_out.m_get_len(), true, ienp_direction);
}

int ds_transaction::m_send_chunked_flush(enum ied_sdh_data_direction ienp_direction)
{
    if(!this->ads_session->dsc_http_hdr_out.bo_hdr_chunked_set)
        return -1;
    if(!this->bo_placeholder_written)
        return 0;
    dsd_const_string hstr_chunked_end(CRLF);
    bool bol_res = this->ads_session->ads_wsp_helper->m_send_data(hstr_chunked_end.m_get_ptr(), hstr_chunked_end.m_get_len(), ienp_direction);
    this->bo_placeholder_written = false;
    this->in_len_chunked_out = 0;
    if(!bol_res)
        return -1;
    return 1;
}

int ds_transaction::m_send_chunked_end(enum ied_sdh_data_direction ienp_direction)
{
    if(!this->ads_session->dsc_http_hdr_out.bo_hdr_chunked_set)
        return -1;
	 if(!this->bo_send_chunked) {
		  return -1;
	 }
	if(this->m_must_compress() && !ads_session->dsg_zlib_comp.m_finished(true)) {
		int in_ret = this->m_write_as_chunked(NULL, 0, true, ienp_direction, true, true);
		if(in_ret < 0)
			return in_ret;
		//ads_session->dsg_zlib_comp.m_reset();
	}
    // terminate chunked format
    dsd_const_string hstr_chunked_end1("0" CRLF CRLF);
    dsd_const_string hstr_chunked_end2(CRLF "0" CRLF CRLF);
    dsd_const_string hstr_chunked_end(this->bo_placeholder_written ? hstr_chunked_end2 : hstr_chunked_end1);
    bool bol_res = this->ads_session->ads_wsp_helper->m_send_data(hstr_chunked_end.m_get_ptr(), hstr_chunked_end.m_get_len(), ienp_direction);
    this->bo_placeholder_written = false;
    this->in_len_chunked_out = 0;
	 this->bo_send_chunked = false;
    if(!bol_res)
        return -1;
    return 1;
}

/*! \brief Send data unmodified
 *
 * @ingroup webserver
 *
 * pass data unchanged to browser or webserver
 */
int ds_transaction::m_pass_data(int in_len_data, bool bo_send, ds_hstring* ahstr_data)
{
    char* ach_start = NULL;
    int in_copied = 0;
    int in_len_this_block = m_get_next_unprocessed_data(&ach_start);
    if (in_len_this_block < 1) {
        return 0; // we must wait for more data
    }

    // at least one block is available
    if ( (ach_start != NULL) && (in_len_this_block >= 0) ) {
        if (in_len_this_block >= in_len_data) { // this data-block contains all (or more than the) requested data -> write pointers of data into wa
            if (bo_send) {
                if (ahstr_data != NULL) {
                    ahstr_data->m_write(ach_start, in_len_data);
                }
                if (!ads_session->ads_wsp_helper->m_send_data(ach_start, in_len_data)) { // an error occurred -> WHAT TODO
                    ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE626E: sending data failed." );
                    return -1;
                }
            }
            m_mark_as_processed((char*)(ach_start + in_len_data));
            return in_len_data;
        }
        // this data-block contains NOT ALL requested data -> we must collect more
        if (bo_send) {
            if (ahstr_data != NULL) {
                ahstr_data->m_write(ach_start, in_len_this_block);
            }
            if (!ads_session->ads_wsp_helper->m_send_data(ach_start, in_len_this_block)) { // an error occurred -> WHAT TODO
                ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE627E: sending data failed." );
                return -1;
            }
        }
        m_mark_as_processed((char*)(ach_start + in_len_this_block));
        in_copied += in_len_this_block;

        int in_expected = in_len_data - in_len_this_block;
        while (in_expected > 0) { 
            ds_datablock ds_data = m_get_next_block();
            if (ds_data.m_get_length() == -1) { // no input-data...
                return in_copied; // not an error; we must wait for more data
            }
            else if (ds_data.m_get_length() >= in_expected) { // data are complete
                if (bo_send) {
                    if (ahstr_data != NULL) {
                        ahstr_data->m_write(ds_data.m_get_start(), in_expected);
                    }
                    if (!ads_session->ads_wsp_helper->m_send_data(ds_data.m_get_start(), in_expected)) { // an error occurred -> WHAT TODO
                        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE639E: sending data failed." );
                        return -1;
                    }
                }
                in_copied += in_expected;
                m_mark_as_processed((char*)(ds_data.m_get_start() + in_expected));
                return in_copied;
            }
            else if (ds_data.m_get_length() < in_expected) { // data are not complete
                if (bo_send) {
                    if (ahstr_data != NULL) {
                        ahstr_data->m_write(ds_data.m_get_start(), ds_data.m_get_length());
                    }
                    if (!ads_session->ads_wsp_helper->m_send_data(ds_data.m_get_start(), ds_data.m_get_length())) { // an error occurred -> WHAT TODO
                        ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE628E: sending data failed." );
                        return -1;
                    }
                }
                m_mark_as_processed((char*)(ds_data.m_get_start() + ds_data.m_get_length()));
                in_copied += ds_data.m_get_length();
                in_expected = in_expected - ds_data.m_get_length();
            }
        }
    }

    return in_copied;
}


/*! \brief Passes all data
 *
 * @ingroup webserver
 *
 * pass all data, which are in input
 * 27.01.09 return the count of passed data (JF)
 */
int ds_transaction::m_pass_all_available_data(bool bo_send)
{
    int in_count = 0;
    ds_datablock ds_data = m_get_next_unprocessed_block();
    while (ds_data.m_get_length() != -1) {
        in_count += ds_data.m_get_length();
        if (bo_send) { // JF 23.04.10
            ds_wsp_helper::dsd_gather_pos dsl_pos;
				if (!ads_session->ads_wsp_helper->m_send_data(ds_data.m_get_start(), ds_data.m_get_length(), false, ied_sdh_dd_auto, dsl_pos)) {
                ads_session->ads_wsp_helper->m_log( ied_sdh_log_error, "HIWSE328E: sending data failed." );
                return -1;
            }
        }
        m_mark_as_processed((char*)(ds_data.m_get_start() + ds_data.m_get_length()));
        ds_data = m_get_next_unprocessed_block();
    }
    return in_count; // JF 27.01.09 0
}


/*! \brief Get next unprocessed block
 *
 * @ingroup webserver
 */
ds_datablock ds_transaction::m_get_next_unprocessed_block(void)
{
    ds_datablock ds_ret;
    char* ach_start = NULL;
    int in_len = m_get_next_unprocessed_data(&ach_start, false);
    if ( (ach_start != NULL) && (in_len > -1) ) {
        ds_ret.m_set_start(ach_start);
        ds_ret.m_set_end(ach_start + in_len);
    }
    return ds_ret;
}
