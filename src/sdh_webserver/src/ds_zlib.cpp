#include <stdio.h>

#if defined WIN32 || defined WIN64
    #include <winsock2.h>
    #include <Ws2tcpip.h>
    #include <windows.h>
#endif
#include "ds_zlib.h"

#ifdef USED_BY_SDH
#include "ds_session.h"
#else
static BOOL m_cdaux( void *, int, void *, int );
#endif // USED_BY_SDH


ds_zlib::ds_zlib():in_len_out_buffer_default(32768)
{
    ach_output_start = NULL; // ensure that there is nothing
    memset( &dss_cf, 0, sizeof(dss_cf) );

    in_len_out_buffer = in_len_out_buffer_default;

    m_reset();
}

ds_zlib::~ds_zlib(void)
{
    if (ach_output_start != NULL) {
#ifdef USED_BY_SDH
        ads_session->ads_wsp_helper->m_cb_free_memory(ach_output_start, in_len_out_buffer);
#else
        delete[] ach_output_start;
#endif // USED_BY_SDH
    }
}

#ifdef USED_BY_SDH
/*! \brief Init the class
 *
 * @ingroup creator
 *
 * Initializes the class
 */
void ds_zlib::m_init1(/*MJ dsd_hl_clib_1 * ads_trans_in,*/ ds_session* ads_session_in)
{
//MJ    ads_trans = ads_trans_in;
    ads_session = ads_session_in;
}
#endif // USED_BY_SDH

/*! \brief Resets the class
 *
 * @ingroup creator
 */
int ds_zlib::m_reset(void)
{
    bo_init_done = false;
    return 0;
}

/*! \brief Create buffer for output
 *
 * @ingroup creator
 */
int ds_zlib::m_create_out_buffer(int in_len, bool bo_reset)
{
#ifdef USED_BY_SDH
    char* ach_new = ads_session->ads_wsp_helper->m_cb_get_memory(in_len, false);
#else
    char* ach_new = new char[in_len];
#endif // USED_BY_SDH
    size_t in_len_old = 0;

    if (ach_output_start != NULL) {
        // copy existing output to new one and delete old buffer
        in_len_old = (ach_output_end - ach_output_start);
        if (!bo_reset) {
            memcpy(ach_new, ach_output_start, in_len_old);
        }
#ifdef USED_BY_SDH
        ads_session->ads_wsp_helper->m_cb_free_memory(ach_output_start, (int)in_len_old);
#else
        delete[] ach_output_start;
#endif // USED_BY_SDH
    }

    ach_output_start = ach_new;
    ach_output_end = (char*)(ach_output_start + in_len);

    if (bo_reset) {
		dss_cf.achc_outa = ach_output_start;
	    dss_cf.achc_oute = ach_output_end;
        //m_setup_zlib_buffers(NULL, NULL, ach_output_start, ach_output_end);
    }
    else {
		dss_cf.achc_outa = ach_output_start + in_len_old;
	    dss_cf.achc_oute = ach_output_end;
        //m_setup_zlib_buffers(NULL, NULL, ach_output_start + in_len_old, ach_output_end);
    }

    return 0;
}

/*! \brief Setup the working buffers
 *
 * @ingroup creator
 */
int ds_zlib::m_setup_zlib_buffers(const char* ach_start_input, const char* ach_end_input, char* ach_out_curr, char* ach_out_end) {
    //if ( (ach_start_input != NULL) && (ach_end_input != NULL) ) {
        dss_cf.achc_inpa = const_cast<char*>(ach_start_input);
        dss_cf.achc_inpe = const_cast<char*>(ach_end_input);
    //}
    dss_cf.achc_outa = ach_out_curr;
    dss_cf.achc_oute = ach_out_end;
    return 0;
}

/*! \brief Initializes the class
 *
 * @ingroup creator
 */
int ds_zlib::m_init(const char* ach_start_input, const char* ach_end_input, bool bo_compress)
{
    in_len_out_buffer = in_len_out_buffer_default;
    m_create_out_buffer(in_len_out_buffer, true);

    dss_cf.inc_func = DEF_IFUNC_START;
    dss_cf.boc_eof = FALSE;
    m_setup_zlib_buffers(ach_start_input, ach_end_input, ach_output_start, ach_output_end);
#ifdef USED_BY_SDH
    dsd_hl_clib_1* ads_tmp = (dsd_hl_clib_1*)ads_session->ads_wsp_helper->m_get_structure();
    dss_cf.amc_aux     = ads_tmp->amc_aux;
    dss_cf.vpc_userfld = ads_tmp->vpc_userfld;
#else
    dss_cf.amc_aux = m_cdaux;
#endif // USED_BY_SDH

    // initialize
    if (bo_compress) {
        m_cd_enc( &dss_cf );
    }
    else {
        m_cd_dec( &dss_cf );
    }

    if (dss_cf.inc_return) {
#ifdef USED_BY_SDH
     ads_session->ads_wsp_helper->m_cb_printf_out("Error first call dss_cf.inc_return = %d\n", dss_cf.inc_return);
#else
        printf( "Error first call dss_cf.inc_return = %d\n", dss_cf.inc_return );
#endif
    }

    return dss_cf.inc_return;
}

/*! \brief Start to compress
 *
 * @ingroup creator
 */
int ds_zlib::m_do_work(const char* ach_start_input, const char* ach_end_input, bool bo_compress, bool bo_eof, bool bop_enlarge_buffer)
{
    if (!bo_init_done) {
        int in_ret = m_init(ach_start_input, ach_end_input, bo_compress);
        if (in_ret != 0) { // error
            return -100;
        }
        bo_init_done = true;
    }

    // always set input-buffers and reset output-buffers for this new input data
    m_setup_zlib_buffers(ach_start_input, ach_end_input, ach_output_start, ach_output_end);
#ifdef USED_BY_SDH
    dsd_hl_clib_1* ads_tmp = (dsd_hl_clib_1*)ads_session->ads_wsp_helper->m_get_structure();
	 dss_cf.boc_eof     = bo_eof;
	 dss_cf.amc_aux     = ads_tmp->amc_aux;
    dss_cf.vpc_userfld = ads_tmp->vpc_userfld;
#endif // USED_BY_SDH
    //char* achl_cur = dss_cf.achc_inpa;

    bool bo_go_on = true; // to keep compiler happy
    while (bo_go_on) {
        if (bo_compress) {
            m_cd_enc( &dss_cf );
        }
        else {
            m_cd_dec( &dss_cf );
        }

        if  ( (dss_cf.inc_return != DEF_IRET_NORMAL) && (dss_cf.inc_return != DEF_IRET_END) ) {
#ifdef USED_BY_SDH
            ads_session->ads_wsp_helper->m_cb_printf_out("Error m_do_work = %d\n", dss_cf.inc_return);
#else
            printf( "Error m_do_work = %d\n", dss_cf.inc_return );
#endif
            return dss_cf.inc_return * (-1); // return a negative number
        }

        if(!bop_enlarge_buffer) {
            break;
        }
#if 1
        // if the output area is full -> setup a larger output area
        if (dss_cf.achc_outa >= ach_output_end) {
            ads_session->ads_wsp_helper->m_cb_printf_out(
                "ds_zlib::m_do_work ENLARGING BUFFER to %d\n", in_len_out_buffer);
            in_len_out_buffer = 3 * in_len_out_buffer;
            m_create_out_buffer(in_len_out_buffer, false);
        }
#endif

        // is there an input, which is not processed (if not -> if DEF_IRET_END is set, then zlib detected that the whole data (the whole file) were processed)
        if (dss_cf.achc_inpa < dss_cf.achc_inpe) {
            continue;
        }
        else {
            break; // we are ready
        }
    }

    return dss_cf.achc_inpa-ach_start_input;
}

bool ds_zlib::m_finished(bool bo_compress) const {
    if(bo_compress)
        return dss_cf.inc_return == DEF_IRET_END;
    return dss_cf.inc_return == DEF_IRET_END;
}

/*! \brief Get the result
 *
 * @ingroup creator
 */
int ds_zlib::m_get_output_data(const char** ach_data_out)
{
    char* achl_cur_out = dss_cf.achc_outa;
    *ach_data_out = ach_output_start;
    dss_cf.achc_outa = ach_output_start;
    return (int)(achl_cur_out - ach_output_start);
}


#ifndef USED_BY_SDH
/* subroutine for miscellaneous functions                              */
static BOOL m_cdaux( void * vpp_userfld, int inp_func, void * achp_addr, int inp_length ) {
#define X_AUADDR  *((void **) achp_addr)
   if (inp_func == DEF_AUX_MEMGET) {
     X_AUADDR = malloc( inp_length );
     if (X_AUADDR) return TRUE;
     return FALSE;
   }
   if (inp_func == DEF_AUX_MEMFREE) {
     free( X_AUADDR );
     return TRUE;
   }
   return FALSE;
}
#endif // USED_BY_SDH
