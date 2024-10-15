#ifndef DS_ZLIB_H
#define DS_ZLIB_H

#if defined WIN32 || defined WIN64
#include <windows.h>
#endif // WIN32 || WIN64

#include "xscddef2.h"


#define USED_BY_SDH


#ifdef USED_BY_SDH
#include <types_defines.h>
// MJ 05.05.09:
#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include <hob-xsclib01.h>
#endif //_HOB_XSCLIB01_H
class ds_session; //forward-definition!!
#endif // USED_BY_SDH


/*! \brief ZLIB Compression class
 *
 * @ingroup creator
 *
 * Compresses Data
 */
class ds_zlib
{

public:

    //ds_zlib(int in_len_out_buffer_in);
    ds_zlib();
    ~ds_zlib(void);

#ifdef USED_BY_SDH
    void m_init1(/*MJ dsd_hl_clib_1 * ads_trans_in,*/ ds_session* ads_session_in);
#endif // USED_BY_SDH
    int m_init(const char* ach_start_input, const char* ach_end_input, bool bo_compress);
    int m_do_work(const char* ach_start_input, const char* ach_end_input, bool bo_compress, bool bo_eof, bool bop_enlarge_buffer);
    bool m_finished(bool bop_compress) const;
    int m_get_output_data(const char** ach_data_out);
    int m_reset(void);

private:
    int m_create_out_buffer(int in_len, bool bo_reset);
    int m_setup_zlib_buffers(const char* ach_start_input, const char* ach_end_input, char* ach_output_start, char* ach_output_end);

#ifdef USED_BY_SDH
    ds_session* ads_session;
//MJdsd_hl_clib_1 *ads_trans;
#endif // USED_BY_SDH
    struct dsd_hl_cd_2 dss_cf;
    char* ach_output_start;
    char* ach_output_end;
    int in_len_out_buffer;
    int in_len_out_buffer_default;
    bool bo_init_done;
};

#endif // DS_ZLIB_H
