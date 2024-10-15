/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include "ds_wsp_helper.h"
#include <rdvpn_globals.h>
#include <hob-libwspat.h>
#include <sys/timeb.h>
#include <time.h>
#if defined WIN32 || defined WIN64
    #include <windows.h>
    #include <direct.h>
#else
    #include <sys/stat.h>
    #include <sys/types.h>
    #include <fcntl.h>
    #include <stdarg.h>
    #include <hob-unix01.h>
    #define min(a,b) (((a) < (b)) ? (a) : (b))
    #define max(a,b) (((a) > (b)) ? (a) : (b))
#endif
#ifdef HL_HPUX
    #include <sys/param.h>
    #include <sys/pstat.h>
#endif
#ifdef HL_AIX
    #include <sys/ldr.h>
#endif
#ifndef HOB_XSLUNIC1_H
    #define HOB_XSLUNIC1_H
    #include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H
/* AKre*/
#ifndef EXT_BASE64
    #define EXT_BASE64
    #include <hob-tab-mime-base64.h>
#endif // EXT_BASE64
/* end AKre */
#include <xercesc/dom/DOMNode.hpp>
#include <stdint.h>
#include <hob-encry-1.h>
/* pseudo-entry, cannot be used in Server-Data-Hook                    */
extern "C" int m_hl1_printf( char *aptext, ... ) {
   return 0;
} /* end m_hl1_printf()                                                */
//#include <stdexcept>

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
#define WSPH_NAME           "WSP Helper Library"
#define WSPH_VERSION        "2.3.0.5"
#define WSPH_SHORTCUT       "WSPH"
#define WSPH_VERSION_STR    WSPH_NAME" V"WSPH_VERSION

// commands for wsp admin interface:
#define COM_WSP_ADMIN_CLUSTER    (char*)"cluster"
#define COM_WSP_ADMIN_LISTEN     (char*)"listen"
#define COM_WSP_ADMIN_SESSION    (char*)"session"
#define COM_WSP_ADMIN_LOG        (char*)"log"
#define COM_WSP_ADMIN_PERFDATA   (char*)"perfdata"
#define COM_WSP_ADMIN_DISCONNECT (char*)"cancel-session"
#define COM_WSP_ADMIN_WSPTRACEI	 (char*)"wsp-tr-act"
#define COM_WSP_ADMIN_WSPTRACEQ  (char*)"wsp-trace"
// The strings above have to be the same as in "achrs_adm_command[]"  in "xs-gw-admin.cpp"

#ifndef HL_UNIX
    #pragma warning(disable:4311)   // for function m_cb_get_node_type
#endif

#ifdef HL_UNIX
    #define GET_LOCK pthread_mutex_lock
    #define UN_LOCK  pthread_mutex_unlock
#else //windows
    #define GET_LOCK EnterCriticalSection
    #define UN_LOCK  LeaveCriticalSection
#endif //HL_UNIX

/*+-------------------------------------------------------------------------+*/
/*| macros:                                                                 |*/
/*+-------------------------------------------------------------------------+*/
//#define WSPH_INFO(x)        "H"WSPH_SHORTCUT"I%03dI: %s", x
//#define WSPH_WARN(x)        "H"WSPH_SHORTCUT"W%03dW: %s", x
//#define WSPH_ERROR(x)       "H"WSPH_SHORTCUT"E%03dE: %s", x

#ifdef _DEBUG
    #define m_debug_printf(...)    printf(__VA_ARGS__)
    #define m_cb_printf_debug(...) m_cb_printf_out(__VA_ARGS__)
#else // NOT _DEBUG
    #define m_debug_printf(...)
    #define m_cb_printf_debug(...)
#endif //_DEBUG

static const int BUF_SIZE = 8192;

/*+-------------------------------------------------------------------------+*/
/*| constructor:                                                            |*/
/*+-------------------------------------------------------------------------+*/
/**
 * ds_wsp_helper::ds_wsp_helper
*/
ds_wsp_helper::ds_wsp_helper(void)
{
    ads_trans      = NULL;
    ads_conf       = NULL;
    ads_wspat3     = NULL;
    work_mode      = ien_undefined;
    ads_storage    = NULL;
#ifdef _DEBUG
    inc_cma_write  = 0;
    inc_cma_read   = 0;
#endif
    ienc_tcp_conn  = ied_unknown;
} //end of ds_wsp_helper::ds_wsp_helper


/**
 * ds_wsp_helper::ds_wsp_helper
*/
ds_wsp_helper::ds_wsp_helper( struct dsd_hl_clib_1* ads_trans_input )
{
    ads_trans  = ads_trans_input;
    ads_conf   = NULL;
    ads_wspat3 = NULL;
    work_mode  = ien_trans;
    ads_storage    = NULL;
#ifdef _DEBUG
    inc_cma_write  = 0;
    inc_cma_read   = 0;
#endif
    ienc_tcp_conn  = ied_unknown;
} // end of ds_wsp_helper::ds_wsp_helper


/**
 * ds_wsp_helper::ds_wsp_helper
*/
ds_wsp_helper::ds_wsp_helper( struct dsd_hl_clib_dom_conf* ads_conf_input )
{
    ads_conf   = ads_conf_input;
    ads_trans  = NULL;
    ads_wspat3 = NULL;
    work_mode  = ien_conf;
    ads_storage    = NULL;
#ifdef _DEBUG
    inc_cma_write  = 0;
    inc_cma_read   = 0;
#endif
    ienc_tcp_conn  = ied_unknown;
} // end of ds_wsp_helper::ds_wsp_helper


/**
 * ds_wsp_helper::ds_wsp_helper
*/
ds_wsp_helper::ds_wsp_helper( struct dsd_wspat3_1 *adsp_auth_input )
{
    ads_wspat3 = adsp_auth_input;
    ads_trans  = NULL;
    ads_conf   = NULL;
    work_mode  = ien_wspat3;
    ads_storage    = NULL;
#ifdef _DEBUG
    inc_cma_write  = 0;
    inc_cma_read   = 0;
#endif
    ienc_tcp_conn  = ied_unknown;
} // end of ds_wsp_helper::ds_wsp_helper


/*+-------------------------------------------------------------------------+*/
/*| destructor:                                                             |*/
/*+-------------------------------------------------------------------------+*/
/**
 * ds_wsp_helper::~ds_wsp_helper
*/
ds_wsp_helper::~ds_wsp_helper(void)
{
} //end of ds_wsp_helper::~ds_wsp_helper


/*+-------------------------------------------------------------------------+*/
/*| init functions:                                                         |*/
/*+-------------------------------------------------------------------------+*/
/** \brief Init function
 *
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_init_trans
 * Set working mode to dsd_hl_clib_1
 *
 * @param[in] struct dsd_hl_clib_1* ads_trans_input
*/
void ds_wsp_helper::m_init_trans( struct dsd_hl_clib_1* ads_trans_input )
{
    ads_trans  = ads_trans_input;
    ads_conf   = NULL;
    ads_wspat3 = NULL;
    work_mode  = ien_trans;
    adsc_send_last_to_client = NULL;
    adsc_send_last_to_server = NULL;
} // end of ds_wsp_helper::m_init_trans


/** \brief Init class
 *
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_init_conf
 * Set working mode to configuration
 *
 * @param[in] struct dsd_hl_clib_dom_conf* ads_conf_input
*/
void ds_wsp_helper::m_init_conf( struct dsd_hl_clib_dom_conf* ads_conf_input )
{
    ads_conf   = ads_conf_input;
    ads_trans  = NULL;
    ads_wspat3 = NULL;
    work_mode  = ien_conf;
    adsc_send_last_to_client = NULL;
    adsc_send_last_to_server = NULL;
} // end of ds_wsp_helper::m_init_conf


/** \brief Init class
 *
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_init_auth
 * Set working mode to authentication
 *
 * @param[in] struct dsd_hl_clib_dom_conf* ads_conf_input
*/
void ds_wsp_helper::m_init_auth( struct dsd_wspat3_1 *adsp_auth_input )
{
    ads_wspat3 = adsp_auth_input;
    ads_trans  = NULL;
    ads_conf   = NULL;
    work_mode  = ien_wspat3;
    adsc_send_last_to_client = NULL;
    adsc_send_last_to_server = NULL;
} // end of ds_wsp_helper::m_init_auth


/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_get_version
 * get a version string from this library
 *
 * @return const char*          Version string
*/
const char* ds_wsp_helper::m_get_version()
{
    return WSPH_VERSION_STR;
} // end of ds_wsp_helper::m_get_version


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_get_wsp_path
 *
 * this function tries to get installation path of wsp
 * (not the path were it was started from)
 * path can be relative
 *
 * normally this function should be added to wsp itself
 *
 * @param[in/out]   char*   ach_path        buffer for holding dir
 * @param[in]       int     in_len          length of buffer
 *
 * @return          bool                    true = succcess
*/
bool ds_wsp_helper::m_get_wsp_path( char* ach_path, int in_len )
{
    // initialize some variables:
    int  in_return      = 0;    // return value
    int  in_pos         = 0;    // working position
    char ach_slash      = '/';  // directory delimiter


    //------------------------------------
    // check incoming data:
    //------------------------------------
    if ( ach_path == NULL || in_len < 4 ) {
        return false;
    }

    //------------------------------------
    // init buffer:
    //------------------------------------
    memset( ach_path, 0, in_len );

    //------------------------------------
    // get actual path:
    //------------------------------------
#if defined WIN32 || defined WIN64
    ach_slash = '\\';

    wchar_t wcrl_buf[_MAX_PATH];
    in_return = GetModuleFileNameW( NULL, wcrl_buf, _MAX_PATH );
    if ( in_return < 1 ) {
        return false;
    }
    int inl_ret = m_cpy_vx_vx(ach_path, in_len,
        ied_chs_utf_8, wcrl_buf, in_return, ied_chs_utf_16);
    if(inl_ret < 0)
        return false;
#endif // WIN32 || WIN64

#ifdef HL_LINUX
    in_return = readlink( "/proc/self/exe", ach_path, in_len );
    if ( in_return == -1 ) {
        return false;
    }
#endif // HL_LINUX

#ifdef HL_SOLARIS
    const char* ach_test = getexecname();
    if ( ach_test == NULL || strlen(ach_test) < 1 ) {
        return false;
    }
    in_return = (int)strlen(ach_test);
    if ( in_return > in_len ) {
        return false;
    }
    memcpy( ach_path, ach_test, in_return );
#endif // HL_SOLARIS

#ifdef HL_HPUX
    struct pst_status ds_status;
    int               in_pid    = getpid();

    if ( pstat_getproc( &ds_status, sizeof(ds_status), 0, in_pid ) == -1 ) {
        return false;
    }

    in_return = pstat_getpathname( ach_path, in_len, &ds_status.pst_fid_text );
    if ( in_return == -1 ) {
        return false;
    }
#endif // HL_HPUX

#ifdef HL_AIX
    struct ld_info ds_info;
    memset( &ds_info, 0, sizeof(ld_info) );

    in_return = loadquery( L_GETINFO, &ds_info, sizeof(ld_info) );
//    if ( in_return < 0 ) {
//        return false;
//    }
    in_return = (int)strlen(ds_info.ldinfo_filename);
    if ( in_return > in_len ) {
        return false;
    }
    memcpy( ach_path, ds_info.ldinfo_filename, in_return );
#endif // HL_AIX

    //------------------------------------------------
    // remove wsp name
    //------------------------------------------------
    for ( in_pos = in_return - 1; in_pos >= 0; in_pos-- ) {
        if ( ach_path[in_pos] != ach_slash ) {
            ach_path[in_pos] = 0;
        } else {
            break;
        }
    }

    return true;
} // end of ds_wsp_helper::m_get_wsp_path


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_mkdir
 *
 * this function tries create a given directory
 *
 * @param[in]   const char* ach_path        dir (zero terminated)
 * @return      bool                        true = succcess
*/
bool ds_wsp_helper::m_mkdir( const char* ach_path )
{
    int in_ret;

#if 0
    // MJ TESTING:
    char* achl_sub = (char*)ach_path;
    bool  bol_ret;
    do {
        bol_ret = m_split_path( achl_sub, &achl_sub );
    } while ( bol_ret == true );
    // end MJ testing
#endif

#ifndef HL_UNIX
    in_ret = _mkdir( ach_path );
#else
    in_ret = mkdir( ach_path, 0777 );
#endif
    return (in_ret == 0);
} // end of ds_wsp_helper::m_mkdir


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_split_path
 *
 * @param[in]   const char*     achp_path
 * @param[out]  char**          aachp_part
*/
bool ds_wsp_helper::m_split_path( const char* achp_path, char** aachp_part )
{
    char* achl_cur = (char*)achp_path;

    while (     achl_cur != NULL
            && *achl_cur != 0    ) {
        if (    *achl_cur == '/'
#ifndef HL_UNIX
             || *achl_cur == '\\'
#endif
                                 ) {
            achl_cur++;
            if ( *achl_cur == '0' ) {
                return false;
            }
            *aachp_part = achl_cur;
            return true;
        }
        achl_cur++;
    }
    return false;
} // end of ds_wsp_helper::m_split_path


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_open_cma
 *
 * @param[in]   const char* ach_name        get cma by name
 * @param[in]   int         in_len_name     length of name
 * @param[out]  void**      aav_data        output data
 * @param[out]  int*        ain_len         length of output data
 * @param[in]   bool        bo_write        give write access
 *                                          default = true
 *
 * @return      void*                       NULL = error
 *                                          otherwise cma handle
*/
void* ds_wsp_helper::m_cb_open_cma( const char* ach_name, int in_len_name, 
                                    void** aav_data, int* ain_len, 
                                    bool bo_write )
{
    // initialize some variables:
    dsd_hl_aux_c_cma_1* ads_cma = NULL;

	 //printf("#ds_wsp_helper::m_cb_open_cma: ach_name=%.*s bo_write=%d\n", in_len_name, ach_name, bo_write);
    //----------------------------------
    // get memory for cma structure:
    //----------------------------------
    ads_cma = (struct dsd_hl_aux_c_cma_1*)m_cb_get_memory( (int)sizeof(dsd_hl_aux_c_cma_1), true );
    if ( ads_cma == NULL ) {
        return NULL;
    }

    //----------------------------------
    // init cma structure:
    //----------------------------------
    ads_cma->ac_cma_name      = (void*)ach_name;
    ads_cma->inc_len_cma_name = in_len_name;
    ads_cma->iec_chs_name     = ied_chs_utf_8;

	if(!m_cb_open_cma2(ach_name, in_len_name, ads_cma, bo_write)) {
		m_cb_free_memory( ads_cma, (int)sizeof(dsd_hl_aux_c_cma_1) );
        return NULL;
	}
    //----------------------------------
    // check if data is valid:
    //----------------------------------
    if ( ads_cma->achc_cma_area == NULL || ads_cma->inc_len_cma_area <= 0 ) {
        m_unlock_cma( ads_cma );
		m_cb_free_memory( ads_cma, (int)sizeof(dsd_hl_aux_c_cma_1) );
        return NULL;
    }
    //----------------------------------
    // set output pointers:
    //----------------------------------
    *aav_data = ads_cma->achc_cma_area;
    *ain_len  = ads_cma->inc_len_cma_area;

    return ads_cma;
} // end of ds_wsp_helper::m_cb_open_cma

bool ds_wsp_helper::m_cb_open_cma2(
	const char* ach_name, int in_len_name, struct dsd_hl_aux_c_cma_1* adsp_cma, bool bo_write )
{
    //----------------------------------
    // init cma structure:
    //----------------------------------
    memset( adsp_cma, 0, sizeof(dsd_hl_aux_c_cma_1) );
    adsp_cma->ac_cma_name      = (void*)ach_name;
    adsp_cma->inc_len_cma_name = in_len_name;
    adsp_cma->iec_chs_name     = ied_chs_utf_8;

    //----------------------------------
    // lock cma:
    //----------------------------------
    if ( m_lock_cma( adsp_cma, bo_write ) == false ) {
        return false;
    }

#ifdef _DEBUG
    //----------------------------------
    // count cma access:
    //----------------------------------
    if ( bo_write == true ) {
        inc_cma_write++;
    } else {
        inc_cma_read++;
    }
#endif

    return true;
}

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_open_cma
 *
 * @param[in]   const char* ach_name        get cma by name
 * @param[in]   int         in_len_name     length of name
 * @param[out]  void**      aav_data        output data
 * @param[out]  int*        ain_len         length of output data
 * @param[in]   bool        bo_write        give write access
 *                                          default = true
 *
 * @return      void*                       NULL = error
 *                                          otherwise cma handle
*/
bool ds_wsp_helper::m_cb_open_or_create_cma(const char* ach_name, int in_len_name, 
                                    struct dsd_hl_aux_c_cma_1* ads_cma,
									int inp_retention_time)
{
    //----------------------------------
    // init cma structure:
    //----------------------------------
	memset( ads_cma, 0, sizeof(dsd_hl_aux_c_cma_1) );
    ads_cma->ac_cma_name      = (void*)ach_name;
    ads_cma->inc_len_cma_name = in_len_name;
    ads_cma->iec_chs_name     = ied_chs_utf_8;
	
    //----------------------------------
    // lock cma:
    //----------------------------------
    if ( m_lock_cma( ads_cma, true ) == false ) {
        return false;
    }
	if(!m_cb_set_retention_cma2(ads_cma, inp_retention_time))
		return false;
#ifdef _DEBUG
    inc_cma_write++;
#endif
    return true;
} // end of ds_wsp_helper::m_cb_open_cma

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_exist_cma
 * create (or resize) a new cma and put the data inside
 *
 * @param[in]   const char* ach_name        get cma by name
 * @param[in]   int         in_len_name     length of name
 *
*/
bool ds_wsp_helper::m_cb_exist_cma( const char* ach_name, int in_len_name )
{
    // initialize some variables:
    int inl_ret = m_cb_exist_cma2(ach_name, in_len_name);
	return (inl_ret == 1);
} // end of ds_wsp_helper::m_cb_exist_cma


int ds_wsp_helper::m_cb_exist_cma2( const char* ach_name, int in_len_name )
{
	// initialize some variables:
    dsd_hl_aux_c_cma_1 ds_cma;

    memset( &ds_cma, 0, sizeof(dsd_hl_aux_c_cma_1) );
    ds_cma.ac_cma_name      = (void*)ach_name;
    ds_cma.inc_len_cma_name = in_len_name;
    ds_cma.iec_chs_name     = ied_chs_utf_8;
    
    if ( !m_query_cma( &ds_cma ) ) {
		return -1;
    }

    if ( ds_cma.inc_len_cma_area < 1 ) {
        return 0;
    }

    return 1;
} // end of ds_wsp_helper::m_cb_exist_cma2

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_create_cma
 * create (or resize) a cma and put the data inside
 *
 * @param[in]   const char* ach_name        get cma by name
 * @param[in]   int         in_len_name     length of name
 * @param[out]  void*       av_data         input data
 * @param[out]  int         in_len          length of input data
 *
*/
bool ds_wsp_helper::m_cb_create_cma( const char* ach_name, int in_len_name,
                                     void* av_data, int in_len, int inp_retention_time )
{
    // initialize some variables:
    dsd_hl_aux_c_cma_1 ds_cma;

    memset( &ds_cma, 0, sizeof(dsd_hl_aux_c_cma_1) );
    ds_cma.ac_cma_name      = (void*)ach_name;
    ds_cma.inc_len_cma_name = in_len_name;
    ds_cma.iec_chs_name     = ied_chs_utf_8;
    
	bool bo_ret = m_lock_cma( &ds_cma, true );
    if ( !bo_ret )
        return false;
	if( ds_cma.inc_len_cma_area != in_len ) {
		bo_ret = m_resize_cma(&ds_cma, in_len);
		if (!bo_ret) {
			goto LBL_FAILED;
        }
	}
    // copy input data to cma:
    if ( av_data != NULL ) {
        memcpy( ds_cma.achc_cma_area, av_data, in_len );
    }

	bo_ret = this->m_cb_set_retention_cma2(&ds_cma, inp_retention_time);
LBL_FAILED:
    // close cma:
    if ( m_unlock_cma( &ds_cma ) == false ) {
        return false;
    }

    return bo_ret;
} // end of ds_wsp_helper::m_cb_create_cma

ds_wsp_helper::ied_cma_result ds_wsp_helper::m_cb_create_cma_excl(
	const char* ach_name, int in_len_name, void* av_data, int in_len, int inp_retention_time )
{
    // initialize some variables:
    dsd_hl_aux_c_cma_1 ds_cma;

    memset( &ds_cma, 0, sizeof(dsd_hl_aux_c_cma_1) );
    ds_cma.ac_cma_name      = (void*)ach_name;
    ds_cma.inc_len_cma_name = in_len_name;
    ds_cma.iec_chs_name     = ied_chs_utf_8;
    
    if ( !m_lock_cma( &ds_cma, true ) ) {
        return iec_cma_failed;
    }

	ds_wsp_helper::ied_cma_result iel_result = iec_cma_failed;
	if(ds_cma.inc_len_cma_area != 0) {
		iel_result = iec_cma_exists;
		goto LBL_FAILED1;
	}
	if ( ds_cma.inc_len_cma_area != in_len && !m_resize_cma( &ds_cma, in_len ) ) {
		goto LBL_FAILED1;
	}
	// copy input data to cma:
    if(av_data != NULL) {
        memcpy( ds_cma.achc_cma_area, av_data, in_len );
    }
	if(!this->m_cb_set_retention_cma2(&ds_cma, inp_retention_time))
		goto LBL_FAILED1;
	iel_result = iec_cma_success;
LBL_FAILED1:
	 // close cma:
    if ( !m_unlock_cma( &ds_cma ) ) {
        return iec_cma_failed;
    }
    return iel_result;
}

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_resize_cma
 * resize a cma
 *
 * @param[in]   const char* ach_name        get cma by name
 * @param[in]   int         in_len_name     length of name
 * @param[out]  int         in_size         length of input data
*/
bool ds_wsp_helper::m_cb_resize_cma( const char* ach_name, int in_len_name, int in_size )
{
    // initialize some variables:
    bool               bo_ret = false;
    dsd_hl_aux_c_cma_1 ds_cma;

    memset( &ds_cma, 0, sizeof(dsd_hl_aux_c_cma_1) );
    ds_cma.ac_cma_name      = (void*)ach_name;
    ds_cma.inc_len_cma_name = in_len_name;
    ds_cma.iec_chs_name     = ied_chs_utf_8;
    
    // open cma:
    if ( m_lock_cma( &ds_cma ) == false ) {
        return false;
    }

    bo_ret = m_resize_cma( &ds_cma, in_size );

    // close cma:
    if ( m_unlock_cma( &ds_cma ) == false ) {
        return false;
    }

    return bo_ret;
} // end of ds_wsp_helper::m_cb_resize_cma


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_delete_cma
 * delete a cma (means set size to zero)
 *
 * @param[in]   const char* ach_name        get cma by name
 * @param[in]   int         in_len_name     length of name
*/
bool ds_wsp_helper::m_cb_delete_cma( const char* ach_name, int in_len_name )
{
    return m_cb_resize_cma( ach_name, in_len_name, 0 );
} // end of ds_wsp_helper::m_cb_delete_cma


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_close_cma
 * close cma
 *
 * @param[in]   void**      aav_cma_handle      handle from open cma call
 * 
 * @return      bool        true = success
*/
bool ds_wsp_helper::m_cb_close_cma( void** aav_cma_handle )
{
    // initialize some variables:
    bool                bo_ret;
    dsd_hl_aux_c_cma_1* ads_cma;

    //----------------------------------
    // get input handle:
    //----------------------------------
    ads_cma = (struct dsd_hl_aux_c_cma_1*)(*aav_cma_handle);
    if ( ads_cma == NULL ) {
        return false;
    }

    //----------------------------------
    // close cma:
    //----------------------------------
    bo_ret = m_unlock_cma( ads_cma );

    //----------------------------------
    // free cma structure:
    //----------------------------------
    m_cb_free_memory( ads_cma, (int)sizeof(dsd_hl_aux_c_cma_1) );
    *aav_cma_handle = NULL;

	 //printf("#ds_wsp_helper::m_cb_close_cma: ads_cma=%p\n", ads_cma);
    return bo_ret;
} // end of ds_wsp_helper::m_cb_close_cma

bool ds_wsp_helper::m_cb_close_cma2(struct dsd_hl_aux_c_cma_1* adsp_cma_data) {
	bool bol_ret = m_unlock_cma(adsp_cma_data);
	adsp_cma_data->ac_cma_handle = NULL;
	return bol_ret;
}

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_resize_cma
 * resize a cma
 *
 * @param[in]   void*       av_cma_handle   handle from open cma call
 * @param[out]  void**      aav_data        output data
 * @param[in]   int         in_size         requested size
 * @return      bool                        true = success
*/
bool ds_wsp_helper::m_cb_resize_cma( void* av_cma_handle, void** aav_data, int in_size )
{
    // initialize some variables:
    dsd_hl_aux_c_cma_1* ads_cma;
    bool                bo_ret;

    //----------------------------------
    // get input handle:
    //----------------------------------
    ads_cma = (struct dsd_hl_aux_c_cma_1*)av_cma_handle;
    if ( ads_cma == NULL ) {
        return false;
    }

    //----------------------------------
    // resize cma:
    //----------------------------------
    bo_ret =  m_resize_cma( ads_cma, in_size );

    //----------------------------------
    // set output pointers:
    //----------------------------------
    if ( bo_ret == true ) {
        *aav_data = ads_cma->achc_cma_area;
    }

    return bo_ret;
} // end of ds_wsp_helper::m_cb_resize_cma


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_resize_cma
 * resize a cma
 *
 * @param[in]   void*       av_cma_handle   handle from open cma call
 * @param[out]  void**      aav_data        output data
 * @param[in]   int         in_size         requested size
 * @return      bool                        true = success
*/
bool ds_wsp_helper::m_cb_resize_cma2( struct dsd_hl_aux_c_cma_1* adsp_cma, int in_size )
{
    // initialize some variables:
    bool                bo_ret;

    //----------------------------------
    // get input handle:
    //----------------------------------
    if ( adsp_cma == NULL ) {
        return false;
    }

    //----------------------------------
    // resize cma:
    //----------------------------------
    bo_ret = m_resize_cma( adsp_cma, in_size );

    return bo_ret;
} // end of ds_wsp_helper::m_cb_resize_cma

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_retention_cma
 * get retention time of cma ( lifetime in case of inactivty)
 *
 * @param[in]   const char* ach_name        get cma by name
 * @param[in]   int         in_len_name     length of name
 * 
 * @return      int                         lifetime in sec
*/
int ds_wsp_helper::m_cb_get_retention_cma( const char* ach_name, int in_len_name )
{
    // initialize some variables:
    dsd_hl_aux_c_cma_1 ds_cma;

    memset( &ds_cma, 0, sizeof(dsd_hl_aux_c_cma_1) );
    ds_cma.ac_cma_name      = (void*)ach_name;
    ds_cma.inc_len_cma_name = in_len_name;
    ds_cma.iec_chs_name     = ied_chs_utf_8;
    ds_cma.iec_ccma_def     = ied_ccma_retention_get;

    m_call_aux( DEF_AUX_COM_CMA, &ds_cma, sizeof(dsd_hl_aux_c_cma_1) );
    return ds_cma.imc_retention_time;
} // end of ds_wsp_helper::m_cb_get_retention_cma

#if 0
/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_set_retention_cma
 * set retention time of cma ( lifetime in case of inactivty)
 *
 * @param[in]   const char* ach_name        get cma by name
 * @param[in]   int         in_len_name     length of name
 * @param[in]   int         in_sec          lifetime in sec
 * 
 * @return      bool                        true = success
*/
bool ds_wsp_helper::m_cb_set_retention_cma( const char* ach_name, int in_len_name, int in_sec )
{
    // initialize some variables:
    dsd_hl_aux_c_cma_1 ds_cma;

    memset( &ds_cma, 0, sizeof(dsd_hl_aux_c_cma_1) );
    ds_cma.ac_cma_name        = (void*)ach_name;
    ds_cma.inc_len_cma_name   = in_len_name;
    ds_cma.iec_chs_name       = ied_chs_utf_8;
    ds_cma.iec_ccma_def       = ied_ccma_retention_set;
    ds_cma.imc_retention_time = in_sec;

    return m_call_aux( DEF_AUX_COM_CMA, &ds_cma, sizeof(dsd_hl_aux_c_cma_1) );
} // end of ds_wsp_helper::m_cb_set_retention_cma
#endif

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_set_retention_cma
 * set retention time of cma ( lifetime in case of inactivty)
 *
 * @param[in]   const char* ach_name        get cma by name
 * @param[in]   int         in_len_name     length of name
 * @param[in]   int         in_sec          lifetime in sec
 * 
 * @return      bool                        true = success
*/
bool ds_wsp_helper::m_cb_set_retention_cma2( dsd_hl_aux_c_cma_1* adsp_cma, int in_sec )
{
    adsp_cma->iec_ccma_def = ied_ccma_retention_set;
    adsp_cma->imc_retention_time = in_sec;
    return m_call_aux( DEF_AUX_COM_CMA, adsp_cma, sizeof(dsd_hl_aux_c_cma_1) );
} // end of ds_wsp_helper::m_cb_set_retention_cma

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_next_cma
 * get next cma by name
 *
 * @param[in]   const char* ach_name            get cma by name
 * @param[in]   int         in_len_name         length of name
 * @param[in]   char*       ach_found           found cma name
 * @param[in]   int         in_len_fbuffer      max length of found buffer
 * @return      int                             length of return name
*/
int ds_wsp_helper::m_cb_get_next_cma( const char* ach_name, int in_len_name, 
                                      char* ach_found, int in_len_fbuffer )
{
    // initialize some variables:
    bool               bo_ret;
    dsd_hl_aux_c_cma_1 ds_cma;

    memset( &ds_cma, 0, sizeof(dsd_hl_aux_c_cma_1) );
    ds_cma.ac_cma_name             = (void*)ach_name;
    ds_cma.inc_len_cma_name        = in_len_name;
    ds_cma.iec_chs_name            = ied_chs_utf_8;
    ds_cma.iec_ccma_def            = ied_ccma_browse_entry_greater;
    ds_cma.ac_cma_browse_name      = (void*)ach_found;
    ds_cma.imc_mem_cma_browse_name = in_len_fbuffer;
    ds_cma.iec_chs_browse_name     = ied_chs_utf_8;

    bo_ret = m_call_aux( DEF_AUX_COM_CMA, &ds_cma, sizeof(dsd_hl_aux_c_cma_1) );
    if ( bo_ret == true ) {
        return ds_cma.imc_len_cma_browse_name;
    }

    return -1;
} // end of ds_wsp_helper::m_cb_get_next_cma


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_print_out
 *
 * print something (e.g. an error message) to the console
 *
 * @param[in] const char* ach_to_print zero-terminated string
 * @return bool
*/
bool ds_wsp_helper::m_cb_print_out( const dsd_const_string& ach_to_print)
{
    HL_WCHAR chr_buffer[1024 + 1];

	struct dsd_unicode_string dsl_ucs;
	dsl_ucs.iec_chs_str = ied_chs_utf_8;
	dsl_ucs.imc_len_str = ach_to_print.m_get_len();
	dsl_ucs.ac_str = (void*)ach_to_print.m_get_ptr();
	int inl_res_len = m_hlsnprintf( chr_buffer, sizeof(chr_buffer)/sizeof(chr_buffer[0]), ied_chs_utf_16, "%(ucs)s", &dsl_ucs );
	return m_call_aux( DEF_AUX_CO_UNICODE,
        (void*)chr_buffer, inl_res_len );

    /* // until KB fixes bug in aux-call
    return m_call_aux( DEF_AUX_CONSOLE_OUT,
                       (void*)ach_to_print, (int)(strlen(ach_to_print)) );*/

} // end of ds_wsp_helper::m_cb_print_out


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_printf_out
 * print message (up to 512 signs) to wsp console in common printf way
 * wsp will cut longer message, so a greater buffer makes no sence
 *
 * @param[in]   const char* ach_format
 * @return      bool
*/
bool ds_wsp_helper::m_cb_printf_out( HL_FORMAT_STRING const char* ach_format, ...  )
{
    // initialize some variables:
    char    rch_buffer[BUF_SIZE + 1];    // buffer for printing
    int     in_size;                // used buffer size
    va_list args;                   // argument list

    // try to print in our memory (function will give us needed mem size)
    va_start( args, ach_format );
    in_size = vsnprintf( &rch_buffer[0], BUF_SIZE, ach_format, args );
    va_end( args );

    // zero termination:
    if ( in_size > BUF_SIZE || in_size < 0 ) {
        in_size = BUF_SIZE;
    }
    rch_buffer[in_size] = 0;
    
    return m_call_aux( DEF_AUX_CONSOLE_OUT,
                       (void*)rch_buffer, in_size );
} // end of ds_wsp_helper::m_cb_printf_out

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_printf_out
 * print message (up to 512 signs) to wsp console in common printf way
 * wsp will cut longer message, so a greater buffer makes no sence
 *
 * @param[in]   const char* ach_format
 * @return      bool
*/
bool ds_wsp_helper::m_cb_printf_out2( const char* ach_format, ...  )
{
    // initialize some variables:
    char    rch_buffer[BUF_SIZE + 1];    // buffer for printing
    int     in_size;                // used buffer size
    va_list args;                   // argument list

    // try to print in our memory (function will give us needed mem size)
    va_start( args, ach_format );
    in_size = m_hlvsnprintf( &rch_buffer[0], BUF_SIZE, ied_chs_utf_8, ach_format, args );
    va_end( args );

    // zero termination:
    if ( in_size > BUF_SIZE || in_size < 0 ) {
        in_size = BUF_SIZE;
    }
    rch_buffer[in_size] = 0;
    
    return m_call_aux( DEF_AUX_CONSOLE_OUT,
                       (void*)rch_buffer, in_size );
} // end of ds_wsp_helper::m_cb_printf_out

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_file_access
 *
 * @param[in] struct dsd_hl_aux_diskfile_1* ds_read_diskfile
 *
 * @return bool
*/
bool ds_wsp_helper::m_cb_file_access(struct dsd_hl_aux_diskfile_1* ds_read_diskfile)
{
    bool bo_ret = false;

    if ( work_mode == ien_conf ) {
        bo_ret = m_read_file_conf( ds_read_diskfile );
    } else {
        bo_ret = m_call_aux( DEF_AUX_DISKFILE_ACCESS,
                             ds_read_diskfile, (int)sizeof(dsd_hl_aux_diskfile_1) );
    }

    if (    (bo_ret == false)                               /* aux return error        */
         || (ds_read_diskfile->iec_dfar_def != ied_dfar_ok) /* diskfile returned error */
         || (ds_read_diskfile->adsc_int_df1 == NULL) )      /* diskfile not accessed   */ {
        return false;
    } 
    return true;
} // end of ds_wsp_helper::m_cb_file_access


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_file_lastmodified
 *
 * @param[in] struct dsd_hl_aux_diskfile_1* ds_read_diskfile
 *
 * @return bool
*/
bool ds_wsp_helper::m_cb_file_lastmodified(struct dsd_hl_aux_diskfile_1* ds_read_diskfile)
{
    bool bo_ret = false;

    bo_ret = m_call_aux( DEF_AUX_DISKFILE_TIME_LM,
                         ds_read_diskfile, (int)sizeof(dsd_hl_aux_diskfile_1) );

    if (    (bo_ret == false)
         || (ds_read_diskfile->iec_dfar_def != ied_dfar_ok) ) {// diskfile returned error
        return false;
    }
    return true;
} // end of ds_wsp_helper::m_cb_file_lastmodified


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_file_release
 *
 * @param[in] struct dsd_hl_aux_diskfile_1* ds_read_diskfile
 *
 * @return bool
*/
bool ds_wsp_helper::m_cb_file_release(struct dsd_hl_aux_diskfile_1* ds_read_diskfile)
{
    if ( ds_read_diskfile->ac_handle == NULL ) {
        return true; // nothing todo!
    }

#if 0
	if ( work_mode == ien_conf ) {
        return m_release_file_conf( ds_read_diskfile );
    }
#endif

    BOOL bol_res = m_call_aux( DEF_AUX_DISKFILE_RELEASE,
                       &(ds_read_diskfile->ac_handle),
                       (int)sizeof(ds_read_diskfile->ac_handle) );
    ds_read_diskfile->ac_handle = NULL;
    return bol_res != FALSE;
} // end of ds_wsp_helper::m_cb_file_release


/**
 * \ingroup winterface
 *
 * public method ds_wsp_helper::m_open_file
 *  open a file
 *
 * @param[in]   const char  *achp_path      path in UTF8
 * @param[in]   int         inp_length      length of file path
 * @return      void*                       file handle
 *                                          NULL in error cases
*/
void* ds_wsp_helper::m_open_file( const char *achp_path, int inp_length )
{
    struct dsd_hl_aux_diskfile_1 *adsl_file;

    adsl_file = (struct dsd_hl_aux_diskfile_1 *)
                m_cb_get_memory( sizeof(struct dsd_hl_aux_diskfile_1), true );
    if ( adsl_file == NULL ) {
        return NULL;
    }

#ifndef WSP_V24
    adsl_file->iec_chs_name = ied_chs_utf_8;
    adsl_file->ac_name      = (void*)achp_path;
    adsl_file->inc_len_name = inp_length;
#endif
#ifdef WSP_V24
    adsl_file->dsc_ucs_file_name.iec_chs_str = ied_chs_utf_8;
    adsl_file->dsc_ucs_file_name.ac_str      = (void*)achp_path;
    adsl_file->dsc_ucs_file_name.imc_len_str = inp_length;
#endif

    return (void*)adsl_file;
} /* end of ds_wsp_helper::m_open_file */


/**
 * \ingroup winterface
 *
 * public method ds_wsp_helper::m_read_file
 *  read file content
 *
 * @param[in]   void    *avp_handle         file handle
 * @param[out]  char    **aachp_content     ptr to file content
 * @param[out]  int     *ainp_length        length of file content
 * @return      bool                        true = success
 *                                          false otherwise
*/
bool ds_wsp_helper::m_read_file( void *avp_handle, char **aachp_content, int *ainp_length )
{
    struct dsd_hl_aux_diskfile_1 *adsl_file;
    bool                         bol_ret;

    if ( avp_handle == NULL ) {
        return false;
    }
    adsl_file = (struct dsd_hl_aux_diskfile_1*)avp_handle;
    bol_ret   = m_cb_file_access( adsl_file );
    if ( bol_ret == false ) {
        return false;
    }

    *aachp_content = adsl_file->adsc_int_df1->achc_filecont_start;
    *ainp_length   = (int)(   adsl_file->adsc_int_df1->achc_filecont_end
                            - adsl_file->adsc_int_df1->achc_filecont_start );
    return true;
} /* end of ds_wsp_helper::m_read_file */


/**
 * \ingroup winterface
 *
 * public method ds_wsp_helper::m_close_file
 *  close file
 *
 * @param[in]   void    *avp_handle         file handle
 * @return      nothing
*/
void ds_wsp_helper::m_close_file( void *avp_handle )
{
    struct dsd_hl_aux_diskfile_1 *adsl_file;

    if ( avp_handle == NULL ) {
        return;
    }
    adsl_file = (struct dsd_hl_aux_diskfile_1*)avp_handle;

    if ( adsl_file->adsc_int_df1 != NULL ) {
        m_cb_file_release( adsl_file );
    }

    m_cb_free_memory( adsl_file );
} /* end of ds_wsp_helper::m_close_file */


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_string_from_epoch
 *
 * @param[in] struct dsd_hl_aux_epoch_1* ds_epoch_to_str
 *
 * @return bool
*/
bool ds_wsp_helper::m_cb_string_from_epoch(struct dsd_hl_aux_epoch_1* ds_epoch_to_str)
{
    return m_call_aux( DEF_AUX_STRING_FROM_EPOCH,
                       ds_epoch_to_str, (int)sizeof(dsd_hl_aux_epoch_1) );
} // end of ds_wsp_helper::m_cb_string_from_epoch


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_epoch_from_string
 * 
 * @param[in]   struct dsd_hl_aux_epoch_1* ds_epoch_from_str
 *
 * @return      bool
*/
bool ds_wsp_helper::m_cb_epoch_from_string( struct dsd_hl_aux_epoch_1* ds_epoch_from_str )
{
    return m_call_aux( DEF_AUX_EPOCH_FROM_STRING,
                       ds_epoch_from_str, (int)sizeof(dsd_hl_aux_epoch_1) );
} // end of ds_wsp_helper::m_cb_epoch_from_string


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_memory
 *
 * @param[in]   int  in_len
 * @param[in]   bool bo_init_zeros 
 *
 * @return      char*
*/
char* ds_wsp_helper::m_cb_get_memory(int in_len, bool bo_init_zeros)
{
    bool  bo_ret   = false;
    char* ach_dest = NULL;

    // use storage container if it is set active:
    if ( ads_storage != NULL ) {
        m_init_storage();
        ach_dest = (char*)m_aux_stor_alloc( ads_storage, in_len );
        if ( ach_dest != NULL ) {
            if ( bo_init_zeros == true ) {
                memset(ach_dest, 0, in_len);
            }
            return ach_dest;
        }
        // fallback to normal memget mode if storage container failed
        m_cb_print_out( "HWSPHW001W storage container failed - fall back to normal mode" );
    }

	//m_cb_printf_out( "m_cb_get_memory: this=%p in_len=%d\n", this, in_len);
    // call aux function:
    bo_ret = m_call_aux( DEF_AUX_MEMGET, &ach_dest, in_len );

    if ( bo_ret == false ) {
        m_cb_print_out( "HWSPHW002W Cannot allocate memory.");
        return NULL;  // if this happens, it's a desaster...
    }
    if ( bo_init_zeros ) {
        memset(ach_dest, 0, in_len);
    }

    return ach_dest;
} // end of ds_wsp_helper::m_cb_get_memory


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_free_memory
 *
 * @param[in]   void*   av_free
 * @param[in]   int     in_len      default = 0, because KB will not read this param
*/
void ds_wsp_helper::m_cb_free_memory(void* av_free, int in_len)
{
    bool bo_ret = false;

	//m_cb_printf_out( "m_cb_free_memory: this=%p av_free=%p\n", this, av_free);
    // use storage container if it is set active:
    if ( ads_storage != NULL ) {
        m_init_storage();
        m_aux_stor_free( ads_storage, av_free );
        return;
    }

    bo_ret = m_call_aux( DEF_AUX_MEMFREE,
                         &av_free, in_len );

    if ( bo_ret == false ) {
        m_cb_print_out("HWSPHW003W Cannot free memory.");
    }
} // end of ds_wsp_helper::m_cb_free_memory


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_big_memory
 * allocate memory without using storage container
 *
 * @param[in]   int  in_len
 * @param[in]   bool bo_init_zeros 
 *
 * @return      char*
*/
char* ds_wsp_helper::m_cb_get_big_memory(int in_len, bool bo_init_zeros)
{
    bool  bo_ret   = false;
    char* ach_dest = NULL;

	//m_cb_printf_out( "m_cb_get_big_memory: this=%p in_len=%d\n", this, in_len);
    // call aux function:
    bo_ret = m_call_aux( DEF_AUX_MEMGET, &ach_dest, in_len );

    if ( bo_ret == false ) {
        m_cb_print_out( "HWSPHW053W Cannot allocate big memory.");
        return NULL;  // if this happens, it's a desaster...
    }
    if ( bo_init_zeros ) {
        memset(ach_dest, 0, in_len);
    }

    return ach_dest;
} // end of ds_wsp_helper::m_cb_get_big_memory


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_free_big_memory
 * free memory without using storage container
 *
 * @param[in]   void*   av_free
*/
void ds_wsp_helper::m_cb_free_big_memory(void* av_free )
{
    bool bo_ret = false;

    bo_ret = m_call_aux( DEF_AUX_MEMFREE,
                         &av_free, 0 );

    if ( bo_ret == false ) {
        m_cb_print_out("HWSPHW054W Cannot free big memory.");
    }
} // end of ds_wsp_helper::m_cb_free_big_memory

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_random
 * 
 * @param[in]   char* ach_dest
 * @param[in]   int   in_length
 *
 * @return      bool
*/
bool ds_wsp_helper::m_cb_get_random(char* ach_dest, int in_length)
{
    return m_call_aux( DEF_AUX_RANDOM_BASE64, (void*)ach_dest, in_length );
	
} // end of ds_wsp_helper::m_cb_get_random
/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_random_cookie
 * A random cookie via the secure random function will be created
 * 
 * @param[in]   char* ach_dest
 * @param[in]   int   in_length
 *
 * @return      bool
*/
bool ds_wsp_helper::m_cb_get_random_cookie(char* ach_dest, int in_length)
{

    bool bol_ret;
    
    bol_ret = m_call_aux( DEF_AUX_RANDOM_VISIBLE, (void*)ach_dest, in_length );

    /*64 bits needed
    every byte contains 6 bits information
    64 / 6 = 10 + 1 rounded up
    get secure random 11 bytes ==> in_length*/

    for ( int inl_i = 0; inl_i < in_length; inl_i++ ) {
      ach_dest[ inl_i ] = ucrs_base64[ ach_dest[ inl_i ] & 0X3F ]; 
    }
    

    return bol_ret;
	
} // end of ds_wsp_helper::m_cb_get_random_cookie

bool ds_wsp_helper::m_cb_get_secure_random(char* ach_dest, int in_length)
{

    bool bol_ret;
    
    bol_ret = m_call_aux( DEF_AUX_SECURE_RANDOM, (void*)ach_dest, in_length );

    return bol_ret;
	
} // end of ds_wsp_helper::m_cb_get_random_cookie


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_tcp_connect
 * 
 * @param[in]   dsd_aux_tcp_conn_1* ds_tcp
 *
 * @return      bool
*/
bool ds_wsp_helper::m_cb_tcp_connect( struct dsd_aux_tcp_conn_1* ds_tcp )
{
    bool bo_ret = false;

    bo_ret = m_call_aux( DEF_AUX_TCP_CONN,
                         ds_tcp, sizeof(dsd_aux_tcp_conn_1) );

    if (    (bo_ret == false)
         || (ds_tcp->iec_tcpconn_ret != (ied_tcpconn_ret)ied_tcr_ok) ) {
        // TCP-connect returned error
        return false;
    }
    ienc_tcp_conn = ied_connected;
    return true;
} // end of ds_wsp_helper::m_cb_tcp_connect


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_tcp_close
 * 
 * @return      bool
*/
bool ds_wsp_helper::m_cb_tcp_close()
{
    bool bol_ret = m_call_aux( DEF_AUX_TCP_CLOSE, NULL, 0 );
    if ( bol_ret == true ) {
        ienc_tcp_conn = ied_disconnected;
    }
    return bol_ret;
} // end of ds_wsp_helper::m_cb_tcp_close


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_clientip
 * 
 * @param[in]   struct dsd_aux_query_client* ads_client
 * @return      bool
*/
bool ds_wsp_helper::m_cb_get_clientip( struct dsd_aux_query_client* ads_client )
{
    memset( ads_client, 0, sizeof(dsd_aux_query_client) );
    return m_call_aux( DEF_AUX_QUERY_CLIENT, ads_client, sizeof(dsd_aux_query_client) );
} // end of ds_wsp_helper::m_cb_get_clientip


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_time
 * get current system time
 *
 * @return  hl_time_t
*/
hl_time_t ds_wsp_helper::m_cb_get_time()
{
    int inl_time;
    // KB uses int in his implementation
    BOOL bo_ret = m_call_aux( DEF_AUX_GET_TIME, &inl_time, sizeof(inl_time) );
    if ( bo_ret ) {
        // Ticket 34385: Although t_ret is (currently) a 64bit variable, it is being truncated
        //     to 32bit inside the DEF_AUX_GET_TIME in WSP, and then implicitly casted to 64bit in RDVPN.
        //     This leads to an unsafe behaviour of the higher 4 bytes of t_ret, and therefore,
        //     this can lead to an incorrect evaluation of its value by the callers of this function.
        //     Casting it to an unsigned integer corrects the value of the higher 4 bytes by
        //     putting all of them to 0.
        return (hl_time_t) (unsigned int) inl_time;
    } 
    return 0;
} // end of ds_wsp_helper::m_cb_get_time

HL_LONGLONG ds_wsp_helper::m_cb_get_time_epoch_ms() {
    HL_LONGLONG ull_time;
    if(!m_call_aux( DEF_AUX_GET_T_MSEC, &ull_time, sizeof(ull_time)))
        return 0;
    return ull_time;
}

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_set_timer
 *
 * @param[in]   int     in_secs     time out in milliseconds
 * @return      bool
*/
bool ds_wsp_helper::m_cb_set_timer( int in_msecs )
{
    // wsp takes timer in milliseconds
    return m_call_aux( DEF_AUX_TIMER1_SET, NULL, in_msecs );
} // end of ds_wsp_helper::m_cb_set_timer


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_rel_timer
 *
 * @return      bool
*/
bool ds_wsp_helper::m_cb_rel_timer()
{
    return m_call_aux( DEF_AUX_TIMER1_REL, NULL, 0 );
} // end of ds_wsp_helper::m_cb_rel_timer


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_cb_query_timer
 *
 * @param[in]   struct dsd_timer1_ret* ads_timer
 * @return      bool
*/
bool ds_wsp_helper::m_cb_query_timer( struct dsd_timer1_ret* ads_timer )
{
    return m_call_aux( DEF_AUX_TIMER1_QUERY, ads_timer, sizeof(dsd_timer1_ret) );
} // end of ds_wsp_helper::m_cb_query_timer


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_workarea
 *
 * @param[out]  char**      aach_wa         will point to new wa
 * @param[out]  int*        *ain_len        will contain length of new wa
 * @return      bool                        true = success
*/
bool ds_wsp_helper::m_cb_get_workarea( char** aach_wa, int* ain_len )
{
    // initialize some variables:
    struct dsd_aux_get_workarea ds_wa;
    bool   bo_ret;

    // call aux:
    bo_ret = m_call_aux( DEF_AUX_GET_WORKAREA, &ds_wa,
                         sizeof(dsd_aux_get_workarea) );

    // set return values:
    if ( bo_ret == true ) {
        *aach_wa = ds_wa.achc_work_area;
        *ain_len = ds_wa.imc_len_work_area;
    } else {
        *aach_wa = NULL;
        *ain_len = 0;
    }
    return bo_ret;
} // end of ds_wsp_helper::m_cb_get_workarea


/**
 * \ingroup winterface
 *
 * get persistent workarea
 *
 * @param[in/out]	struct dsd_aux_get_workarea*	adsp_wa		wa struct
 * @return			bool										true = success
*/
bool ds_wsp_helper::m_cb_get_persistent_workarea(
	struct dsd_aux_get_workarea *adsp_wa, int inp_min_size )
{
	int inl_size = max(inp_min_size, 8192);
   BOOL bol_ret;

	bol_ret = m_call_aux( DEF_AUX_MEMGET, &adsp_wa->achc_work_area, inl_size);
	if( !bol_ret )
		return false;
	adsp_wa->imc_len_work_area = inl_size;
    return true;
} // end of ds_wsp_helper::m_cb_get_workarea


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_wsp_info
 *
 * @return      char*
*/
const char* ds_wsp_helper::m_cb_get_wsp_info()
{
    bool  bo_ret   = false;
    void* ach_info = NULL;

    bo_ret = m_call_aux( DEF_AUX_QUERY_MAIN_STR,
                         &ach_info, sizeof(void*) );

    if ( bo_ret == false ) {
        return NULL;
    }
    return (const char*)ach_info;
} // end of ds_wsp_helper::m_cb_get_wsp_info


/**
 * \ingroup winterface
 *
 * Read major and minor number of WSP's version number. Construct an int, which is in_major*10 + in_minor.
 * function ds_wsp_helper::m_get_wsp_version
 *
 * @return      char*
*/
int ds_wsp_helper::m_get_wsp_version()
{
    const char* ach_wsp_info = m_cb_get_wsp_info();
    if (ach_wsp_info == NULL) {
        return -1;
    }

    // Info starts with: "HOB WebSecureProxy V2.2"
    // Find and skip "HOB WebSecureProxy V"
    const char* ach_start = strstr(ach_wsp_info, WSP_VERSION_PREFIX);
    if (ach_start == NULL) {
        return -2;
    }
    // Make sure that string-len is at least strlen(WSP_VERSION_PREFIX)+3 (3 foe e.g. '2.2')
    if ((int)strlen(ach_wsp_info) < (strlen(WSP_VERSION_PREFIX)+3)) {
        return -3;
    }
    ach_start = ach_start + strlen(WSP_VERSION_PREFIX);

    // Read major and minor numbers and construct an int, which is in_major*10 + in_minor
    int in_major = *ach_start     - '0';
    int in_minor = *(ach_start+2) - '0';
    return (in_major*10 + in_minor);
} // end of ds_wsp_helper::m_get_wsp_version


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_get_session_id
 *
 * @return      int
*/
int ds_wsp_helper::m_get_session_id()
{
    bool bo_ret = false;
    int  in_id  = 0;

    bo_ret = m_call_aux( DEF_AUX_GET_CONN_SNO,
                         &in_id, sizeof(int) );
    if ( bo_ret == false ) {
        return -1;
    }
    return in_id;
} // end of ds_wsp_helper::m_get_session_id


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_get_listen_port
 *
 * @return      int
*/
int ds_wsp_helper::m_get_listen_port()
{   
    bool                        bol_ret;
    struct dsd_aux_query_client ds_conn_params;
    memset(&ds_conn_params, 0, sizeof(struct dsd_aux_query_client));

    bol_ret = m_call_aux( DEF_AUX_QUERY_CLIENT,
                          &ds_conn_params, sizeof(dsd_aux_query_client) );

    if (    bol_ret                 == true
         && ds_conn_params.inc_port >  0 
         && ds_conn_params.inc_port <= 65535 ) {
        return ds_conn_params.inc_port;
    }
    return -1;
} // end of ds_wsp_helper::m_get_listen_port

ied_sdh_data_direction ds_wsp_helper::m_get_default_direction() {
	// we need to select the direction:
   switch ( ads_trans->inc_func ) {
      case DEF_IFUNC_REFLECT:
         /*
               after a dynamic tcp connect our function
               will still be DEF_IFUNC_REFLECT!
         */
         switch( ienc_tcp_conn ) {
               case ied_connected:
                  return ied_sdh_dd_toserver;
               default:
                  return ied_sdh_dd_toclient;
         }
         break;

      case DEF_IFUNC_TOSERVER:
         switch( ienc_tcp_conn ) {
               case ied_disconnected:
                  return ied_sdh_dd_toclient;
               default:
                  return ied_sdh_dd_toserver;
         }
         break;

      case DEF_IFUNC_FROMSERVER:
         return ied_sdh_dd_toclient;

      default:
         m_cb_printf_out( "HWSPHW052W auto-detect send direction not possible in mode %d",
                           ads_trans->inc_func );
         return ied_sdh_dd_auto;
   }
}

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_get_input
*/
struct dsd_gather_i_1* ds_wsp_helper::m_get_input()
{
    switch( work_mode ) {
        case ien_trans:
            return ads_trans->adsc_gather_i_1_in;
        case ien_conf:
            m_cb_print_out( "HWSPHW008W get input data not allowed in conf mode" );
            return NULL;
        case ien_wspat3:
            return ads_wspat3->adsc_gai1_in_from_client;
        default:
            // if no valid mode is defined, we must use normal
            // printf to print an error message!
            m_debug_printf("HWSPHW009W no valid mode in ds_wsp_helper::m_get_input selected!\n");
            return NULL;
    }
} // end of ds_wsp_helper::m_get_input


struct dsd_gather_i_1* ds_wsp_helper::m_get_output(enum ied_sdh_data_direction ienp_direction) {
	 if(ienp_direction == ied_sdh_dd_auto) {
		 ienp_direction = m_get_default_direction();
	 }
    switch( work_mode ) {
        case ien_trans:
				switch(ienp_direction) {
				case ied_sdh_dd_toclient:
					return ads_trans->adsc_gai1_out_to_client;
				case ied_sdh_dd_toserver:
					return ads_trans->adsc_gai1_out_to_server;
				}
				return NULL;
        case ien_conf:
            m_cb_print_out( "HWSPHW010W get output data not allowed in conf mode" );
            return NULL;
        case ien_wspat3:
				switch(ienp_direction) {
				case ied_sdh_dd_toclient:
					return ads_trans->adsc_gai1_out_to_client;
				case ied_sdh_dd_toserver:
					return ads_wspat3->adsc_gai1_out_to_server;
				}
				return NULL;
        default:
            // if no valid mode is defined, we must use normal
            // printf to print an error message!
            m_debug_printf("HWSPHW011W no valid mode in ds_wsp_helper::m_get_output selected!\n");
            return NULL;
    }
}

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_get_output
*/
struct dsd_gather_i_1* ds_wsp_helper::m_get_output()
{
    switch( work_mode ) {
        case ien_trans:
            return (ads_trans->adsc_gai1_out_to_client != NULL) ? ads_trans->adsc_gai1_out_to_client
                                                                : ads_trans->adsc_gai1_out_to_server;
        case ien_conf:
            m_cb_print_out( "HWSPHW010W get output data not allowed in conf mode" );
            return NULL;
        case ien_wspat3:
            return ads_wspat3->adsc_gai1_out_to_client;
        default:
            // if no valid mode is defined, we must use normal
            // printf to print an error message!
            m_debug_printf("HWSPHW011W no valid mode in ds_wsp_helper::m_get_output selected!\n");
            return NULL;
    }
} // end of ds_wsp_helper::m_get_output

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_send_data
 * out data into workarea and set gather pointer
 *
 * @param[in]   const char              *achp_data      data to send
 * @param[in]   int                     inp_len_data    length of data
 * @param[in]   ied_sdh_data_direction  ienp_direction  data direction              
 * @return      bool                                    true = success
*/
bool ds_wsp_helper::m_send_data( const char* achp_data, int inp_len_data,
                                 enum ied_sdh_data_direction ienp_direction )
{
	 struct dsd_gather_pos dsl_pos;
    return ds_wsp_helper::m_send_data(achp_data, inp_len_data, true, ienp_direction, dsl_pos);
}

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_send_data
 * out data into workarea and set gather pointer
 *
 * @param[in]   const char              *achp_data      data to send
 * @param[in]   int                     inp_len_data    length of data
 * @param[in]   ied_sdh_data_direction  ienp_direction  data direction              
 * @return      bool                                    true = success
*/
bool ds_wsp_helper::m_send_data( const char* achp_data, int inp_len_data,
                                bool bop_copy_data,
                                enum ied_sdh_data_direction ienp_direction,
										  struct dsd_gather_pos& rdsp_pos)
{
    // check incoming data:
    if ( achp_data == NULL || inp_len_data < 1 ) {
        // nothing todo:
        return true;
    }

    /*
        workarea should look like this:
        +------------------+--------------------------- ... -+
        | gather structure | data                            |
        +------------------+--------------------------- ... -+
        | 12 bytes         | start and end pointer in gather |

        if workarea is too small, we get another one and
        set next pointer in first gather
    */

    struct dsd_gather_i_1** aadsl_trans_gather;
    char** aachl_work_area;
    int* ainl_len_work_area;
	 struct dsd_gather_i_1** aadsl_send_last = NULL; 
    //--------------------------------------------
    // init output gather:
    // determinate direction where data will be send.
    //--------------------------------------------
    switch ( work_mode ) {
        case ien_trans:
            //------------------------------------
            // get first workarea:
            //------------------------------------
            aachl_work_area = &ads_trans->achc_work_area;
            ainl_len_work_area = &ads_trans->inc_len_work_area;


            if ( ienp_direction == ied_sdh_dd_auto ) {
                // we need to select the direction:
                switch ( ads_trans->inc_func ) {
                    case DEF_IFUNC_REFLECT:
                        /*
                             after a dynamic tcp connect our function
                             will still be DEF_IFUNC_REFLECT!
                        */
                        switch( ienc_tcp_conn ) {
                            case ied_connected:
                                ienp_direction = ied_sdh_dd_toserver;
                                break;
                            default:
                                ienp_direction = ied_sdh_dd_toclient;
                                break;
                        }
                        break;

                    case DEF_IFUNC_TOSERVER:
                        switch( ienc_tcp_conn ) {
                            case ied_disconnected:
                                ienp_direction = ied_sdh_dd_toclient;
                                break;
                            default:
                                ienp_direction = ied_sdh_dd_toserver;
                                break;
                        }
                        break;

                    case DEF_IFUNC_FROMSERVER:
                        ienp_direction = ied_sdh_dd_toclient;
                        break;

                    default:
                        m_cb_printf_out( "HWSPHW052W auto-detect send direction not possible in mode %d",
                                         ads_trans->inc_func );
                        return false;
                }
            }

            switch( ienp_direction ) {
                case ied_sdh_dd_toserver:
                    aadsl_trans_gather = &ads_trans->adsc_gai1_out_to_server;
						  aadsl_send_last = &this->adsc_send_last_to_server;
                    break;

                case ied_sdh_dd_toclient:
                    aadsl_trans_gather = &ads_trans->adsc_gai1_out_to_client;
						  aadsl_send_last = &this->adsc_send_last_to_client;
                    break;

                default:
                    return false;
            }
            break;

        case ien_wspat3:
            //------------------------------------
            // get first workarea:
            //------------------------------------
            aachl_work_area = &ads_wspat3->achc_work_area;
            ainl_len_work_area = &ads_wspat3->imc_len_work_area;
            aadsl_trans_gather = &ads_wspat3->adsc_gai1_out_to_client;
				aadsl_send_last = &this->adsc_send_last_to_client;
            break;

        default:
            return false;
    }

    char* achl_wa_lower = *aachl_work_area;
    char* achl_wa_upper = achl_wa_lower + *ainl_len_work_area;

    if((*aadsl_trans_gather) == NULL) {
        int inl_len_work_area = achl_wa_upper - achl_wa_lower;
        if(inl_len_work_area < sizeof(struct dsd_gather_i_1)) {
            //------------------------------------
            // get new wa:
            //------------------------------------
            if ( m_cb_get_workarea( aachl_work_area, ainl_len_work_area ) == false ) {
                m_cb_print_out( "HWSPHW012W cannot get a new workarea" );
                return false;
            }
            achl_wa_lower = *aachl_work_area;
            achl_wa_upper = achl_wa_lower + *ainl_len_work_area;
        }
        achl_wa_upper -= sizeof(struct dsd_gather_i_1);
        dsd_gather_i_1* adsl_out = (struct dsd_gather_i_1*)achl_wa_upper;
        adsl_out->achc_ginp_cur = achl_wa_lower;
        adsl_out->achc_ginp_end = adsl_out->achc_ginp_cur;
        adsl_out->adsc_next = NULL;

        *aadsl_send_last = adsl_out;
        *aadsl_trans_gather = adsl_out;
    }

    //--------------------------------------------
    // get last output gather from chain:
    //--------------------------------------------
    // TODO: Remove loop
#if 0
    dsd_gather_i_1* adsl_out = (*aadsl_trans_gather);
    while ( adsl_out->adsc_next != NULL ) {
        adsl_out = adsl_out->adsc_next;
    }
    if(adsl_out != this->adsc_send_last)
        throw std::runtime_error("bad");
#else
    dsd_gather_i_1* adsl_out = *aadsl_send_last;
#endif
	 rdsp_pos.adsc_gai1 = adsl_out;
	 rdsp_pos.achl_ptr = adsl_out->achc_ginp_end;

    //--------------------------------------------
    // copy loop:
    //--------------------------------------------
    int inl_copied = 0;          // copied bytes
    while ( inl_copied < inp_len_data ) {
        /* Do we need a new gather? */
        int inl_len_target = achl_wa_upper - achl_wa_lower;

        if(    adsl_out->achc_ginp_end != achl_wa_lower // first time
            || inl_len_target <= 0                      // need more memory
            || !bop_copy_data )                         // no need to copy
        {
            struct dsd_gather_i_1* adsl_gather_prev = adsl_out;
            achl_wa_upper -= sizeof(struct dsd_gather_i_1);

            if(achl_wa_upper <= achl_wa_lower) {
                //------------------------------------
                // get new wa:
                //------------------------------------
                if ( m_cb_get_workarea( aachl_work_area, ainl_len_work_area ) == false ) {
                    m_cb_print_out( "HWSPHW012W cannot get a new workarea" );
                    return false;
                }
                achl_wa_lower = *aachl_work_area;
                achl_wa_upper = achl_wa_lower + *ainl_len_work_area;
                achl_wa_upper -= sizeof(struct dsd_gather_i_1);
            }
            adsl_out = (struct dsd_gather_i_1*)achl_wa_upper;

            adsl_out->achc_ginp_cur = achl_wa_lower;
            adsl_out->achc_ginp_end = adsl_out->achc_ginp_cur;
            adsl_out->adsc_next = NULL;
            
            adsl_gather_prev->adsc_next = adsl_out;
            *aadsl_send_last = adsl_out;

            if(!bop_copy_data) {
                int inl_check = inp_len_data - inl_copied;
                adsl_out->achc_ginp_cur = const_cast<char*>(&achp_data[inl_copied]);
                adsl_out->achc_ginp_end = adsl_out->achc_ginp_cur + inl_check;
                inl_copied += inl_check;
                continue;
            }

            inl_len_target = achl_wa_upper - achl_wa_lower;
        }
        
        //----------------------------------------
        // copy data itself:
        //----------------------------------------
        int inl_offset = 0;
        int inl_check = m_copy_data( &achp_data[inl_copied], inp_len_data - inl_copied,
                                 adsl_out->achc_ginp_end, inl_len_target,
                                 &inl_offset,                     false         );
        if ( inl_check < 0 ) {
            return false;
        }
        inl_copied += inl_check;

        //----------------------------------------
        // update gather end pointer:
        //----------------------------------------
        achl_wa_lower += inl_check;
        adsl_out->achc_ginp_end += inl_check;
    }

    *aachl_work_area = achl_wa_lower;
    *ainl_len_work_area = achl_wa_upper - achl_wa_lower;
    return true;
} // end of ds_wsp_helper::m_send_data


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_send_replace
 * replace data in workarea
 *
 * @param[in]   int         in_offset       position to start replacement
 * @param[in]   const char* ach_data        data to send
 * @param[in]   int         in_len_data     length of data
 * @return      bool                        true = success
*/
bool ds_wsp_helper::m_send_replace( int in_offset, const char* ach_data, int in_len_data )
{
    // initialize some variables:
    dsd_gather_i_1* ads_out;                    // output gather structure
    int             in_len_gather;              // length of output gather
    int             in_copied      = 0;         // copied bytes
    int             in_check;                   // check copied bytes

    // check incoming data:
    if ( in_offset < 0 || ach_data == NULL || in_len_data < 1 ) {
        // nothing todo:
        return true;
    }

    //--------------------------------------------
    // get output gather:
    //--------------------------------------------
    switch ( work_mode ) {
        case ien_trans:
            ads_out = (ads_trans->adsc_gai1_out_to_client != NULL) ? ads_trans->adsc_gai1_out_to_client
                                                                   : ads_trans->adsc_gai1_out_to_server;
            break;

        case ien_wspat3:
            ads_out = ads_wspat3->adsc_gai1_out_to_client;
            break;

        default:
            return false;
    }
    if ( ads_out == NULL ) {
        return false;
    }

    //--------------------------------------------
    // get length of first gather:
    //--------------------------------------------
    in_len_gather = (int)( ads_out->achc_ginp_end - ads_out->achc_ginp_cur );

    //--------------------------------------------
    // get right gather from chain:
    //--------------------------------------------
    while ( in_offset > in_len_gather ) {
        in_offset -= in_len_gather;

        if ( ads_out->adsc_next == NULL ) {
            return false;
        }

        ads_out       = ads_out->adsc_next;
        in_len_gather = (int)( ads_out->achc_ginp_end - ads_out->achc_ginp_cur );
    }

    //--------------------------------------------
    // replace loop:
    //--------------------------------------------
    while ( in_copied < in_len_data ) {
        in_check = m_copy_data( (void*)(&ach_data[in_copied]), in_len_data - in_copied,
                                ads_out->achc_ginp_cur,        in_len_gather,
                                &in_offset,                    false                    );
        if ( in_check < 0 ) {
            return false;
        }
        in_copied += in_check;

        if ( in_copied < in_len_data ) {
            if ( ads_out->adsc_next == NULL ) {
                return m_send_data( &ach_data[in_copied], in_len_data - in_copied );
            }
            ads_out       = ads_out->adsc_next;
            in_len_gather = (int)( ads_out->achc_ginp_end - ads_out->achc_ginp_cur );
            in_offset     = 0;
        }
    }

    return (in_copied == in_len_data)?true:false;
} // end of ds_wsp_helper::m_send_replace


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_get_gather_len
 *
 * @param[in]       dsd_gather_i_1*  ads_gather
 * @return          int                             length
*/
int ds_wsp_helper::m_get_gather_len( struct dsd_gather_i_1* ads_gather )
{
    // initialize some variables:
    int in_return = 0;

    while ( ads_gather != NULL ) {
        in_return += (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
        ads_gather = ads_gather->adsc_next;
    }

    return in_return;
} // end of ds_wsp_helper::m_get_gather_len


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_get_ptr
 * find and return the pointer to the end of stream.
 *
 * @param[in]       dsd_gather_i_1*  ads_gather
 * @param[in/out]   int              in_offset
 * @return          char* 
*/
char* ds_wsp_helper::m_get_end_ptr( struct dsd_gather_i_1* ads_gather, int in_offset )
{
    //initialize some variables:
    char* ach_ptr = NULL;
    int   in_len  = 0;

    if ( ads_gather == NULL ) {
        return NULL;
    }

    in_len = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
    while ( in_offset >= in_len ) {
        in_offset  -= in_len;
        ads_gather  = ads_gather->adsc_next;
        if ( ads_gather == NULL ) {
            return NULL;
        }
        in_len = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
    }
    
    ach_ptr = ads_gather->achc_ginp_cur + in_offset;
    return ach_ptr;
} // end of ds_wsp_helper::m_get_ptr


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_get_buf
 * request a buffer from length in_wanted from gather
 * if in_wanted is not available at once, *ain_get will give you 
 * the received data length
 *
 * @param[in]   struct dsd_gather_i_1*  ads_gather
 * @param[in]   int                     in_offset           offset in gather
 * @param[in]   int                     in_requested        requested length
 * @param[out]  int*                    ain_received        returned length
 * @return      char*                                       pointer to data
*/
char* ds_wsp_helper::m_get_buf( struct dsd_gather_i_1* ads_gather, int in_offset,
                                int in_requested, int* ain_received )
{
    // initialize some variables:
    char* ach_ptr = NULL;
    int   in_len  = 0;

    in_len = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
    while ( in_offset >= in_len ) {
        in_offset -= in_len;
        ads_gather = ads_gather->adsc_next;
        if ( ads_gather == NULL ) {
            return NULL;
        }
        in_len = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
    }

    ach_ptr = ads_gather->achc_ginp_cur + in_offset;
    if ( in_len - in_offset < in_requested ) {
        *ain_received = (in_len - in_offset);
    } else {
        *ain_received = in_requested;
    }

    return ach_ptr;
} // end of ds_wsp_helper::m_get_buf


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_mark_processed
 * mark gather as processed until offset and get new length
 *
 * @param[in]   struct dsd_gather_i_1*  ads_gather
 * @param[in]   int*                    ain_offset
 * @param[in]   int*                    ain_length
*/
void ds_wsp_helper::m_mark_processed( struct dsd_gather_i_1* ads_gather,
                                      int* ain_offset, int* ain_length )
{
    //initialize some variables:
    int in_len = 0;

    if ( ads_gather == NULL ) {
        *ain_offset = 0;
        *ain_length = 0;
        return;
    }

    in_len = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
    while ( (*ain_offset) >= in_len ) {
        (*ain_offset) -= in_len;
        (*ain_length) -= in_len;
        ads_gather->achc_ginp_cur = ads_gather->achc_ginp_end;
        ads_gather = ads_gather->adsc_next;
        if ( ads_gather == NULL ) {
            *ain_offset = 0;
            *ain_length = 0;
            return;
        }
        in_len = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
    }

    ads_gather->achc_ginp_cur = ads_gather->achc_ginp_cur + *ain_offset;
    (*ain_length) -= *ain_offset;
    (*ain_offset)  = 0;
    return;
} // end of ds_wsp_helper::m_mark_processed


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_protocol_type
 * get type of protocol
 *
 * @param[in]   const char* ach_proto
 * @param[in]   int         in_len_proto
 * @return      ied_scp_def                     type of protocol  
*/
ied_scp_def ds_wsp_helper::m_cb_get_protocol_type( const char* ach_proto, int in_len_proto )
{
    // initialize some variables:
    bool              bo_ret   = false;             // return from auxcall
    ied_scp_def       ien_type = ied_scp_undef;     // our return value
    dsd_get_sc_prot_1 ds_proto;                     // WSP call structure
    

    ds_proto.iec_chs_scp  = ied_chs_utf_8;
    ds_proto.ac_scp       = (void*)ach_proto;
    ds_proto.inc_len_scp  = in_len_proto;
    ds_proto.aiec_scp_def = &ien_type;
    bo_ret = m_call_aux( DEF_AUX_GET_SC_PROT,
                         &ds_proto, sizeof(struct dsd_get_sc_prot_1) );

    // handle response:
    if ( bo_ret == false ) {
        m_cb_print_out( "HWSPHW048W m_cb_get_protocol_type failed!" );
        return ied_scp_undef;
    }
    return ien_type;
} // end of ds_wsp_helper::m_cb_get_protocol_type


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_count_servers
 * count number of serverentries with given protocol for current user 
 *
 * @param[in]   ied_scp_def ien_protocol        type of protocol
 * @param[in]   const char* ach_proto           name of protocol
 * @param[in]   int         in_len_proto        length of protocol
 * @return      int                             number of servers for current protocol
*/
int ds_wsp_helper::m_cb_count_servers( void* av_userentry, void* av_usergroup,
                                       ied_scp_def ien_protocol,
                                       const char* ach_proto, int in_len_proto )
{
    // initialize some variables:
    int                      inl_count = 0;     // number of server entries
    bool                     bol_ret;           // return from auxcall
    struct dsd_get_servent_1 dsl_srv;           // WSP call structure

    memset( &dsl_srv, 0, sizeof(struct dsd_get_servent_1 ) );
    dsl_srv.vpc_usent       = av_userentry;
    dsl_srv.vpc_usgro       = av_usergroup;
    dsl_srv.ainc_no_servent = &inl_count;
    if (    ien_protocol == ied_scp_undef
         || ien_protocol == ied_scp_spec  ) {
        dsl_srv.dsc_ucs_protocol.ac_str      = (void*)ach_proto;
        dsl_srv.dsc_ucs_protocol.imc_len_str = in_len_proto;
        dsl_srv.dsc_ucs_protocol.iec_chs_str = ied_chs_utf_8;
    }
    dsl_srv.iec_scp_def = ien_protocol;

    bol_ret = m_call_aux( DEF_AUX_COUNT_SERVENT,
                          &dsl_srv, sizeof(struct dsd_get_servent_1) );

    // handle response:
    if ( bol_ret == false ) {
        m_cb_print_out( "HWSPHW049W m_cb_count_servers failed!" );
        return 0;
    }
    return inl_count;
} // end of ds_wsp_helper::m_cb_count_servers


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_server_entry
 * get type of protocol
 *
 * @param[in]     ied_scp_def   ien_protocol        type of protocol
 * @param[in]     const char*   ach_proto           name of protocol
 * @param[in]     int           in_len_proto        length of protocol
 * @param[in]     char*         ach_target          buffer for name of server
 * @param[in]     int*          ain_len_target      length of buffer
 * @param[in]     void*         av_previous         handle from previous call (to get next entry)
 *                                                  default = NULL
 * @param[in/out] int*          ain_function        pointer to server entry function
 * @return        void*                             server entry handle
 *                                                  NULL = last entry
*/
void* ds_wsp_helper::m_cb_get_server_entry( void* av_userentry, void* av_usergroup,
                                            ied_scp_def ien_protocol,
                                            const char* ach_proto, int in_len_proto,
                                            char* ach_target, int* ain_len_target,
                                            void* av_previous, int* ain_function )
{
    // initialize some variables:
    bool                     bol_ret;           // return from auxcall
    struct dsd_get_servent_1 dsl_srv;           // WSP call structure

    memset( &dsl_srv, 0, sizeof( dsd_get_servent_1 ) );
    dsl_srv.vpc_handle            = av_previous;
    dsl_srv.vpc_usent             = av_userentry;
    dsl_srv.vpc_usgro             = av_usergroup;
    dsl_srv.ac_servent_target     = ach_target;
    dsl_srv.ainc_len_target_bytes = ain_len_target;
    dsl_srv.iec_chs_target        = ied_chs_utf_8;
    if (    ien_protocol == ied_scp_undef
         || ien_protocol == ied_scp_spec  ) {
        dsl_srv.dsc_ucs_protocol.ac_str      = (void*)ach_proto;
        dsl_srv.dsc_ucs_protocol.imc_len_str = in_len_proto;
        dsl_srv.dsc_ucs_protocol.iec_chs_str = ied_chs_utf_8;
    }
    dsl_srv.iec_scp_def = ien_protocol;

    // get server entry function:
    dsl_srv.aimc_function = ain_function;

    bol_ret = m_call_aux( DEF_AUX_GET_SERVENT,
                          &dsl_srv, sizeof(struct dsd_get_servent_1) );

    // handle response:
    if ( bol_ret == false ) {
        m_cb_print_out( "HWSPHW050W m_cb_get_server_entry failed!" );
        return NULL;
    }

    return dsl_srv.vpc_handle;
} // end of ds_wsp_helper::m_cb_get_server_entry


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_prepare_connect
 * prepare connect call for hobwspat
 *
 * @param[in]   dsd_wspat3_conn *adsp_conn          connection structure
 * @return      bool                                false = error in aux call
*/
bool ds_wsp_helper::m_cb_prepare_connect( dsd_wspat3_conn *adsp_conn )
{
    // check working mode:
    if ( work_mode != ien_wspat3 ) {
        m_cb_print_out( "HWSPHW051W m_cb_prepare_connect only allowed in auth mode" );
        return false;
    }

    // initialize some variables:
    bool bol_ret;
    
    bol_ret =  m_call_aux( DEF_AUX_CONN_PREPARE,
                          adsp_conn, sizeof(struct dsd_wspat3_conn) );

    if ( bol_ret == false ) {
        return false;
    }
    return true;
} // end of ds_wsp_helper::m_cb_prepare_connect


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_get_own_srv_entry
 * get name and protocol of own server-entry
 *
 * @param[out]  char*   achp_name       pointer to buffer to be filled with name
 * @param[in]   int     inp_max_name    length of name buffer
 * @param[out]  int*    ainp_len_name   length of name (filled bytes)
 * @param[out]  char*   achp_proto      pointer to buffer to be filled with proto
 * @param[in]   int     inp_max_proto   length of protocol buffer
 * @param[out]  int*    ainp_len_proto  length of proto (filled bytes)
 * @return      bool                    true = success
*/
bool ds_wsp_helper::m_get_own_srv_entry( char* achp_name,  int inp_max_name,  int* ainp_len_name,
                                         char* achp_proto, int inp_max_proto, int* ainp_len_proto )
{
    // initialize some variables:
    struct dsd_wspadm1_q_session dsl_query;
    struct dsd_wspadm1_session   dsl_response;
    struct dsd_gather_i_1*       adsl_gather;
    int                          inl_session;
    int                          inl_total_len;
    int                          inl_block_len;
    int                          inl_pos;
    char                         chl_typeset;
    bool                         bol_ret;

    //-------------------------------------------
    // ask wsp fur current session info:
    //-------------------------------------------
    inl_session = m_get_session_id();
    memset( &dsl_query, 0, sizeof( struct dsd_wspadm1_q_session ) );
    dsl_query.imc_session_no = inl_session - 1;     // session number last before
    dsl_query.imc_no_session = 1;                   // receive just our current session!
	dsl_query.imc_len_userid = 0;
	dsl_query.imc_len_user_group = -1;
	dsl_query.imc_len_userfld = 0;

    adsl_gather = m_cb_adm_session( 0, true, dsl_query, NULL, NULL, NULL );
    if ( adsl_gather == NULL ) {
        return false;
    }

    //-------------------------------------------
    // get length of gather and first block:
    //-------------------------------------------
    inl_pos       = 0;
    inl_total_len = m_get_gather_len( adsl_gather );
    inl_block_len = m_get_nhasnlen( adsl_gather, &inl_pos );
    if (    inl_block_len < 0                        /* invalid length           */
         || inl_block_len + inl_pos != inl_total_len /* we accept only one block */ ) {
        return false;
    }

    //-------------------------------------------
    // get typeset of data block:
    //-------------------------------------------
    chl_typeset = m_get_end_ptr( adsl_gather, inl_pos )[0];
    inl_pos++;       // reading pos after typeset
    inl_block_len--; // first byte does not content to following struct
    if ( chl_typeset != 0 ) {
        return false;
    }

    //-------------------------------------------
    // copy data to our memory:
    //-------------------------------------------
    bol_ret = m_copy_data( adsl_gather, &inl_pos, 
                           sizeof(dsd_wspadm1_session), 
                           ((char*)(&dsl_response))    );
    if (    bol_ret     == false
         || inl_session != dsl_response.imc_session_no ) {
        return false;
    }

    // go over gate name:
    inl_pos += dsl_response.imc_len_gate_name;

    //-------------------------------------------
    // copy name of server entry:
    //-------------------------------------------
    if (    achp_name    != NULL
         && inp_max_name >= dsl_response.imc_len_serv_ent ) {
        bol_ret = m_copy_data( adsl_gather, &inl_pos,
                               dsl_response.imc_len_serv_ent,
                               achp_name );
        if ( bol_ret == true ) {
            *ainp_len_name = dsl_response.imc_len_serv_ent;
        }
    } else {
        inl_pos += dsl_response.imc_len_serv_ent;
    }

    //-------------------------------------------
    // copy protocol:
    //-------------------------------------------
    if (    achp_proto    != NULL
         && inp_max_proto >= dsl_response.imc_len_protocol ) {
        bol_ret = m_copy_data( adsl_gather, &inl_pos,
                               dsl_response.imc_len_protocol,
                               achp_proto );
        if ( bol_ret == true ) {
            *ainp_len_proto = dsl_response.imc_len_protocol;
        }
    }
    return true;
} // end of ds_wsp_helper::m_get_own_srv_entry


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_cb_config_session
 * configure session, means
 * set active serverlist and
 * set active targetfilters
 *
 * @param[in]   dsd_aux_session_conf_1* ads_config
 * @return      bool                                    true = success
*/
bool ds_wsp_helper::m_cb_config_session( struct dsd_aux_session_conf_1* ads_config )
{
    return m_call_aux( DEF_AUX_SESSION_CONF,
                       ads_config, sizeof(struct dsd_aux_session_conf_1) );
} // end of ds_wsp_helper::m_cb_config_session


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_return_error
 * set return code for wsp to error
*/
void ds_wsp_helper::m_return_error()
{
    // check working mode:
    if ( work_mode != ien_trans ) {
        m_cb_print_out( "HWSPHW014W return error only allowed in trans mode" );
        return;
    }

    ads_trans->inc_return = DEF_IRET_ERRAU;
} // end of ds_wsp_helper::m_return_error

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_return_error
 *   check if return code for wsp is an error
*/
bool ds_wsp_helper::m_has_error()
{
    if ( work_mode == ien_trans ) {
        return (ads_trans->inc_return == DEF_IRET_ERRAU);
    }
    return false;
} // end of ds_wsp_helper::m_has_error()


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_return_close
 * set return code for wsp to close connection
*/
void ds_wsp_helper::m_return_close()
{
    // check working mode:
    if ( work_mode != ien_trans ) {
        m_cb_print_out( "HWSPHW015W return error only allowed in trans mode" );
        return;
    }

    ads_trans->inc_return = DEF_IRET_END;
} // end of ds_wsp_helper::m_return_close


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_get_structure
 * get working structure
 *
 * @return  void*
*/
void* ds_wsp_helper::m_get_structure()
{
    switch( work_mode ) {
        case ien_trans:
            return (void*)ads_trans;
        case ien_conf:
            return (void*)ads_conf;
        case ien_wspat3:
            return (void*)ads_wspat3;
        default:
            // if no valid mode is defined, we must use normal
            // printf to print an error message!
            m_debug_printf("HWSPHW047W no valid mode in ds_wsp_helper::m_get_structure selected!\n");
            return NULL;
    }
} // end of ds_wsp_helper::m_get_structure


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_get_func
 * get func
 *
 * @return int
*/
int ds_wsp_helper::m_get_func()
{
    switch ( work_mode ) {
        case ien_trans:
            return ads_trans->inc_func;
        case ien_conf:
            return -1;
        case ien_wspat3:
            return (int)ads_wspat3->iec_at_function;          
    }
    return -1;
} // end of ds_wsp_helper::m_get_func


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_adm_cluster
 *
 * ask wsp for admin cluster informations
 *
 * @param[in]   bool                bo_free_buffer      free buffer from previous call
 * @return      dsd_gather_i_1 *                        NULL in error case!
*/
struct dsd_gather_i_1 * ds_wsp_helper::m_cb_adm_cluster( bool bo_free_buffer )
{    
    // initialize some variables:
    struct dsd_aux_admin_1 ds_admin;
    struct dsd_gather_i_1* ads_gather = NULL;

    // initialize admin structure:
    memset( &ds_admin, 0, sizeof(dsd_aux_admin_1) );
    if ( bo_free_buffer == true ) {
        ds_admin.boc_free_buffers = TRUE;
    }

    ds_admin.achc_command = m_get_adm_command( COM_WSP_ADMIN_CLUSTER, 
                                &ds_admin.imc_len_command, NULL, 0 );
    // call aux method:
    ads_gather = m_cb_admin( ds_admin );

    // free command memory:
    m_cb_free_memory( ds_admin.achc_command, ds_admin.imc_len_command );

    return ads_gather;
} // end of ds_wsp_helper::m_cb_adm_cluster


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_adm_listen
 *
 * ask wsp for admin listen informations
 * give cluster_handle = 0 for own wsp
 *
 * @param[in]   HL_LONGLONG         il_handle_cluster
 * @param[in]   bool                bo_free_buffer      free buffer from previous call
 *
 * @return      dsd_gather_i_1 *                        NULL in error case!
*/
struct dsd_gather_i_1 * ds_wsp_helper::m_cb_adm_listen( HL_LONGLONG il_handle_cluster, bool bo_free_buffer )
{    
    // initialize some variables:
    struct dsd_aux_admin_1 ds_admin;
    struct dsd_gather_i_1* ads_gather = NULL;

    // initialize admin structure:
    memset( &ds_admin, 0, sizeof(dsd_aux_admin_1) );
    ds_admin.ilc_handle_cluster = il_handle_cluster;
    if ( bo_free_buffer == true ) {
        ds_admin.boc_free_buffers = TRUE;
    }

    ds_admin.achc_command = m_get_adm_command( COM_WSP_ADMIN_LISTEN, 
                                &ds_admin.imc_len_command, NULL, 0 );
    // call aux method:
    ads_gather = m_cb_admin( ds_admin );

    // free command memory:
    m_cb_free_memory( ds_admin.achc_command, ds_admin.imc_len_command );

    return ads_gather;
} // end of ds_wsp_helper::m_cb_adm_listen


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_adm_perfdata
 *
 * ask wsp for admin performace informations
 * give cluster_handle = 0 for own wsp
 *
 * @param[in]   HL_LONGLONG         il_handle_cluster
 * @param[in]   bool                bo_free_buffer      free buffer from previous call
 *
 * @return      dsd_gather_i_1 *                        NULL in error case!
*/
struct dsd_gather_i_1 * ds_wsp_helper::m_cb_adm_perfdata( HL_LONGLONG il_handle_cluster, bool bo_free_buffer )
{
    // initialize some variables:
    struct dsd_aux_admin_1 ds_admin;
    struct dsd_gather_i_1* ads_gather = NULL;

    // initialize admin structure:
    memset( &ds_admin, 0, sizeof(dsd_aux_admin_1) );
    ds_admin.ilc_handle_cluster = il_handle_cluster;
    if ( bo_free_buffer == true ) {
        ds_admin.boc_free_buffers = TRUE;
    }

    ds_admin.achc_command = m_get_adm_command( COM_WSP_ADMIN_PERFDATA, 
                                &ds_admin.imc_len_command, NULL, 0 );

    // call aux method:
    ads_gather = m_cb_admin( ds_admin );

    // free command memory:
    m_cb_free_memory( ds_admin.achc_command, ds_admin.imc_len_command );

    return ads_gather;
} // end of ds_wsp_helper::m_cb_adm_perfdata


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_adm_session
 *
 * ask wsp for admin session informations
 * give cluster_handle = 0 for own wsp
 *
 * @param[in]   HL_LONGLONG             il_handle_cluster
 * @param[in]   bool                    bo_free_buffer      free buffer from previous call
 * @param[in]   dsd_wspadm1_q_session   ds_adm_session
 * @param[in]   char*                   ach_user            get info for user
 * @param[in]   char*                   ach_group           get info for group
 *
 * @return      dsd_gather_i_1 *                            NULL in error case!
*/
struct dsd_gather_i_1 * ds_wsp_helper::m_cb_adm_session( HL_LONGLONG il_handle_cluster, bool bo_free_buffer,
                                                         struct dsd_wspadm1_q_session ds_adm_session,
                                                         const char* ach_user, const char* ach_group, const char* achp_userfield )
{
    // initialize some variables:
    struct dsd_aux_admin_1       ds_admin;
    struct dsd_gather_i_1*       ads_gather   = NULL;
    char*                        ach_query    = NULL;   // query packet
    int                          in_len_query = 0;      // length of query packet
    int                          in_position  = 0;      // working position in query packet
    
    
    // evaluate length of query packet:
    in_len_query =   (int)sizeof(dsd_wspadm1_q_session)
                   + ds_adm_session.imc_len_userid
				   + max(ds_adm_session.imc_len_user_group, 0)
						 + ds_adm_session.imc_len_userfld;
    ach_query = m_cb_get_memory( in_len_query, true );

    // copy query structure to query packet:
    memcpy( ach_query, &ds_adm_session, sizeof(dsd_wspadm1_q_session) );
    in_position += (int)sizeof(dsd_wspadm1_q_session);

    // copy user name to query packet:
    if ( ds_adm_session.imc_len_userid > 0 ) {
        memcpy( &ach_query[in_position], ach_user, ds_adm_session.imc_len_userid );
        in_position += ds_adm_session.imc_len_userid;
    }

    // copy usergroup name to query packet:
    if ( ds_adm_session.imc_len_user_group > 0 ) {
        memcpy( &ach_query[in_position], ach_group, ds_adm_session.imc_len_user_group );
        in_position += ds_adm_session.imc_len_user_group;
    }

    // copy usergroup name to query packet:
    if ( ds_adm_session.imc_len_userfld > 0 ) {
        memcpy( &ach_query[in_position], achp_userfield, ds_adm_session.imc_len_userfld );
        in_position += ds_adm_session.imc_len_userfld;
    }

    // initialize admin structure:
    memset( &ds_admin, 0, sizeof(dsd_aux_admin_1) );
    ds_admin.ilc_handle_cluster = il_handle_cluster;
    if ( bo_free_buffer == true ) {
        ds_admin.boc_free_buffers = TRUE;
    }

    ds_admin.achc_command = m_get_adm_command( COM_WSP_ADMIN_SESSION, 
                                &ds_admin.imc_len_command, ach_query, in_len_query );

    // call aux method:
    ads_gather = m_cb_admin( ds_admin );

    // free command memory:
    m_cb_free_memory( ds_admin.achc_command, ds_admin.imc_len_command );
    // free query memory:
    m_cb_free_memory( ach_query, in_len_query );

    return ads_gather;
} // end of ds_wsp_helper::m_cb_adm_session


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_adm_log
 *
 * ask wsp for admin log informations
 * give cluster_handle = 0 for own wsp
 *
 * @param[in]   HL_LONGLONG             il_handle_cluster       cluster handle
 * @param[in]   bool                    bo_free_buffer          free buffer from previous call
 * @param[in]   dsd_wspadm1_q_log       ds_log
 * @param[in]   char*                   ach_search              search word (UTF8, zero terminated)
 *
 * @return      dsd_gather_i_1 *                                NULL in error case!
*/
struct dsd_gather_i_1 * ds_wsp_helper::m_cb_adm_log( HL_LONGLONG il_handle_cluster, bool bo_free_buffer,
                                                     struct dsd_wspadm1_q_log ds_log,
                                                     const char* ach_search )
{
    // initialize some variables:
    struct dsd_aux_admin_1  ds_admin;
    struct dsd_gather_i_1*  ads_gather    = NULL;
    int                     in_len_search = 0;      // length of search string
    char*                   ach_query     = NULL;   // query packet
    int                     in_len_query  = 0;      // length of query packet
    int                     in_position   = 0;      // working position in query packet
    
    
    if ( ach_search != NULL ) {
        in_len_search = (int)strlen(ach_search);
    }

    // evaluate length of query packet:
    in_len_query =   (int)sizeof(dsd_wspadm1_q_log)
                   + in_len_search;
    ach_query = m_cb_get_memory( in_len_query, true );

    // setup log query structure:
    ds_log.imc_len_query = in_len_search;
    
    // copy query structure to query packet:
    memcpy( ach_query, &ds_log, sizeof(dsd_wspadm1_q_log) );
    in_position += (int)sizeof(dsd_wspadm1_q_log);

    // copy search string to query packet:
    if ( in_len_search > 0 ) {
        memcpy( &ach_query[in_position], ach_search, in_len_search );
        in_position += in_len_search;
    }

    // initialize admin structure:
    memset( &ds_admin, 0, sizeof(dsd_aux_admin_1) );
    ds_admin.ilc_handle_cluster = il_handle_cluster;
    if ( bo_free_buffer == true ) {
        ds_admin.boc_free_buffers = TRUE;
    }

    ds_admin.achc_command = m_get_adm_command( COM_WSP_ADMIN_LOG, 
                                &ds_admin.imc_len_command, ach_query, in_len_query );

    // call aux method:
    ads_gather = m_cb_admin( ds_admin );

    // free command memory:
    m_cb_free_memory( ds_admin.achc_command, ds_admin.imc_len_command );
    // free query memory:
    m_cb_free_memory( ach_query, in_len_query );

    return ads_gather;
} // end of ds_wsp_helper::m_cb_adm_log


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_sess_disconnect
 *
 * ask wsp for disconnect a SSL/TCP session
 * give cluster_handle = 0 for own wsp
 *
 * @param[in]   HL_LONGLONG                 il_handle_cluster   cluster handle
 * @param[in]   bool                        bo_free_buffer      free buffer from previous call
 * @param[in]   dsd_wspadm1_q_can_sess_1    ds_disconnect
 *
 * @return      dsd_gather_i_1 *                                NULL in error case!
*/
struct dsd_gather_i_1 * ds_wsp_helper::m_cb_sess_disconnect( HL_LONGLONG il_handle_cluster, bool bo_free_buffer,
                                                             struct dsd_wspadm1_q_can_sess_1 ds_disconnect )
{
    // initialize some variables:
    struct dsd_aux_admin_1 ds_admin;
    struct dsd_gather_i_1* ads_gather = NULL;
    
    // initialize admin structure:
    memset( &ds_admin, 0, sizeof(dsd_aux_admin_1) );
    ds_admin.ilc_handle_cluster = il_handle_cluster;
    if ( bo_free_buffer == true ) {
        ds_admin.boc_free_buffers = TRUE;
    }

    ds_admin.achc_command = m_get_adm_command( COM_WSP_ADMIN_DISCONNECT, 
                                               &ds_admin.imc_len_command,
                                               &ds_disconnect,
                                               (int)sizeof(dsd_wspadm1_q_can_sess_1) );

    // call aux method:
    ads_gather = m_cb_admin( ds_admin );

    // free command memory:
    m_cb_free_memory( ds_admin.achc_command, ds_admin.imc_len_command );

    return ads_gather;
} // end of ds_wsp_helper::m_cb_sess_disconnect


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_confsection
 * get sdh configuration section DOMNode
 *
 * @return DOMNode*
*/
DOMNode* ds_wsp_helper::m_cb_get_confsection()
{
    switch( work_mode ) {
        case ien_trans:
            m_cb_print_out( "HWSPHW016W xerces call is not supported in trans mode\n" );
            return NULL;
        case ien_conf:
            return m_cb_get_firstchild( ads_conf->adsc_node_conf );
        case ien_wspat3:
            m_cb_print_out( "HWSPHW017W xerces call is not supported in auth mode\n" );
            return NULL;
        default:
            // if no valid mode is defined, we must use normal
            // printf to print an error message!
            m_debug_printf("HWSPHW018W no valid mode in ds_wsp_helper::m_call_xerces selected!\n");
            return NULL;
    }
} // end of ds_wsp_helper::m_cb_get_confsection

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_firstchild
 * 
 * @param[in]   DOMNode*    ads_node
 * @return      DOMNode*
*/
DOMNode* ds_wsp_helper::m_cb_get_firstchild( DOMNode* ads_node )
{
    return (DOMNode*)m_call_xerces( ads_node, ied_hlcldom_get_first_child );
} // end of ds_wsp_helper::m_cb_get_firstchild


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_nextsibling
 * 
 * @param[in]   DOMNode*    ads_node
 * @return      DOMNode*
*/
DOMNode* ds_wsp_helper::m_cb_get_nextsibling( DOMNode* ads_node )
{
    return (DOMNode*)m_call_xerces( ads_node, ied_hlcldom_get_next_sibling );
} // end of ds_wsp_helper::m_cb_get_nextsibling


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_node_type
 * 
 * @param[in]   DOMNode*    ads_node
 * @return      DOM_CAST
*/
DOM_CAST ds_wsp_helper::m_cb_get_node_type( DOMNode* ads_node )
{
    return (DOM_CAST)m_call_xerces( ads_node, ied_hlcldom_get_node_type );
} // end of ds_wsp_helper::m_cb_get_node_type


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_node_name
 * 
 * @param[in]   DOMNode*    ads_node
 * @return      HL_WCHAR*
*/
const HL_WCHAR* ds_wsp_helper::m_cb_get_node_name ( DOMNode* ads_node )
{
    return (const HL_WCHAR*)m_call_xerces( ads_node, ied_hlcldom_get_node_name );
} // end of ds_wsp_helper::m_cb_get_node_name


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_node_value
 * 
 * @param[in]   DOMNode*    ads_node
 * @return      HL_WCHAR*
*/
const HL_WCHAR*  ds_wsp_helper::m_cb_get_node_value ( DOMNode* ads_node )
{
    if ( m_cb_get_node_type(ads_node) != DOMNode::TEXT_NODE ) {
         ads_node = m_cb_get_firstchild( ads_node );
         if (    ads_node == NULL 
              || m_cb_get_node_type(ads_node) != DOMNode::TEXT_NODE ) {
             return NULL;
         }
    }
    return (const HL_WCHAR*)m_call_xerces( ads_node, ied_hlcldom_get_node_value );
} // end of ds_wsp_helper::m_cb_get_node_value


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_node_line
 * 
 * @param[in]   DOMNode*    ads_node
 * @return      int
*/
int ds_wsp_helper::m_cb_get_node_line( DOMNode* ads_node )
{
    size_t uinl_temp = (size_t)m_call_xerces( ads_node, ied_hlcldom_get_file_line );
    return (int)uinl_temp;
} // end of ds_wsp_helper::m_cb_get_node_line


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_node_colm
 * 
 * @param[in]   DOMNode*    ads_node
 * @return      int
*/
int ds_wsp_helper::m_cb_get_node_colm( DOMNode* ads_node )
{
    size_t uinl_temp = (size_t)m_call_xerces( ads_node, ied_hlcldom_get_file_column );
    return (int)uinl_temp;
} // end of ds_wsp_helper::m_cb_get_node_colm


/**
 * \ingroup winterface
 *
 * public funcion ds_wsp_helper::m_cb_count_ldap_srv
 * get number of configured ldap servers
 *
 * @return      int
*/
int ds_wsp_helper::m_cb_count_ldap_srv()
{
    // initialize some variables:
    bool                   bo_ret;
    dsd_aux_get_ldap_entry ds_ldap_req;

    ds_ldap_req.imc_no_entry = -1;
    bo_ret = m_call_aux( DEF_AUX_GET_LDAP_CONF, &ds_ldap_req,
                         sizeof(dsd_aux_get_ldap_entry) );
    if ( bo_ret == false ) {
        return 0;
    }
    return (int)ds_ldap_req.imc_ret_conf_entry;
} // end of ds_wsp_helper::m_cb_get_ldap_srv


/**
 * \ingroup winterface
 *
 * public funcion ds_wsp_helper::m_cb_get_ldap_srv
 * get name and comment a ldap server with given index number
 *
 * @param[in]   int                 in_index    index number of ldap server
 * @param[out]  dsd_unicode_string* ads_name    name of ldap server
 * @param[out]  dsd_unicode_string* ads_comment comment of ldap server
 * @return      bool                            true = success
*/
bool ds_wsp_helper::m_cb_get_ldap_srv( int in_index,
                                       dsd_unicode_string* ads_name,
                                       dsd_unicode_string* ads_comment )
{
    // initialize some variables:
    bool                   bo_ret;
    dsd_aux_get_ldap_entry ds_ldap_req;

    ds_ldap_req.imc_no_entry = in_index;
    bo_ret = m_call_aux( DEF_AUX_GET_LDAP_CONF, &ds_ldap_req,
                         sizeof(dsd_aux_get_ldap_entry) );
    if (    bo_ret == false 
         || ds_ldap_req.boc_ret_ok == FALSE ) {
        return false;
    }

    if ( ads_name != NULL ) {
        memcpy( ads_name, &ds_ldap_req.dsc_ret_name,
                sizeof(dsd_unicode_string) );
    }
    if ( ads_comment != NULL ) {
        memcpy( ads_comment, &ds_ldap_req.dsc_ret_comment,
                sizeof(dsd_unicode_string) );
    }
    return true;
} // end of ds_wsp_helper::m_cb_get_ldap_srv


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_cb_set_ldap_srv
 *
 * @param[in]   int         in_index
 * @return      bool                        true = success
*/
bool ds_wsp_helper::m_cb_set_ldap_srv( int in_index )
{
    // initialize some variables:
    bool                   bo_ret;
    dsd_aux_set_ldap_entry ds_ldap_req;

    ds_ldap_req.imc_no_entry = in_index;
    bo_ret = m_call_aux( DEF_AUX_SET_LDAP_CONF, &ds_ldap_req,
                         sizeof(dsd_aux_set_ldap_entry) );

    if (    bo_ret == false 
         || ds_ldap_req.boc_ret_ok == FALSE ) {
        return false;
    }
    return true;
} // end of ds_wsp_helper::m_cb_set_ldap_srv


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_set_ldap_srv
 *
 * @param[in]   const char* ach_name        name of ldap server
 * @param[in]   int         in_len_name     length of name
 * @return      bool                        true = success
*/
bool ds_wsp_helper::m_set_ldap_srv( const char* ach_name, int in_len_name )
{
    // initialize some variables:
    int                       inl_count;     // total number of ldap servers
    int                       inl_server;    // current ldap server
    bool                      bol_ret;       // return value
    struct dsd_unicode_string dsl_srv_name;  // current server name
    BOOL                      bol_compare;   // result of string compare
    int                       inl_compare;   // result of string compare

    inl_count = m_cb_count_ldap_srv();
    for ( inl_server = 0; inl_server < inl_count; inl_server++ ) {
        bol_ret = m_cb_get_ldap_srv( inl_server, &dsl_srv_name, NULL );
        if (    bol_ret     == true
             && in_len_name == m_len_vx_vx( ied_chs_utf_8,
                                            dsl_srv_name.ac_str, 
                                            dsl_srv_name.imc_len_str,
                                            dsl_srv_name.iec_chs_str ) ) {
            bol_compare = m_cmp_vx_vx( &inl_compare,
                                       (void*)ach_name, in_len_name, ied_chs_utf_8,
                                       dsl_srv_name.ac_str, dsl_srv_name.imc_len_str,
                                       dsl_srv_name.iec_chs_str );
            if ( bol_compare == TRUE && inl_compare == 0 ) {
                m_cb_set_ldap_srv( inl_server );
                return true;
            }
        }
    }
    return false;
} // end of ds_wsp_helper::m_set_ldap_srv


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_reset_ldap_srv
 * reset selected ldap server
 *
 * @return  bool                true = success
*/
bool ds_wsp_helper::m_reset_ldap_srv()
{
    // initialize some variables:
    struct dsd_aux_rel_ldap_entry dsl_ldap;
    bool                          bol_ret;

    bol_ret = m_call_aux( DEF_AUX_REL_LDAP_CONF, &dsl_ldap,
                          sizeof(struct dsd_aux_rel_ldap_entry) );
    if (    bol_ret                   == true
         && dsl_ldap.iec_ret_rel_ldap == ied_ret_rel_ldap_ok ) {
        return true;
    }
    return false;
} // end of ds_wsp_helper::m_reset_ldap_srv


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_ldap_request
 * do ldap request
 *
 * @param[in]   dsd_co_ldap_1*
*/
bool ds_wsp_helper::m_cb_ldap_request( dsd_co_ldap_1* adsp_co_ldap )
{
    return m_call_aux( DEF_AUX_LDAP_REQUEST, adsp_co_ldap, sizeof(struct dsd_co_ldap_1) );
} // end of ds_wsp_helper::m_cb_ldap_request


/**
 * \ingroup winterface
 *
 * public funcion ds_wsp_helper::m_cb_count_radius_srv
 * get number of configured radius servers
 *
 * @return      int
*/
int ds_wsp_helper::m_cb_count_radius_srv()
{
    bool                            bol_ret;
    struct dsd_aux_get_radius_entry dsl_rad_req;

    dsl_rad_req.imc_no_entry = -1;
    bol_ret = m_call_aux( DEF_AUX_GET_RADIUS_CONF, &dsl_rad_req,
                          sizeof(struct dsd_aux_get_radius_entry) );
    if ( bol_ret == false ) {
        return 0;
    }
    return (int)dsl_rad_req.imc_ret_conf_entry;
} // end of ds_wsp_helper::m_cb_count_radius_srv


/**
 * \ingroup winterface
 *
 * public funcion ds_wsp_helper::m_cb_get_radius_srv
 * get name and comment from radius server with given index number
 *
 * @param[in]   int                inp_index        index number of ldap server
 * @param[out]  dsd_unicode_string *adsp_name       name of ldap server
 * @param[out]  dsd_unicode_string *adsp_comment    comment of ldap server
 * @return      bool                                true = success
*/
bool ds_wsp_helper::m_cb_get_radius_srv( int inp_index,
                                         struct dsd_unicode_string *adsp_name,
                                         struct dsd_unicode_string *adsp_comment )
{
    bool                            bol_ret;
    struct dsd_aux_get_radius_entry dsl_rad_req;

    dsl_rad_req.imc_no_entry = inp_index;
    bol_ret = m_call_aux( DEF_AUX_GET_RADIUS_CONF, &dsl_rad_req,
                          sizeof(struct dsd_aux_get_radius_entry) );
    if (    bol_ret                == false 
         || dsl_rad_req.boc_ret_ok == FALSE ) {
        return false;
    }

    if ( adsp_name != NULL ) {
        memcpy( adsp_name, &dsl_rad_req.dsc_ret_name,
                sizeof(struct dsd_unicode_string) );
    }
    if ( adsp_comment != NULL ) {
        memcpy( adsp_comment, &dsl_rad_req.dsc_ret_comment,
                sizeof(struct dsd_unicode_string) );
    }
    return true;
} // end of ds_wsp_helper::m_cb_get_radius_srv


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_cb_set_radius_srv
 *
 * @param[in]   int         inp_index
 * @return      bool                        true = success
*/
bool ds_wsp_helper::m_cb_set_radius_srv( int inp_index )
{
    bool                            bol_ret;
    struct dsd_aux_set_radius_entry dsl_rad_req;

    dsl_rad_req.imc_no_entry = inp_index;
    bol_ret = m_call_aux( DEF_AUX_SET_RADIUS_CONF, &dsl_rad_req,
                          sizeof(struct dsd_aux_set_radius_entry) );

    if (    bol_ret                == false 
         || dsl_rad_req.boc_ret_ok == FALSE ) {
        return false;
    }
    return true;
} // end of ds_wsp_helper::m_cb_set_radius_srv


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_set_radius_srv
 *
 * @param[in]   const char  *achp_name      name of ldap server
 * @param[in]   int         inp_len_name    length of name
 * @return      bool                        true = success
*/
bool ds_wsp_helper::m_set_radius_srv( const char* achp_name, int inp_len_name )
{
    int                       inl_count;     // total number of servers
    int                       inl_server;    // current ldap server
    bool                      bol_ret;       // return value
    struct dsd_unicode_string dsl_srv_name;  // current server name
    BOOL                      bol_compare;   // result of string compare
    int                       inl_compare;   // result of string compare

    inl_count = m_cb_count_radius_srv();
    for ( inl_server = 0; inl_server < inl_count; inl_server++ ) {
        bol_ret = m_cb_get_radius_srv( inl_server, &dsl_srv_name, NULL );
        if (    bol_ret      == true
             && inp_len_name == m_len_vx_vx( ied_chs_utf_8,
                                             dsl_srv_name.ac_str, 
                                             dsl_srv_name.imc_len_str,
                                             dsl_srv_name.iec_chs_str ) ) {
            bol_compare = m_cmp_vx_vx( &inl_compare,
                                       (void*)achp_name, inp_len_name, ied_chs_utf_8,
                                       dsl_srv_name.ac_str, dsl_srv_name.imc_len_str,
                                       dsl_srv_name.iec_chs_str );
            if ( bol_compare == TRUE && inl_compare == 0 ) {
                m_cb_set_radius_srv( inl_server );
                return true;
            }
        }
    }
    return false;
} // end of ds_wsp_helper::m_set_radius_srv


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_reset_radius_srv
 * reset selected radius server
 *
 * @return  bool                true = success
*/
bool ds_wsp_helper::m_reset_radius_srv()
{
    // initialize some variables:
    struct dsd_aux_rel_radius_entry dsl_rad;
    bool                            bol_ret;

    bol_ret = m_call_aux( DEF_AUX_REL_RADIUS_CONF, &dsl_rad,
                          sizeof(struct dsd_aux_rel_radius_entry) );
    if (    bol_ret                   == true
        && dsl_rad.iec_ret_rel_radius == ied_ret_rel_radius_ok ) {
        return true;
    }
    return false;
} // end of ds_wsp_helper::m_reset_radius_srv


/**
 * \ingroup winterface
 *
 * public funcion ds_wsp_helper::m_cb_count_krb5_srv
 * get number of configured kerberos servers
 *
 * @return      int
*/
int ds_wsp_helper::m_cb_count_krb5_srv()
{
    // initialize some variables:
    bool                   bo_ret;
    dsd_aux_get_krb5_entry ds_krb5_req;

    ds_krb5_req.imc_no_entry = -1;
    bo_ret = m_call_aux( DEF_AUX_GET_KRB5_CONF, &ds_krb5_req,
                         sizeof(dsd_aux_get_krb5_entry) );
    if ( bo_ret == false ) {
        return 0;
    }
    return (int)ds_krb5_req.imc_ret_conf_entry;
} // end of ds_wsp_helper::m_cb_count_krb5_srv


/**
 * \ingroup winterface
 *
 * public funcion ds_wsp_helper::m_cb_get_krb5_srv
 * get name and comment of a kerberos server with given index number
 *
 * @param[in]   int                 in_index    index number of krb5 server
 * @param[out]  dsd_unicode_string* ads_name    name of krb5 server
 * @param[out]  dsd_unicode_string* ads_comment comment of krb5 server
 * @return      bool                            true = success
*/
bool ds_wsp_helper::m_cb_get_krb5_srv( int in_index,
                                       dsd_unicode_string* ads_name,
                                       dsd_unicode_string* ads_comment )
{
    // initialize some variables:
    bool                   bo_ret;
    dsd_aux_get_krb5_entry ds_krb5_req;

    ds_krb5_req.imc_no_entry = in_index;
    bo_ret = m_call_aux( DEF_AUX_GET_KRB5_CONF, &ds_krb5_req,
                         sizeof(dsd_aux_get_krb5_entry) );
    if (    bo_ret == false 
         || ds_krb5_req.boc_ret_ok == FALSE ) {
        return false;
    }

    if ( ads_name != NULL ) {
        memcpy( ads_name, &ds_krb5_req.dsc_ret_name,
                sizeof(dsd_unicode_string) );
    }
    if ( ads_comment != NULL ) {
        memcpy( ads_comment, &ds_krb5_req.dsc_ret_comment,
                sizeof(dsd_unicode_string) );
    }
    return true;
} // end of ds_wsp_helper::m_cb_get_krb5_srv


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_cb_set_krb5_srv
 *
 * @param[in]   int         in_index
 * @return      bool                        true = success
*/
bool ds_wsp_helper::m_cb_set_krb5_srv( int in_index )
{
    // initialize some variables:
    bool                   bo_ret;
    dsd_aux_set_krb5_entry ds_krb5_req;

    ds_krb5_req.imc_no_entry = in_index;
    bo_ret = m_call_aux( DEF_AUX_SET_KRB5_CONF, &ds_krb5_req,
                         sizeof(dsd_aux_set_krb5_entry) );

    if (    bo_ret == false 
         || ds_krb5_req.boc_ret_ok == FALSE ) {
        return false;
    }
    return true;
} // end of ds_wsp_helper::m_cb_set_krb5_srv


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_set_krb5_srv
 *
 * @param[in]   const char* ach_name        name of ldap server
 * @param[in]   int         in_len_name     length of name
 * @return      bool                        true = success
*/
bool ds_wsp_helper::m_set_krb5_srv( const char* ach_name, int in_len_name )
{
    // initialize some variables:
    int                       inl_count;     // total number of ldap servers
    int                       inl_server;    // current ldap server
    bool                      bol_ret;       // return value
    struct dsd_unicode_string dsl_srv_name;  // current server name
    BOOL                      bol_compare;   // result of string compare
    int                       inl_compare;   // result of string compare

    inl_count = m_cb_count_krb5_srv();
    for ( inl_server = 0; inl_server < inl_count; inl_server++ ) {
        bol_ret = m_cb_get_krb5_srv( inl_server, &dsl_srv_name, NULL );
        if (    bol_ret     == true
             && in_len_name == m_len_vx_vx( ied_chs_utf_8,
                                            dsl_srv_name.ac_str, 
                                            dsl_srv_name.imc_len_str,
                                            dsl_srv_name.iec_chs_str ) ) {
            bol_compare = m_cmp_vx_vx( &inl_compare,
                                       (void*)ach_name, in_len_name, ied_chs_utf_8,
                                       dsl_srv_name.ac_str, dsl_srv_name.imc_len_str,
                                       dsl_srv_name.iec_chs_str );
            if ( bol_compare == TRUE && inl_compare == 0 ) {
                m_cb_set_krb5_srv( inl_server );
                return true;
            }
        }
    }
    return false;
} // end of ds_wsp_helper::m_set_krb5_srv


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_reset_krb5_srv
 * reset selected krb5 server
 *
 * @return  bool                true = success
*/
bool ds_wsp_helper::m_reset_krb5_srv()
{
    // initialize some variables:
    struct dsd_aux_rel_krb5_entry dsl_krb5;
    bool                          bol_ret;

    bol_ret = m_call_aux( DEF_AUX_REL_KRB5_CONF, &dsl_krb5,
                          sizeof(struct dsd_aux_rel_krb5_entry) );
    if (    bol_ret                   == true
         && dsl_krb5.iec_ret_rel_krb5 == ied_ret_rel_krb5_ok ) {
        return true;
    }
    return false;
} // end of ds_wsp_helper::m_reset_krb5_srv


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_cb_auth_krb5
 * do kerberos authentication
 *
 * @param[in]   dsd_aux_krb5_sign_on_1* ads_krb5_auth
 * @return      bool                                    true = auth successful
*/
bool ds_wsp_helper::m_cb_auth_krb5( struct dsd_aux_krb5_sign_on_1* ads_krb5_auth )
{
    // initialize some variables:
    bool bo_ret;

    bo_ret = m_call_aux( DEF_AUX_KRB5_SIGN_ON, ads_krb5_auth,
                         sizeof(dsd_aux_krb5_sign_on_1 ) );
    if (    bo_ret == false
         || ads_krb5_auth->iec_ret_krb5 != ied_ret_krb5_ok ) {
        return false;
    }
    return true;
} // end of ds_wsp_helper::m_cb_auth_krb5


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_cb_krb5_get_service_ticket
 * get a service ticket from KDC
 *
 * @param[in]   dsd_aux_krb5_se_ti_get_1* ads_krb5
 * @return      bool true = successful
*/
bool ds_wsp_helper::m_cb_krb5_get_service_ticket( struct dsd_aux_krb5_se_ti_get_1* ads_krb5 )
{
    // initialize some variables:
    bool bo_ret;

    bo_ret = m_call_aux( DEF_AUX_KRB5_SE_TI_GET, ads_krb5,
                         sizeof(dsd_aux_krb5_se_ti_get_1) );
    if (    bo_ret == false
         || ads_krb5->iec_ret_krb5 != ied_ret_krb5_ok ) {
        return false;
    }
    return true;
} // end of ds_wsp_helper::m_cb_krb5_get_service_ticket


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_cb_krb5_check_service_ticket_response
 * A service ticket was delivered to a server and for example 'mutual authentication'
 * requested. Investigate the server's response.
 *
 * @param[in]   dsd_aux_krb5_se_ti_c_r_1* ads_krb5
 * @return      bool true = successful
*/
bool ds_wsp_helper::m_cb_krb5_check_service_ticket_response( struct dsd_aux_krb5_se_ti_c_r_1* ads_krb5 )
{
    // initialize some variables:
    bool bo_ret;

    bo_ret = m_call_aux( DEF_AUX_KRB5_SE_TI_C_R, ads_krb5,
                         sizeof(dsd_aux_krb5_se_ti_c_r_1) );
    if (    bo_ret == false
         || ads_krb5->iec_ret_krb5 != ied_ret_krb5_ok ) {
        return false;
    }
    return true;
} // end of ds_wsp_helper::m_cb_krb5_check_service_ticket_response


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_cb_logout_krb5
 * logout from kerberos, means delete TGT cma for current user
 *
 * @return  bool        true = logoff successful
*/
bool ds_wsp_helper::m_cb_logout_krb5()
{
    // initialize some variables:
    bool                       bol_ret;
    struct dsd_aux_krb5_logoff dsl_krb5_logout;

    bol_ret = m_call_aux( DEF_AUX_KRB5_LOGOFF, &dsl_krb5_logout,
                          sizeof(dsd_aux_krb5_logoff) );

    if (    bol_ret == false
         || dsl_krb5_logout.iec_ret_krb5 != ied_ret_krb5_ok ) {
        return false;
    }
    return true;
} // end of ds_wsp_helper::m_cb_logout_krb5


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_use_storage
 * activate usage of storage container
 *
 * @param[in]   void**  aav_storage     pointer pointer to storage container struct
 * @param[in]   int     in_size         default size of storage container
*/
void ds_wsp_helper::m_use_storage( void** aav_storage, int in_size )
{
#ifndef IGNORE_STORAGE_CONTAINER
    bool bo_init = false;

    if ( *aav_storage == NULL ) {
        bo_init = true;

        // get memory for storage container:
        *aav_storage = (struct dsd_stor_sdh_1*)m_cb_get_memory(  sizeof(struct dsd_stor_sdh_1), true );
        if ( *aav_storage == NULL ) {
            m_cb_print_out( "HWSPHW019W cannot get storage structure memory" );
            return;
        }
    }
    
    // save our structure pointer (for internal use):
    ads_storage = (struct dsd_stor_sdh_1*)*aav_storage;

    // initialize storage struct:
    m_init_storage();

    if ( bo_init == true ) {
        // set default block size:
        ads_storage->imc_stor_size = in_size;

        // init storage container:
        m_aux_stor_start( ads_storage );
    }
#else
    *aav_storage = NULL;
#endif
} // end of ds_wsp_helper::m_use_storage


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_no_storage
 * deactivate usage of storage container
 *
 * @param[in]   void**  aav_storage     pointer pointer to storage container struct
*/
void ds_wsp_helper::m_no_storage( void** aav_storage )
{
    // save our structure pointer (for internal use):
    ads_storage = (struct dsd_stor_sdh_1*)*aav_storage;

    if ( ads_storage != NULL ) {
        m_init_storage();
        m_aux_stor_end( ads_storage );

        ads_storage = NULL;

        m_cb_free_memory( *aav_storage, sizeof(struct dsd_stor_sdh_1) );
        *aav_storage = NULL;
    }
} // end of ds_wsp_helper::m_no_storage


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_new_storage_cont
 *  create a new storage container for your own use
 *
 * @param[in]   dsd_stor_sdh_1  *adsp_container
 * @param[in]   int             inp_size
 * @return      bool
*/
bool ds_wsp_helper::m_new_storage_cont( struct dsd_stor_sdh_1 *adsp_container,
                                        int inp_size )
{
    switch ( work_mode ) {
        case ien_trans:
            adsp_container->amc_aux     = ads_trans->amc_aux;
            adsp_container->vpc_userfld = ads_trans->vpc_userfld;
            break;
        case ien_conf:
            adsp_container->amc_aux     = ads_conf->amc_aux;
            adsp_container->vpc_userfld = ads_conf->vpc_userfld;
            break;
        case ien_wspat3:
            adsp_container->amc_aux     = ads_wspat3->amc_aux;
            adsp_container->vpc_userfld = ads_wspat3->vpc_userfld;
            break;
        default:
            return false;
    }
    adsp_container->imc_stor_size = inp_size;
    m_aux_stor_start( adsp_container );
    return true;
} // end of ds_wsp_helper::m_new_storage_cont


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_del_storage_cont
 *  delete a storage container for your own use
 *
 * @param[in]   dsd_stor_sdh_1  *adsp_container
*/
void ds_wsp_helper::m_del_storage_cont( struct dsd_stor_sdh_1 *adsp_container )
{
    m_aux_stor_end( adsp_container );
} // end of ds_wsp_helper::m_no_storage


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_init_storage
 * initialize userfield and aux function for storage container
*/
void ds_wsp_helper::m_init_storage()
{
    if ( ads_storage == NULL ) {
        return;
    }
    switch ( work_mode ) {
        case ien_trans:
            ads_storage->amc_aux     = ads_trans->amc_aux;
            ads_storage->vpc_userfld = ads_trans->vpc_userfld;
            break;
        case ien_conf:
            ads_storage->amc_aux     = ads_conf->amc_aux;
            ads_storage->vpc_userfld = ads_conf->vpc_userfld;
            break;
        case ien_wspat3:
            ads_storage->amc_aux     = ads_wspat3->amc_aux;
            ads_storage->vpc_userfld = ads_wspat3->vpc_userfld;
            break;
        default:
            // if no valid mode is defined, we must use normal
            // printf to print an error message!
            m_debug_printf("HWSPHW020W no valid mode in ds_wsp_helper::m_init_storage selected!\n");
            break;
    }
} // end of ds_wsp_helper::m_init_storage


/**
 * \ingroup winterface
 *
 * ds_wsp_helper::m_get_config
 * get our configuration as structure
 *
 * @return  void*       pointer to config
*/
void* ds_wsp_helper::m_get_config()
{
    switch ( work_mode ) {
        case ien_trans:
            return (void*)ads_trans->ac_conf;
        case ien_conf:
            return (void*)(*ads_conf->aac_conf);
        case ien_wspat3:
            return (void*)ads_wspat3->ac_conf;
        default:
            // if no valid mode is defined, we must use normal
            // printf to print an error message!
            m_debug_printf("HWSPHW021W no valid mode in ds_wsp_helper::m_get_config selected!\n");
            return NULL;
    }
} // end of ds_wsp_helper::m_get_config


/**
 * \ingroup winterface
 *
 * ds_wsp_helper::m_get_wspat_config
 * get configuration from wpat as structure
 *
 * @return      dsd_wspat_pconf_t*      pointer to public config structure
*/
dsd_wspat_pconf_t* ds_wsp_helper::m_get_wspat_config()
{
    switch ( work_mode ) {
        case ien_trans:
            if ( ads_trans->ac_hobwspat3_conf != NULL ) {
                return (dsd_wspat_pconf_t*)((char*)ads_trans->ac_hobwspat3_conf + sizeof(dsd_sdh_log_t));
            }
            return NULL;

        case ien_conf:
            return NULL;

        case ien_wspat3:
            if ( ads_wspat3->ac_conf != NULL ) {
                return (dsd_wspat_pconf_t*)((char*)ads_wspat3->ac_conf + sizeof(dsd_sdh_log_t));
            }
            return NULL;

        default:
            // if no valid mode is defined, we must use normal
            // printf to print an error message!
            m_debug_printf("HWSPHW042W no valid mode in ds_wsp_helper::m_get_config selected!\n");
            return NULL;
    }
} // end of ds_wsp_helper::m_get_wspat_config


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_init_config
 * initialize (means get memory) config
 *
 * @param[in]   int     in_size         needed size
 * @return      bool                    true = success
*/
bool ds_wsp_helper::m_init_config( int in_size )
{
    bool bo_ret = false;

    switch ( work_mode ) {
        case ien_trans:
            m_cb_print_out( "HWSPHW022W m_init_conf not allowed in trans mode" );
            break;
        case ien_conf:
            *(ads_conf->aac_conf) = (void*)m_cb_get_memory( in_size, false );
            if ( *ads_conf->aac_conf != NULL ) {
                bo_ret = true;
            }
            break;
        case ien_wspat3:
            m_cb_print_out( "HWSPHW023W m_init_conf not allowed in auth mode" );
            break;
        default:
            // if no valid mode is defined, we must use normal
            // printf to print an error message!
            m_debug_printf("HWSPHW024W no valid mode in ds_wsp_helper::m_init_config selected!\n");
            break;
    }
    return bo_ret;
} // end of ds_wsp_helper::m_init_config
    

/**
 * \ingroup winterface
 *
 * ds_wsp_helper::m_copy_to_config
 * copy data into our config memory
 *
 * @param[in]       void*   av_data         data to copy in
 * @param[in]       int     in_len          length of data
 * @param[in/out]   int*    ain_offset      offset in config buffer
 * @param[in]       int     in_max_len      max len off config buffer
 * @param[in]       bool    bo_align        align data?
 * @return          bool                    true = success
*/
bool ds_wsp_helper::m_copy_to_config( const void* av_data,   int in_len, 
                                      int* ain_offset, int in_max_len,
                                      bool bo_align )
{
    if ( work_mode != ien_conf ) {
        m_cb_print_out( "HWSPHW025W copy config to memory only allowed in conf mode" );
        return false;
    }

    int in_copied = m_copy_data( av_data, in_len,
                                 *(ads_conf->aac_conf), in_max_len,
                                 ain_offset, bo_align );
    if ( in_copied != in_len ) {
        m_cb_print_out( "HWSPHW026W copy config to memory failed" );
        return false;
    }
    return true;
} // end of ds_wsp_helper::m_copy_to_config



/**
 * \ingroup winterface
 *
 * Determines, whether the passed log-level would lead to a log entry.
 * public function ds_wsp_helper::m_is_logable
 *
 * @param[in]   ied_sdh_log_level   ien_level
 * @return      bool                true =  The passed log-level would lead to a log entry.
*/
bool ds_wsp_helper::m_is_logable( ied_sdh_log_level ien_level )
{
    // get our configuration
    dsd_sdh_log_t*  ads_config = (dsd_sdh_log_t*)m_get_config();
    if ( ads_config == NULL ) {
        return false;
    }

    // check if log is activated
    if ( ads_config->boc_active == false ) {
        return false;
    }

    // check log level:
    if ( ien_level < ads_config->iec_level ) {
        return false;
    }

    return true;
}



/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_log
 *
 * @param[in]   ied_sdh_log_level   ien_level
 * @param[in]   const char*         ach_to_log      log messages
*/
void ds_wsp_helper::m_log( ied_sdh_log_level ien_level, const dsd_const_string& ach_to_log )
{
    // initialize some variables:
    FILE*           av_log;
    const char*     ach_version;
    const char*     ach_timestamp;
#ifdef HL_UNIX
    struct timeb    ds_time;
#else
    struct _timeb   ds_time;
#endif

    //---------------------------------------------
    // print non-info messages also on console:
    //---------------------------------------------
    if ( ien_level > ied_sdh_log_info ) {
        m_cb_print_out( ach_to_log );
    }

    //---------------------------------------------
    // open logfile:
    //---------------------------------------------
    av_log = m_open_log( ien_level, &ach_version );
    if ( av_log == NULL ) {
        return;
    }

    //---------------------------------------------
    // get timestamp:
    //---------------------------------------------
#ifdef HL_UNIX
    ftime( &ds_time );
#else
    _ftime( &ds_time );
#endif
    ach_timestamp = ctime( &ds_time.time );

    //---------------------------------------------
    // print to file:
    //---------------------------------------------
    fprintf( av_log, "*********************************\n");
    fprintf( av_log, "Connection-ID: %d   %.*s   Time: %.15s.%03hu   Version: %s\n", 
                     m_get_session_id(), ach_to_log.m_get_len(), ach_to_log.m_get_ptr(),
                     &ach_timestamp[4],  ds_time.millitm,
                     ach_version );
    fprintf( av_log, "*********************************\n");

    //---------------------------------------------
    // close logfile:
    //---------------------------------------------
    m_close_log( av_log );
} // end of ds_wsp_helper::m_log


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_logf
 *
 * @param[in]   ied_sdh_log_level   ien_level
 * @param[in]   const char*         ach_format
 * ...
*/
void ds_wsp_helper::m_logf( ied_sdh_log_level ien_level, HL_FORMAT_STRING const char* ach_format, ... )
{
    // initialize some variables:
    char    rch_buffer[BUF_SIZE + 1];    // buffer for printing
    int     in_size;                // used buffer size
    va_list args;                   // argument list

    // try to print in our memory (function will give us needed mem size)
    va_start( args, ach_format );
    in_size = vsnprintf( &rch_buffer[0], BUF_SIZE, ach_format, args );
    va_end( args );

    // zero termination:
    if ( in_size > BUF_SIZE || in_size < 0 ) {
        in_size = BUF_SIZE;
    }
    rch_buffer[in_size] = 0;

    return m_log( ien_level, dsd_const_string(rch_buffer, in_size) );
} // end of ds_wsp_helper::m_logf

/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_logf
 *
 * @param[in]   ied_sdh_log_level   ien_level
 * @param[in]   const char*         ach_format
 * ...
*/
void ds_wsp_helper::m_logf2( ied_sdh_log_level ien_level, const char* ach_format, ... )
{
    // initialize some variables:
    char    rch_buffer[BUF_SIZE + 1];    // buffer for printing
    int     in_size;                // used buffer size
    va_list args;                   // argument list

    // try to print in our memory (function will give us needed mem size)
    va_start( args, ach_format );
    in_size = m_hlvsnprintf( &rch_buffer[0], BUF_SIZE, ied_chs_utf_8, ach_format, args );
    va_end( args );

    // zero termination:
    if ( in_size > BUF_SIZE || in_size < 0 ) {
        in_size = BUF_SIZE;
    }
    rch_buffer[in_size] = 0;

    return m_log( ien_level, rch_buffer );
} // end of ds_wsp_helper::m_logf

/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_log_input
 *
 * log data from input gather
*/
void ds_wsp_helper::m_log_input()
{
    // initialize some variables:
    FILE*           av_log;
    const char*     ach_version;
    const char*     ach_timestamp;
    const char*     ach_connection = "";
    const char*     ach_closed     = "";
    dsd_gather_i_1* ads_input;
    int             in_gathers;
    int             in_length;
#ifdef HL_UNIX
    struct timeb    ds_time;
#else
    struct _timeb   ds_time;
#endif

    //---------------------------------------------
    // check workmode:
    //---------------------------------------------
    if (    work_mode != ien_trans
         && work_mode != ien_wspat3 ) {
        return;
    }

    //---------------------------------------------
    // open logfile:
    //---------------------------------------------
    av_log = m_open_log( ied_sdh_log_error, &ach_version );
    if ( av_log == NULL ) {
        return;
    }

    //---------------------------------------------
    // get timestamp:
    //---------------------------------------------
#ifdef HL_UNIX
    ftime( &ds_time );
#else
    _ftime( &ds_time );
#endif
    ach_timestamp = ctime( &ds_time.time );

    //---------------------------------------------
    // get special messages:
    //---------------------------------------------
    if ( work_mode == ien_trans ) {
        //-----------------------------------------
        // get connection string:
        //-----------------------------------------
        if ( ads_trans->inc_func == DEF_IFUNC_START ) {
            ach_connection = (char*)"Connection OPENED";
        } else if ( ads_trans->inc_func == DEF_IFUNC_CLOSE ) {
            ach_connection = (char*)"Connection CLOSED";
        } else if ( ads_trans->inc_func == DEF_IFUNC_FROMSERVER ) {
            ach_connection = (char*)"FromServer";
        } else if ( ads_trans->inc_func == DEF_IFUNC_TOSERVER ) {
            ach_connection = (char*)"FromClient";
        } else {
            ach_connection = (char*)"Reflection";
        }
        
        //-----------------------------------------
        // get close string:
        //-----------------------------------------
        if ( ads_trans->boc_eof_client == TRUE ) {
            ach_closed = (char*)"- closed by client";
        } else if ( ads_trans->boc_eof_server == TRUE ) {
            ach_closed = (char*)"- closed by server";
        }
    } else {
        //-----------------------------------------
        // get close string:
        //-----------------------------------------
        if ( ads_wspat3->boc_eof_client == TRUE ) {
            ach_closed = (char*)"- closed by client";
        }        
    }

    //---------------------------------------------
    // print header:
    //---------------------------------------------
    fprintf( av_log, "--------------------------------------------------------\n" );
    fprintf( av_log, "Connection-ID: %d   Time: %.15s.%03hu   Version: %s\n",
                     m_get_session_id(), &ach_timestamp[4], ds_time.millitm,
                     ach_version );
    if ( work_mode == ien_trans ) {
        fprintf( av_log, "WSP-FUNCTION: %d(%s) (IN %s) callagain: %d  callrevdir: %d\n",
                         ads_trans->inc_func, ach_connection, ach_closed,
                         ads_trans->boc_callagain, ads_trans->boc_callrevdir );
    } else {
        fprintf( av_log, "WSP-FUNCTION: %d (IN %s) callagain: %d\n",
                         ads_wspat3->iec_at_function, ach_closed,
                         ads_wspat3->boc_callagain );
    }

    //---------------------------------------------
    // print gather chain:
    //---------------------------------------------
    ads_input = m_get_input();
    if ( ads_input != NULL ) {
        in_gathers = 1;

        do {
            in_length = (int)(ads_input->achc_ginp_end - ads_input->achc_ginp_cur);
            fprintf( av_log, "INPUT gather item %d:  achc_ginp_cur: %p  achc_ginp_end: %p    len: %d / 0x%x\n",
                             in_gathers,
                             ads_input->achc_ginp_cur, ads_input->achc_ginp_end,
                            in_length, in_length );

            // print hex:
            m_dump_data( (unsigned char *)ads_input->achc_ginp_cur, in_length, (FILE*)av_log );

            // get next from chain:
            ads_input = ads_input->adsc_next;
            in_gathers++;
        } while ( ads_input != NULL );
    }

    //---------------------------------------------
    // close logfile:
    //---------------------------------------------
    m_close_log( av_log );
} // end of ds_wsp_helper::m_log_input


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_log_output
 *
 * log data from output gather
*/
void ds_wsp_helper::m_log_output()
{
    // initialize some variables:
    FILE*           av_log;
    const char*     ach_version;
    const char*     ach_timestamp;
    const char*     ach_connection = "";
    const char*     ach_closed     = "";
    dsd_gather_i_1* ads_gather;
    int             in_gathers;
    int             in_length;
#ifdef HL_UNIX
    struct timeb    ds_time;
#else
    struct _timeb   ds_time;
#endif

    //---------------------------------------------
    // check workmode:
    //---------------------------------------------
    if (    work_mode != ien_trans
         && work_mode != ien_wspat3 ) {
        return;
    }

    //---------------------------------------------
    // open logfile:
    //---------------------------------------------
    av_log = m_open_log( ied_sdh_log_error, &ach_version );
    if ( av_log == NULL ) {
        return;
    }

    //---------------------------------------------
    // get timestamp:
    //---------------------------------------------
#ifdef HL_UNIX
    ftime( &ds_time );
#else
    _ftime( &ds_time );
#endif
    ach_timestamp = ctime( &ds_time.time );

    //---------------------------------------------
    // get special messages:
    //---------------------------------------------
    if ( work_mode == ien_trans ) {
        //-----------------------------------------
        // get connection string:
        //-----------------------------------------
        if ( ads_trans->inc_func == DEF_IFUNC_START ) {
            ach_connection = (char*)"Connection OPENED";
        } else if ( ads_trans->inc_func == DEF_IFUNC_CLOSE ) {
            ach_connection = (char*)"Connection CLOSED";
        } else if ( ads_trans->inc_func == DEF_IFUNC_FROMSERVER ) {
            ach_connection = (char*)"ToClient";
        } else if ( ads_trans->inc_func == DEF_IFUNC_TOSERVER ) {
            ach_connection = (char*)"ToServer";
        } else {
            ach_connection = (char*)"Reflection";
        }

        if ( ads_trans->adsc_gai1_out_to_client ) {
            ach_connection = (char*)"ToClient";
        } else if ( ads_trans->adsc_gai1_out_to_server ) {
            ach_connection = (char*)"ToServer";
        }
        
        //-----------------------------------------
        // get close string:
        //-----------------------------------------
        if ( ads_trans->boc_eof_client == TRUE ) {
            ach_closed = (char*)"- closed by client";
        } else if ( ads_trans->boc_eof_server == TRUE ) {
            ach_closed = (char*)"- closed by server";
        }
    } else {
        //-----------------------------------------
        // get close string:
        //-----------------------------------------
        if ( ads_wspat3->boc_eof_client == TRUE ) {
            ach_closed = (char*)"- closed by client";
        }        
    }

    //---------------------------------------------
    // print header:
    //---------------------------------------------
    fprintf( av_log, "<<<<<<<<<<<<<<\n" );
    fprintf( av_log, "Connection-ID: %d   Time: %.15s.%03hu   Version: %s\n",
                     m_get_session_id(), &ach_timestamp[4], ds_time.millitm,
                     ach_version );
    if ( work_mode == ien_trans ) {
        fprintf( av_log, "WSP-FUNCTION: %d(%s) (OUT %s) return-value: %d   callagain: %d   callrevdir: %d\n",
                         ads_trans->inc_func, ach_connection, ach_closed,
                         ads_trans->inc_return, ads_trans->boc_callagain, ads_trans->boc_callrevdir );
    } else {
        fprintf( av_log, "WSP-FUNCTION: %d (OUT %s) return-value: %d   callagain: %d\n",
                         ads_wspat3->iec_at_function, ach_closed,
                         ads_wspat3->iec_at_return, ads_wspat3->boc_callagain );
    }

    //---------------------------------------------
    // print input gather chain:
    //---------------------------------------------
    ads_gather = m_get_input();
    if ( ads_gather != NULL ) {
        in_gathers = 1;

        do {
            in_length = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
            fprintf( av_log, "INPUT gather item %d:  achc_ginp_cur: %p  achc_ginp_end: %p    len: %d / 0x%x\n",
                             in_gathers,
                             ads_gather->achc_ginp_cur, ads_gather->achc_ginp_end,
                             in_length, in_length );

            // print hex:
            m_dump_data( (unsigned char *)ads_gather->achc_ginp_cur, in_length, (FILE*)av_log );

            // get next from chain:
            ads_gather = ads_gather->adsc_next;
            in_gathers++;
        } while ( ads_gather != NULL );
    }

    //---------------------------------------------
    // print output gather chain:
    //---------------------------------------------
    ads_gather = m_get_output(ied_sdh_dd_toserver);
    if ( ads_gather != NULL ) {
        in_gathers = 1;

        do {
            in_length = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
            fprintf( av_log, "OUTPUT(ToServer) gather item %d:  achc_ginp_cur: %p  achc_ginp_end: %p len: %d / 0x%x conn-id: %d\n",
                             in_gathers,
                             ads_gather->achc_ginp_cur, ads_gather->achc_ginp_end,
                             in_length, in_length,
                             m_get_session_id() );

            // print hex:
            m_dump_data( (unsigned char *)ads_gather->achc_ginp_cur, in_length, (FILE*)av_log );

            // get next from chain:
            ads_gather = ads_gather->adsc_next;
            in_gathers++;
        } while ( ads_gather != NULL );
    }

	 //---------------------------------------------
    // print output gather chain:
    //---------------------------------------------
    ads_gather = m_get_output(ied_sdh_dd_toclient);
    if ( ads_gather != NULL ) {
        in_gathers = 1;

        do {
            in_length = (int)(ads_gather->achc_ginp_end - ads_gather->achc_ginp_cur);
            fprintf( av_log, "OUTPUT(ToClient) gather item %d:  achc_ginp_cur: %p  achc_ginp_end: %p len: %d / 0x%x conn-id: %d\n",
                             in_gathers,
                             ads_gather->achc_ginp_cur, ads_gather->achc_ginp_end,
                             in_length, in_length,
                             m_get_session_id() );

            // print hex:
            m_dump_data( (unsigned char *)ads_gather->achc_ginp_cur, in_length, (FILE*)av_log );

            // get next from chain:
            ads_gather = ads_gather->adsc_next;
            in_gathers++;
        } while ( ads_gather != NULL );
    }

    //---------------------------------------------
    // close logfile:
    //---------------------------------------------
    m_close_log( av_log );
} // end of ds_wsp_helper::m_log_output


/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/
/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_call_aux
 *
 * @param[in]   int     in_mode     KBs call mode
 * @param[in]   void*   av_data     aux params data
 * @param[in]   int     in_size     size of data
*/
bool ds_wsp_helper::m_call_aux( int in_mode, void* av_data, int in_size )
{
    BOOL bo_ret = FALSE;

    switch ( work_mode ) {
        case ien_trans:
            bo_ret = ads_trans->amc_aux( ads_trans->vpc_userfld,
                                         in_mode, av_data, in_size );
            break;
        case ien_conf:
            bo_ret = ads_conf->amc_aux( ads_conf->vpc_userfld,
                                        in_mode, av_data, in_size );
            break;
        case ien_wspat3:
            bo_ret = ads_wspat3->amc_aux( ads_wspat3->vpc_userfld,
                                          in_mode, av_data, in_size );
            break;
        default:
            // if no valid mode is defined, we must use normal
            // printf to print an error message!
            m_debug_printf("HWSPHW027W no valid mode in ds_wsp_helper::m_call_aux selected!\n");
            break;
    }
    
    return (bo_ret)?true:false;
} // end of ds_wsp_helper::m_call_aux


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_call_xerces
 *
 * @param[in]   DOMNode*            ads_node
 * @param[in]   int                 in_mode
 * @return      void*                           NULL in error cases
*/
void* ds_wsp_helper::m_call_xerces( DOMNode* ads_node, int in_mode )
{
    if ( ads_node == NULL ) {
        return NULL;
    }

    switch( work_mode ) {
        case ien_trans:
            m_cb_print_out( "HWSPHW028W xerces call is not supported in trans mode\n" );
            return NULL;
        case ien_conf:
            return ads_conf->amc_call_dom( ads_node, (ied_hlcldom_def)in_mode );
        case ien_wspat3:
            m_cb_print_out( "HWSPHW029W xerces call is not supported in auth mode\n" );
            return NULL;
        default:
            // if no valid mode is defined, we must use normal
            // printf to print an error message!
            m_debug_printf("HWSPHW030W no valid mode in ds_wsp_helper::m_call_xerces selected!\n");
            return NULL;
    }
} // end of ds_wsp_helper::m_call_xerces


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_admin
 *
 * ask wsp for admin informations
 *
 * @param[in]   dsd_aux_admin_1     ds_admin 
 *
 * @return      dsd_gather_i_1 *                        NULL in error case!
*/
struct dsd_gather_i_1 * ds_wsp_helper::m_cb_admin( struct dsd_aux_admin_1 ds_admin )
{
    // initialize some variables:
    bool bo_ret = false;

    bo_ret = m_call_aux( DEF_AUX_ADMIN,  /* administration request */
                         &ds_admin, sizeof(struct dsd_aux_admin_1) );

    // handle response:
    if ( bo_ret == false ) {
        if (    ds_admin.ilc_handle_cluster != 0
             && ds_admin.adsc_gai1_ret      != NULL ) {
            m_cb_print_out( "HWSPHW031W admin call failed!" );
        }
        return NULL;
    }
    return ds_admin.adsc_gai1_ret;
} // end of ds_wsp_helper::m_cb_admin


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_get_adm_command
 *
 * build admin interface command
 * returned memory must be freed outside!!!
 *
 *      command must look like this:
 *          ~ NHASN Length of following service name
 *          ~ service name itself
 *          ~ NASN Length of following query packet (type + structure + other data)
 *          ~ structure type
 *          ~ query packet
 *      if no query packet is send:
 *          ~ NHASN Length of following service name
 *          ~ service name itself
 *          ~ 1
 *          ~ 0
 *
 *
 * @param[in]   char*   ach_service         service name for command
 * @param[out]  int*    ain_len_out         out: total length of command
 * @param[in]   void*   ach_query           query to add (NULL is default)
 * @param[in]   int     in_len_query        length of query to add (0 is default)
 * @param[in]   char    ch_type             type of inserted query packet (0 is default)
 *
 * @return      char*                       pointer to command memory
 *                                          NULL in error case!
*/
char* ds_wsp_helper::m_get_adm_command( char* ach_service, int* ain_len_out,
                                        void* ach_query, int in_len_query,
                                        char  ch_type )
{
    // initialize some variables:
    char* ach_command  = NULL;  // returning command
    int   in_len_comm  = 0;     // length of command
    int   in_position  = 0;     // working position in command
    int   in_nhasn_ser = 0;     // needed length for nhasn length for service
    int   in_nhasn_que = 0;     // needed length for nhasn length for query
    int   in_len_serv  = (int)strlen(ach_service);

    if ( ach_query == NULL || in_len_query == 0 ) {
        // evaluate needed length:
        in_nhasn_ser = m_count_nhasn_len( in_len_serv );
        in_len_comm  =   in_nhasn_ser
                       + in_len_serv
                       + 2; // for sign '1' and terminating zero

        // get memory for command:
        ach_command = m_cb_get_memory( in_len_comm, true );
        if ( ach_command == NULL ) {
            return NULL;
        }

        // write service nhasn length:
        in_position = m_to_nhasn( in_len_serv, ach_command, in_nhasn_ser );
        if ( in_position < 0 ) {
            m_cb_free_memory( ach_command, in_len_comm );
            return NULL;
        }

        // copy service name
        memcpy( &ach_command[in_position], ach_service, in_len_serv );
        in_position += in_len_serv;
        ach_command[in_position] = 1;
    } else {
        // evaluate needed length:
        in_nhasn_ser = m_count_nhasn_len( in_len_serv );
        in_nhasn_que = m_count_nhasn_len( in_len_query + 1 ); // 1 for ch_type
        in_len_comm  =   in_nhasn_ser
                       + in_len_serv
                       + in_nhasn_que
                       + 1                      // for ch_type
                       + in_len_query;          // TODO: is a terminating zero needed?
        // get memory for command:
        ach_command = m_cb_get_memory( in_len_comm, true );
        if ( ach_command == NULL ) {
            return NULL;
        }

        // write service nhasn length:
        in_position = m_to_nhasn( in_len_serv, ach_command, in_nhasn_ser );
        if ( in_position < 0 ) {
            m_cb_free_memory( ach_command, in_len_comm );
            return NULL;
        }

        // copy service name
        memcpy( &ach_command[in_position], ach_service, in_len_serv );
        in_position += in_len_serv;

        // write query nhasn length:
        in_nhasn_que = m_to_nhasn( in_len_query + 1, 
                                   &ach_command[in_position],
                                   in_nhasn_que );
        if ( in_nhasn_que < 0 ) {
            m_cb_free_memory( ach_command, in_len_comm );
            return NULL;
        }
        in_position += in_nhasn_que;

        // copy ch_type:
        ach_command[in_position] = ch_type;
        in_position++;

        // copy query packet:
        memcpy( &ach_command[in_position], ach_query, in_len_query );
    }

    if ( ain_len_out ) {
        *ain_len_out = in_len_comm;
    }
    return ach_command;
} // end of ds_wsp_helper::m_get_adm_command


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_count_nhasn_len
 * 
 * get neede buffer length for in_input in nhasn format
 *
 * @param[in]   int     in_input
 *
 * @return      int                 needed buffer len
 *                                  or error code
*/
int ds_wsp_helper::m_count_nhasn_len( int in_input )
{
    int in_bytenum = 0;

    do {  //get the number of bytes needed for nhasn number encoded
        in_input >>= 7;
        in_bytenum++;
    } while (in_input);

    return in_bytenum;
} // end of ds_wsp_helper::m_count_nhasn_len


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_count_nhasn_len
 * 
 * get neede buffer length for in_input in nhasn format
 *
 * @param[in]   int     in_input
 * @param[in]   char*   ach_out
 * @param[in]   int     in_max_len
 *
 * @return      int                 written len
 *                                  negativ error
*/
int ds_wsp_helper::m_to_nhasn( int in_input, char* ach_out, int in_max_len )
{
    int   in_bytenum  = m_count_nhasn_len( in_input );
    int   in_work_len = in_bytenum;
    int   in_written  = 0;
    BYTE* ach_work    = (BYTE*)ach_out;

    if ( in_bytenum > in_max_len ) {
        return -1;
    }
                
    for ( int in_1 = 0; (in_1 < in_bytenum && in_work_len) ; in_1++ ) { 
        *ach_work = (BYTE)((in_input >> ((in_bytenum - in_1 - 1)*7)) & 0x0000007F);
        if (in_1 < in_bytenum - 1) {
            *ach_work |= 0x80;
        }
        in_work_len--;
        ach_work++;
        in_written++;
    }
    return in_written;
} // end of ds_wsp_helper::m_to_nhasn


/**
 * \ingroup winterface
 *
 * private function ds_wsp_helper::m_get_nhasnlen
 *
 * @param[in]       dsd_gather_i_1*  ads_gather
 * @param[in/out]   int*             ain_offset
 *
 * @return length                   negativ error code
*/
int ds_wsp_helper::m_get_nhasnlen( struct dsd_gather_i_1 * ads_gather, int* ain_offset )
{
    // initialize some variables:
    int     in_return = 0;
    char*   ach_ptr   = m_get_end_ptr( ads_gather, *ain_offset );
    if ( ach_ptr == NULL ) {
        return -1;
    }

    for ( ; ; ) {
        in_return |= (*ach_ptr &0x7F );
        (*ain_offset)++;
        if ( (*ach_ptr & 0x80) == 0 ) {
            break;
        }
        ach_ptr = m_get_end_ptr( ads_gather, *ain_offset );
        in_return <<= 7;
    }

    return in_return;
} // end of ds_wsp_helper::m_get_nhasnlen


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_setup_cma
 * 
 * @param[in]   dsd_hl_aux_c_cma_1* ads_cma
 * @param[in]   int         in_size
 *
 * @return      bool        true = success
*/
bool ds_wsp_helper::m_setup_cma( dsd_hl_aux_c_cma_1* ads_cma, int in_size )
{
    // initialize some variables:
    bool bo_ret = false;

    // query size (NO LOCK required)
    ads_cma->iec_ccma_def = ied_ccma_query;

    bo_ret = m_call_aux( DEF_AUX_COM_CMA,
                         ads_cma, sizeof(dsd_hl_aux_c_cma_1) );

    if ( bo_ret == false ) {
        // CMA returned error
        m_cb_print_out( "HWSPHW032W query size of CMA failed" );
        return false;
    }

    // check size:
    if (    ( ads_cma->inc_len_cma_area == 0 )        /* no CMA exists    */
         || ( ads_cma->inc_len_cma_area < in_size )   /* CMA is too small */ ) {
        if ( m_resize_cma( ads_cma, in_size ) == false ) {
            bo_ret = false; // do not return
        }
    }
    
    return bo_ret;
} // end of ds_wsp_helper::m_setup_cma


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_resize_cma
 * take care: cma must be fulllocked (write access) for this call
 * 
 * @param[in]   dsd_hl_aux_c_cma_1* ads_cma
 * @param[in]   int                 in_size
 *
 * @return      bool        true = success
*/
bool ds_wsp_helper::m_resize_cma( dsd_hl_aux_c_cma_1* ads_cma,
                                  int in_size )
{
    // initialize some variables:
    bool bo_ret = true;
    
    ads_cma->iec_ccma_def     = ied_ccma_set_size;
    ads_cma->inc_len_cma_area = in_size;
    
    bo_ret = m_call_aux( DEF_AUX_COM_CMA,
                         ads_cma, sizeof(dsd_hl_aux_c_cma_1) );

    // check for CMA errors:
    if ( ( bo_ret == false ) || ( ads_cma->achc_cma_area == NULL && in_size > 0 ) ) {
        m_cb_print_out( "HWSPHW033W cannot set CMA size" );
        bo_ret = false;
    }

    return bo_ret;
} // end of ds_wsp_helper::m_resize_cma


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_query_cma
 * 
 * @param[in]   dsd_hl_aux_c_cma_1* ads_cma
 *
 * @return      bool        true = success
*/
bool ds_wsp_helper::m_query_cma( dsd_hl_aux_c_cma_1* ads_cma )
{
    // initialize some variables:
    bool bo_ret = false;

    ads_cma->iec_ccma_def = ied_ccma_query;    // query size (NO LOCK required)

    bo_ret = m_call_aux( DEF_AUX_COM_CMA,
                         ads_cma, sizeof(dsd_hl_aux_c_cma_1) );
    return bo_ret;
} // end of ds_wsp_helper::m_query_cma


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_lock_cma
 * 
 * @param[in]   dsd_hl_aux_c_cma_1* ads_cma
 * @param[in]   bool                bo_write        lock for write access
 *                                                  default = true
 *
 * @return      bool        true = success
*/
bool ds_wsp_helper::m_lock_cma( dsd_hl_aux_c_cma_1* ads_cma, bool bo_write )
{
    // initialize some variables:
    bool bo_ret = false;

	 ads_cma->iec_ccma_def = ied_ccma_lock_global; // get a lock
    if ( bo_write == true ) {
        ads_cma->imc_lock_type = D_CMA_ALL_ACCESS;
    } else {
        ads_cma->imc_lock_type = D_CMA_READ_DATA | D_CMA_SHARE_READ;
    }

    bo_ret = m_call_aux( DEF_AUX_COM_CMA,
                         ads_cma, sizeof(dsd_hl_aux_c_cma_1) );

    
    if ( bo_ret == false ) {
        dsd_unicode_string dsl_ucs;
        dsl_ucs.ac_str = ads_cma->ac_cma_name;
        dsl_ucs.imc_len_str = ads_cma->inc_len_cma_name;
        dsl_ucs.iec_chs_str = ads_cma->iec_chs_name;
        m_cb_printf_out2( "HWSPHW036W no CMA-lock available (lock-type=%d name=%(ucs)s)",
            ads_cma->imc_lock_type, &dsl_ucs);
    }
    return bo_ret;
} // end of ds_wsp_helper::m_lock_cma


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_unlock_cma
 * 
 * @param[in]   dsd_hl_aux_c_cma_1* ads_cma
 *
 * @return      bool        true = success
*/
bool ds_wsp_helper::m_unlock_cma( dsd_hl_aux_c_cma_1* ads_cma )
{
    // initialize some variables:
    bool bo_ret = false;

    if ( ads_cma->imc_lock_type == D_CMA_ALL_ACCESS ) {
        ads_cma->iec_ccma_def = ied_ccma_lock_rel_upd;
    } else {
        ads_cma->iec_ccma_def = ied_ccma_lock_release;
    }

    bo_ret = m_call_aux( DEF_AUX_COM_CMA,
                         ads_cma, sizeof(dsd_hl_aux_c_cma_1) );
    
    if ( bo_ret == false ) {
        m_cb_print_out( "HWSPHW037W cannot release lock on CMA" );
        return false;
    }
    
    return bo_ret;
} // end of ds_wsp_helper::m_unlock_cma


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_count_cma_lock
 * 
 * @return      int         number of current cma locks
*/
int ds_wsp_helper::m_count_cma_lock()
{
#ifdef _DEBUG
    // initialize some variables:
    dsd_hl_aux_c_cma_1 ds_cma;
    bool               bo_ret;

    memset( &ds_cma, 0, sizeof(dsd_hl_aux_c_cma_1) );

    ds_cma.iec_ccma_def = ied_ccma_check_lock;
    bo_ret = m_call_aux( DEF_AUX_COM_CMA,
                         &ds_cma, sizeof(dsd_hl_aux_c_cma_1) );
    if( bo_ret == false ) {
        m_cb_print_out( "HWSPHW034W check lock failed" );
        return 0;
    }
    
    return ds_cma.imc_ret_no_locks;
#else
    return 0;
#endif
} // end of ds_wsp_helper::m_count_cma_lock


#ifdef _DEBUG
/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_get_cma_writes
 * 
 * @return      int         number of cmas write accesses
*/
int ds_wsp_helper::m_get_cma_writes()
{
    return inc_cma_write;
} // end of ds_wsp_helper::m_get_cma_writes


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_get_cma_writes
 * 
 * @return      int         number of cmas write accesses
*/
int ds_wsp_helper::m_get_cma_reads()
{
    return inc_cma_read;
} // end of ds_wsp_helper::m_get_cma_reads
#endif


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_copy_data
 * copy data from av_input to av_output
 * for av_input == NULL: *ain_offset will just move forward (as far as possible)
 *                       and alignment (if wanted) is also done
 *
 * @param[in]       void*   av_input        data that should be copied from
 * @param[in]       int     in_len_input    length of input data
 * @param[in]       void*   av_target       data target (copied in)
 * @param[in]       int     in_len_target   length of target
 * @param[in/out]   int*    ain_offset      offset in target
 * @param[in]       bool    bo_align        select whether data should be 
 *                                          aligned in target (if necessary)
 * @return          int                     number off copied bytes
 *                                          -1 in error cases
*/
int ds_wsp_helper::m_copy_data( const void* av_input,   int in_len_input,
                                void* av_target,  int in_len_target,
                                int*  ain_offset, bool bo_align )
{
    // initialize some variables:
    char* ach_input  = (char*)av_input;
    char* ach_target = (char*)av_target;
    int   in_copied;     
    int   in_pos     = 0;

    // check for NULL pointer in offset:
    if ( ain_offset == NULL ) {
        ain_offset = &in_pos;
    }

    // check incoming data:
    if (    (ach_target == NULL || in_len_target < 1)
        ||  (*ain_offset < 0) ) {
        return -1;
    }
    if (    (in_len_input < 1)
         || (*ain_offset >= in_len_target) ) {
        return 0;
    }

    // do alignment:
    if ( bo_align == true ) {
        *ain_offset = ALIGN_INT(*ain_offset);
    }

    // check length:
    if ( *ain_offset + in_len_input > in_len_target ) {
        // calculate free space:
        in_copied = in_len_target - *ain_offset;
    } else {
        in_copied = in_len_input;
    }

    // do the copy:
    if ( av_input != NULL ) {
        memmove( &ach_target[*ain_offset], ach_input, in_copied );
    }

    // calculate new offset:
    (*ain_offset) += in_copied;

    return in_copied;
} // end of ds_wsp_helper::m_copy_data


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_copy_data
 *
 * @param[in]       dsd_gather_i_1*  ads_gather
 * @param[in/out]   int*             ain_position
 * @param[in]       int              in_data_len
 * @param[out]      void**           aach_out
 *
 * @return          bool             true = success
*/
bool ds_wsp_helper::m_copy_data( struct dsd_gather_i_1* ads_gather,
                                 int* ain_position, int in_data_len,
                                 char* ach_out )
{
    // initialize some variables:
    char* ach_data  = NULL;

    for ( int in_count = 0; in_count < in_data_len; in_count++ ) {
        // get next data:
        ach_data = m_get_end_ptr( ads_gather, *ain_position );
        if ( ach_data == NULL ) {
            return false;
        }
        // copy data:
        ach_out[in_count] = ach_data[0];
        (*ain_position)++;
    }
    return true;
} // end of ds_wsp_helper::m_copy_data


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_get_ident
 * get user identity
 *
 * @param[in]   struct dsd_sdh_ident_set_1*     ads_ident
 * @return      bool                            true = success
*/
bool ds_wsp_helper::m_cb_get_ident( struct dsd_sdh_ident_set_1* ads_ident )
{
    return m_call_aux( DEF_AUX_GET_IDENT_SETTINGS,
                       ads_ident, sizeof(dsd_sdh_ident_set_1) );
} // end of ds_wsp_helper::m_cb_get_ident()

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_secure_xor
 *
 * XORs a string with a key
*/
bool ds_wsp_helper::m_cb_secure_aux( struct dsd_aux_secure_xor_1* adsp_secure_xor )
{
    return m_call_aux( DEF_AUX_SECURE_XOR,
                       adsp_secure_xor,
                       sizeof( struct dsd_aux_secure_xor_1 ) );
} // end of ds_wsp_helper::m_cb_call_radius

/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_call_radius
 *
 * @param[in]   struct dsd_hl_aux_radius_1*     ads_radius
 * @return      bool                            true = success
*/
bool ds_wsp_helper::m_cb_call_radius( struct dsd_hl_aux_radius_1* ads_radius )
{
    return m_call_aux( DEF_AUX_RADIUS_QUERY,
                       ads_radius,
                       sizeof(struct dsd_hl_aux_radius_1) );
} // end of ds_wsp_helper::m_cb_call_radius


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_free_radius
 *
 * @param[in]   struct dsd_hl_aux_radius_1*     ads_radius
 * @return      bool                            true = success
*/
bool ds_wsp_helper::m_cb_free_radius( struct dsd_hl_aux_radius_1* ads_radius )
{
    return m_call_aux( DEF_AUX_RADIUS_FREE,
                       ads_radius,
                       sizeof(struct dsd_hl_aux_radius_1) );
} // end of ds_wsp_helper::m_cb_free_radius


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_get_wsp_auth
 * get authentication method configured in wsp
 *
 * @return      int
*/
int ds_wsp_helper::m_get_wsp_auth()
{
    // initializse some variables:
    int in_wsp_auth = -1;                   // return value

    switch ( work_mode ) {
        case ien_trans:
            in_wsp_auth = ads_trans->imc_flags_1;
            break;
        case ien_conf:
            m_cb_print_out( "HWSPHW038W wrong workmode in m_get_wsp_auth selected.");
            break;
        case ien_wspat3:
            in_wsp_auth = ads_wspat3->imc_flags_1;
            break;
        default:
            // if no valid mode is defined, we must use normal
            // printf to print an error message!
            m_debug_printf("HWSPHW039W no valid workmode in m_get_wsp_auth selected!\n");
            break;
    }
    return in_wsp_auth;
} // end of ds_wsp_helper::m_get_wsp_auth


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_fbuffer
 * fill buffer in printf style
 *
 * @param[in]   char*       ach_buffer
 * @param[in]   int         in_len_buf
 * @param[in]   const char* ach_format
 * @return      int                         written length of data
*/
int ds_wsp_helper::m_fbuffer( char* ach_buffer, int in_len_buf,
                              HL_FORMAT_STRING const char* ach_format, ... )
{
    // initialize some variables:
    int     in_size;                // used buffer size
    va_list args;                   // argument list

    // print in buffer:
    va_start( args, ach_format );
    in_size = vsnprintf( ach_buffer, in_len_buf - 1, ach_format, args );
    va_end( args );

    // zero termination:
    if ( in_size > in_len_buf - 1 || in_size < 0 ) {
        in_size = -1;
    }
    return in_size;
} // end of ds_wsp_helper::m_fbuffer


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_set_ident
 * set user indentity for wsp
 *
 * @param[in]   const char* achp_usr            user name
 * @param[in]   int         inp_len_usr         length of user name
 * @param[in]   const char* achp_group          user group
 * @param[in]   int         inp_len_group       length of user group
 * @param[in]   const char* achp_usrfld         userfield for multiple key
 * @param[in]   int         inp_len_ufld        length of multiple key
 * @return      bool                            true = success
*/
bool ds_wsp_helper::m_cb_set_ident( const char* achp_usr,    int inp_len_usr,
                                    const char* achp_group,  int inp_len_group,
                                    const char* achp_usrfld, int inp_len_ufld  )
{
    // initialize some variables:
    dsd_aux_set_ident_1 dsl_ident;

    dsl_ident.dsc_userid.ac_str          = (void*)achp_usr;
    dsl_ident.dsc_userid.imc_len_str     = inp_len_usr;
    dsl_ident.dsc_userid.iec_chs_str     = ied_chs_utf_8;
    dsl_ident.dsc_user_group.ac_str      = (void*)achp_group;
    dsl_ident.dsc_user_group.imc_len_str = inp_len_group;
    dsl_ident.dsc_user_group.iec_chs_str = ied_chs_utf_8;
    dsl_ident.achc_userfld               = (char*)achp_usrfld;
    dsl_ident.imc_len_userfld            = inp_len_ufld;

    return m_call_aux( DEF_AUX_SET_IDENT, 
                       &dsl_ident, sizeof(dsd_aux_set_ident_1) );
} // end of ds_wsp_helper::m_cb_set_ident


/**
 * \ingroup winterface
 *
 * function ds_wsp_helper::m_cb_check_ident
 * check user indentity in wsp
 *
 * @param[in]   const char* ach_usr             user name
 * @param[in]   int         in_len_usr          length of user name
 * @param[in]   const char* ach_password        password
 * @param[in]   int         in_len_pwd          length of password
 * @return      bool                            true = success
*/
bool ds_wsp_helper::m_cb_check_ident( struct dsd_hl_aux_ch_ident* ads_auth_usrlist )
{
    return m_call_aux( DEF_AUX_CHECK_IDENT,
                       ads_auth_usrlist, sizeof(dsd_hl_aux_ch_ident) );
} // end ds_wsp_helper::m_cb_check_ident


/**
 * \ingroup winterface
 *
 * public function ds_wsp_helper::m_cb_get_certificate
 * get user certificate if one is present
 *
 * @param[out]  void    **aavp_cert         pointer to certificate
 * @param[out]  int     *ainp_length        length of certificate
 * @return      bool
*/
bool ds_wsp_helper::m_cb_get_certificate( void **aavp_cert, int *ainp_length )
{
    // initialize some variables:
    bool          bol_ret;
    unsigned char *achl_cert;

    bol_ret = m_call_aux( DEF_AUX_GET_CERTIFICATE, &achl_cert, 0 );
    if (    bol_ret   == false
         || achl_cert == NULL  ) {
        return false;
    }

    if (    aavp_cert  != NULL
         && ainp_length != NULL ) {
        *ainp_length = *((int*)achl_cert);
        *aavp_cert   = achl_cert + sizeof(int);
    }
    return true;
} // end of ds_wsp_helper::m_cb_get_certificate


/**
 * \ingroup winterface
 *
* function ds_wsp_helper::m_cb_sip_request
* send a sip related request to the wsp
*
* @param[in]	struct dsd_sdh_sip_requ_1 *ads_sip_request	the request containing structure
* @return		bool							true = success
*/
bool ds_wsp_helper::m_cb_sip_request( struct dsd_sdh_sip_requ_1 *ads_sip_request ) {
    bool bol_ret = m_call_aux( DEF_AUX_SIP_REQUEST, ads_sip_request, sizeof(dsd_sdh_sip_requ_1 ));
    return (bol_ret && (ads_sip_request->iec_ret_sipr1 == ied_ret_sipr1_ok));
} // end ds_wsp_helper::m_cb_sip_request

/**
 * \ingroup winterface
 *
* function ds_wsp_helper::m_cb_udp_request
* send a udp related request to the wsp
*
* @param[in]	struct dsd_sdh_udp_requ_1 *ads_udp_request	the request containing structure
* @return		bool							true = success
*/
bool ds_wsp_helper::m_cb_udp_request( struct dsd_sdh_udp_requ_1 *ads_udp_request ) {
	return m_call_aux( DEF_AUX_UDP_REQUEST, ads_udp_request, sizeof(dsd_sdh_udp_requ_1 ));
} // end ds_wsp_helper::m_cb_udp_request

/**
 * \ingroup winterface
 *
* function ds_wsp_helper::m_cb_udp_gate
* send a udp gate related request to the wsp
*
* @param[in]	struct dsd_aux_cmd_udp_gate *ads_udp_gate	the request containing structure
* @return		bool							true = success
*/
bool ds_wsp_helper::m_cb_udp_gate( struct dsd_aux_cmd_udp_gate *ads_udp_gate ) {
    return m_call_aux( DEF_AUX_UDP_GATE, ads_udp_gate, sizeof(dsd_aux_cmd_udp_gate ));
} // end ds_wsp_helper::m_cb_udp_gate

/**
 * \ingroup winterface
 *
 * private function ds_wsp_helper::m_open_log
 *
 * @param[in]   ied_sdh_log_level   ien_level       log level
 * @param[out]  char**              aach_version    datahook version string
 * @return      FILE*                               pointer to file handle
 *                                                  null if log is not active (or error)
*/
FILE* ds_wsp_helper::m_open_log( ied_sdh_log_level ien_level, const char** aach_version )
{
    // initialize some variables:
    dsd_sdh_log_t*  ads_config;             // our config pointer
    FILE*           a_file;                 // logfile handle

    // get our configuration:
    ads_config = (dsd_sdh_log_t*)m_get_config();
    if ( ads_config == NULL ) {
        return NULL;
    }

    // check if log is activated
    if ( ads_config->boc_active == false ) {
        return NULL;
    }

    // check log level:
    if ( ien_level < ads_config->iec_level ) {
        return NULL;
    }

    // enter critical section:
    GET_LOCK(&(ads_config->dsc_lock));

    // open given file:
    a_file = fopen( ads_config->achc_file, "a+" );
    if ( a_file == NULL ) {
        UN_LOCK(&(ads_config->dsc_lock));
    }

    // get calling datahook version:
    *aach_version = (char*)"unknown";
    if ( ads_config->achc_version != NULL ) {
        *aach_version = ads_config->achc_version;
    }

    return a_file;
} // end of ds_wsp_helper::m_open_log


/**
 * \ingroup winterface
 *
 * private function ds_wsp_helper::m_close_log
 *
 * @param[in]   FILE*   pointer to file handle
*/
void  ds_wsp_helper::m_close_log( FILE* av_log )
{
    // initialize some variables:
    dsd_sdh_log_t*  ads_config;             // our config pointer

    // get our configuration:
    ads_config = (dsd_sdh_log_t*)m_get_config();
    if ( ads_config == NULL ) {
        return;
    }

    // check if log is activated
    if ( ads_config->boc_active == false ) {
        return;
    }

    // close logfile:
    fclose( av_log );

    // leave critical section:
    UN_LOCK(&(ads_config->dsc_lock));
} // end of ds_wsp_helper::m_close_log


/**
 * \ingroup winterface
 *
 * private function ds_wsp_helper::m_dump_data
 *
 * @param[in]   unsigned char*  ach_data
 * @param[in]   int             in_len
 * @param[in]   FILE*           a_file
*/
void ds_wsp_helper::m_dump_data( unsigned char * ach_data, int in_len, FILE* a_file )
{
    // initialize some variables:
    char chr_line[100];
    char chr_temp[10];
    char chr_ascii[20];
    int  in_count = 0;
    int  in_pos;
	int  in_line_index = 0;
    chr_line[0] = 0;

    // JF 05.01.07 we support only 6-digit-counts; therefore limit the length
    if (in_len > 0xFFFFFF-1) {
        in_len = 0xFFFFFF-1;
        fprintf( a_file, "DumpData was limited to 0xFFFFFF\n" );
    }

    for ( in_pos = 0; in_pos < in_len; in_pos++ ) {
        if ( in_count == 0 ) {
            sprintf(chr_line, "%06X ", in_pos);
			in_line_index += 7;
            sprintf(chr_ascii, " -                 ");
        }

        // hex-output of data
#ifdef HL_UNIX  // e.g. FF gets displayed as FFFFFFFF
        sprintf( chr_temp, "%02X ", (ach_data[in_pos] & 0xFF) );
#else      
        sprintf( chr_temp, "%02X ", ach_data[in_pos] );
#endif      

        chr_ascii[in_count + 3]= ach_data[in_pos];
        if (    ((unsigned int)chr_ascii[in_count+3] < 0x20)
             || ((unsigned int)chr_ascii[in_count+3] > 0x7E) ) {
            chr_ascii[in_count + 3]= '.';
        }

		memcpy((void*)&chr_line[in_line_index], (void*)chr_temp, 3);
		in_line_index += 3;

        in_count++;

        if ( in_count == 16 ) {
			memcpy((void*)&chr_line[in_line_index], (void*)chr_ascii, 20);
            fprintf( a_file, "%s\n", chr_line );
            in_count = 0;
            chr_line[0] = 0;
			in_line_index = 0;
        }
    } // for 

    // fill up a line which is not yet complete
    if( chr_line[0] ) {
        for( ; in_count < 16; in_count++ ) {
			memcpy((void*)&chr_line[in_line_index], "   ", 3);
			in_line_index += 3;
        }
		memcpy((void*)&chr_line[in_line_index], (void*)chr_ascii, 20);
        fprintf( a_file, "%s\n", chr_line );
    } // if ( chr_line[0] )

} // end of ds_wsp_helper::m_dump_data


/**
 * \ingroup winterface
 *
 * private function ds_wsp_helper::m_read_file_conf
 * open a file from disk in conf mode
 * Attention: this functionality has to be included in WSP
 *
 * @param[in]   struct dsd_hl_aux_diskfile_1*   adsp_file
 * @return      bool                                        true = success
*/
bool ds_wsp_helper::m_read_file_conf( struct dsd_hl_aux_diskfile_1* adsp_file )
{
    // initialize some variables:
#ifndef HL_UNIX
    WCHAR                           chrl_fname[MAX_PATH];        // file name in utf8
	const enum ied_charset          iel_fs_charset = ied_chs_utf_16;
#else
    char                            chrl_fname[PATH_MAX];        // file name in utf8
	const enum ied_charset          iel_fs_charset = ied_chs_utf_8;
#endif
    int                             inl_flength;            // length of file name (in utf8)
    void*                           avl_fhandle;            // file handle
    long long int                   ill_fsize;              // file size
    BOOL                            bol_ret;                // return value for some func
    long long int                   ill_pos_file;           // position in file
    int                             inl_read;               // length to get read
    unsigned long                   unl_read_ret;           // read bytes
    char*                           achl_buffer;            // read helper
    struct dsd_hl_int_diskfile_1*   adsl_fdata;             
	const int                       inl_max_path = sizeof(chrl_fname)/sizeof(chrl_fname[0]);

    //-------------------------------------------
    // convert incoming file name to utf8:
    //-------------------------------------------
#ifndef WSP_V24
    inl_flength = m_len_vx_vx( iel_fs_charset, adsp_file->ac_name,
                               adsp_file->inc_len_name, adsp_file->iec_chs_name );
#endif
#ifdef WSP_V24
    inl_flength = m_len_vx_ucs( iel_fs_charset,
                                &adsp_file->dsc_ucs_file_name );
#endif
    if ( inl_flength > inl_max_path - 1 ) {
        adsp_file->iec_dfar_def = ied_dfar_file_read;
        return false;
    }
#ifndef WSP_V24
    int inl_retc = m_cpy_vx_vx( chrl_fname, inl_max_path, iel_fs_charset,
                 adsp_file->ac_name, adsp_file->inc_len_name,
                 adsp_file->iec_chs_name );
#endif
#ifdef WSP_V24
    int inl_retc = m_cpy_vx_ucs( chrl_fname, inl_max_path, iel_fs_charset,
                  &adsp_file->dsc_ucs_file_name );
#endif
	if(inl_retc < 0)
		return false;
	chrl_fname[inl_retc] = 0;

#ifndef HL_UNIX
    // open file:
    avl_fhandle = CreateFileW( chrl_fname, GENERIC_READ, FILE_SHARE_READ, 0,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
    if ( avl_fhandle == INVALID_HANDLE_VALUE ) {
        adsp_file->iec_dfar_def = ied_dfar_os_error;
        return false;
    }

    do { // pseudo loop
        // get file size:
        *( (DWORD*) &ill_fsize + 0 ) = GetFileSize( avl_fhandle,
                                                    ((DWORD*) &ill_fsize + 1) );
        if ( *( (DWORD*) &ill_fsize + 0 ) == INVALID_FILE_SIZE ) {
            adsl_fdata = NULL;
            adsp_file->iec_dfar_def = ied_dfar_get_file_size;
            break;
        }

        // create output structure:
        adsl_fdata = (struct dsd_hl_int_diskfile_1*)m_cb_get_memory( 
                            (int)(sizeof(struct dsd_hl_int_diskfile_1) + ill_fsize),
                            false );
        if (adsl_fdata == NULL) {
            adsp_file->iec_dfar_def = ied_dfar_mem_entry;
            break;
        }
        memset( adsl_fdata, 0, sizeof(struct dsd_hl_int_diskfile_1) );

        // read file data
        achl_buffer = (char*)(adsl_fdata + 1);
        inl_read    = 0X01000000;              // maximum length read
        for ( ill_pos_file = 0; ill_pos_file < ill_fsize; ill_pos_file += unl_read_ret ) {
            if ( inl_read > (int)(ill_fsize - ill_pos_file) ) {
                inl_read = (int)(ill_fsize - ill_pos_file);
            }
            bol_ret = ReadFile( avl_fhandle, achl_buffer, inl_read, &unl_read_ret, 0 );
            if ( bol_ret == FALSE ) {
                break;
            }
            achl_buffer += unl_read_ret;
        }

        if ( ill_pos_file < ill_fsize ) {
            adsp_file->iec_dfar_def = ied_dfar_file_read;
            break;
        }
        adsp_file->iec_dfar_def = ied_dfar_ok;
    } while ( FALSE );

    CloseHandle( avl_fhandle );
#else
    struct stat dsl_stat;
    int         inl_fhandle;
    int         inl_ret;

    // open file:
    inl_fhandle = open( chrl_fname, O_RDONLY );
    if ( inl_fhandle < 0 ) {
        adsp_file->iec_dfar_def = ied_dfar_os_error;
        return false;
    }

    do { //pseudo loop
        // get file properties:
        memset( &dsl_stat, 0, sizeof(struct stat) );
        inl_ret = fstat( inl_fhandle, &dsl_stat );
        if ( inl_ret < 0 ) {
            adsp_file->iec_dfar_def = ied_dfar_get_file_inf;
            break;
        }

        // create output structure:
        adsl_fdata = (struct dsd_hl_int_diskfile_1*)m_cb_get_memory( 
                            (int)(sizeof(struct dsd_hl_int_diskfile_1) + dsl_stat.st_size),
                            false );
        if (adsl_fdata == NULL) {
            adsp_file->iec_dfar_def = ied_dfar_mem_entry;
            break;
        }
        memset( adsl_fdata, 0, sizeof(struct dsd_hl_int_diskfile_1) );

        // read file data:
        achl_buffer = (char*)(adsl_fdata + 1);
        inl_read    = 0X01000000;              // maximum length read
        for ( ill_pos_file = 0; ill_pos_file < dsl_stat.st_size; ) {
            if ( inl_read > (dsl_stat.st_size - ill_pos_file) ) {
                inl_read = (dsl_stat.st_size - ill_pos_file);
            }
            inl_ret = read( inl_fhandle, achl_buffer, inl_read );
            if ( inl_ret < 0 ) {
                break;
            }
            achl_buffer  += inl_ret;
            ill_pos_file += inl_ret;
        }

        if ( ill_pos_file < dsl_stat.st_size ) {
            adsp_file->iec_dfar_def = ied_dfar_file_read;
            break;
        }
        adsp_file->iec_dfar_def       = ied_dfar_ok;
        adsp_file->imc_time_last_mod  = dsl_stat.st_mtime;
        adsl_fdata->imc_time_last_mod = dsl_stat.st_mtime;
        ill_fsize                     = dsl_stat.st_size;
    } while ( FALSE );

    close( inl_fhandle );
#endif
    
    if ( adsp_file->iec_dfar_def == ied_dfar_ok ) {
        adsl_fdata->achc_filecont_start = (char*)(adsl_fdata + 1);
        adsl_fdata->achc_filecont_end   = (char*)(adsl_fdata + 1) + ill_fsize;
        adsp_file->adsc_int_df1 = adsl_fdata;
        adsp_file->ac_handle    = adsl_fdata;
        return true;
    }
    return false;
} // end of ds_wsp_helper::m_read_file_conf


/**
 * \ingroup winterface
 *
 * private function ds_wsp_helper::m_release_file_conf
 * free diskfile memory
 * Attention: this functionality has to be included in WSP
 *
 * @param[in]   struct dsd_hl_aux_diskfile_1*   adsp_file
 * @return      bool                                        true = success
*/
bool ds_wsp_helper::m_release_file_conf( struct dsd_hl_aux_diskfile_1* adsp_file )
{
    m_cb_free_memory( adsp_file->ac_handle );
    adsp_file->ac_handle = NULL;
    return true;
} // end of ds_wsp_helper::m_release_file_conf


/**
 * \ingroup winterface
 *
 * Sends the WSP-Trace query to the WSP
 *
 * @param[in]   HL_LONGLONG         ilp_handle_cluster  The cluster's handle to which the query should be sent.
 * @param[in]   bool                bop_free_buffer     To free (or not) the buffer.
 * @param[in]   struct dsd_wspadm1_q_wsp_trace_1    dsp_query_wsptrace  The query to be sent to the WSP
 * @param[in]   int                 imp_len_data        Length of the data appended to the query structure (output file name, INETA(s)...
 * @param[in]   char*               achp_data           Pointer to the appended data.
 * @return      dsd_gather_i_1*                         A NULL gather is always returned as WSP does not give back any info.
*/
struct dsd_gather_i_1* ds_wsp_helper::m_cb_adm_wsptrace_query	( HL_LONGLONG ilp_handle_cluster, bool bop_free_buffer,
                                                             struct dsd_wspadm1_q_wsp_trace_1 dsp_query_wsptrace, int imp_len_data, const char* achp_data )
{
	
    // initialize some variables:
    struct dsd_aux_admin_1 dsl_admin;
    struct dsd_gather_i_1* adsl_gather = NULL;
    char*  achl_query    = NULL;   // query packet
    int    inl_len_query = 0;      // length of query packet
    int    inl_position  = 0;      // working position in query packet
    
    
    // evaluate length of query packet:
    inl_len_query =   (int)sizeof(dsd_wspadm1_q_wsp_trace_1)
                   + imp_len_data; 
    achl_query = m_cb_get_memory( inl_len_query, true );

    // copy query structure to query packet:
    memcpy( achl_query, &dsp_query_wsptrace, sizeof(dsd_wspadm1_q_wsp_trace_1) );
    inl_position += (int)sizeof(dsd_wspadm1_q_wsp_trace_1);

    // copy attached data to query packet:
    if ( imp_len_data > 0 ) {
        memcpy( &achl_query[inl_position], achp_data, imp_len_data);
        inl_position += imp_len_data;
    }

    // initialize admin structure:
    memset( &dsl_admin, 0, sizeof(dsd_aux_admin_1) );
    dsl_admin.ilc_handle_cluster = ilp_handle_cluster;
    if ( bop_free_buffer == true ) {
        dsl_admin.boc_free_buffers = TRUE;
    }

    dsl_admin.achc_command = m_get_adm_command( COM_WSP_ADMIN_WSPTRACEQ, 
                                               &dsl_admin.imc_len_command,
                                               achl_query,
											   inl_len_query);

    // call aux method:
    adsl_gather = m_cb_admin( dsl_admin );

    // free command memory:
    m_cb_free_memory( dsl_admin.achc_command, dsl_admin.imc_len_command );

    return adsl_gather;
}   // End of ds_wsp_helper::m_cb_adm_wsptrace_query

                                                             /**
 * \ingroup winterface
 *
 * Sends the WSP-Trace query to the WSP
 *
 * @param[in]   HL_LONGLONG         ilp_handle_cluster  The cluster's handle to which the query should be sent.
 * @param[in]   bool                bop_free_buffer     To free (or not) the buffer.
 * @return      dsd_gather_i_1*                         A gather containg the information requested.
*/
struct dsd_gather_i_1* ds_wsp_helper::m_cb_adm_wsptrace_info	( HL_LONGLONG ilp_handle_cluster, bool bop_free_buffer)
{
	
	// initialize some variables:
    struct dsd_aux_admin_1 dsl_admin;
    struct dsd_gather_i_1* adsl_gather = NULL;

    // initialize admin structure:
    memset( &dsl_admin, 0, sizeof(dsd_aux_admin_1) );
    dsl_admin.ilc_handle_cluster = ilp_handle_cluster;
    if ( bop_free_buffer == true ) {
        dsl_admin.boc_free_buffers = TRUE;
    }
    dsl_admin.achc_command = m_get_adm_command( COM_WSP_ADMIN_WSPTRACEI, 
                                &dsl_admin.imc_len_command, NULL, 0 );

    // call aux method:
    adsl_gather = m_cb_admin( dsl_admin );

    // free command memory:
    m_cb_free_memory( dsl_admin.achc_command, dsl_admin.imc_len_command );

    return adsl_gather;
}   // End of ds_wsp_helper::m_cb_adm_wsptrace_info

void ds_wsp_helper::m_sha1_init(struct dsd_sha1& rdps_sha1) {
    SHA1_Init(rdps_sha1.inrc_data);
}

void ds_wsp_helper::m_sha1_update(struct dsd_sha1& rdps_sha1, const void* avop_data, int inp_len) {
    SHA1_Update(rdps_sha1.inrc_data, (char*)avop_data, 0, inp_len);
}

void ds_wsp_helper::m_sha1_final(struct dsd_sha1& rdps_sha1, void* avop_data) {
    SHA1_Final(rdps_sha1.inrc_data, (char*)avop_data, 0);
}
