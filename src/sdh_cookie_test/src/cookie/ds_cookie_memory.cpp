/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include <time.h>
#include <ds_wsp_helper.h>
#include "ds_cookie_memory.h"

/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
wstring wst_cma_name_wsp_wsg_ck_mem = L"cma_wsp_wsg_ck_mem";  // memory CMA

/**
 *
 * function ds_cookie_memory::m_setup
 *
*/
void ds_cookie_memory::m_setup( ds_wsp_helper* adsl_wsp_helper, int in_items )
{
    adsc_wsp_helper = adsl_wsp_helper;
    in_count_locks = 0;

    // setup Common Memory Area (CMA)
    memset(&ds_cma_memory, 0, sizeof(struct dsd_hl_aux_c_cma_1));
#ifdef HL_UNIX
    // structure dsd_hl_aux_c_cma_1 cannot handle 4-byte-WCHARS; therefore we must convert to 2-byte-WCHAR
    memset(awc_cma_name_wsp_wsg_ck_mem, 0, LEN_ATTR);
    ads_session->dsc_str_helper.m_conv_utf32_to_utf16((char*)&awc_cma_name_wsp_wsg_ck_mem, LEN_ATTR, (char*)wst_cma_name_wsp_wsg_ck_mem.c_str(), wst_cma_name_wsp_wsg_ck_mem.length()*4);
    ds_cma_memory.ac_cma_name = (void*)awc_cma_name_wsp_wsg_ck_mem;
    ds_cma_memory.inc_len_cma_name = m_len_u16z((HL_WCHAR*)ds_cma_memory.ac_cma_name);
#else
    ds_cma_memory.ac_cma_name = (void*)wst_cma_name_wsp_wsg_ck_mem.c_str();
    ds_cma_memory.inc_len_cma_name = static_cast<int>(wst_cma_name_wsp_wsg_ck_mem.length());
#endif // HL_UNIX
    ds_cma_memory.iec_chs_name = ied_chs_utf_16;

    // create CMA buffer
    m_create_cma_buf( in_items );

} // end of ds_cookie_memory::m_setup


/**
 *
 * function ds_cookie_memory::m_insert_entry
 *
 * give in_old_index = -1 to save cookie at next free position
 * otherwise cookie will overwrite cookie at position in_old_index
 *
 * @param[in]       char*   ach_cookie
 * @param[in]       int     in_len_cookie
 * @param[in]       char*   ach_host
 * @param[in]       int     in_len_host
 * @param[in]       time_t  t_expires
 * @param[in]       bool    bo_secure
 * @param[in]       int     in_old_index
 *
 * @return          int                         -1 = error occured
 *                                              otherwise saved at index
 *
*/
int ds_cookie_memory::m_insert_entry( char* ach_cookie, int in_len_cookie,
                                      char* ach_host,   int in_len_host,
                                      time_t t_expires, bool bo_secure,
                                      int in_old_index )
{
    // lock cma:
    if ( !m_get_cma_lock() ) {
        return -1;
    }

    // initialize some variables:
    ds_cookie* ads_cookie = NULL;       // pointer to actual cookie storage
    int   in_old_pos      = -1;
    int   in_first_id     = -1;         // index to first buffer (used for return)
    int   in_index        = -1;
    bool  bo_overwrite    = false;

    // get cookie at in_old_index
    ds_cookie* ads_cookie_in = m_get_ck_by_pos( in_old_index );


    for ( ; ; ) {
        // get storage for saving:
        if ( ads_cookie_in == NULL ) {
            // get next free storage:
            in_index   = m_find_next_free();
            ads_cookie = m_get_ck_by_pos(in_index);
        } else {
            // overwrite mode!
            if ( in_old_pos < 0 ) {
                // first run through loop
                in_index   = in_old_index;
                ads_cookie = ads_cookie_in;
                bo_overwrite = true;
            } else if ( ads_cookie->in_next > -1 ) {
                in_index   = ads_cookie->in_next;
                ads_cookie = m_get_ck_by_pos( in_index );
                bo_overwrite = true;
            } else {
                // get next free storage:
                in_index   = m_find_next_free();
                ads_cookie = m_get_ck_by_pos(in_index);
                bo_overwrite = false;
            }
        }

        if ( ads_cookie == NULL ) {
            // enlarge memory:
            m_set_cma_size( 2* ads_capacity->in_capacity );
            in_index   = m_find_next_free();
            ads_cookie = m_get_ck_by_pos(in_index);
            if ( ads_cookie == NULL ) {
                // big error, should never happen!
                break;    // finish loop
            }
        }

        if ( !bo_overwrite ) {
            // decrease free counter
            ads_capacity->in_free--;
        }

        // now, a storage is found:
        // save time and secure information:
        ads_cookie->t_expires = t_expires;
        ads_cookie->bo_secure = bo_secure;
        if ( in_old_pos > -1 ) {
            ds_cookie* ads_cookie_old = m_get_ck_by_pos(in_old_pos);
            ads_cookie_old->in_next = in_index;
        }

        // save host information:
        if ( in_len_host >= CK_MAX_HOST_LEN ) {
            in_len_host = CK_MAX_HOST_LEN - 1;
        }
        memcpy( &(ads_cookie->rch_host)[0], ach_host, in_len_host );

        // save first pointer of memory
        if ( in_first_id == -1 ) {
            in_first_id = in_index;
        }
            
        // save data:
        if ( in_len_cookie < CK_MEM_SIZE ) {
            ads_cookie->in_length = in_len_cookie;
            memcpy( &((ads_cookie->rch_cookie)[0]), ach_cookie, in_len_cookie );
            ads_cookie->in_next = -1;
            break;    // finish loop
        } else {
            ads_cookie->in_length = CK_MEM_SIZE;
            memcpy( &((ads_cookie->rch_cookie)[0]), ach_cookie, CK_MEM_SIZE );
            // save old pointer to set next pointer
            in_old_pos = in_index;
            // move ach_cookie
            ach_cookie += CK_MEM_SIZE;
            in_len_cookie -= CK_MEM_SIZE;
        }
    }

    // release cma:
    m_release_cma_lock();

    return in_first_id;
} // end of ds_cookie_memory::m_insert_entry


/**
 *
 * function ds_cookie_memory::m_delete_entry
 *
 * @param[in]   int     in_index
 *
 * @return      bool                         true = success
 *
*/
bool ds_cookie_memory::m_delete_entry( int in_index )
{
    // lock cma:
    if ( !m_get_cma_lock() ) {
        return false;
    }

    // initialize some variables:
    ds_cookie* ads_cookie = NULL;
    int        in_next    = -1;

    // get cookie pointer:
    ads_cookie = m_get_ck_by_pos( in_index );

    while ( ads_cookie != NULL ) {
        ads_cookie->in_length = 0;
        memset( &ads_cookie->rch_host[0], 0, CK_MAX_HOST_LEN );
        in_next = ads_cookie->in_next;
        ads_cookie->in_next = -1;
        ads_cookie = m_get_ck_by_pos( in_next );
    }

    // release cma:
    m_release_cma_lock();

    return true;
} // end of ds_cookie_memory::m_delete_entry


/**
 *
 * function ds_cookie_memory::m_get_entries
 *
 * @param[in]   vector<int>     v_indices
 * @param[in]   bool            bo_secure
 * @param[out]  int*            ain_counter
 *
 * @return      string
 *
*/
string ds_cookie_memory::m_get_entries( vector<int> v_indices, bool bo_secure, int* ain_counter )
{
    // lock cma:
    if ( !m_get_cma_lock() ) {
        return "";
    }

    // initialize some variables:
    string  str_return = "";
    int     in_index   = -1;
    int     in_counter =  0;
    int     in_old_len =  0;

    for ( int in_1 = 0; in_1 < (int)v_indices.size(); in_1++ ) {
        in_index = v_indices.at(in_1);
        if ( in_index > -1 ) {
            if ( in_old_len < (int)str_return.length() ) {
                str_return += "; ";
            }
            in_old_len = (int)str_return.length();
            str_return += m_get_entry( in_index, bo_secure, false );
            if ( in_old_len < (int)str_return.length() ) {
                in_counter++;
            }
        }
    }
    
    // release cma:
    m_release_cma_lock();

    if ( ain_counter != NULL ) {
        *ain_counter = in_counter;
    }

    return str_return;
} // end of ds_cookie_memory::m_get_entries


/**
 *
 * function ds_cookie_memory::m_get_detailed_entries
 *
 * @param[in]   vector<int>     v_indices
 * @param[in]   bool            bo_secure
 *
 * @return      vector<string>
 *
*/
vector<string> ds_cookie_memory::m_get_detailed_entries( vector<int> v_indices, bool bo_secure )
{
    // initialize some variables:
    vector<string>  vstr_return;
    int             in_index = -1;

    // lock cma:
    if ( !m_get_cma_lock() ) {
        return vstr_return;
    }

    for ( int in_1 = 0; in_1 < (int)v_indices.size(); in_1++ ) {
        in_index = v_indices.at(in_1);
        if ( in_index > -1 ) {
            vstr_return.push_back( m_get_entry( in_index, bo_secure, true ) );
        }
    }
    
    // release cma:
    m_release_cma_lock();

    return vstr_return;
} // end of ds_cookie_memory::m_get_detailed_entries


/**
 *
 * function ds_cookie_memory::m_get_name
 *
 * @param[in]   int     in_index
 * @param[in]   bool    bo_secure
 *
 * @return      string
 *
*/
string ds_cookie_memory::m_get_name( int in_index, bool bo_secure )
{
    // lock cma:
    if ( !m_get_cma_lock() ) {
        return "";
    }

    if ( in_index < 0 ) {
        return "";
    }

    // initialize some variables:
    string str_return = "";
    size_t in_pos     = 0;
    
    str_return = m_get_entry( in_index, bo_secure, false );
    in_pos = str_return.find("=");
    if ( in_pos != string::npos ) {
        str_return = str_return.substr(0, in_pos);
    }

    // release cma:
    m_release_cma_lock();

    return str_return;
} // end of ds_cookie_memory::m_get_name


/**
 *
 * function ds_cookie_memory::m_get_value
 *
 * @param[in]   int     in_index
 *
 * @return      ds_cookie
 *
*/
ds_cookie ds_cookie_memory::m_get_struct_cookie( int in_index )
{
    // initialize some variables:
    ds_cookie ds_return;
    memset( &ds_return, 0, sizeof(ds_cookie) );

    // lock cma:
    if ( !m_get_cma_lock() ) {
        return ds_return;
    }

    ds_cookie* ads_cookie = m_get_ck_by_pos( in_index );

    if ( ads_cookie != NULL ) {
       ds_return = *ads_cookie;
    }

    // release cma:
    m_release_cma_lock();

    return ds_return;
} // end of ds_cookie_memory::m_get_value


/**
 *
 * function ds_cookie_memory::m_delete_all_expired
 *
 * @return      vector<int>
 *
*/
void ds_cookie_memory::m_delete_all_expired()
{
    // lock cma:
    if ( !m_get_cma_lock() ) {
        return;
    }

    // initialize some variables:
    ds_cookie*  ads_cookie;
    time_t      t_now;
    time_t      t_lifetime;
    time(&t_now);

    for ( int in_pos = 0; in_pos < ads_capacity->in_capacity; in_pos++ ) {
        ads_cookie = m_get_ck_by_pos( in_pos );
        if (    ads_cookie != NULL            /* valid pointer                   */
             && ads_cookie->in_length > 0     /* cookie is filled                */
             && ads_cookie->t_expires > -1    /* -1 is sign for delete at logout */ )
        {
            t_lifetime = ads_cookie->t_expires;
            if ( t_lifetime - t_now < 1 ) {
                //ads_session->dsc_ws_gate.dsc_cookie_manager.m_cb_delete_cookie( in_pos );
            }
        }
    }

    // release cma:
    m_release_cma_lock();

    return;
} // end of ds_cookie_memory::m_delete_all_expired


/**
 *
 * function ds_cookie_memory::m_is_persistent
 *
 * @param[in]   int     in_index
 *
 * @return      bool
 *
*/
bool ds_cookie_memory::m_is_persistent( int in_index )
{
    // lock cma:
    if ( !m_get_cma_lock() ) {
        return false;
    }

    // initialize some variables:
    bool       bo_return  = false;
    time_t     t_lifetime = 0;
    time_t     t_now;
    ds_cookie* ads_cookie = NULL;
    time(&t_now);

    ads_cookie = m_get_ck_by_pos( in_index );
    if (    ads_cookie != NULL            /* valid pointer                   */
         && ads_cookie->in_length > 0     /* cookie is filled                */
         && ads_cookie->t_expires > -1    /* -1 is sign for delete at logout */ )
    {
        t_lifetime = ads_cookie->t_expires;
        if ( t_lifetime - t_now < 1 ) {
            //ads_session->dsc_ws_gate.dsc_cookie_manager.m_cb_delete_cookie( in_index );
        } else {
            bo_return = true;
        }
    }

    // release cma:
    m_release_cma_lock();

    return bo_return;
} // end of ds_cookie_memory::m_is_persistent

/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/

/**
*/
ds_cookie* ds_cookie_memory::m_get_ck_by_pos( int in_index )
{
    if (    in_count_locks == 0
         || in_index < 0
         || in_index > ads_capacity->in_capacity -1 ) 
    {
        return NULL;
    }
    
    void* av_start = ((char*)ads_capacity) + sizeof(ds_capacity);
    // try to align on 8byte boundary
    av_start = DO_ALIGN(av_start);
    av_start = ((char*)av_start) + in_index * sizeof(ds_cookie);

    ds_cookie* ads_cookie = (ds_cookie*)av_start;
    return ads_cookie;
}


/**
 *
 * function ds_cookie_memory::m_get_entry
 *
 * @param[in]   int     in_index
 * @param[in]   bool    bo_secure
 * @param[in]   bool    bo_detailed_output
 *
 * @return      string
 *
*/
string ds_cookie_memory::m_get_entry( int in_index, bool bo_secure, bool bo_detailed_output )
{
    // initialize some variables:
    ds_cookie* ads_cookie = NULL;
    string     str_return = "";
    time_t     t_lifetime;
    time_t     t_now;

    
    // get cookie:
    ads_cookie = m_get_ck_by_pos( in_index );

    if ( ads_cookie != NULL ) {
        // check cookies secure state:
        if (    ads_cookie->bo_secure   /* cookie only for a secure connection */
             && !bo_secure              /* but no secure connection            */ ) 
        {
            return "";
        }
        
        time( &t_now );
        t_lifetime = ads_cookie->t_expires;
        if ( t_lifetime > 0 ) {
            if ( t_lifetime - t_now > 0 ) {
                // cookie is actual: add it to return value:
                str_return.append( ads_cookie->rch_cookie, ads_cookie->in_length );
                // read data from next index (if set):
                ads_cookie = m_get_ck_by_pos( ads_cookie->in_next );
                while ( ads_cookie != NULL ) {
                    str_return.append( ads_cookie->rch_cookie, ads_cookie->in_length );
                    ads_cookie = m_get_ck_by_pos( ads_cookie->in_next );
                }
                if ( bo_detailed_output ) {
                    str_return += "; Path="    + m_get_path    ( in_index );
                    str_return += "; Domain="  + m_get_domain  ( in_index );
                }
            } else {
                // cookie is timed out -> delete it:
                //ads_session->dsc_ws_gate.dsc_cookie_manager.m_cb_delete_cookie( in_index );
            } 
        } else if ( t_lifetime == -1 ) {
            // sign for delete cookie at logout:
            str_return.append( ads_cookie->rch_cookie, ads_cookie->in_length );
            // read data from next index (if set):
            ads_cookie = m_get_ck_by_pos( ads_cookie->in_next );
            while ( ads_cookie != NULL ) {
                str_return.append( ads_cookie->rch_cookie, ads_cookie->in_length );
                ads_cookie = m_get_ck_by_pos( ads_cookie->in_next );
            }
            if ( bo_detailed_output ) {
                str_return += "; Path="   + m_get_path( in_index );
                str_return += "; Domain=" + m_get_domain( in_index );
            }
        }
    }

    return str_return;
} // end of ds_cookie_memory::m_get_entry


/**
 *
 * function ds_cookie_memory::m_find_next_free
 *
*/
int ds_cookie_memory::m_find_next_free()
{
    if ( ads_capacity->in_free > 0 ) {
        ds_cookie* ads_cookie;

        if ( ads_capacity != NULL ) {
            for ( int in_1 = 0; in_1 < ads_capacity->in_capacity ; in_1++ ) {
                ads_cookie = m_get_ck_by_pos(in_1);
                if ( ads_cookie != NULL && ads_cookie->in_length < 1 ) {
                    return in_1;
                }
            }
        }
    }

    return -1;
} // end of ds_cookie_memory::m_find_next_free


/**
 *
 * function ds_cookie_memory::m_setup_structs
*/
void ds_cookie_memory::m_setup_structs( bool bo_overwrite )
{
    if ( ads_capacity != NULL ) {
        // initialize some variables:
        ds_cookie* ads_cookie = NULL;
        ads_capacity->in_free = 0;

        for ( int in_pos = 0; in_pos < ads_capacity->in_capacity; in_pos++ ) {
            ads_cookie = m_get_ck_by_pos( in_pos );
            if ( ads_cookie != NULL ) {
                if ( bo_overwrite ) {
                    ads_cookie->in_length = 0;
                }
                if ( ads_cookie->in_length < 1 ) {
                    ads_cookie->bo_secure = false;
                    ads_cookie->in_next   = -1;
                    ads_cookie->t_expires = 0;
                    memset( &ads_cookie->rch_cookie[0], 0, CK_MEM_SIZE );
                    memset( &ads_cookie->rch_host[0],   0, CK_MAX_HOST_LEN );
                    // increase fre counter:
                    ads_capacity->in_free++;
                }
            }
        }
    }
} // end of ds_cookie_memory::m_setup_structs


/**
 *
 * function ds_cookie_memory::m_get_path
 *
 * @param[in]   int in_index
 * 
 * @return      string
 *
*/
string ds_cookie_memory::m_get_path( int in_index )
{
    // initialize some variables:
    string str_return = "";
    ds_cookie* ads_cookie = m_get_ck_by_pos( in_index );
    if ( ads_cookie != NULL ) {
        string str_temp( ads_cookie->rch_host, strlen(ads_cookie->rch_host) );
        size_t in_pos = str_temp.find( "/" );
        if ( in_pos != string::npos ) {
            str_return = str_temp.substr( in_pos, str_temp.length() );
        }
    }

    return str_return;
} // end of ds_cookie_memory::m_get_path


/**
 *
 * function ds_cookie_memory::m_get_domain
 *
 * @param[in]   int in_index
 * 
 * @return      string
 *
*/
string ds_cookie_memory::m_get_domain( int in_index )
{
    // initialize some variables:
    string str_return = "";
    ds_cookie* ads_cookie = m_get_ck_by_pos( in_index );
    if ( ads_cookie != NULL ) {
        string str_temp( ads_cookie->rch_host, strlen(ads_cookie->rch_host) );
        size_t in_pos = str_temp.find( "/" );
        if ( in_pos != string::npos ) {
            str_return = str_temp.substr( 0, in_pos );
        }
    }

    return str_return;
} // end of ds_cookie_memory::m_get_domain


/**
 *
 * function ds_cookie_memory::m_create_cma_buf
 *
 * @param[in]   int in_items
 *
*/
void* ds_cookie_memory::m_create_cma_buf( int in_items )
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    int in_buf_size = sizeof(ds_capacity) + in_items * sizeof(ds_cookie);

    // query size (NO LOCK required)
    ds_cma_memory.iec_ccma_def = ied_ccma_query;
    BOOL bo_cma = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_COM_CMA,
                                      &ds_cma_memory, sizeof(dsd_hl_aux_c_cma_1));
    if (!bo_cma) {   // CMA returned error
        adsc_wsp_helper->m_cb_print_out( "HWSGE509E: query size of CMA failed" );
        return NULL;
    }

    if ( (ds_cma_memory.inc_len_cma_area == 0) || (ds_cma_memory.inc_len_cma_area < in_buf_size) ) { // 1st: no CMA exists -> create it; 2nd: CMA exists but is too small -> resize it
        // get lock
        if (!m_get_cma_lock()) {
            return NULL;
        }
        m_set_cma_size(in_items);
        // release lock
        m_release_cma_lock();
    }
    
    return NULL;
} // end of ds_cookie_memory::m_create_cma_buf


/**
 *
 * function ds_cookie_memory::m_get_cma_lock
 *
*/
bool ds_cookie_memory::m_get_cma_lock()
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    in_count_locks++;
    if ( in_count_locks < 2 ) {
        ds_cma_memory.iec_ccma_def = ied_ccma_lock_global; // get a lock
        ds_cma_memory.imc_lock_type = D_CMA_ALL_ACCESS;

        BOOL bo_cma = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_COM_CMA,
                                          &ds_cma_memory, sizeof(dsd_hl_aux_c_cma_1));
        if ( (!bo_cma) ) { // CMA returned error
            adsc_wsp_helper->m_cb_print_out( "HWSGE510E: no CMA-lock available" );
            return  false;
        }

        ads_capacity = (ds_capacity*)ds_cma_memory.achc_cma_area;
    }
    return true;
} // end of ds_cookie_memory::m_get_cma_lock


/**
 *
 * function ds_cookie_memory::m_release_cma_lock
 *
*/
bool ds_cookie_memory::m_release_cma_lock()
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    in_count_locks--;
    if ( in_count_locks < 1 ) {
        ds_cma_memory.iec_ccma_def = ied_ccma_lock_rel_upd;
        BOOL bo_cma = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_COM_CMA,
                                          &ds_cma_memory, sizeof(dsd_hl_aux_c_cma_1));
        if (!bo_cma) {   // CMA returned error
            adsc_wsp_helper->m_cb_print_out( "HWSGE511E: cannot release lock on CMA" );
            return false;
        }

        ads_capacity = NULL;
    }
    return true;
} // end of ds_cookie_memory::m_release_cma_lock


/**
 *
 * function ds_cookie_memory::m_set_cma_size
 *
*/
bool ds_cookie_memory::m_set_cma_size(int in_items)
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    ds_cma_memory.iec_ccma_def = ied_ccma_set_size;
    ds_cma_memory.inc_len_cma_area =  ((sizeof(ds_capacity)+ 7) & (~ 0x07)) + in_items*((sizeof(ds_cookie) + 7) & (~ 0x07));

    BOOL bo_cma = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_COM_CMA,
                                      &ds_cma_memory, sizeof(dsd_hl_aux_c_cma_1));
    if ((!bo_cma) || (ds_cma_memory.achc_cma_area == NULL) ) {   // CMA returned error
        adsc_wsp_helper->m_cb_print_out( "HWSGE512E: cannot set CMA size" );        
        return false;
    }

    ads_capacity = (ds_capacity*)ds_cma_memory.achc_cma_area;
    ads_capacity->in_capacity = in_items;

    m_setup_structs();

    return true;
} // end of ds_cookie_memory::m_set_cma_size

/*+-------------------------------------------------------------------------+*/
/*| analysing functions:                                                    |*/
/*+-------------------------------------------------------------------------+*/

/**
 *
 * function ds_cookie_memory::m_get_overview
 *
 * @return      string
 *
*/
string ds_cookie_memory::m_get_overview()
{
    return "";
} // end of ds_cookie_memory::m_get_overview


/**
 *
 * function ds_cookie_memory::m_view
 *
 * @param[in]   ds_cookie* ads_cookie
 * @param[in]   int             in_pos
 *
 * @return      string
 *
*/
string ds_cookie_memory::m_view( ds_cookie* ads_cookie, int in_pos )
{
    // initialize some variables:
    string str_return = "";

#if 0
    str_return += "position: ";
    str_return += ads_session->dsc_str_helper.m_int_to_string( in_pos ) + "\n";
    if ( ads_cookie != NULL ) {
        str_return += "\t entry in use:       ";
        if ( ads_cookie->in_length > 0 ) {
            str_return += "YES\n";
        } else {
            str_return += "NO\n";
        }
        str_return += "\t cookie:             ";
        str_return.append( &ads_cookie->rch_cookie[0], ads_cookie->in_length );
        str_return += "\n";
        str_return += "\t host:               ";
        str_return.append( &ads_cookie->rch_host[0], strlen(ads_cookie->rch_host) );
        str_return += "\n";
        str_return += "\t lifetime:           ";
        if ( ads_cookie->t_expires == -1 ) {
            str_return += "delete at logout\n";
        } else {
            str_return += ads_session->dsc_str_helper.m_int_to_string( (int)ads_cookie->t_expires ) + "\n";
        }
        str_return += "\t next:               ";
        str_return += ads_session->dsc_str_helper.m_int_to_string( ads_cookie->in_next ) + "\n";
        if ( ads_cookie->in_next > -1 ) {
            str_return += "\t recomposed cookie:  ";
            str_return.append( &ads_cookie->rch_cookie[0], ads_cookie->in_length );
            ads_cookie = m_get_ck_by_pos( ads_cookie->in_next );
            while ( ads_cookie != NULL ) {
                str_return.append( &ads_cookie->rch_cookie[0], ads_cookie->in_length );
                ads_cookie = m_get_ck_by_pos( ads_cookie->in_next );
            }
            str_return += "\n";
        }
    } else {
        str_return += "\t error: NULL pointer\n";
    }
#endif

    return str_return;
} // end of ds_cookie_memory::m_view
