/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
#include <ds_wsp_helper.h>
#include "ds_cookie_mgmt_table.h"

/*+-------------------------------------------------------------------------+*/
/*| public functions:                                                       |*/
/*+-------------------------------------------------------------------------+*/
wstring wst_cma_name_wsp_wsg_ck_man  = L"cma_wsp_wsg_ck_man";  // managment CMA

/**
 *
 * function ds_cookie_mgmt_table::m_setup
 *
*/
void ds_cookie_mgmt_table::m_setup( ds_wsp_helper* adsl_wsp_helper, int in_items )
{
    adsc_wsp_helper = adsl_wsp_helper;
    in_count_locks = 0;

    // setup Common Memory Area (CMA) for hash table:
    memset(&ds_cma_man, 0, sizeof(struct dsd_hl_aux_c_cma_1));
#ifdef HL_UNIX
    // structure dsd_hl_aux_c_cma_1 cannot handle 4-byte-WCHARS; therefore we must convert to 2-byte-WCHAR
    memset(awc_cma_name_wsp_wsg_ck_man, 0, LEN_ATTR);
    ads_session->dsc_str_helper.m_conv_utf32_to_utf16((char*)&awc_cma_name_wsp_wsg_ck_man, LEN_ATTR, (char*)wst_cma_name_wsp_wsg_ck_man.c_str(), wst_cma_name_wsp_wsg_ck_man.length()*4);
    ds_cma_man.ac_cma_name = (void*)awc_cma_name_wsp_wsg_ck_man;
    ds_cma_man.inc_len_cma_name = m_len_u16z((HL_WCHAR*)ds_cma_man.ac_cma_name);
#else
    ds_cma_man.ac_cma_name = (void*)wst_cma_name_wsp_wsg_ck_man.c_str();
    ds_cma_man.inc_len_cma_name = static_cast<int>(wst_cma_name_wsp_wsg_ck_man.length());
#endif // HL_UNIX
    ds_cma_man.iec_chs_name = ied_chs_utf_16;

    // create CMA buffer
    m_create_cma_buf( in_items );
} // end of ds_cookie_mgmt_table::m_setup


/**
 *
 * function ds_cookie_mgmt_table::m_insert_entry
 *
 * @param[in]   int     in_save_at      position where entry should be saved at
 *                                      give -1 to create a new one
 * @param[in]   int     in_points_to    pointer to position in ds_cookie_memory 
 * @param[in]   int     in_father       pointer to father element in ds_cookie_mgmt_table
 * @param[in]   int     in_mother       pointer to mother element in ds_cookie_mgmt_table
 * @param[in]   int     in_add_childs   increase child counter with this number
 *
 * @return      int                     position where entry is saved at
 *                                      -1 if error occured
 *
*/
int ds_cookie_mgmt_table::m_insert_entry( int in_save_at,
                                          int in_points_to, int in_father,
                                          int in_mother, int in_add_childs )
{
    // get cma lock:
    if ( !m_get_cma_lock() ) {
        return -1;
    }

    // initialize some variables:
    int             in_return = -1;
    ds_cookie_link* ads_link  = NULL;
    int             in_pos    = -1;

    if ( in_save_at > -1 ) {
        // an entry already exists -> just add new informations:
        ads_link = m_get_link_by_pos( in_save_at );
        bool bo_filled = m_fill( ads_link, in_points_to, in_father, in_mother, in_add_childs );
        if ( bo_filled ) {
            // decrease free counter:
            ads_man_cap->in_free--;
            // set return value:
            in_return = in_save_at;
        }
    } else {
        // check free memory:
        if ( ads_man_cap->in_free < 1 ) {
            // enlarge memory with factor 2!
            m_set_size_cma( 2*ads_man_cap->in_capacity );
        }
        // take next free entry:
        ads_link = m_get_next_free( &in_pos );
        if ( ads_link != NULL && in_pos > -1 ) {
            bool bo_filled = m_fill( ads_link, in_points_to, in_father, in_mother, in_add_childs );
            if ( bo_filled ) {
                // decrease free counter:
                ads_man_cap->in_free--;
                // set return value:
                in_return = in_pos;
            }
        }
    }

    // release cma lock:
    m_release_cma_lock();

    return in_return;
} // end of ds_cookie_mgmt_table::m_insert_entry


/**
 *
 * function ds_cookie_mgmt_table::m_delete_entry
 *
 * @param[in]   int     in_points_to        pointer to position in ds_cookie_memory
 * @param[in]   bool    bo_ignore_dependencies    true = entry will be deleted, even if there 
 *                                          exists some childs
 *                                          default should be false!!!
 *
 * @return      vector<int>                 pointer to which must be delete in hash table
 *
*/
vector<int> ds_cookie_mgmt_table::m_delete_entry( int in_points_to, bool bo_ignore_dependencies )
{
    // initialize return value:
    vector<int> vin_hash_pointer;

    // get cma lock:
    if ( !m_get_cma_lock() ) {
        return vin_hash_pointer;
    }

    // initialize some variables:
    ds_cookie_link* ads_link  = NULL;
    int             in_mother = -1;
    int             in_father = -1;

    // search link: ( position will be saved in in_mother )
    ads_link = m_get_link_by_pointer( in_points_to, &in_mother );

    if ( ads_link != NULL && in_mother > -1 ) {
        // remove pointer to ds_cookie_memory:
        m_remove_index( ads_link, in_points_to );

        // loop through all mothers:
        while (    in_mother > -1
                && ads_link != NULL
                && ads_link->bo_occupied )
        {
            // loop through all fathers:
            in_father = ads_link->in_father;
            ads_link  = m_get_link_by_pos( in_father );
            while (    in_father > -1
                    && ads_link != NULL
                    && ads_link->bo_occupied ) {
                // decrease child counter:
                m_remove_child( ads_link );
                // if occupied indices and number of childs are zero
                // we can delete our entries
                if ( ( ads_link->in_occ_indices == 0 && ads_link->in_count_childs == 0 )
                     || bo_ignore_dependencies ) 
                {
                    // set return value:
                    vin_hash_pointer.push_back( in_father );
                    // get next father:
                    in_father = ads_link->in_father;
                    // delete entries:
                    m_free( ads_link );
                    // get next father:
                    ads_link  = m_get_link_by_pos( in_father );
                    // increase free counter:
                    ads_man_cap->in_free++;
                } else {
                    break; // break father loop
                }
            } // end of father loop
    
            // get mother link once again:
            ads_link = m_get_link_by_pos( in_mother );
             // decrease child counter:
            m_remove_child( ads_link );
            // if occupied indices and number of childs are zero
            // we can delete our entries
            if ( ( ads_link->in_occ_indices == 0 && ads_link->in_count_childs == 0 )
                 || bo_ignore_dependencies ) 
            {
                // set return value:
                vin_hash_pointer.push_back( in_mother );
                // get next mother:
                in_mother  = ads_link->in_mother;
                // delete entries:
                m_free( ads_link );
                // get next mother:
                ads_link   = m_get_link_by_pos( in_mother );
                // increase free counter:
                ads_man_cap->in_free++;
            } else {
                break; // break mother loop
            }
        } // end of mother loop
    }


    // release cma lock:
    m_release_cma_lock();

    return vin_hash_pointer;
} // end of ds_cookie_mgmt_table::m_delete_entry


/**
 *
 * function ds_cookie_mgmt_table::m_get_entries
 *
 * @param[in]   int     in_pos          position in ds_cookie_mgmt_table
 * @param[in]   char*   ach_user        user name
 * @param[in]   int     in_len_user     length ot user name
 * @param[in]   char*   ach_host        host ( www.hob.de/test1/test2/ )
 * @param[in]   int     in_len_host     length of host
 *
 * @return      vector<int>             list of positions in ds_cookie_memory
 *
*/
vector<int> ds_cookie_mgmt_table::m_get_entries( int in_pos )
{
    // initialize return value:
    vector<int> v_positions;

    // get cma lock:
    if ( !m_get_cma_lock() ) {
        return v_positions;
    }

    // initialize some variables:
    ds_cookie_link* ads_link = NULL;
    vector<int>     vin_parents;
    int             in_count = 0;

    // get all parents (including in_pos itself!)
    vin_parents = m_get_parents( in_pos );

    for ( int in_1 = 0; in_1 < (int)vin_parents.size(); in_1++ ) {
        ads_link = m_get_link_by_pos( vin_parents.at(in_1) );
        if (    ads_link != NULL
             && ads_link->bo_occupied )
        {
            for ( int in_2 = 0; in_2 < CK_MAX_PER_DOMAIN; in_2++ ) {
                if ( in_count < ads_link->in_occ_indices ) {
                    if ( ads_link->rin_indices[in_2] > -1 ) {
                        v_positions.push_back(ads_link->rin_indices[in_2]);
                        in_count++;
                    }
                } else {
                    break;
                }
            }
            in_count = 0;
        }
    }
    
    // release cma lock:
    m_release_cma_lock();

    return v_positions;
} // end of ds_cookie_mgmt_table::m_get_entries


/**
 *
 * function ds_cookie_mgmt_table::m_get_exact_entries
 *
 * @param[in]   int     in_pos          position in ds_cookie_mgmt_table
 * @param[in]   char*   ach_user        user name
 * @param[in]   int     in_len_user     length ot user name
 * @param[in]   char*   ach_host        host ( www.hob.de/test1/test2/ )
 * @param[in]   int     in_len_host     length of host
 *
 * @return      vector<int>             list of positions in ds_cookie_memory
 *
*/
vector<int> ds_cookie_mgmt_table::m_get_exact_entries( int in_pos )
{
    // initialize return value:
    vector<int> v_positions;

    // get cma lock:
    if ( !m_get_cma_lock() ) {
        return v_positions;
    }

    // initialize some variables:
    ds_cookie_link* ads_link = NULL;
    vector<int>     vin_parents;
    int             in_count = 0;

    ads_link = m_get_link_by_pos( in_pos );
    if (    ads_link != NULL
         && ads_link->bo_occupied )
    {
        for ( int in_2 = 0; in_2 < CK_MAX_PER_DOMAIN; in_2++ ) {
            if ( in_count < ads_link->in_occ_indices ) {
                if ( ads_link->rin_indices[in_2] > -1 ) {
                    v_positions.push_back(ads_link->rin_indices[in_2]);
                    in_count++;
                }
            } else {
                break;
            }
        }
    }
    
    // release cma lock:
    m_release_cma_lock();

    return v_positions;
} // end of ds_cookie_mgmt_table::m_get_exact_entries

/*+-------------------------------------------------------------------------+*/
/*| private functions:                                                      |*/
/*+-------------------------------------------------------------------------+*/

/**
 *
 * function ds_cookie_mgmt_table::m_get_parents
 *
 * @param[in]   int     in_mgmt_pos
 *
 * @return      vector<int>
 *
*/
vector<int> ds_cookie_mgmt_table::m_get_parents( int in_mgmt_pos )
{
    // initialize some variables:
    int             in_mother = -1;
    int             in_father = -1;
    ds_cookie_link* ads_link  = NULL;
    vector<int>     vin_parents;

    if ( in_count_locks == 0 ) {
        return vin_parents;
    }

    // get all parents:
    in_mother = in_mgmt_pos;
    ads_link  = m_get_link_by_pos( in_mgmt_pos );

    // run through mother elements:
    while (    in_mother > -1
            && ads_link != NULL
            && ads_link->bo_occupied )
    {
        vin_parents.push_back( in_mother );
        in_mother = ads_link->in_mother;
        // get father element:
        in_father = ads_link->in_father;
        ads_link  = m_get_link_by_pos( in_father );
        // run through father elements:
        while (    in_father > -1
                && ads_link != NULL
                && ads_link->bo_occupied )
        {
            vin_parents.push_back(in_father);
            in_father = ads_link->in_father;
            ads_link  = m_get_link_by_pos( in_father );
        }
        // get next mother link:
        ads_link = m_get_link_by_pos( in_mother );
    }

    return vin_parents;
} // end of ds_cookie_mgmt_table::m_get_parents

/**
 *
 * function ds_cookie_mgmt_table::m_get_link_by_pointer
 *
 * @param[in]   int     in_points_to
 * @param[out]  int     *ain_pos        position of found ads_link
 *
 * @return      ds_cookie_link*
 *
*/
ds_cookie_link* ds_cookie_mgmt_table::m_get_link_by_pointer( int in_points_to, int *ain_pos )
{
    // initialize some variables:
    ds_cookie_link* ads_link = NULL;
    bool            bo_found = false;

    if ( m_is_cma_locked() ) {
        for ( int in_pos = 0; in_pos < ads_man_cap->in_capacity; in_pos++ ) {
            ads_link = m_get_link_by_pos( in_pos );
            if (    ads_link != NULL
                 && ads_link->bo_occupied
                 && ads_link->in_occ_indices > 0 )
            {
                for ( int in_1 = 0; in_1 < CK_MAX_PER_DOMAIN; in_1++ ) {
                    if ( ads_link->rin_indices[in_1] == in_points_to ) {
                        bo_found = true;
                        *ain_pos = in_pos;
                        in_pos = ads_man_cap->in_capacity; // break second loop too!
                        break;
                    }
                }
            }
        }
    }

    if ( !bo_found ) {
        ads_link = NULL;
        *ain_pos = -1;
    }

    return ads_link;
} // end of ds_cookie_mgmt_table::m_get_link_by_pointer


/**
 *
 * function ds_cookie_mgmt_table::m_fill
 *
 * @param[in]   ds_cookie_link* ads_link        structure that should be filled
 * @param[in]   int             in_points_to    pointer to position in ds_cookie_memory 
 * @param[in]   int             in_father       pointer to father element in ds_cookie_mgmt_table
 * @param[in]   int             in_mother       pointer to mother element in ds_cookie_mgmt_table
 * @param[in]   int             in_add_childs   increase child counter with this number
 *
 * @return      int                             position where entry is saved at
 *                                              -1 if error occured
 *
*/
bool ds_cookie_mgmt_table::m_fill( ds_cookie_link* ads_link,
                                   int in_points_to, int in_father,
                                   int in_mother, int in_add_childs )
{
    // initialize some variables:
    bool bo_return = false;

    if ( ads_link != NULL ) {
        if ( !ads_link->bo_occupied ) {
            ads_link->bo_occupied = true;
        }
        bo_return = m_add_index( ads_link, in_points_to );
        if ( bo_return ) {
            bo_return = m_set_parents( ads_link, in_father, in_mother );
            if ( in_add_childs > 0 ) {
                ads_link->in_count_childs += in_add_childs;
            }
        }
    }

    return bo_return;
} // end of ds_cookie_mgmt_table::m_fill


/**
 *
 * function ds_cookie_mgmt_table::m_free
 *
 * @param[in]   int     in_mgmt_pos     position, where to delete r_mgmt
 *
 * @return      bool                    true = success
 *
*/
bool ds_cookie_mgmt_table::m_free( ds_cookie_link* ads_link )
{
    if (    ads_link != NULL
         && ads_link->bo_occupied ) 
    {
        ads_link->bo_occupied   = false;
        ads_link->in_father     = -1;
        ads_link->in_mother     = -1;
        if ( ads_link->in_occ_indices > 0 ) {
            int in_count = 0;
            for ( int in_1 = 0; in_1 < CK_MAX_PER_DOMAIN; in_1++ ) {
                if ( ads_link->rin_indices[in_1] > -1 ) {
                    in_count++;
                    ads_link->rin_indices[in_1] = -1;
                }
                if ( in_count == ads_link->in_occ_indices ) {
                    break;
                }
            }
            ads_link->in_occ_indices = 0;
        }
        ads_link->in_count_childs = 0;
    }
    return true;
} // end of ds_cookie_mgmt_table::m_free


/**
 *
 * function ds_cookie_mgmt_table::m_add_index
 *
 * @param[in]   ds_cookie_link* ads_link
 * @param[in]   int             in_mem_index    index that should be added
 *
 * @return      bool            true = success
 *
*/
bool ds_cookie_mgmt_table::m_add_index( ds_cookie_link* ads_link, int in_mem_index )
{
    
    if ( in_mem_index < 0 ) {
        return true;
    }

    bool bo_return = false;

    for ( int in_1 = 0; in_1 < CK_MAX_PER_DOMAIN; in_1++ ) {
        if ( ads_link->rin_indices[in_1] == -1 ) {
            ads_link->rin_indices[in_1] = in_mem_index;
            ads_link->in_occ_indices++;
            bo_return = true;
            break;
        } else if ( ads_link->rin_indices[in_1] == in_mem_index ) {
            bo_return = true;
            break;
        }
    }

    return bo_return;
} // end of ds_cookie_mgmt_table::m_add_index


/**
 *
 * function ds_cookie_mgmt_table::m_remove_index
 *
 * @param[in]   ds_cookie_link*     ads_link
 * @param[in]   int in_mem_index    index that should be removed
 *
 * @return      bool                true = success
 *
*/
bool ds_cookie_mgmt_table::m_remove_index( ds_cookie_link* ads_link, int in_mem_index )
{
    if ( in_mem_index < 0 ) {
        return true;
    }

    // initialize some variables:
    bool            bo_return = false;

    for ( int in_1 = 0; in_1 < CK_MAX_PER_DOMAIN; in_1++ ) {
        if ( ads_link->rin_indices[in_1] == in_mem_index ) {
            ads_link->rin_indices[in_1] = -1;
            ads_link->in_occ_indices--;
            bo_return = true;
            break;
        }
    }

    return bo_return;
} // end of ds_cookie_mgmt_table::m_remove_index


/**
 *
 * function ds_cookie_mgmt_table::m_remove_child
 *
 * @param[in]   ds_cookie_link* ads_link
 *
*/
void ds_cookie_mgmt_table::m_remove_child( ds_cookie_link* ads_link )
{
    if ( ads_link->in_count_childs > 0 ) {
        ads_link->in_count_childs--;
    }
} // end of ds_cookie_mgmt_table::m_remove_child


/**
 *
 * function ds_cookie_mgmt_table::m_set_parents
 *
 * @param[in]   ds_cookie_link* ads_link
 * @param[in]   int             in_father
 * @param[in]   int             in_mother
 *
 * @return      bool                        true = success
 *
*/
bool ds_cookie_mgmt_table::m_set_parents( ds_cookie_link* ads_link, int in_father, int in_mother )
{
    bool bo_1 = false;
    bool bo_2 = false;

    if ( in_father > -1 ) {
        if ( ads_link->in_father == -1 ) {
            ads_link->in_father = in_father;
            bo_1 = true;
        } else if ( ads_link->in_father == in_father ) {
            bo_1 = true;
        }
    } else {
        bo_1 = true;
    }

    if ( in_mother > -1 ) {
        if ( ads_link->in_mother == -1 ) {
            ads_link->in_mother = in_mother;
            bo_2 = true;
        } else if ( ads_link->in_mother == in_mother ) {
            bo_2 = true;
        }
    } else {
        bo_2 = true;
    }

    return (bo_1 && bo_2);
} // end of ds_cookie_mgmt_table::m_set_parents


/**
 *
 * function ds_cookie_mgmt_table::m_get_next_free
 *
 * @param[out]   int*             ain_pos       position
 *
 * @return       ds_cookie_link*
 *
*/
ds_cookie_link* ds_cookie_mgmt_table::m_get_next_free( int* ain_pos )
{
    // initialize some variables:
    ds_cookie_link* ads_link = NULL;
    bool            bo_found = false;

    if ( m_is_cma_locked() ) {
        for ( int in_pos = 0; in_pos < ads_man_cap->in_capacity; in_pos++ ) {
            ads_link = m_get_link_by_pos( in_pos );
            if (    ads_link != NULL 
                 && !ads_link->bo_occupied )
            {
                *ain_pos = in_pos;
                bo_found = true;
                break;
            }
        }
    }

    if ( !bo_found ) {
        ads_link = NULL;
        *ain_pos = -1;
    }
    return ads_link;
} // end of ds_cookie_mgmt_table::m_get_next_free


/**
 *
 * function ds_cookie_mgmt_table::m_get_link_by_pos
 *
 * @param[in]   int in_pos
 *
 * @return      ds_cookie_link*
 *
*/
ds_cookie_link* ds_cookie_mgmt_table::m_get_link_by_pos( int in_pos )
{
    // initialize some variables:
    ds_cookie_link* ads_link = NULL;

    if (    m_is_cma_locked()   /* we have lock on cma */
         && in_pos > -1         /* in_pos is between 0 and capacity */
         && in_pos < ads_man_cap->in_capacity )
    {
        void* av_start = ((char*)ads_man_cap) + sizeof(ds_capacity);
        // try to align on 8byte boundary
        av_start = DO_ALIGN(av_start);
        av_start = ((char*)av_start) + in_pos * sizeof(ds_cookie_link);
        ads_link = (ds_cookie_link*)av_start;
    }

    return ads_link;
} // end of ds_cookie_mgmt_table::m_get_link_by_pos


/**
 *
 * function ds_cookie_mgmt_table::m_create_cma_buf
 *
 * @param[in]   int in_items
 *
*/
bool ds_cookie_mgmt_table::m_create_cma_buf( int in_items )
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    int in_buf_size = sizeof(ds_capacity) + in_items * sizeof(ds_cookie_link);

    // query size (NO LOCK required)
    ds_cma_man.iec_ccma_def = ied_ccma_query;
    BOOL bo_cma = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_COM_CMA,
                                             &ds_cma_man, sizeof(dsd_hl_aux_c_cma_1));
    if (!bo_cma) {   // CMA returned error
        adsc_wsp_helper->m_cb_print_out( "HWSGE513E: query size of CMA failed" );
        return false;
    }

    if ( (ds_cma_man.inc_len_cma_area == 0) || (ds_cma_man.inc_len_cma_area < in_buf_size) ) { // 1st: no CMA exists -> create it; 2nd: CMA exists but is too small -> resize it
        // get lock
        if (!m_get_cma_lock()) {
            return false;
        }
        m_set_size_cma(in_items);
        // release lock
        m_release_cma_lock();
    }
    
    return true;
} // end of ds_cookie_mgmt_table::m_create_cma_buf


/**
 *
 * function ds_cookie_mgmt_table::m_get_cma_lock
 *
*/
bool ds_cookie_mgmt_table::m_get_cma_lock()
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    in_count_locks++;
    if ( in_count_locks < 2 ) {
        ds_cma_man.iec_ccma_def = ied_ccma_lock_global; // get a lock
        ds_cma_man.imc_lock_type = D_CMA_ALL_ACCESS;

        BOOL bo_cma = ads_trans->amc_aux( ads_trans->vpc_userfld, DEF_AUX_COM_CMA,
                                                 &ds_cma_man, sizeof(dsd_hl_aux_c_cma_1));
        if ( (!bo_cma) ) { // CMA returned error
            adsc_wsp_helper->m_cb_print_out( "HWSGE514E: no CMA-lock available" );
            return  false;
        }

        ads_man_cap = (ds_capacity*)ds_cma_man.achc_cma_area;
    }
    return true;
} // end of ds_cookie_mgmt_table::m_get_cma_lock


/**
 *
 * function ds_cookie_mgmt_table::m_release_cma_lock
 *
*/
bool ds_cookie_mgmt_table::m_release_cma_lock()
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    in_count_locks--;
    if ( in_count_locks < 1 ) {
        ds_cma_man.iec_ccma_def = ied_ccma_lock_rel_upd;
        BOOL bo_cma = ads_trans->amc_aux(ads_trans->vpc_userfld, DEF_AUX_COM_CMA,
                                                 &ds_cma_man, sizeof(dsd_hl_aux_c_cma_1));
        if (!bo_cma) {   // CMA returned error
            adsc_wsp_helper->m_cb_print_out("HWSGE515E: cannot release lock on CMA");
            return false;
        }

        ads_man_cap = NULL;
    }
    return true;
} // end of ds_cookie_mgmt_table::m_release_cma_lock


/**
 *
 * function ds_cookie_mgmt_table::m_set_size_cma
 *
*/
bool ds_cookie_mgmt_table::m_set_size_cma(int in_items)
{
    struct dsd_hl_clib_1* ads_trans = (dsd_hl_clib_1*)adsc_wsp_helper->m_get_structure();
    ds_cma_man.iec_ccma_def = ied_ccma_set_size;
    ds_cma_man.inc_len_cma_area =              ((sizeof(ds_capacity)   + 7) & (~ 0x07))
                                  + in_items * ((sizeof(ds_cookie_link)    + 7) & (~ 0x07));

    BOOL bo_cma = ads_trans->amc_aux(ads_trans->vpc_userfld, DEF_AUX_COM_CMA,
                                             &ds_cma_man, sizeof(dsd_hl_aux_c_cma_1));
    if ((!bo_cma) || (ds_cma_man.achc_cma_area == NULL) ) {   // CMA returned error
        adsc_wsp_helper->m_cb_print_out("HWSGE516E: cannot set CMA size");        
        return false;
    }

    ads_man_cap = (ds_capacity*)ds_cma_man.achc_cma_area;
    ads_man_cap->in_capacity = in_items;
    m_setup_structs();
    return true;
} // end of ds_cookie_mgmt_table::m_set_size_cma



/**
 *
 * function ds_cookie_mgmt_table::m_is_cma_locked
 *
 * @return    bool   true = we have lock on cma, otherwise false
 *
*/
bool ds_cookie_mgmt_table::m_is_cma_locked()
{
    if ( in_count_locks > 0 ) {
        return true;
    } else {
        return false;
    }
} // end of ds_cookie_mgmt_table::m_is_cma_locked


/**
 *
 * function ds_cookie_mgmt_table::m_setup_structs
 *
*/
void ds_cookie_mgmt_table::m_setup_structs()
{
    if ( m_is_cma_locked() ) {
        // initialize some variables:
        ds_cookie_link* ads_link = NULL;
        ads_man_cap->in_free     = 0;

        for ( int in_pos = 0; in_pos < ads_man_cap->in_capacity; in_pos++ ) {
            ads_link = m_get_link_by_pos( in_pos );
            if (    ads_link != NULL
                 && !ads_link->bo_occupied )
            {
                ads_link->in_occ_indices = 0;
                for ( int in_1 = 0; in_1 < CK_MAX_PER_DOMAIN; in_1++ ) {
                    ads_link->rin_indices[in_1] = -1;
                }
                ads_link->in_father       = -1;
                ads_link->in_mother       = -1;
                ads_link->in_count_childs =  0;

                // enlarge free counter
                ads_man_cap->in_free++;
            }
        }
    }
} // end of ds_cookie_mgmt_table::m_setup_structs

/*+-------------------------------------------------------------------------+*/
/*| analysing functions:                                                    |*/
/*+-------------------------------------------------------------------------+*/

/**
 *
 * function ds_cookie_mgmt_table::m_get_overview
 *
 * @return      string
 *
*/
string ds_cookie_mgmt_table::m_get_overview()
{
#if 0
    // get cma locks:
    if ( !m_get_cma_lock() ) {
        return "";
    }

    // initialize some variables:
    string          str_return      = "";
    string          str_temp        = "";
    int             in_used_entries = 0;
    int             in_used_indices = 0;
    ds_cookie_link* ads_link        = NULL;

    // get entries from mgmt table:
    for ( int in_1 = 0; in_1 < ads_man_cap->in_capacity; in_1++ ) {
        ads_link = m_get_link_by_pos( in_1 );
        if ( ads_link != NULL && ads_link->bo_occupied ) {
            in_used_entries++;
        }
        in_used_indices += ads_link->in_occ_indices;
        str_temp += m_view( ads_link, in_1 );
    }

    str_return  = "mgmt table - capacity:     ";
    str_return += ads_session->dsc_str_helper.m_int_to_string( ads_man_cap->in_capacity ) + "\n";
    str_return += "           - used entries: ";
    str_return += ads_session->dsc_str_helper.m_int_to_string( in_used_entries ) + "\n";
    str_return += "pointer to memory - capacity: ";
    str_return += ads_session->dsc_str_helper.m_int_to_string( ads_man_cap->in_capacity*CK_MAX_PER_DOMAIN ) + "\n";
    str_return += "                  - used:     ";
    str_return += ads_session->dsc_str_helper.m_int_to_string( in_used_indices ) + "\n\n";
    str_return += str_temp;  

    // release cma locks:
    m_release_cma_lock();

    return str_return;
#endif
    return "";
} // end of ds_cookie_mgmt_table::m_get_overview


/**
 *
 * function ds_cookie_mgmt_table::m_view
 *
 * @param[in]   ds_cookie_link* ads_link
 * @param[in]   int             in_pos
 *
 * @return      string
 *
*/
string ds_cookie_mgmt_table::m_view( ds_cookie_link* ads_link, int in_pos )
{
#if 0
    // initialize some variables:
    string str_return = "";

    str_return += "position: ";
    str_return += ads_session->dsc_str_helper.m_int_to_string( in_pos ) + "\n";
    if ( ads_link != NULL ) {
        str_return += "\t entry in use:       ";
        if ( ads_link->bo_occupied ) {
            str_return += "YES\n";
        } else {
            str_return += "NO\n";
        }
        //str_return += "\t used pointers to memory: ";
        //str_return += ads_session->dsc_str_helper.m_int_to_string( ads_link->in_occ_indices ) + "\n";
        str_return += "\t pointers to memory: ";
        for ( int in_1 = 0; in_1 < CK_MAX_PER_DOMAIN; in_1++ ) {
            if ( ads_link->rin_indices[in_1] > -1 ) {
                str_return += ads_session->dsc_str_helper.m_int_to_string( ads_link->rin_indices[in_1] ) + ", ";
            }
        }
        str_return += "\n";
        str_return += "\t father entry:       ";
        str_return += ads_session->dsc_str_helper.m_int_to_string( ads_link->in_father ) + "\n";
        str_return += "\t mother entry:       ";
        str_return += ads_session->dsc_str_helper.m_int_to_string( ads_link->in_mother ) + "\n";
        str_return += "\t number of childs:   ";
        str_return += ads_session->dsc_str_helper.m_int_to_string( ads_link->in_count_childs ) + "\n";
    } else {
        str_return += "\t error: NULL pointer\n";
    }

    return str_return;
#endif
    return "";

} // end of ds_cookie_mgmt_table::m_view
