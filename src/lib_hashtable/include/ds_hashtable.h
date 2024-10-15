#ifndef DS_HASHTABLE_H
#define DS_HASHTABLE_H
/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_hashtable                                                          |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   November 2009                                                         |*/
/*|                                                                         |*/
/*| VERSION:                                                                |*/
/*| ========                                                                |*/
/*|   0.9                                                                   |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
#define DEF_MAX_HASH_LOAD 0.75
#define DEF_HASH_RESIZE   2

/*+-------------------------------------------------------------------------+*/
/*| forward defintions:                                                     |*/
/*+-------------------------------------------------------------------------+*/
class ds_wsp_helper;
class ds_hstring;

/*+-------------------------------------------------------------------------+*/
/*| element class:                                                          |*/
/*+-------------------------------------------------------------------------+*/
template <class T> class dsd_hash_element {
public:
    size_t               uinc_hash;             // hash value
    int                  inc_key_offset;        // offset of key in key buffer
    int                  inc_len;               // length of key
    T                    dsc_value;             // value
    dsd_hash_element<T>* adsc_coll;             // collusion
};


/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
template <class T> class ds_hashtable {
public:
    /**
     * class default constructor
    */
    ds_hashtable()
    {
        adsc_wsp_helper = NULL;
        adsc_table      = NULL;
        uinc_elems      = 0;
        uinc_used       = 0;
#ifdef _DEBUG
        uinc_colls      = 0;
#endif
    } // end of ds_hashtable::ds_hashtable


    /**
     * class constructor
     *
     * @param[in]   ds_wsp_helper*  adsl_wsp_helper     wsp helper class
     * @param[in]   size_t          uinl_size           start size of hashtable
     *                                                  default = 10
    */
    ds_hashtable( ds_wsp_helper* adsl_wsp_helper, size_t uinl_size = 10 )
    {
        m_setup( adsl_wsp_helper, uinl_size );
    } // end of ds_hashtable::ds_hashtable

    
    /**
     * class destructor
    */
    ~ds_hashtable()
    {
        m_clear();

        //-------------------------------------------
        // free hash table memory:
        //-------------------------------------------
        adsc_wsp_helper->m_cb_free_memory( adsc_table );
    } // end of ds_hashtable::~ds_hashtable


    /**
     * public function ds_hashtable::m_setup
     *
     * @param[in]   ds_wsp_helper*  adsl_wsp_helper     wsp helper class
     * @param[in]   size_t          uinl_size           start size of hashtable
     *                                                  default = 10
    */
    void m_setup( ds_wsp_helper* adsl_wsp_helper, size_t uinl_size = 10 )
    {
        dsc_key_buffer.m_setup( adsl_wsp_helper );

        adsc_wsp_helper = adsl_wsp_helper;

        //-------------------------------------------
        // get memory:
        //-------------------------------------------
        adsc_table = (dsd_hash_element<T>*)adsc_wsp_helper->m_cb_get_memory(
                                        uinl_size * sizeof(dsd_hash_element<T>),
                                        true );

        //-------------------------------------------
        // set sizes:
        //-------------------------------------------
        uinc_elems = (adsc_table != NULL)?uinl_size:0;
        uinc_used  = 0;
#ifdef _DEBUG
        uinc_colls = 0;
#endif
    } // end of ds_hashtable::m_setup


    /**
     * public function ds_hashtable::m_init
     *
     * @param[in]   ds_wsp_helper*  adsl_wsp_helper     wsp helper class
    */
    void m_init( ds_wsp_helper* adsl_wsp_helper )
    {
        dsc_key_buffer.m_init( adsl_wsp_helper );

		if ( adsc_table == NULL ) {
			m_setup( adsl_wsp_helper );
		} else {
			adsc_wsp_helper = adsl_wsp_helper;
		}
    } // end of ds_hashtable::m_init


    /**
     * public function ds_hashtable::m_add
     *
     * add a key value pair to our hashtable
     *
     * @param[in]   const char* achl_key        key
     * @param[in]   int         inl_len         length of key
     * @param[in]   T           dsl_value       value
     * @return      bool                        true = entry added
     *                                          false otherwise
    */
    bool m_add( const char* achl_key, int inl_len, T dsl_value )
    {
        // initialize some variables:
        bool                 bol_ret;               // return for function calls
        size_t               uinl_hash;             // hash
        size_t               uinl_pos;              // position in hash table
        size_t               uinl_free;             // free entries
        dsd_hash_element<T>* adsl_element;          // element to insert

        //-------------------------------------------
        // check input data:
        //-------------------------------------------
        if (    achl_key  == NULL
             || inl_len    < 1    ) {
            return false;
        }

        //-------------------------------------------
        // check load of hash table:
        //-------------------------------------------
        uinl_free = (uinc_elems > uinc_used)?(uinc_elems - uinc_used):0;
        if ( uinl_free <= (1-DEF_MAX_HASH_LOAD) * uinc_elems ) {
            bol_ret = m_enlarge();
            if ( bol_ret == false ) {
                return false;
            }
        }

        //-------------------------------------------
        // evaluate hash and it's position:
        //-------------------------------------------
        uinl_hash = m_get_hash( achl_key, inl_len );
        uinl_pos  = uinl_hash%uinc_elems;

        //-------------------------------------------
        // get element at position from hash table:
        //-------------------------------------------
        adsl_element = m_get_element( adsc_table, uinl_pos );
        if ( adsl_element == NULL ) {
            return false;
        }

        //-------------------------------------------
        // insert entry:
        //-------------------------------------------
        if ( adsl_element->inc_len < 1 ) {
            /*
                entry at current position is free
                -> fill it
                -> save given key
            */
            adsl_element->uinc_hash      = uinl_hash;
            adsl_element->inc_key_offset = (int)(   (    dsc_key_buffer.m_get_ptr()
                                                      +  dsc_key_buffer.m_get_len() ) 
                                                  - dsc_key_buffer.m_get_ptr() );
            adsl_element->inc_len        = inl_len;
            adsl_element->dsc_value      = dsl_value;
            adsl_element->adsc_coll      = NULL;

            dsc_key_buffer.m_write( achl_key, inl_len );
        } else {
            /*
                entry at current position is already used
                -> if keys are equal: replace value
                -> else: create a coll entry
            */
            if ( adsl_element->inc_len == inl_len
                && dsc_key_buffer.m_starts_with( adsl_element->inc_key_offset, achl_key, inl_len ))
            {
                adsl_element->dsc_value = dsl_value;
                return true;
            } else {
                // get last coll entry:
                while ( adsl_element->adsc_coll != NULL ) {
                    adsl_element = adsl_element->adsc_coll;
                }

                // get memory:
                adsl_element->adsc_coll = (dsd_hash_element<T>*)adsc_wsp_helper->m_cb_get_memory(
                                            sizeof(dsd_hash_element<T>),
                                            false );
                adsl_element = adsl_element->adsc_coll;
                if ( adsl_element == NULL ) {
                    return false;
                }

                // fill new entry:
                adsl_element->uinc_hash      = uinl_hash;
                adsl_element->inc_key_offset = (int)(   (    dsc_key_buffer.m_get_ptr()
                                                          +  dsc_key_buffer.m_get_len() ) 
                                                      - dsc_key_buffer.m_get_ptr() );
                adsl_element->inc_len        = inl_len;
                adsl_element->dsc_value      = dsl_value;
                adsl_element->adsc_coll      = NULL;

                dsc_key_buffer.m_write( achl_key, inl_len );
#ifdef _DEBUG
                uinc_colls++;
#endif
            }
        }

        //-------------------------------------------
        // count element:
        //-------------------------------------------
        uinc_used++;
        return true;
    } // end of ds_hashtable::m_add


    /**
     * public function ds_hashtable::m_add
     *
     * add a key value pair to our hashtable
     *
     * @param[in]   const char* achl_key        key (zero termintated)
     * @param[in]   T           dsl_value       value
     * @return      bool                        true = entry added
     *                                          false otherwise
    */
    bool m_add( const char* achl_key, T dsl_value )
    {
        if ( achl_key == NULL ) {
            return false;
        }
        return m_add( achl_key, strlen(achl_key), dsl_value );
    } // end of ds_hashtable::m_add


    /**
     * public function ds_hashtable::m_replace
     *
     * replace a value for given key
     *
     * @param[in]   const char*     ach_key         search for this key
     * @param[in]   int             in_len          length of key
     * @param[in]   T               ds_value        key value
     * @return      bool                            true = entry replaced
     *                                              false otherwise
    */
    bool m_replace( const char* ach_key, int in_len, T ds_value )
    {
        // initialize some variables:
        size_t               uinl_hash;             // hash
        size_t               uinl_pos;              // position in hash table
        dsd_hash_element<T>* adsl_element;          // element to insert

        //-------------------------------------------
        // check input data:
        //-------------------------------------------
        if (    ach_key  == NULL
             || in_len    < 1    ) {
            return false;
        }

        //-------------------------------------------
        // evaluate hash and it's position:
        //-------------------------------------------
        uinl_hash = m_get_hash( ach_key, in_len );
        uinl_pos  = uinl_hash%uinc_elems;

        //-------------------------------------------
        // get element at position from hash table:
        //-------------------------------------------
        adsl_element = m_get_element( adsc_table, uinl_pos );
        if ( adsl_element == NULL ) {
            return false;
        }

        //-------------------------------------------
        // check if key is equal:
        //-------------------------------------------
        if (    adsl_element->inc_len == in_len
             && dsc_key_buffer.m_search( ach_key, in_len, false,
                                         adsl_element->inc_key_offset,
                                         false ) == 0                   ) {
            adsl_element->dsc_value = ds_value;
            return true;            
        }
        return false;
    } // end of ds_hashtable::m_replace


    /**
     * public function ds_hashtable::m_replace
     *
     * replace a value for given key
     *
     * @param[in]   const char* ach_key         key (zero termintated)
     * @param[in]   T           ds_value        value
     * @return      bool                        true = entry added
     *                                          false otherwise
    */
    bool m_replace( const char* ach_key, T ds_value )
    {
        if ( ach_key == NULL ) {
            return false;
        }
        return m_replace( ach_key, strlen(ach_key), ds_value );
    } // end of ds_hashtable::m_replace


    /**
     * public function ds_hashtable::m_get
     *
     * search in hash table for entry with key and return it's value
     *
     * @param[in]   const char*     achl_key        search for this key
     * @param[in]   int             inl_len         length of key
     * @param[out]  T*              ads_value       found key value
     * @return      bool                            true = entry found
     *                                              false otherwise
    */
    bool m_get( const char* achl_key, int inl_len, T* ads_value ) const
    {
        // initialize some variables:
        size_t               uinl_hash;             // hash
        size_t               uinl_pos;              // position in hash table
        dsd_hash_element<T>* adsl_element;          // found element

        //-------------------------------------------
        // check input data:
        //-------------------------------------------
        if (    achl_key  == NULL
             || inl_len    < 1
             || ads_value == NULL ) {
            return false;
        }

        //-------------------------------------------
        // evaluate hash and it's position:
        //-------------------------------------------
        uinl_hash = m_get_hash( achl_key, inl_len );
        uinl_pos  = uinl_hash%uinc_elems;

        //-------------------------------------------
        // get element at position from hash table:
        //-------------------------------------------
        adsl_element = m_get_element( adsc_table, uinl_pos );
        if (    adsl_element          == NULL
             || adsl_element->inc_len < 1     ) {
            return false;
        }

        //-------------------------------------------
        // check if element is equal:
        //-------------------------------------------
        if ( m_equals( adsl_element, uinl_hash, achl_key, inl_len ) ) {
            /*
                found element in hash table
            */
            *ads_value = adsl_element->dsc_value;
            return true;
        } else if ( adsl_element->adsc_coll != NULL ) {
            /*
                element not found in hashtable, but coll pointer is set
                 -> loop through list of coll pointers
            */
            while ( adsl_element->adsc_coll != NULL ) {
                adsl_element = adsl_element->adsc_coll;
                if ( m_equals( adsl_element, uinl_hash, achl_key, inl_len ) ) {
                    *ads_value = adsl_element->dsc_value;
                    return true;
                }
            }
        }
        return false;
    } // end of ds_hashtable::m_get

    
    /**
     * public function ds_hashtable::m_get
     *
     * search in hash table for entry with key and return it's value
     *
     * @param[in]   const char*     achl_key        search for this key (zero terminated)
     * @param[out]  T*              ads_value       found key value
     * @return      bool                            true = entry found
     *                                              false otherwise
    */
    bool m_get( const char* achl_key, T* ads_value ) const
    {
        if ( achl_key == NULL ) {
            return false;
        }
        return m_get( achl_key, strlen(achl_key), ads_value );
    } // end of ds_hashtable::m_get


    /**
     * public function ds_hashtable::m_clear
     *
     * delete all entries in hashtable
    */
    void m_clear()
    {
        // initialize some variables:
        size_t               uinl_pos;              // current position
        dsd_hash_element<T>* adsl_element;          // current element
        dsd_hash_element<T>* adsl_coll1;
        dsd_hash_element<T>* adsl_coll2;

        //-------------------------------------------
        // loop through all entries:
        //-------------------------------------------
        for ( uinl_pos = 0; uinl_pos < uinc_elems; uinl_pos++ ) {
            adsl_element = m_get_element( adsc_table, uinl_pos );

            //---------------------------------------
            // delete all collosion entries:
            //---------------------------------------
            adsl_coll1 = adsl_element->adsc_coll;
            while ( adsl_coll1 != NULL ) {
                adsl_coll2 = adsl_coll1->adsc_coll;
                adsl_coll1->dsd_hash_element<T>::~dsd_hash_element();
                adsc_wsp_helper->m_cb_free_memory( adsl_coll1 );
                adsl_coll1 = adsl_coll2;
            }

            //---------------------------------------
            // reset entry:
            //---------------------------------------
            adsl_element->uinc_hash      = 0;
            adsl_element->inc_key_offset = 0;
            adsl_element->inc_len        = 0;
            adsl_element->adsc_coll      = NULL;
        }

        //-------------------------------------------
        // reset used counter:
        //-------------------------------------------
        uinc_used = 0;
#ifdef _DEBUG
        uinc_colls = 0;
#endif
    } // end of ds_hashtable::m_clear

private:
      // variables:
    ds_wsp_helper*       adsc_wsp_helper;           // wsp helper class
    size_t               uinc_elems;                // number of elements in table
    size_t               uinc_used;                 // used entries
#ifdef _DEBUG
    size_t               uinc_colls;
#endif
    dsd_hash_element<T>* adsc_table;                // hash table itself
    ds_hstring           dsc_key_buffer;            // buffer for different keys


    /**
     * private function ds_hashtable::m_enlarge
     *
     * enlarge hash table
     * 
     * @return  bool
    */
    bool m_enlarge()
    {
        // initialize some variables:
        bool                 bol_ret;               // return from function calls
        size_t               uinl_old_elems;        // old number of elements
        size_t               uinl_coll_elems;       // number of coll elements
        size_t               uinl_pos;              // position in backup
        dsd_hash_element<T>* adsl_backup;           // backup old hash table
        dsd_hash_element<T>* adsl_element;          // current element
        dsd_hash_element<T>* adsl_coll1;
        dsd_hash_element<T>* adsl_coll2;

        //-------------------------------------------
        // backup old hash table:
        //-------------------------------------------
        adsl_backup    = adsc_table;
        uinl_old_elems = uinc_elems;

        //-------------------------------------------
        // evaluate new number of elements:
        //-------------------------------------------
        uinl_coll_elems = (uinc_used > uinc_elems)?(uinc_used - uinc_elems):0;
        uinc_elems      = (size_t)(   ( 2 - DEF_MAX_HASH_LOAD )
                                    * ( DEF_HASH_RESIZE * uinl_old_elems + uinl_coll_elems ) );
        uinc_used       = 0;
#ifdef _DEBUG
        uinc_colls      = 0;
#endif

        //-------------------------------------------
        // get memory for new table:
        //-------------------------------------------
        adsc_table = (dsd_hash_element<T>*)adsc_wsp_helper->m_cb_get_memory(
                                        uinc_elems * sizeof(dsd_hash_element<T>),
                                        true );
        if ( adsc_table == NULL ) {
            return false;
        }

        //-------------------------------------------
        // loop through all elements in backup:
        //-------------------------------------------
        for ( uinl_pos = 0; uinl_pos < uinl_old_elems; uinl_pos++ ) {
            adsl_element = m_get_element( adsl_backup, uinl_pos );
            if (    adsl_element != NULL
                 && adsl_element->inc_len > 0 ) {
                //-----------------------------------
                // insert element itself:
                //-----------------------------------
                bol_ret = m_add( (dsc_key_buffer.m_get_ptr() + adsl_element->inc_key_offset),
                                 adsl_element->inc_len, adsl_element->dsc_value );
                if ( bol_ret == false ) {
                    return false;
                }

                //-----------------------------------
                // insert and delete coll entries:
                //-----------------------------------
                adsl_coll1 = adsl_element->adsc_coll;
                while ( adsl_coll1 != NULL ) {
                    // insert entry:
                    bol_ret = m_add( (dsc_key_buffer.m_get_ptr() + adsl_coll1->inc_key_offset),
                                     adsl_coll1->inc_len, adsl_coll1->dsc_value );
                    if ( bol_ret == false ) {
                        return false;
                    }

                    // delete it:
                    adsl_coll2 = adsl_coll1->adsc_coll;
                    adsl_coll1->dsd_hash_element<T>::~dsd_hash_element();
                    adsc_wsp_helper->m_cb_free_memory( adsl_coll1 );
                    adsl_coll1 = adsl_coll2;
                }
            }
        } // end of loop through backup entries

        //-------------------------------------------
        // free backup memory:
        //-------------------------------------------
        adsc_wsp_helper->m_cb_free_memory( adsl_backup );
        return true;
    } // end of ds_hashtable::m_enlarge

    /**
     * private function ds_hashtable::m_get_hash
     *
     * @param[in]   const char* achl_key
     * @param[in]   int         inl_len
    */
    size_t m_get_hash( const char* achl_key, int inl_len ) const
    {
        // initialize some variables:
        size_t uin_hash = 5381;
        int    in_pos;

        for ( in_pos = 0; in_pos < inl_len; in_pos++ ) {
            uin_hash = ((uin_hash << 5) + uin_hash) + achl_key[in_pos];
        }
        return uin_hash;
    } // end of ds_hashtable::m_get_hash


    /**
     * private function ds_hashtable::m_get_element
     *
     * @param[in]   dsd_hash_element<T>*    adsl_table
     * @param[in]   size_t                  uinl_index
     * @return      dsd_hash_element<T>*
    */
    dsd_hash_element<T>* m_get_element( dsd_hash_element<T>* adsl_table, size_t uinl_index ) const
    {
        return adsl_table + uinl_index;
    } // end of ds_hashtable::m_get_element


    /**
     * private function ds_hashtable::m_equals
     *
     * @param[in]   dsd_hash_element<T>*    ads_element
     * @param[in]   size_t                  uin_hash
     * @param[in]   const char*             ach_key
     * @param[in]   int                     in_len
     * @return      bool
    */
    bool m_equals( dsd_hash_element<T>* ads_element, size_t uin_hash,
                   const char* ach_key, int in_len                    ) const
    {
        // check length:
        if ( in_len != ads_element->inc_len ) {
            return false;
        }

        // check hash:
        if ( uin_hash != ads_element->uinc_hash ) {
            return false;
        }

        // check string itself:
        return ( dsc_key_buffer.m_starts_with( ads_element->inc_key_offset, ach_key, in_len  ) );
        //return dsc_key_buffer.m_starts_with( ach_key, in_len, false, ads_element->inc_key_offset, false );
    } // end of ds_hashtable::m_equals
};

#endif // DS_HASHTABLE_H
