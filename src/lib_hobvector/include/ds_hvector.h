#ifndef DS_HVECTOR_H
#define DS_HVECTOR_H
/*+-------------------------------------------------------------------------+*/
/*|                                                                         |*/
/*| PROJECT-NAME:                                                           |*/
/*| =============                                                           |*/
/*|   ds_hvector                                                            |*/
/*|   TAKE CARE: this vector is not thread save, so                         |*/
/*|              DONT USE THE SAME VECTOR ON MORE THAN ONE THREAD           |*/
/*|                                                                         |*/
/*| AUTHOR:                                                                 |*/
/*| =======                                                                 |*/
/*|   Michael Jakobs                                                        |*/
/*|                                                                         |*/
/*| DATE:                                                                   |*/
/*| =====                                                                   |*/
/*|   30. September 2009                                                    |*/
/*|                                                                         |*/
/*| VERSION:                                                                |*/
/*| ========                                                                |*/
/*|   2                                                                     |*/
/*|                                                                         |*/
/*| COPYRIGHT:                                                              |*/
/*| ==========                                                              |*/
/*|  HOB GmbH & Co. KG, Germany                                             |*/
/*|                                                                         |*/
/*+-------------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------------+*/
/*| includes:                                                               |*/
/*+-------------------------------------------------------------------------+*/
#include <assert.h>
#include <new>
#include <ds_wsp_helper.h>
/*+-------------------------------------------------------------------------+*/
/*| helper structure                                                        |*/
/*+-------------------------------------------------------------------------+*/
template <class T> class dsd_hvec_elem {
public:
    T              dsc_element;         // current element
    dsd_hvec_elem* ads_next;            // next element pointer
};

#define HVECTOR_NEXT(V) V=V->ads_next
#define HVECTOR_ITERATE(T, V, I, E) const dsd_hvec_elem<T>* V=I; V != (E); V=V->ads_next
#define HVECTOR_ITERATE2(T, V, I, E) dsd_hvec_elem<T>* V=I; V != (E); V=V->ads_next
#define HVECTOR_FOREACH(T, V, X) const dsd_hvec_elem<T>* V=(X).m_get_first_element(); V != NULL; V=V->ads_next
#define HVECTOR_FOREACH2(T, V, X) dsd_hvec_elem<T>* V=(X).m_get_first_element2(); V != NULL; V=V->ads_next
#define HVECTOR_GET(V) (V)->dsc_element

template <class T, size_t OFFSET_NEXT> struct dsd_hl_slist {
private:
	T* adsc_first;
	T** aadsc_tailp;

public:
	static T** m_next_ptr(T* adsl_elem) {
		return (T**)(((char*)adsl_elem)+OFFSET_NEXT);
	}

	dsd_hl_slist() {
		this->adsc_first = NULL;
		this->aadsc_tailp = &this->adsc_first;
	}

	void m_reset() {
		this->adsc_first = NULL;
		this->aadsc_tailp = &this->adsc_first;
	}

	T* m_get_first() {
		return this->adsc_first;
	}

	T* m_get_last() {
		if(this->aadsc_tailp == &this->adsc_first)
			return NULL;
		T* adsl_last = (T*)(((char*)this->aadsc_tailp)-OFFSET_NEXT);
		return adsl_last;
	}

	T* m_remove_first() {
		T* adsl_elem = this->adsc_first;
		if(adsl_elem == NULL)
			return NULL;
		T** aadsl_np = m_next_ptr(adsl_elem);
		this->adsc_first = *aadsl_np;
		if(this->adsc_first != NULL) {
			*aadsl_np = NULL;
			return adsl_elem;
		}
		this->aadsc_tailp = &this->adsc_first;
		return adsl_elem;
	}

	void m_append(T* adsp_elem) {
		*m_next_ptr(adsp_elem) = NULL;
		*this->aadsc_tailp = adsp_elem;
		this->aadsc_tailp = m_next_ptr(adsp_elem);
	}

	void m_prepend(T* adsp_elem) {
		T* adsl_old = this->adsc_first;
		*m_next_ptr(adsp_elem) = adsl_old;
		this->adsc_first = adsp_elem;
		if(adsl_old == NULL)
			this->aadsc_tailp = m_next_ptr(adsp_elem);
	}
};

template <class T, size_t OFFSET_NEXT, size_t OFFSET_PREV> struct dsd_hl_dlist {
private:
	dsd_hl_slist<T, OFFSET_NEXT> dsc_slist;

	static T** m_prev_ptr(T* adsp_elem) {
		return (T**)(((char*)adsp_elem)+OFFSET_PREV);
	}
public:
	dsd_hl_dlist() : dsc_slist() {
	}

	void m_reset() {
		this->dsc_slist.m_reset();
	}

	void m_append(T* adsp_elem) {
		T* adsl_last = this->dsc_slist.m_get_last();
		*m_prev_ptr(adsp_elem) = adsl_last;
		this->dsc_slist.m_append(adsp_elem);
	}

	void m_prepend(T* adsp_elem) {
		T* adsl_first = this->dsc_slist.m_get_first();
		this->dsc_slist.m_prepend(adsp_elem);
		*m_prev_ptr(adsp_elem) = NULL;
		if(adsl_first == NULL)
			return;
		*m_prev_ptr(adsl_first) = adsp_elem;
	}

	T* m_get_first() {
		return this->dsc_slist.m_get_first();
	}

	T* m_get_last() {
		return this->dsc_slist.m_get_last();
	}
};

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
template <class T> class ds_hvector_btype {
public:
    /**
     * constructor ds_hvector_btype::ds_hvector_btype
    */
    ds_hvector_btype()
    {
        this->adsc_wsp_helper = NULL;
        this->adsc_first   = NULL;
        this->adsc_last   = NULL;
        this->uinc_elements   = 0;
    } // end of ds_hvector_btype::ds_hvector_btype


    /**
     * constructor ds_hvector_btype::ds_hvector_btype
     * 
     * @param[in]   ds_wsp_helper* ads_wsp_helper
    */
    ds_hvector_btype( ds_wsp_helper* ads_wsp_helper )
    {
        adsc_wsp_helper = ads_wsp_helper;
        this->adsc_first   = NULL;
        this->adsc_last = NULL;
        this->uinc_elements   = 0;
    } // end of ds_hvector_btype::ds_hvector_btype


    /**
     * copy constructor ds_hvector_btype::ds_hvector_btype
     *
     * @param[in]   const ds_hvector_btype&  dc_copy
    */
    ds_hvector_btype( const ds_hvector_btype& dc_copy )
    {
        this->adsc_wsp_helper = NULL;
        this->adsc_first   = NULL;
        this->adsc_last = NULL;
        this->uinc_elements   = 0;
        m_copy( dc_copy );
    } // end of ds_hvector_btype::ds_hvector_btype


    /**
     * destructor ds_hvector_btype::~ds_hvector_btype
    */
    ~ds_hvector_btype()
    {
        m_clear();
    } // end of ds_hvector_btype::~ds_hvector_btype

    void m_check_consistency()
    {
#if _DEBUG
        size_t uinl_pos = 0;
        dsd_hvec_elem<T>* adsl_temp = this->adsc_first;
        while(adsl_temp != NULL) {
            uinl_pos++;
            adsl_temp = adsl_temp->ads_next;
        }
        if(uinl_pos != uinc_elements)
            throw 0;
        assert( uinl_pos == uinc_elements );
#endif
    }

    /**
     * ds_hvector_btype::operator =
     *
     * @param[in]   const ds_hvector_btype&  dc_in
     * @return      ds_hvector_btype&
    */
    ds_hvector_btype& operator = ( const ds_hvector_btype& dc_in )
    {
        m_copy( dc_in );
        return *this;
    } // end of ds_hvector_btype::operator =


#if 0
    /**
     * ds_hvector_btype::operator []
     * get element at requested index
     *
     * @param[in]   size_t  uin_index       requested position
     * @return      T                       requested element
    */
    const T& operator [] ( size_t uin_index ) const
    {
        return m_get( uin_index );
    } // end of ds_hvector_btype::operator[]
#endif

#if 0
    /**
     * ds_hvector_btype::operator []
     * get element at requested index
     *
     * @param[in]   size_t  uin_index       requested position
     * @return      T                       requested element
    */
    T& operator [] ( size_t uin_index )
    {
        return const_cast<T&>(m_get( uin_index ));
    } // end of ds_hvector_btype::operator[]
#endif

    /**
     * function ds_hvector_btype::m_setup
     * 
     * @param[in]   ds_wsp_helper* ads_wsp_helper
    */
    void m_setup( ds_wsp_helper* ads_wsp_helper )
    {
        this->adsc_wsp_helper = ads_wsp_helper;
        this->adsc_first   = NULL;
        this->adsc_last   = NULL;
        this->uinc_elements   = 0;
    } // end of ds_hvector_btype::m_setup


    /**
     * function ds_hvector_btype::m_init
     * 
     * @param[in]   ds_wsp_helper* ads_wsp_helper
    */
    void m_init( ds_wsp_helper* ads_wsp_helper )
    {
        adsc_wsp_helper = ads_wsp_helper;
    } // end of ds_hvector_btype::m_init


    dsd_hvec_elem<T>* m_add2( const T& ds_item ) {
        // initialize some variables:
        dsd_hvec_elem<T>* adsl_temp;

        // check if first element
        if ( this->adsc_first == NULL ) {
            adsl_temp = (dsd_hvec_elem<T>*)adsc_wsp_helper->m_cb_get_memory( sizeof(dsd_hvec_elem<T>), true );
            if ( adsl_temp == NULL ) {
                return NULL;
            }
            new(&adsl_temp->dsc_element) T(ds_item);
            adsl_temp->ads_next = NULL;
            this->adsc_first = adsl_temp;
            this->adsc_last = adsl_temp;
            this->uinc_elements = 1;
            m_check_consistency();
            return adsl_temp;
        }

        // get last element:
        adsl_temp = (dsd_hvec_elem<T>*)adsc_wsp_helper->m_cb_get_memory( sizeof(dsd_hvec_elem<T>), true );
        if ( adsl_temp == NULL ) {
            return NULL;
        }
        new(&adsl_temp->dsc_element) T(ds_item);
        adsl_temp->ads_next = NULL;
        this->adsc_last->ads_next = adsl_temp;
        this->adsc_last = adsl_temp;
        this->uinc_elements++;
        m_check_consistency();
        return adsl_temp;
    }
    
    /**
     * function ds_hvector_btype::m_add
     * add an element to vector
     *
     * @param[in]   T       ds_item         element to add
     * @return      bool                    true = success
    */
    bool m_add( const T& ds_item )
    {
        return (this->m_add2(ds_item) != NULL);
    } // end of ds_hvector_btype::m_add


    /**
     * public function ds_hvector_btype::m_insert
     * insert a value to given position
     *
     * @param[in]   dsd_hvec_elem<T>*  adsp_before  position to insert (specify NULL for front)
     * @param[in]   T       ds_item         element to insert
     * @return      bool                    true = success
    */
    bool m_insert_after( dsd_hvec_elem<T>* adsp_before, const T& ds_item )
    {
        // insert new element:
        if ( adsp_before == NULL ) {
            dsd_hvec_elem<T>* adsl_new = (dsd_hvec_elem<T>*)adsc_wsp_helper->m_cb_get_memory( sizeof(dsd_hvec_elem<T>), true );
            if ( adsl_new == NULL ) {
                return false;
            }
            new(&adsl_new->dsc_element) T(ds_item);
 
            adsl_new->ads_next = this->adsc_first;
            if(this->adsc_first == NULL)
                this->adsc_last = adsl_new;
            this->adsc_first = adsl_new;
            this->uinc_elements++;
        } else {
            dsd_hvec_elem<T>* adsl_new = (dsd_hvec_elem<T>*)adsc_wsp_helper->m_cb_get_memory( sizeof(dsd_hvec_elem<T>), true );
            if ( adsl_new == NULL ) {
                return false;
            }
            new(&adsl_new->dsc_element) T(ds_item);
            adsl_new->ads_next = adsp_before->ads_next;
            adsp_before->ads_next = adsl_new;
            if(adsp_before == this->adsc_last)
                this->adsc_last = adsl_new;
            this->uinc_elements++;
        }
        m_check_consistency();
        return true;
    } // end of ds_hvector_btype::m_insert

    bool m_add_first( const T& ds_item )
    {
        dsd_hvec_elem<T>* adsl_new = (dsd_hvec_elem<T>*)adsc_wsp_helper->m_cb_get_memory( sizeof(dsd_hvec_elem<T>), true );
        if ( adsl_new == NULL ) {
            return false;
        }
        new(&adsl_new->dsc_element) T(ds_item);
        this->uinc_elements++;

        adsl_new->ads_next = this->adsc_first;
        if(this->adsc_first == NULL)
            this->adsc_last = adsl_new;
        this->adsc_first = adsl_new;
        m_check_consistency();
        return true;
    }

    /**
     * function ds_hvector_btype::m_set
     * set value for element at position
     *
     * @param[in]   size_t  uin_index       position to set
     * @param[in]   T       ds_item         element to set
     * @return      bool                    true = success
    */
    bool m_set( size_t uin_index, const T& ds_item )
    {
        // initialize some variables:
        dsd_hvec_elem<T>* adsl_temp;
        size_t            uinl_pos;

        if ( uin_index < uinc_elements ) {
            adsl_temp = this->adsc_first;
            for ( uinl_pos = 0; uinl_pos < uin_index; uinl_pos++ ) {
                adsl_temp = adsl_temp->ads_next;
            }
            adsl_temp->dsc_element = ds_item;
            return true;
        }
        return false;
    } // end of ds_hvector_btype::m_set


    /**
     * function ds_hvector_btype::m_set_first
     * set value for first element
     *
     * @param[in]   T       ds_item         element to set
     * @return      bool                    true = success
    */
    bool m_set_first( const T& ds_item )
    {
        dsd_hvec_elem<T>* adsl_temp = this->adsc_first;
        if(adsl_temp == NULL)
            return false;
        adsl_temp->dsc_element = ds_item;
        return true;
    } // end of ds_hvector_btype::m_set_first


    /**
     * function ds_hvector_btype::m_set_last
     * set value for last element
     *
     * @param[in]   T       ds_item         element to set
     * @return      bool                    true = success
    */
    bool m_set_last( const T& ds_item )
    {
        if(this->adsc_first == NULL)
            return false;
        this->adsc_last->dsc_element = ds_item;
        return true;
    } // end of ds_hvector_btype::m_set_last

#if 1
    /**
     * function ds_hvector_btype::m_get
     * get element at requested position
     *
     * @param[in]   size_t  uin_index       requested position
     * @return      T                       requested element
    */
    const T& m_get( size_t uin_index ) const
    {
        // initialize some variables:
        dsd_hvec_elem<T>* adsl_temp;
        size_t            uinl_pos;

        assert( uin_index < uinc_elements );

        adsl_temp = this->adsc_first;
        for ( uinl_pos = 0; uinl_pos < uin_index; uinl_pos++ ) {
            adsl_temp = adsl_temp->ads_next;
        }
        return adsl_temp->dsc_element;
    } // end of ds_hvector_btype::m_get
#endif

	 const dsd_hvec_elem<T>* m_get_first_element() const {
		 return this->adsc_first;	
	 }

     const dsd_hvec_elem<T>* m_get_last_element() const {
		 return this->adsc_last;	
	 }

	 dsd_hvec_elem<T>* m_get_first_element2() {
		 return this->adsc_first;	
	 }

	 dsd_hvec_elem<T>* m_get_last_element2() {
		 return this->adsc_last;	
	 }

     /**
     * function ds_hvector_btype::m_get_first
     * get first element
     *
     * @return      T                       first element
    */
    const T& m_get_first() const
    {
        assert( uinc_elements > 0 );
        return this->adsc_first->dsc_element;
    } // end of ds_hvector_btype::m_get_first


    /**
     * function ds_hvector_btype::m_get_last
     * get last element
     *
     * @return      T                       last element
    */
    const T& m_get_last() const
    {
        assert( uinc_elements > 0 );
        return this->adsc_last->dsc_element;
    } // end of ds_hvector_btype::m_get_last


    /**
     * function ds_hvector_btype::m_delete
     * delete element at requested index
     *
     * @param[in]   size_t  uin_index       requested position
     * @return      bool                    true = success
    */
    bool m_delete( dsd_hvec_elem<T>* adsp_before, dsd_hvec_elem<T>* adsp_delete )
    {
        // initialize some variables:
        if ( adsp_before == NULL ) {
			if(adsp_delete != this->adsc_first)
				return false;
            return this->m_delete_first();
        }
		if(adsp_delete != adsp_before->ads_next)
			return false;

        adsp_before->ads_next = adsp_delete->ads_next;            /* remove from chain */
        adsp_delete->dsd_hvec_elem<T>::~dsd_hvec_elem();         /* destructor call   */
        this->adsc_wsp_helper->m_cb_free_memory( adsp_delete );        /* free memory       */
        if(adsp_delete == this->adsc_last) {
            this->adsc_last = adsp_before;
        }
        this->uinc_elements--;
        m_check_consistency();
        return true;
    } // end of ds_hvector_btype::m_delete

    /**
     * function ds_hvector_btype::m_delete
     * delete element at requested index
     *
     * @param[in]   size_t  uin_index       requested position
     * @return      bool                    true = success
    */
    bool m_delete( size_t uin_index )
    {
        // initialize some variables:
        dsd_hvec_elem<T>* adsl_temp1;
        dsd_hvec_elem<T>* adsl_temp2;
        size_t            uinl_pos;

        if ( uin_index >= uinc_elements ) {
            return false;
        }
        if ( uin_index == 0 ) {
            return this->m_delete_first();
        }

        adsl_temp1 = this->adsc_first;
        adsl_temp2 = this->adsc_first;
        for ( uinl_pos = 0; uinl_pos < uin_index; uinl_pos++ ) {
            adsl_temp2 = adsl_temp1;                            /* parent element    */
            adsl_temp1 = adsl_temp1->ads_next;                  /* entry to delete   */
        }
        adsl_temp2->ads_next = adsl_temp1->ads_next;            /* remove from chain */
        adsl_temp1->dsd_hvec_elem<T>::~dsd_hvec_elem();         /* destructor call   */
        this->adsc_wsp_helper->m_cb_free_memory( adsl_temp1 );        /* free memory       */
        if(adsl_temp1 == this->adsc_last) {
            this->adsc_last = adsl_temp2;
        }
        this->uinc_elements--;
        m_check_consistency();
        return true;
    } // end of ds_hvector_btype::m_delete

    /**
     * function ds_hvector_btype::m_delete_first
     * delete element at first index
     *
     * @return      bool                    true = success
    */
    bool m_delete_first()
    {
        dsd_hvec_elem<T>* adsl_temp1 = this->adsc_first;                         /* entry to delete   */
        if(adsl_temp1 == NULL)
            return false;
        this->adsc_first = adsl_temp1->ads_next;            /* remove from chain */
        adsl_temp1->dsd_hvec_elem<T>::~dsd_hvec_elem();     /* destructor call   */
        this->adsc_wsp_helper->m_cb_free_memory( adsl_temp1 );    /* free memory       */
        this->uinc_elements--;
        m_check_consistency();
        return true;
    } // end of ds_hvector_btype::m_delete_first


#if 0
    /**
     * function ds_hvector_btype::m_delete_last
     * delete element at last index
     *
     * @return      bool                    true = success
    */
    bool m_delete_last()
    {

        if ( uinc_elements > 0 ) {
            return m_delete(uinc_elements - 1);
        }
        return false;
    } // end of ds_hvector_btype::m_delete_last
#endif

    /**
     * function ds_hvector_btype::m_clear
     * delete all entries
    */
    void m_clear()
    {
        // initialize some variables:
        dsd_hvec_elem<T>* adsl_temp1;
        dsd_hvec_elem<T>* adsl_temp2;

        adsl_temp1 = this->adsc_first;
        while( adsl_temp1 != NULL ) {
            adsl_temp2 = adsl_temp1->ads_next;
            adsl_temp1->dsd_hvec_elem<T>::~dsd_hvec_elem();
            this->adsc_wsp_helper->m_cb_free_memory( adsl_temp1 );
            adsl_temp1 = adsl_temp2;
        }
        this->adsc_first = NULL;
        this->adsc_last = NULL;
        this->uinc_elements = 0;
    } // end of ds_hvector_btype::m_clear


    /**
     * function ds_hvector_btype::m_size
     * get current element number
     *
     * @return size_t
    */
    size_t m_size() const
    {
        return this->uinc_elements;
    } // end of ds_hvector_btype::m_size


    /**
     * function ds_hvector_btype::m_empty
     * is vector empty?
     *
     * @return bool
    */
    bool m_empty() const
    {
        return (this->uinc_elements == 0);
    } // end of ds_hvector_btype::m_empty


    bool m_stack_push(const T& ds_item) {
        return this->m_add_first(ds_item);    
    }

    bool m_stack_pop() {
        return this->m_delete_first();    
    }

    const T& m_stack_current() const {
        return this->m_get_first();    
    }

    T& m_stack_current_ref() {
        return this->adsc_first->dsc_element;    
    }

    void m_stack_set_current(const T& rdsp_value) {
        this->adsc_first->dsc_element = rdsp_value;
    }

	const dsd_hvec_elem<T>* m_stack_current_element() const {
	    return this->adsc_first;	
	}

protected:
    // variables:
    ds_wsp_helper*    adsc_wsp_helper;      // wsp helper class
    dsd_hvec_elem<T>* adsc_first;        // element list
    dsd_hvec_elem<T>* adsc_last;            // last element in list
    size_t            uinc_elements;        // members

    /**
     * function ds_hvector_btype::m_copy
     *
     * @param[in]   const ds_hvector_btype&  dc_copy
    */
    void m_copy( const ds_hvector_btype& dc_copy )
    {
        // initialize some variables:
        dsd_hvec_elem<T>* adsl_temp;
        size_t            uinl_pos;

        if ( this->adsc_wsp_helper && this->adsc_first != NULL ) {
            m_clear();
        }
        this->adsc_wsp_helper = dc_copy.adsc_wsp_helper;

        adsl_temp = dc_copy.adsc_first;
        for ( uinl_pos = 0; uinl_pos < dc_copy.uinc_elements; uinl_pos++ ) {
            m_add( adsl_temp->dsc_element );
            adsl_temp = adsl_temp->ads_next;
        }
        m_check_consistency();
     } // end of ds_hvector_btype::m_copy
};


/**
 * special implementation for our own class with init functions
*/
template <class T> class ds_hvector : public ds_hvector_btype<T> {
public:
    /**
     * constructor ds_hvector::ds_hvector
    */
    ds_hvector() : ds_hvector_btype<T>()
    {
    } // end of ds_hvector::ds_hvector


    /**
     * constructor ds_hvector::ds_hvector
     * 
     * @param[in]   ds_wsp_helper* ads_wsp_helper
    */
    ds_hvector( ds_wsp_helper* ads_wsp_helper ) : ds_hvector_btype<T>(ads_wsp_helper)
    {
    } // end of ds_hvector::ds_hvector


    /**
     * function ds_hvector::m_init
     * 
     * @param[in]   ds_wsp_helper* ads_wsp_helper
    */
    void m_init( ds_wsp_helper* ads_wsp_helper )
    {
        // initialize some variables:
        dsd_hvec_elem<T>* adsl_temp;
        size_t            uinl_pos;

        this->adsc_wsp_helper = ads_wsp_helper;

        // initialize elements too:
        adsl_temp = this->adsc_first;
        for ( uinl_pos = 0; uinl_pos < this->uinc_elements; uinl_pos++ ) {
            adsl_temp->dsc_element.m_init( this->adsc_wsp_helper );
            adsl_temp = adsl_temp->ads_next;
        }
    } // end of ds_hvector::m_init

    template<typename T2> dsd_hvec_elem<T>* m_add3( const T2& ds_item ) {
        // initialize some variables:
        dsd_hvec_elem<T>* adsl_temp;

        // check if first element
        if ( this->adsc_first == NULL ) {
            adsl_temp = (dsd_hvec_elem<T>*)this->adsc_wsp_helper->m_cb_get_memory( sizeof(dsd_hvec_elem<T>), true );
            if ( adsl_temp == NULL ) {
                return NULL;
            }
            new(&adsl_temp->dsc_element) T(this->adsc_wsp_helper, ds_item);
            adsl_temp->ads_next = NULL;
            this->adsc_first = adsl_temp;
            this->adsc_last = adsl_temp;
            this->uinc_elements = 1;
            this->m_check_consistency();
            return adsl_temp;
        }

        // get last element:
        adsl_temp = (dsd_hvec_elem<T>*)this->adsc_wsp_helper->m_cb_get_memory( sizeof(dsd_hvec_elem<T>), true );
        if ( adsl_temp == NULL ) {
            return NULL;
        }
        new(&adsl_temp->dsc_element) T(this->adsc_wsp_helper, ds_item);
        adsl_temp->ads_next = NULL;
        this->adsc_last->ads_next = adsl_temp;
        this->adsc_last = adsl_temp;
        this->uinc_elements++;
        this->m_check_consistency();
        return adsl_temp;
    }
};


/**
 * special implementation for our own class with init functions
*/
template <class T> class ds_hvector_p : public ds_hvector_btype<T> {
public:
    /**
     * constructor ds_hvector_p::ds_hvector_p
    */
	ds_hvector_p() : ds_hvector_btype<T>()
    {
    } // end of ds_hvector_p::ds_hvector_p


    /**
     * constructor ds_hvector_p::ds_hvector_p
     * 
     * @param[in]   ds_wsp_helper* ads_wsp_helper
    */
    ds_hvector_p( ds_wsp_helper* ads_wsp_helper ) : ds_hvector_btype<T>(ads_wsp_helper)
    {
    } // end of ds_hvector_p::ds_hvector_p


    /**
     * public function ds_hvector_p::m_init
     * 
     * @param[in]   ds_wsp_helper* ads_wsp_helper
    */
    void m_init( ds_wsp_helper* ads_wsp_helper )
    {
        // initialize some variables:
        dsd_hvec_elem<T>* adsl_temp;
        size_t            uinl_pos;

        this->adsc_wsp_helper = ads_wsp_helper;

        // initialize elements too:
        adsl_temp = this->adsc_first;
        for ( uinl_pos = 0; uinl_pos < this->uinc_elements; uinl_pos++ ) {
            adsl_temp->dsc_element->m_init( this->adsc_wsp_helper );
            adsl_temp = adsl_temp->ads_next;
        }
    } // end of ds_hvector_p::m_init
};

/*+-------------------------------------------------------------------------+*/
/*| class definition:                                                       |*/
/*+-------------------------------------------------------------------------+*/
template <class T> class ds_hstack_btype : private ds_hvector_btype<T> {
public:
    ds_hstack_btype() : ds_hvector_btype<T>()
    {
    }

    ds_hstack_btype(ds_wsp_helper* ads_wsp_helper) : ds_hvector_btype<T>(ads_wsp_helper) {
    }

    const T& m_get_last() const
    {
        return ds_hvector_btype<T>::m_stack_current();
    } // end of ds_hvector_btype::m_get_las

    T* m_get_last_ref()
    {
        return &ds_hvector_btype<T>::m_stack_current_ref();
    } // end of ds_hvector_btype::m_get_las

    const T& m_get_prev_last() const
    {
        return ds_hvector_btype<T>::m_get_first_element()->ads_next->dsc_element;
    } // end of ds_hvector_btype::m_get_last

    T* m_get_prev_last_ref()
    {
        return &ds_hvector_btype<T>::m_get_first_element2()->ads_next->dsc_element;
    } // end of ds_hvector_btype::m_get_last

    bool m_set_last( const T& ds_item )
    {
        ds_hvector_btype<T>::m_stack_set_current(ds_item);
        return true;
    } // end of ds_hvector_btype::m_set_last

    bool m_delete_last()
    {
        return ds_hvector_btype<T>::m_stack_pop();
    } // end of ds_hvector_btype::m_delete_last

    size_t m_size() const
    {  
        return ds_hvector_btype<T>::m_size();
    }

    bool m_add( const T& ds_item )
    {
        return ds_hvector_btype<T>::m_stack_push(ds_item);
    } // end of ds_hvector_btype::m_add
};

#endif // DS_HVECTOR_H
