#ifndef HOB_ARRAYLIST_H
#define HOB_ARRAYLIST_H

/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| FILE:                                                               |*/
/*| -----                                                               |*/
/*|  hob-arraylist.h                                                    |*/
/*|                                                                     |*/
/*| Description:                                                        |*/
/*| ------------                                                        |*/
/*|  defines the arraylist object which is an array and some info       |*/
/*|  numbers such as capacity and size                                  |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| -------                                                             |*/
/*|  James Farrugia, June/July 2012                                     |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/**
* The arraylist is a normal array of void pointers.  It also stores information about
* the capacity, current size and the last added index.
*/
typedef struct dsd_arraylist
{
    struct dsd_hl_clib_1 *adsp_hlclib;
	void    **avrc_data;
	size_t  szc_capacity;
	size_t  szc_size;
    size_t  szc_last_add;
	int     inc_last_index;
} dsd_arraylist;

/**
* Creates a new arraylist by allocating memory for the array and initialises the other numbers
*
* @param[in] ump_initial_size the expected initial size of the array.  The more accurate the better, so as to avoid unecessary resizing
* @param[in] *adsp_hlclib the memory allocation function
*/
dsd_arraylist *m_new_arraylist(unsigned int ump_initial_size, struct dsd_hl_clib_1 *adsp_hlclib);

/**
* Destroys the given arraylist by freeing the memory taken up by the array.  !WARNING!  The data in the stored locations
* is NOT destroyed.  If ALL the memory, including that taken up by the stored elements is to be freed, one must go
* through the list and free up every element before destroying the arraylist.
*
* @param[in] *adsp_alist the pointer to the arraylist to destroy
*/
void m_destory_arraylist(dsd_arraylist *adsp_alist);

/**
* Sets the next empty element in the array as the given void pointer value.  If the size is equating the capacity,
* then it must be increased and a call to double the size is made.
*
* @param[in] *adsp_alist the list to which to add
* @param[in] *avp_elem the element to add
*/
void m_add_element(dsd_arraylist *adsp_alist, void* avp_elem);

/**
* Removes an element from the arraylist.  Unlike the m_add, this will not check for sizes, so if the list
* had a lot of elements and then all or many of them were removed, the size will still remain at it largest.
* This function will copy the next element from the indicated index until the end into the one before it, so 
* automatically the one to be removed is replaced by the one before it.  The size int is then reduced so the last
* one is basically dereferenced and can be overwritten by the next add.
*
* @param[in] *adsp_alist the list from which to remove
* @param[in] sz_index the element index to remove
*/
void m_remove_element(dsd_arraylist *adsp_alist, size_t sz_index);

/**
* Returns an element from the arraylist.  This is a wrapper for just referencing th array.
*
* @param[in] *adsp_alist the list from which to retrieve
* @param[in] sz_index the element index to get
*/
void *m_get_element(dsd_arraylist *adsp_alist, size_t sz_index);

/**
* Returns true if the element is in the list, or false if not.
*
* @param[in] *adsp_alist the list to search
* @param[in] *avp_elem the element to check
* @return TRUE if found, FALSE otherwise
*/
BOOL m_contains_element(dsd_arraylist *adsp_alist, void* avp_element);

/**
* Returns true if the list is empty
*
* @param[in] *adsp_alist the list to check
* @return TRUE if there are no elements in array, FALSE otherwise
*/
BOOL m_is_empty(dsd_arraylist *adsp_alist);

#endif