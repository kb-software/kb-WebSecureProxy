/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program                                                             |*/
/*| =======                                                             |*/
/*|   arraylist                                                         |*/
/*|   An arrylist library implementation                                |*/
/*|                                                                     |*/
/*| Author                                                              |*/
/*| ======                                                              |*/
/*|   James Farrugia June 2012                                          |*/
/*|                                                                     |*/
/*| Copyright                                                           |*/
/*| =========                                                           |*/
/*|   HOB GmbH 2012                                                     |*/
/*|                                                                     |*/ 
/*+---------------------------------------------------------------------+*/

/*+=====================================================================+*/
/*|| For further comments, please refer to hob-arraylist.h              ||*/
/*+=====================================================================+*/

/*+---------------------------------------------------------------------+*/
/*| global includes                                                     |*/
/*+---------------------------------------------------------------------+*/
#ifndef HL_UNIX
    #include <windows.h>
#endif //HL_UNIX
#include <stdio.h>
#include <stdlib.h>
#include <hob-arraylist.h>

#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include <hob-xsclib01.h>
#endif //_HOB_XSCLIB01_H

/*+---------------------------------------------------------------------+*/
/*| static functions                                                    |*/
/*+---------------------------------------------------------------------+*/
static void m_increase_capacity(dsd_arraylist *adsp_alist);

/**
* Internal function to increase the size of the arraylist.
*/
static void m_increase_capacity(dsd_arraylist *adsp_alist)
{
	size_t sz_counter;
	size_t sz_arr_size = sizeof(void*) * adsp_alist->szc_capacity;

	void **tmp_arr;// = malloc(sz_arr_size);                               //### MALLOC
    adsp_alist->adsp_hlclib->amc_aux( adsp_alist->adsp_hlclib->vpc_userfld, DEF_AUX_MEMGET, &tmp_arr, sz_arr_size );

	for (sz_counter = 0; sz_counter < adsp_alist->szc_size; sz_counter++)
		tmp_arr[sz_counter] = adsp_alist->avrc_data[sz_counter];

	//free(adsp_alist->avrc_data);                                        //### FREE
    adsp_alist->adsp_hlclib->amc_aux( adsp_alist->adsp_hlclib->vpc_userfld, DEF_AUX_MEMFREE, &adsp_alist->avrc_data, 0 );

	//adsp_alist->avrc_data = malloc(sz_arr_size * 2);                    //### MALLOC
    adsp_alist->adsp_hlclib->amc_aux( adsp_alist->adsp_hlclib->vpc_userfld, DEF_AUX_MEMGET, &adsp_alist->avrc_data, sz_arr_size * 2);

	for (sz_counter = 0; sz_counter < adsp_alist->szc_size; sz_counter++)
		adsp_alist->avrc_data[sz_counter] = tmp_arr[sz_counter];
	
	//free(tmp_arr);                                                      //### FREE
    adsp_alist->adsp_hlclib->amc_aux( adsp_alist->adsp_hlclib->vpc_userfld, DEF_AUX_MEMFREE, &tmp_arr, 0 );
	adsp_alist->szc_capacity *= 2;
}


/*+---------------------------------------------------------------------+*/
/*| public functions                                                    |*/
/*+---------------------------------------------------------------------+*/
/**
* Create a new arraylist by initialising a pointer to an arraylist struct and returning it.
*
* @param ump_initial_size[in] the initial size of the array.
*/
dsd_arraylist *m_new_arraylist(unsigned int ump_initial_size, struct dsd_hl_clib_1 *adsp_hlclib)
{
    dsd_arraylist *alist;

	//dsd_arraylist *alist = malloc(sizeof(dsd_arraylist));               //### MALLOC
    adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_MEMGET, &alist, sizeof(dsd_arraylist) );

	//alist->avrc_data = malloc (sizeof(void*) * initial_size);           //### MALLOC
    adsp_hlclib->amc_aux( adsp_hlclib->vpc_userfld, DEF_AUX_MEMGET, &alist->avrc_data, ( ((int)sizeof(void*)) * ump_initial_size) );

	alist->szc_capacity = ump_initial_size;
	alist->szc_last_add = 0;
	alist->szc_size = 0;
	alist->inc_last_index = -1;
    alist->adsp_hlclib = adsp_hlclib;

	return alist;
}

/**
* Destroy the arraylist struct.
*
* @param *adsp_alist the arraylist to destroy
*/
void m_destory_arraylist(dsd_arraylist *adsp_alist)
{
	//free(adsp_alist->avrc_data);                                         //### FREE
    adsp_alist->adsp_hlclib->amc_aux( adsp_alist->adsp_hlclib->vpc_userfld, DEF_AUX_MEMFREE, &adsp_alist->avrc_data, 0 );

	//free(adsp_alist);                                                   //### FREE
    adsp_alist->adsp_hlclib->amc_aux( adsp_alist->adsp_hlclib->vpc_userfld, DEF_AUX_MEMFREE, &adsp_alist, 0 );
}

/**
* Add a new element to the pointed arraylist.
*/
void m_add_element(dsd_arraylist *adsp_alist, void* avp_elem)
{
    if (adsp_alist->szc_last_add >= adsp_alist->szc_capacity)
		m_increase_capacity(adsp_alist);
	
	adsp_alist->avrc_data[adsp_alist->szc_last_add] = avp_elem;
	adsp_alist->szc_last_add ++;
	adsp_alist->szc_size ++;
	adsp_alist->inc_last_index ++;
}

/**
* Remove an element from the pointed arraylist.
*/
void m_remove_element(dsd_arraylist *adsp_alist, size_t sz_index)
{
	size_t szl_count = sz_index;
	for (; szl_count < adsp_alist->szc_size; szl_count ++)
		adsp_alist->avrc_data[szl_count] = adsp_alist->avrc_data[szl_count + 1];
	
	adsp_alist->szc_last_add --;
	adsp_alist->szc_size --;
    adsp_alist->inc_last_index --;
}

/**
* Returns a void pointer to something in the arraylist referenced by the passed index.
*/
void *m_get_element(dsd_arraylist *adsp_alist, size_t sz_index)
{
	return adsp_alist->avrc_data[sz_index];
}

/**
* Return true if the array list contains the given element
*/
BOOL m_contains_element(dsd_arraylist *adsp_alist, void* avp_element)
{
	size_t szc_count = 0;

	for (; szc_count < adsp_alist->szc_size; szc_count++)
		if (adsp_alist->avrc_data[szc_count] == avp_element)
            return TRUE;
	return FALSE;
}

/**
* Return true if this array list is empty
*/
int is_empty(dsd_arraylist *adsp_alist)
{
    return adsp_alist->szc_size == 0? 1 : 0;
}

