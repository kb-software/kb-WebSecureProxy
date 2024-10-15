#include "ds_datablock.h"
#ifndef NULL
#define NULL 0
#endif

ds_datablock::ds_datablock(void)
: ach_start(NULL)
, ach_end(NULL)
, in_length(-1)
, in_total_len(0)
{
}

ds_datablock::~ds_datablock(void)
{
}

/*! \brief Get the starting pointer
 *
 * get the starting pointer of this datablock
 * Attention: may be NULL
 */
char* ds_datablock::m_get_start(void)
{
    return ach_start;
}

/*! \brief Get the terminating pointer of this datablock
 *
 * get the terminating pointer of this datablock
 * it is the position AFTER the last byte of the datablock
 * Attention: may be NULL
*/
char* ds_datablock::m_get_end(void)
{
    return ach_end;
}

/*! \brief Get the length of the data in this datablock
 *
 * get the length of the data in this datablock
*/
int ds_datablock::m_get_length(void)
{
    return in_length;
}

/*! \brief Set the start address
 *
 * Set the start address
 */
void ds_datablock::m_set_start(char* ach_start_in)
{
    ach_start = ach_start_in;
    m_calc_len();
}


/*! \brief Set the end of the memory area
 *
 * Set the end of the memory area
 */
void ds_datablock::m_set_end(char* ach_end_in)
{
    ach_end = ach_end_in;
    m_calc_len();
}

/*! \brief Calculate the length
 *
 *
 */
void ds_datablock::m_calc_len(void)
{
    if ((ach_start == NULL) || (ach_end == NULL)) {
        in_length = -1;
    }
    else {
        in_length = (int)(ach_end - ach_start);
    }
}


/*! \brief Set the total length
 *
 *
 */
void ds_datablock::m_set_total_len(int in_total_len_in)
{
    in_total_len = in_total_len_in;
}


/*! \brief Get the total length
 *
 *
 */
int ds_datablock::m_get_total_len()
{
    return in_total_len;
}