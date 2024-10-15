#ifndef DS_DATABLOCK_H
#define DS_DATABLOCK_H

#if defined WIN32 || defined WIN64
#include <windows.h>
#else
#include <sys/types.h>
#include <errno.h>
#include <hob-unix01.h>
#endif


/*! \brief Structure which represents an internal memory area
 *
 *
 */
class ds_datablock
{
public:
    ds_datablock(void);
    ~ds_datablock(void);
    // get the starting pointer of this datablock
    char* m_get_start(void);
    // get the terminating pointer of this datablock; it is the position AFTER the last byte of the datablock
    char* m_get_end(void);
    // get the length of this datablock
    int m_get_length(void);
    void m_set_start(char* ach_start_in);
    void m_set_end(char* ach_end_in);
    void m_set_total_len(int in_total_len_in);
    int m_get_total_len();
private:
    // pointer to begin of data
    char* ach_start;
    // pointer to end of data (first byte after the real data)
    char* ach_end;
    // length of this datablock
    int in_length;
    void m_calc_len(void);
    // total length of this datablock (is fitted to the size of the working area of WSP)
    int in_total_len;
};

#endif // DS_DATABLOCK_H
