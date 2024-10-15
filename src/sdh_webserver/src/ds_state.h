#ifndef DS_STATE_H
#define DS_STATE_H

#if defined WIN32 || defined WIN64
#include <windows.h>
#else
#include <sys/types.h>
#include <errno.h>
#include <hob-unix01.h>
#endif

/*! \brief State class
 *
 * @ingroup creator
 *
 * Holds the encodings
 */
class ds_state
{
public:
    ds_state(void);
    ~ds_state(void);
    int m_reset(void);
    // browser tells the encodings, which it supports
    int in_accept_encoding;
};

#endif // DS_STATE_H
