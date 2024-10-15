#ifndef DS_USER_AGENT_WORKER_H
#define DS_USER_AGENT_WORKER_H
#ifdef _WIN32
#pragma once
#endif

/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| FILE:                                                               |*/
/*|   user agent worker reads UserAgent string                          |*/
/*|                                                                     |*/
/*| AUTHOR:                                                             |*/
/*|   Beljajew Georg Jan 2016                                           |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/



/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*|     constants                                                       |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

#define UA_CHECKED     1 // means that this client's user agent was checked and there is no need to do this again.
#define UA_MOBILE      2 // second bit set means it is a mobile device



/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*|     methods                                                         |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/


// this method takes a user agent string and its length and returns a bitfield as int
int m_check_user_agent(const char * cachp_user_agent, const int cinp_length);

// this method decides if a portlet should be hidden on this device.
int m_is_portlet_to_hide(int ibp_portlet_filter, char * strp_portlet_name, int inp_name_length);

#endif /* DS_USER_AGENT_WORKER_H */
