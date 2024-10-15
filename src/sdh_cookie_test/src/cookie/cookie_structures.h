#ifndef COOKIE_STRUCTURES_H
#define COOKIE_STRUCTURES_H

/*+-------------------------------------------------------------------------+*/
/*| include local headers                                                   |*/
/*+-------------------------------------------------------------------------+*/
//#include "../../utils/helper.h"
#if defined WIN32 || defined WIN64
    #include <windows.h>
#endif

#include <vector>
#include <string>
using namespace std;

#include "rdvpn_globals.h"
// MJ 05.05.09:
#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include <hob-xsclib01.h>
#endif //_HOB_XSCLIB01_H
//#include <time.h>

#ifdef HL_UNIX  // in case of unix we need conversion methods (for e.g. wtoi)
    #include <hob-hunix01.h>
    #ifndef HOB_XSLUNIC1_H
        #define HOB_XSLUNIC1_H
        #include "hob-xslunic1.h"
    #endif // HOB_XSLUNIC1_H
#endif // #ifdef HL_UNIX

/*+-------------------------------------------------------------------------+*/
/*| defines:                                                                |*/
/*+-------------------------------------------------------------------------+*/
#define CK_MEM_SIZE         256
#define CK_MAX_PER_DOMAIN    20
#define CK_MAX_HOST_LEN     LEN_ATTR + _MAX_PATH

/*+-------------------------------------------------------------------------+*/
/*| structure definitions:                                                  |*/
/*+-------------------------------------------------------------------------+*/
// define some structures needed for cookie handling

struct ds_user_entry {
    int         in_points_to;
    char        rch_host[CK_MAX_HOST_LEN];         
};

// used in ds_cookie_memory:
struct ds_cookie {
    int         in_length;                  // 0 = empty!
    char        rch_cookie[CK_MEM_SIZE];    // name=value
    char        rch_host[CK_MAX_HOST_LEN];  // host "www.hob.de/test1/test2/"
    time_t      t_expires;                  // -1 = delete at logout
    BOOL        bo_secure;                  // true = cookie only for secure connections
    int         in_next;                    // next cookie mem (if larger than CK_MEM_SIZE)
};

// managment structures:
struct ds_capacity {
    int in_free;            // count free entries
    int in_capacity;        // element capacity in cma
};

struct ds_cookie_link {
    BOOL         bo_occupied;                       // sign if this structure is in use
    int          in_occ_indices;                    // count oocupied indices in rin_indices
    int          rin_indices[CK_MAX_PER_DOMAIN];    // links to cookies in ds_cookie_memory
    int          in_father;                         // pointer to father element
    int          in_mother;                         // pointer to mother element
    int          in_count_childs;                   // count child elements
};

struct ds_cookie_hash {
    BOOL         bo_occupied;                       // sign if this structure is in use
    unsigned int uin_hash;                          // hash over user and host
    char         rch_user[LEN_ATTR];                // username
    char         rch_host[CK_MAX_HOST_LEN];         // host "www.hob.de/test1/test2/"
    unsigned int uin_user_hash;                     // userhash
    int          in_points_to;                      // pointer to position in ds_cookie_mgmt_table
    int          in_next_in_rest;                   // pointer to next in rest with equal hash!
};

#endif //COOKIE_STRUCTURES_H
