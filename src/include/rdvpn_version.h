#ifndef _RDPVN_VERSION_H
#define _RDPVN_VERSION_H

#define RC_COMPANY_NAME             "HOB Germany"
#define RC_PRODUCT_NAME             "HOB RD VPN"
#define RC_MAJOR_PRODUCT_VERSION    "2.4"
#define RC_MINOR_PRODUCT_VERSION    "0.0"

#ifdef _DEBUG
    #define RC_DEBUG                "dbg"
#else
    #define RC_DEBUG
#endif

#ifdef WIN64
    #ifdef _IA64_
        #define RC_ARCH             "IPF"
    #else
        #define RC_ARCH             "EM64T"
    #endif
#else
    #define RC_ARCH                 "x86"
#endif

#endif // _RDPVN_VERSION_H
