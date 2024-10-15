#ifndef _WS_VERSION_H
#define _WS_VERSION_H

#define STRINGIFY2(x) #x
#define STRINGIFY(x) STRINGIFY2(x)
#define MAKE_VERSION(v1, v2, v3, v4) STRINGIFY(v1) "." STRINGIFY(v2) "." STRINGIFY(v3) "." STRINGIFY(v4)

/*+---------------------------------------------------------------------+*/
/*| Version Numbers for WebServer(Gate)                                 |*/
/*+---------------------------------------------------------------------+*/
#define WS_VERSION_1_NO       2
#define WS_VERSION_2_NO       3
#define WS_VERSION_3_NO       204
#define WS_VERSION_4_NO       7276

#define WS_VERSION_STRING MAKE_VERSION(WS_VERSION_1_NO, WS_VERSION_2_NO, WS_VERSION_3_NO, WS_VERSION_4_NO)

/*+---------------------------------------------------------------------+*/
/*| Version Numbers for WebServer(Gate)                                 |*/
/*+---------------------------------------------------------------------+*/
#define WEBSERVER_NAME        "ServerDataHook: Web Server"
#define WS_FILENAME           "xl-sdh-webserver-01.dll"

#endif // _WS_VERSION_H
