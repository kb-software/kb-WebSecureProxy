//#define TRY_150218_01                       /* problem gather          */
#define NEW_REPORT_1501
#define WA_150216_01
#ifdef TRACE_KB
#define TRACEHL_SDH_COUNT_1
//#define TRACE_TCP_FLOW_01
#define PROBLEM_140406_01
//#define TRACEHL_SDH_01                      /* problem DoD             */
//#define WSP_TRACE_130801
//#define WSP_CLUSTER_DISP_LOAD
#define DEBUG_150220_01                     /* Dod connect too earl    */
#define HELP_DEBUG
#endif
//#define WSP_TRACE_SPECIAL_121001
//#define WSP_TRACE_SLEEP 100
#ifdef D_RELEASE_1205
#endif
#ifdef __INSURE__ // MJ
    #define D_STOR_ONE_TIME
    #define LOG_INSURE_01
#endif
#ifndef D_RELEASE_1205
//#define NO_AUTH_RADIUS                      /* 09.05.12 KB - for test password change */
#endif
#ifdef TO_DO
/**
  HOB-TUN with driver
  maybe does not run over localhost
  changes needed at m_tcp_conn() p_ineta_20:
*/
--- 16.03.13 KB ---
SSL should not be started and ended
when plain-HTTP-library
but additional flags are needed
at this moment, SSL is started immediately
after stating receiving from the client
#endif
/* test HSM 07.07.11 KB - start */
//#define D_STOR_ONE_TIME                     /* 24.04.06 KB - use storage only once */
/* test HSM 07.07.11 KB - end */
//#define D_STOR_ONE_TIME                     /* 24.04.06 KB - use storage only once */
#define HL_THRID GetCurrentThreadId()
#ifdef B160708
#define DEBUG_120530_01 16                    /* warning SDHs too many work-areas */
#define DEBUG_120121_01                     /* connect callback not called - TCPCOMP error */
#define DEBUG_130502_01                     /* loop connection failed PTTD */
#define DEBUG_130722_01                     /* HTCP connect fails      */
#define DEBUG_130919_01                     /* problem DoD             */
#define DEBUG_131129_01                     /* adsc_seco1_previous - configuration server previous */
//#define DEBUG_131225_01                     /* signal - dsl_pd_work.imc_hookc */
//#define DEBUG_140118_01                     /* load-balancing problem  */
//#define DEBUG_140203_01                     /* memory-leak authentication-library m_auth_delete() */
#define DEBUG_140402_01                     /* memory-leak PPP authentication */
#define DEBUG_141118_01                     /* 18.11.14 KB - sequence number does not match */
//#define NEW_1112                          /* removed 04.10.13 KB     */
//#define EXAMINE_SIGN_ON_01                  /* 10.08.11 KB examine sign on time */
#define DEBUG_111202_01 24                  /* 02.12.11 KB check too many sdhc1 */
//#define DEBUG_120206_01 32                  /* 06.02.12 KB check storage in use - sdhc1 */
//#define DEBUG_120206_01 256                 /* 06.02.12 KB check storage in use - sdhc1 */
//#define DEBUG_120118_01                     /* watch inc_no_sdh        */
//#define TCP_SET_SNDBUF     (32 * 1024)      /* 10.08.11 KB + MJ TCP SNDBUF */
#define DEBUG_130509_01 16                  /* 09.05.13 KB check queue send buffers */
#define DEBUG_140123_01                     /* SSL close problem       */
#define DEBUG_140819_01                     /* SSL called after close  */
#ifdef TRACE_TCP_FLOW_01
#define DEBUG_140819_01                     /* SSL called after close  */
#endif
#endif
//#define DEBUG_140803_01                     /* problems boc_act_conn_send */
//#define DEBUG_130716_01                     /* 16.07.13 KB loop in Web Server Gate */
//#define DEBUG_150218_01                     /* problem gather          */
#ifdef DEBUG_150218_01                      /* problem gather          */
static void m_check_gai_recv_server_1( struct dsd_sdh_control_1 *adsp_sdhc1, char *achp_msg, int imp_line );
#define D_STOR_ONE_TIME
#endif
#define TRY_110523_01                       /* VDI problem             */
#ifdef B160708
#define TRY_110523_02                       /* HOB-TUN / HTCP session end */
//#define TRY_110523_03                     /* changes Mr. Jakob HOB-TUN / HTCP */
#define TRY_110719_01                       /* SDH append gather       */
#ifdef B130923
#define TRY_120126_01                       /* m_tcp_close() wait HOB-TUN HTCP */
#endif
//#define TRY_110805_01 3000                  /* length maximum WSASend  */
#endif
#define TRY_120306_01                       /* flow-control send       */
#ifdef B160708
#ifdef B150217
#define TRY_120405_01                       /* optimize sdhc1 garbage collector */
#endif
#define TRY_121123_01                       /* secure-XOR SHA-384      */
#define TRACEHL_CO_OUT
#define TRY_130511_01                       /* HOB-TUN remove gai1     */
#endif
#define TRY_130624_01                       /* problems HTCP           */
#ifdef B160708
#define TRY_130716_01                       /* problem loop Web Server Gate */
#define TRY_140319_01                       /* end TCPCOMP without received end */
//#define TRY_140803_01                       /* problems boc_act_conn_send */
#define TRY_140806_01                       /* problems boc_act_conn_send */
#define TRY_150220_01                       /* problems DoD WebSocket     */
#endif
#ifdef TRACE_KB
//#define KB$DEBUG
#define WSP_TRACE_FILE_01 "WSP-trace-01.dat"
#ifndef WSP_TRACE_130801
#define WSP_TRACE_FILE_PID "WSP-trace-PID-%010d.dat"
#endif
#ifdef WSP_TRACE_130801
#define WSP_TRACE_FILE_BIN
#endif
#endif
//#define WSP_TRACE_FILE_BIN
//#define WSP_TRACE_CONSOLE
//#define WSP_TRACE_SLEEP 100
#define TRY_090429_01
#ifdef KB$DEBUG
//#define DEBUG_110315_01
#define WSP_TRACE_110309 (1+2+4+8+16+32+64+128+256+512+1024)
#define DEBUG_101216_01
#define TRACEHL_101209
#endif
#define TRY_D_INCL_HTUN
#define D_HPPPT1_1
#ifdef KB$DEBUG
#define DEBUG_100903_01
#define DEBUG_100907_01
#define DEBUG_100908_01
#define DEBUG_100923_01
#define D_FOR_VC
#endif
#ifdef DEBUG_100903_01
#define TRACE_HL_SESS_01
#define TRACEHL_SEND
//#define TRACEHL_STOR_USAGE
#endif
#ifdef KB$DEBUG
//#define TRACEHL1
//#define DEBUG_100809
#define DEBUG_100824_01
#define DEBUG_100830_01
#define DEBUG_100830_02
//#define DEBUG_100831_01
//#define TRACEHL_SDH_01
#define TRACEHL_CHECK_SDH                   /* 22.01.07 KB             */
//#define TRACEHL1
#endif
#ifdef DEBUG_130716_01                      /* 16.07.13 KB loop in Web Server Gate */
#define DEBUG_LOOP_PROC_DATA_01 16
#define DEBUG_130711_01                     /* 11.07.13 KB hangs after HTCP session end */
#endif
#define TRY_SNMP_100812
#ifdef KB$DEBUG
#define DEBUG_100810
#define DEBUG_100816
#endif
#ifdef DEBUG_100809
#define D_NO_SERVICE                        /* 24.04.09 KB             */
#define TRACEHL_P_COUNT
#define D_STOR_ONE_TIME                     /* 24.04.06 KB - use storage only once */
#endif
#ifdef DEBUG_100816
#define D_NO_SERVICE                        /* 24.04.09 KB             */
#define TRACEHL_P_COUNT
#endif
#define SSL_DEBUG_100710 32                 /* check loop in SSL       */
#define TRY_HSM_1007
#define D_ALERT_01                          /* 07.04.10 KB - check if illogic */
#define D_PROD_A2
#ifdef XYZ1
#define TRY100514$01
#define TRY100514$02
#define D_STOR_ONE_TIME                     /* 24.04.06 KB - use storage only once */
#endif
#ifdef DEBUG_100816
#ifndef D_PROD_A2
#define TRACE_HL_SESS_01
#define TRACE_091121_01
#define TRACE_091013_01
#define TRACE_090506
/* check xs-gw-admin.cpp because of TRACEHL_P_COUNT 30.01.10 KB */
#endif
//#define TRY_090617
#ifndef D_PROD_A2
#define TRACEHL_090912_01
#define TRACEHL_090429_01
#endif
#define TRY_090429_01
#ifndef D_PROD_A2
#define D_NO_SERVICE                        /* 24.04.09 KB             */
#define HL_DEBUG_02
#endif
#define TRACEHL_CO_OUT
//#define TRY_090121
//#define TRACEHL_081125
//#define TRACEHL_070716                      /* 25.03.08 KB             */
//#define TRACEHL_P_DISP                      /* 25.03.08 KB             */
//#define B080322
//define D_REFUSE_CONNECT_1                  /* 25.06.07 KB             */
#define TRACEHL_WOL2
#define TRACEHL_HOBPHONE
#define TRACEHL_FLUSH
#endif
#ifdef TRACEHL_HOBPHONE
#define D_NAEGLE_ALGOR_OFF
#define D_HPPPT1_1
#define D_HPPPT1_SIM
#endif
//#define HL_DEBUG_02
#ifdef HL_DEBUG_02
#define TRACEHL_USER_080202
#define TRACEHL_SEND
#define TRACEHL_RADIUS
#define D_FILL_LOG "wsp-log-sample-01.txt"  /* 24.04.08 KB             */
#define D_HPPPT1_1
#define D_HPPPT1_SIM
//#define TRACEHL1
//#define NO_WSP_SOCKS_MODE_01
//#define TRACEHLA
#define TRACEHL_CO_OUT
#define PROB070717
#define TRACEHL_070505
#define D_STOR_ONE_TIME                     /* 24.04.06 KB - use storage only once */
#define D_NO_DUMP
#define D_NO_SERVICE                        /* 22.09.06 KB             */
#define TRACEHL_P_COUNT
#define TRACEHL_TCP_BLOCK                   /* 18.07.07 KB count TCP blocking */
#define TRACEHL_WA_COUNT                    /* 17.09.09 KB count work area inc / dec */
#endif
//#define HL_DEBUG_01
#ifdef HL_DEBUG_01
#define TRACEHL1
#define TRACEHL_060710
#define TRACEHL_070716
#define TRACEHL_T_050131
//#define TRACEHL_WOL1
//#define TRACEHL_WOL2
//#define TRACEHL_061220
//#define CHECK_PROB_070113
#define TRACEHL_P_DISP
#define TRACEHL_SEND                        /* 27.06.07 KB             */
//#define TRACEHL_SDH_01
#define D_NO_DUMP
#define D_NO_SERVICE                        /* 22.09.06 KB             */
//#define TRACE_PRINTF
#define TRACEHL_070427
#define TRACEHL_070505
#define TRACEHL_050419
#endif
#ifdef TRACEHL_SDH_01
#define TRACEHL_CHECK_SDH
#endif
#define CSSSL_060620
#ifndef PROB070717
#define PROB070717                          /* really needed 11.03.10 KB */
#endif
//#define TRACEHL_P_COUNT                            /* set 27.09.06 KB for insure++ */
//#define PROB_061016                         /* timed out sessions do not close */
#ifdef TODO
--- 03.06.06 ---
Firewall
Load-Balancing
Blade Twin-Trimming
Error Numbers
Event-Log with Name
clear-used-memory
m_tcp_conn with multiple INETA from gethostbyname
--- 17.09.07 KB ---
B070917
#endif
//#define DEF_NO_WSOCK2                       /* 11.05.06 KB             */
//#define B060415
//#define D_NO_SERVICE                        /* 22.09.06 KB             */
//#define PROB_T_060504                       /* problem with timer      */
#ifndef B060719
#define CHECK_SDH_01
//#define TRACEHL1
//#define TRACEHL3
//#define TRACEHL_SEND
#define TRACE_SHANG_050720
//#define TRACE_P_060922                      /* problem received data   */
#define HELP_DEBUG                          /* 04.04.06 KB - help in tracing */
#endif
#ifdef DEBUG_050628
#define TRACEHL_050630
#define PROB_NEDAP_050620
#define XYZ1
#define XYZ2
#define TRACEHL_061220                      /* problems target-filter person */
#endif
//#define TRACEHL_050419
//#define TRACEHL_050427
#define NEW_HLSE_0502
#define NEW_HLSE_050413
#ifdef XYZ1
#define TRACEHL_050207
#define TRACEHL1
#define TRACEHL_P_050118
#define TRACEHL_T_050130
#define TRACEHL_T_050131
#define TRACEHL3
#endif
#define TRY_041111
#ifdef XYZ2 /* PROD = Release 22.02.05 KB */
#ifndef TRACEHL_P_050118
#define TRACEHL_P_050118 /* error 23.02.05 KB */
#endif
#define CHECK_THR_1
//#define TRACEHL1
#define TRACEHL_P_COUNT
#define TRACEHLY
#define D_NO_DUMP
//#define TRACE_SL1
#define TRACE_PRINTF
#endif
#ifdef TRACEHL_CMA_050413
#ifndef TRACE_PRINTF
#define TRACE_PRINTF
#endif
#endif
#ifdef TRACEHL_050419
#ifndef TRACE_PRINTF
#define TRACE_PRINTF
#endif
#endif
#ifdef TRACEHL_P_DISP
#ifndef TRACEHL_P_COUNT
#define TRACEHL_P_COUNT
#endif
#endif
#ifdef XYZ3 /* only for test m_proc_data suspend 01.03.05 KB */
#define CHECK_050301
#endif
#ifdef TO_DO_050223
1. Client-side-SSL
2. Error Messages RADIQ1
3. Blade-Control Reload-Configuration
4. Numbers of Error Messages
5. Authentication Interface Version 2 hlwsat2.h with XML
6. m_aux: get authentication - solved 01.03.05 KB
7. WTS + Blade Load Balancing new: double entries, IPV6,
   when list at client: check if connect request came from list
   (otherwise security hole)
8. <server-list> <server-entry> <protocol> required, if not error message - was already included, 02.03.05 KB
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: IBIPGW08                                            |*/
/*| -------------                                                     |*/
/*|  IP-Gateway Telnet for Win32 with SSL                             |*/
/*|  WebSecureProxy for Windows                                       |*/
/*|  KB 29.03.00                                                      |*/
/*|  Win64 KB 24.01.05                                                |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB electronic 2000                                |*/
/*|  Copyright (C) HOB electronic 2001                                |*/
/*|  Copyright (C) HOB electronic 2002                                |*/
/*|  Copyright (C) HOB electronic 2003                                |*/
/*|  Copyright (C) HOB 2004                                           |*/
/*|  Copyright (C) HOB Germany 2005                                   |*/
/*|  Copyright (C) HOB Germany 2006                                   |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  XERCES 3.1.0                                                     |*/
/*|                                                                   |*/
/*| EXPECTED INPUT:                                                   |*/
/*| ---------------                                                   |*/
/*| The first parameter (when called from the command prompt)         |*/
/*| gives the name of the .XML-file.                                  |*/
/*|                                                                   |*/
/*| The XML-file is scanned by a subroutine.                          |*/
/*|                                                                   |*/
/*| EXPECTED OUTPUT:                                                  |*/
/*| ----------------                                                  |*/
/*|                                                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

//define HL_SPECIAL_OFFER_CEBIT_04 5
//#define HL_IPV6
/* define TRACEHL1 */
/* define TRACEWSAT */
#ifdef TRACEHL1
#define TRACEHLB
#ifndef TRACEHL_P_COUNT
#define TRACEHL_P_COUNT
#endif
#ifndef TRACEHL_SDH_01
//#define TRACEHL_SDH_01
#endif
#endif
#ifdef TRACEHL_P_COUNT
#ifndef D_STOR_ONE_TIME                     /* 24.04.06 KB - use storage only once */
#define D_STOR_ONE_TIME                     /* 24.04.06 KB - use storage only once */
#endif
#endif
#ifdef TRACEHL1
#ifndef TRACEHL_CO_OUT
#define TRACEHL_CO_OUT
#endif
#endif

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#include <iostream>
#include <ostream>
#include <fstream>

using namespace std;

#define WINVER               0X0501
#define _WIN32_WINNT         0X0501
#define _WIN32_IE            0X0500
//#define _USE_32BIT_TIME_T

#define D_INCL_OCSP

#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <time.h>
#include <sys/timeb.h>
#include <wchar.h>
#include <winsock2.h>
//#ifdef HL_IPV6
#include <ws2tcpip.h>
//#include <wspiapi.h>
//#endif
#include <windows.h>
#ifndef B160501
#include <stdint.h>
#endif
#include <stdio.h>
#include <process.h>
#include <hob-tcp-sync-01.h>
#include <hob-xslunic1.h>
#include <hob-xsltime1.h>
#include <hob-http-header-1.h>
#include <hob-tab-ascii-ansi-1.h>
/* attention 17.03.09 KB start */
#include <hltabaw2.h>
/* attention 17.03.09 KB end */
#include <hob-tab-mime-base64.h>
#include <hob-tabau.h>
#include <hob-thread.hpp>
#include <hob-xslhcla1.hpp>
#include <hob-xslcontr.h>
#include <hobmsg01.h>
#include <hob-perf-data-1.h>
#include <iswcord1.h>
#ifdef B110912
#include <hsha.h>
#endif
#include <hob-encry-1.h>
#ifdef OLD01
#include "HLWSAT1.H"
#endif
#ifdef OLD_1112
#include "hob-hlwspat2.h"
#else
#include "hob-wspat3.h"
#endif
#include <hob-ssl-01.h>
#ifndef B170213
#include <hob-cert-ext.h>
#endif
#ifdef B121009
#include <hob-xshlse03.h>
#ifdef CSSSL_060620
#include <hob-xshlcl01.h>
#endif
#endif
#include <hob-xsrerrm1.h>
#include "hob-xshlssle.h"
#ifdef B121009
#include "HOBSSLTP.H"
#endif
#include <hob-wspsu1.h>
#include <hob-netw-01.h>
#include <hob-nblock_acc.hpp>
#ifndef TRY_090121
#include <hob-tcpco1.hpp>
#else
#include "E:\Garkuscha\Tests\tcpcomp_sample\hob-tcpco1.hpp"
#endif
#ifndef HL_UNIX
#include <hob-avl03.h>
#else
#include "hob-avl03.h"
#endif

/*+-------------------------------------------------------------------+*/
/*| System and library header files for XERCES.                       |*/
/*+-------------------------------------------------------------------+*/

#define READDISKXML

#ifdef B100518
#include <xercesc/util/PlatformUtils.hpp>
#include <xercesc/parsers/AbstractDOMParser.hpp>
#include <xercesc/dom/DOMImplementation.hpp>
#include <xercesc/dom/DOMImplementationLS.hpp>
#include <xercesc/dom/DOMImplementationRegistry.hpp>
#include <xercesc/dom/DOMBuilder.hpp>
#include <xercesc/dom/DOMException.hpp>
#include <xercesc/dom/DOMDocument.hpp>
#include <xercesc/dom/DOMNodeList.hpp>
#include <xercesc/dom/DOMError.hpp>
#include <xercesc/dom/DOMLocator.hpp>
#include <xercesc/dom/DOMInputSource.hpp>
#include <xercesc/util/BinMemInputStream.hpp>
#else
#include <xercesc/parsers/XercesDOMParser.hpp>
#include <xercesc/parsers/DOMLSParserImpl.hpp>
#include <xercesc/dom/DOMImplementation.hpp>
#include <xercesc/util/BinInputStream.hpp>
#include <xercesc/util/BinMemInputStream.hpp>
#include <xercesc/sax/InputSource.hpp>
#include <xercesc/sax/SAXParseException.hpp>
#include <xercesc/sax/ErrorHandler.hpp>
#include <xercesc/dom/DOMLocator.hpp>
#include <xercesc/internal/XMLScanner.hpp>
#include <xercesc/dom/impl/DOMElementImpl.hpp>
#include <xercesc/dom/impl/DOMDocumentImpl.hpp>
#include <xercesc/dom/DOMMemoryManager.hpp>
#endif
#include "IBIPGW08-X1.hpp"

/*+-------------------------------------------------------------------+*/
/*| header files for Server-Data-Hook.                                |*/
/*+-------------------------------------------------------------------+*/

#define DEF_HL_INCL_DOM
#define DEF_HL_INCL_INET
#define DEF_HL_INCL_SSL
#include "hob-xsclib01.h"
/* header files for LDAP                                               */
#include "hob-ldap01.hpp"

/*+-------------------------------------------------------------------+*/
/*| header files for this Gateway and corresponding sources           |*/
/*+-------------------------------------------------------------------+*/

#define D_INCL_CONF
#define INCL_GW_ALL
#define INCL_GW_ADMIN
#define INCL_GW_L2TP
#define INCL_GW_LISTEN
#define D_INCL_HOB_TUN
#define D_INCL_AUX_UDP
#define D_INCL_SWAP_STOR
#ifdef D_HPPPT1_1
#include <string>
#include <map>
#include <list>
#include <queue>
#ifdef D_INCL_HOB_TUN
#include <Iprtrmib.h>
#include <Iphlpapi.h>
#include <Iptypes.h>
#endif
#include "hob-tun01.h"
#ifdef B130813
#include "hob-htcp-int-types.h"
#include "hob-htcp-misc.h"
#include "hob-htcp.h"
#include "hob-htcp-bit-reference.h"
#include "hob-htcp-tcpip-hdr.h"
#include "hob-htcp-connection.h"
#endif
#ifdef B130813
#include "hob-session01.h"
#include "hob-htcp-session.h"
#endif
#include "hob-gw-ppp-1.h"
#ifdef B130813
#include "hob-hppp01.h"
#include "hob-hsstp01.h"
#include "hob-tun02.h"
#endif
#endif
#include "hob-wsppriv.h"                    /* privileges              */
#include "hob-xbipgw08-1.h"
#include "hob-xbipgw08-2.h"
#include "hob-xbipgw08-3.h"
#include "hob-wsp-admin-1.h"
#include "hob-wsp-snmp-1.h"
#ifdef B130813
#include "hob-tuntapif01.h"
#endif
#ifndef B130825
#include <setupapi.h>
#include "hob-tuntapif01.h"
#endif
#ifdef XYZ1
---
#include "hob-avl03.h"
/* new 19.03.09 start */
#include <hob-xslhcla1.hpp>
#include <hob-netw-01.h>
#include <string>
#include <map>
#include <list>
#include <stddef.h>
#include <iostream>
#include "hob-xslcontr.h"
#include "hob-tun01.h"
#include "hob-htcp-int-types.h"
#include "hob-htcp.h"
#include "hob-htcp-bit-reference.h"
#include "hob-htcp-tcpip-hdr.h"
#include "hob-htcp-misc.h"
#include "hob-htcp-connection.h"
#ifdef B130813
#include "hob-session01.h"
#endif
#include "hob-htcp-session.h"
#include "hob-tun02.h"
/* new 19.03.09 end */
---
#endif

/*+-------------------------------------------------------------------+*/
/*| Constant Values.                                                  |*/
/*+-------------------------------------------------------------------+*/

#define DEF_APPL_NAME          "HOB IBIPGW08"  /* application name     */
#define WSP_TRACE_FILE_NOT_AUS "WSP-trace-not-aus.dat"
#ifdef OLD01
#ifndef DEF_PRIO_DEFAULT
#define DEF_PRIO_DEFAULT       3            /* default priority        */
#define DEF_PRIO_MINIMUM       1            /* minimum priority        */
#define DEF_PRIO_MAXIMUM       5            /* maximum priority        */
#endif
#define DEF_BLACO_SIONTIME     120          /* sign on time            */
#define DEF_DELAY_RELOAD_CONF_FILE 20       /* delay in seconds before loading the file */
#define DEF_NO_WTHR_DEFAULT    64           /* default no work threads */
#define DEF_NO_WTHR_S_DEFAULT  64           /* default no work threads */
#define DEF_NO_WTHR_A_DEFAULT  8            /* default no work threads */
#define DEF_NO_WTHR_MINIMUM    4            /* minimum no work threads */
#define DEF_NO_WTHR_MAXIMUM    1024         /* maximum no work threads */
#define NO_WAIT_THR_S          32           /* no of waiting thread b  */
#define DEF_MAX_MULT_TH (WSA_MAXIMUM_WAIT_EVENTS - 1)  /* maximum in t */
#define DEF_MAX_LEN_CO         256          /* maximum length console output */
#define DEF_MAX_LEN_PROT       64           /* maximum length protocol */
#define DEF_OCSP_TIMEOUT       60           /* standard OCSP receive timeout */
#define DEF_OCSP_RETRY         300          /* standard OCSP retry connect */
#define DEF_TCP_BACKLOG        16           /* default TCP/IP backlog  */
#define DEF_SEND_WSASEND       32           /* for WSASend()           */
#define DEF_UDP_PORT           4095         /* port LB default         */
#define DEF_UDP_RECLEN         4096         /* length UDP receive      */
#define DEF_WOL_PORT           65535        /* port wake-on-lan        */
#define DEF_SSL_TIMEOUT        120          /* default timeout SSL     */
#define DEF_LB_TIME1           2            /* timeout wait all        */
#define DEF_LB_TIME2           8            /* timeout wait any        */
#define DEF_MAX_LEN_CERT_NAME  512          /* maximum length cert nam */
#define DEF_WOTHR_LOOP         4            /* compare loop counter    */
//#define LEN_TCP_RECV           8192         /* length of TCP/IP recv   */
//#define LEN_TCP_SEND           2048         /* length of TCP/IP send   */
//#define LEN_TCP_RECV           (16 * 1024)  /* length of TCP/IP recv   */
#define LEN_STA_DIR            2048         /* length directory sect   */
#define HL_ERROR_GETHOSTBYNAME (20000 + 0)  /* HOBLink Error Code      */
#define DEF_REC_NO_B           3            /* number for buffer 1 / 2 */
#define LEN_HOST_IPA           255          /* length host IP address  */
#define DEF_DATA_PTR_TYPE unsigned char *
#define DEF_MAX_LEN_CONF_FILE  0X00100000   /* maximum length configuration file */
#define DEF_TIME_CACHE_DISK_FILE (15 * 60)  /* time in seconds         */
#define DEF_TIME_RELOAD_DISK_FILE (5 * 60)  /* time in seconds         */
#define CHAR_CR                0X0D         /* carriage-return         */
#define CHAR_LF                0X0A         /* line-feed               */
#endif
#define HL_ERROR_HTCP_CONN     (20000 + 1)  /* HOBLink Error Code      */
#define HL_AES_LEN             16
#define HLOG_XYZ1              0            /* to be replaced later    */
#ifndef HL_SPECIAL_OFFER_CEBIT_04
//#define MSG_CONS_P1            "HWSPM001I IBIPGW08 started / Version 2.2 "
#define MSG_CONS_P1            "HWSPM001I IBIPGW08 started / Version 2.3 "
#else
#define MSG_CONS_P1            "IBIPGW08 started / Version 2.2-SO-CeBIT-04 "
#endif
#define MSG_CONS_P2            " / HOB WebSecureProxy / SSL gateway"
#define MSG_QUERY              "HOB WebSecureProxy V2.3 "
#ifndef WIN64
#define MSG_CPU_TYPE           "x86 "
#else
#ifndef _IA64_
#ifndef _AMD64_
#define MSG_CPU_TYPE           "unknown 64-Bit "
#else
#define MSG_CPU_TYPE           "EM64T "
#endif
#else
#define MSG_CPU_TYPE           "IPF "
#endif
#endif
#ifndef __LITTLE_ENDIAN
#define __LITTLE_ENDIAN
#endif

#ifdef OLD01
#define DEF_FUNC_DIR           0            /* set function direct     */
#define DEF_FUNC_RDP           1            /* set function RDP        */
#define DEF_FUNC_ICA           2            /* set function ICA        */
#define DEF_FUNC_PTTD          3            /* PASS-THRU-TO-DESKTOP    */
#define DEF_FUNC_SS5H          4            /* SELECT-SOCKS5-HTTP      */
#define DEF_FUNC_WTS           -1           /* set function WTSGATE    */
#define DEF_FUNC_BLADE         -2           /* set function BLADEGATE  */

#define HL_LANG_EN             (('e' << 8) | 'n')  /* en English       */
#define HL_LANG_ES             (('e' << 8) | 's')  /* es Spanish              */
#define HL_LANG_FR             (('f' << 8) | 'r')  /* fr French               */
#define HL_LANG_DE             (('d' << 8) | 'e')  /* de German               */
#define HL_LANG_IT             (('i' << 8) | 't')  /* it Italian              */
#define HL_LANG_NL             (('n' << 8) | 'l')  /* nl Dutch                */
#endif

#ifdef XYZ2
#define GHFW(str) ((ULONG) ((str & 0X000000FF) << 24) \
        | ((str & 0X0000FF00) << 8) | ((str & 0X00FF0000) >> 8) \
        | ((str & 0XFF000000) >> 24))

#define GHHW(str) ((USHORT) ((str & 0X00FF) << 8) \
        | ((str & 0XFF00) >> 8))
#endif

#define HEV    void *
#define HQUEUE void *
#define APIRET int
#ifndef UNSIG_MED
#define UNSIG_MED unsigned int
#endif
#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif

#ifdef OLD01
#ifndef WIN64
typedef long int dsd_time_1;
#else
typedef __int64 dsd_time_1;
#define NEW_VISUAL_C
#endif
#endif

#ifdef B140328
#ifndef HL_AUX_AUTH_DEF
#define HL_AUX_AUTH_DEF
enum ied_auth_def { ied_ad_ok,              /* userid and password fit */
                    ied_ad_inv_user,        /* userid invalid - not fo */
                    ied_ad_inv_password };  /* password invalid        */
#endif
#endif
#ifndef HL_UNIX
#define D_TCP_ERROR WSAGetLastError()
#define D_TCP_CLOSE closesocket
#define D_CHARSET_IP ied_chs_ansi_819       /* ANSI 819                */
#else
#define D_TCP_ERROR errno
#define D_TCP_CLOSE close
#define D_CHARSET_IP ied_chs_ascii_850      /* ASCII 850               */
#endif

extern "C" {
typedef int (WINAPI* fnIP_WSAStartup) (WORD wVersionRequested, LPWSADATA lpWSAData);
}

extern "C" {
typedef int (WINAPI* fnIP_WSACleanup) ( void );
}

extern "C" {
typedef int (WINAPI* fnIP_send) (
  SOCKET s,
  const char FAR *buf,
  int len,
  int flags );
}

extern "C" {
typedef int (WINAPI* fnIP_recv) (
  SOCKET s,
  char FAR *buf,
  int len,
  int flags );
}

extern "C" {
typedef SOCKET (WINAPI* fnIP_socket) (
  int af,
  int type,
  int protocol);
}

extern "C" {
typedef SOCKET (WINAPI* fnIP_accept) (
  SOCKET s,
  struct sockaddr FAR *addr,
  int FAR *addrlen );
}

extern "C" {
typedef int (WINAPI* fnIP_listen) (
  SOCKET s,
  int backlog  );
}

extern "C" {
typedef int (WINAPI* fnIP_connect) (
  SOCKET s,
  const struct sockaddr FAR *name,
  int namelen );
}

extern "C" {
typedef int (WINAPI* fnIP_bind) (
  SOCKET s,
  const struct sockaddr FAR *name,
  int namelen );
}

extern "C" {
typedef int (WINAPI* fnIP_shutdown) (SOCKET s, int how);
}

extern "C" {
typedef int (WINAPI* fnIP_closesocket) (SOCKET s);
}

extern "C" {
typedef int (WINAPI* fnIP_recvfrom) (
  SOCKET s,
  const char FAR *buf,
  int len,
  int flags,
  const struct sockaddr FAR *from,
  int *fromlen );
}

extern "C" {
typedef int (WINAPI* fnIP_sendto) (
  SOCKET s,
  const char FAR *buf,
  int len,
  int flags,
  const struct sockaddr FAR *to,
  int tolen );
}

extern "C" {
typedef int (WINAPI* fnIP_setsockopt) (
  SOCKET s,
  int level,
  int optname,
  const char FAR *optval,
  int optlen );
}

#ifndef OLD01
extern "C" {
typedef long (WINAPI* fnIP_inet_addr) (const char   FAR *cp );
}
#else
typedef long (WINAPI* fnIP_inet_addr) (const char   FAR *cp );
#endif

extern "C" {
typedef long (WINAPI* fnIP_htons) (u_short hostshort );
}

extern "C" {
typedef long (WINAPI* fnIP_ntohs) (u_short hostshort );
}

extern "C" {
typedef hostent* (WINAPI* fnIP_gethostbyname) (const char *name );
}

extern "C" {
typedef hostent* (WINAPI* fnIP_gethostbyaddr) (const char *addr, int len, int type );
}

#ifdef HL_IPV6
extern "C" {
typedef int (WINAPI* fnIP_getaddrinfo) (
  const char FAR *nodename,
  const char FAR *servname,
  const struct addrinfo FAR *hints,
  struct addrinfo FAR *FAR *res );
}

extern "C" {
typedef int (WINAPI* fnIP_getnameinfo) (
  const struct sockaddr FAR *sa,
  socklen_t salen,
  char FAR *host,
  DWORD hostlen,
  char FAR *serv,
  DWORD servlen,
  int flags );

}

extern "C" {
typedef int (WINAPI* fnIP_getsockname) (
  SOCKET s,
  struct sockaddr FAR *name,
  int *namelen );
}

extern "C" {
typedef void (WINAPI* fnIP_freeaddrinfo) (
  struct addrinfo FAR * );
}
#endif
fnIP_WSAStartup lpfnWSAStartup;
fnIP_WSACleanup lpfnWSACleanup;
fnIP_htons lpfnhtons;
fnIP_ntohs lpfnntohs;
fnIP_inet_addr lpfninet_addr;
fnIP_gethostbyname lpfngethostbyname;
fnIP_gethostbyaddr lpfngethostbyaddr;
fnIP_socket lpfnsocket;
fnIP_bind lpfnbind;
fnIP_connect lpfnconnect;
fnIP_listen lpfnlisten;
fnIP_accept lpfnaccept;
fnIP_recv lpfnrecv;
fnIP_send lpfnsend;
fnIP_shutdown lpfnshutdown;
fnIP_closesocket lpfnclosesocket;
fnIP_recvfrom lpfnrecvfrom;
fnIP_sendto lpfnsendto;
fnIP_setsockopt lpfnsetsockopt;
#ifdef HL_IPV6
fnIP_getaddrinfo lpfngetaddrinfo;
fnIP_getnameinfo lpfngetnameinfo;
fnIP_getsockname lpfngetsockname;
fnIP_freeaddrinfo lpfnfreeaddrinfo;
#endif

#define IP_WSAStartup lpfnWSAStartup
#define IP_WSACleanup lpfnWSACleanup
#define IP_htons lpfnhtons
#define IP_ntohs lpfnntohs
#define IP_inet_addr lpfninet_addr
#define IP_gethostbyname lpfngethostbyname
#define IP_gethostbyaddr lpfngethostbyaddr
#define IP_socket lpfnsocket
#define IP_bind lpfnbind
#define IP_connect lpfnconnect
#define IP_listen lpfnlisten
#define IP_accept lpfnaccept
#define IP_recv lpfnrecv
#define IP_send lpfnsend
#define IP_shutdown lpfnshutdown
#define IP_closesocket lpfnclosesocket
#define IP_recvfrom lpfnrecvfrom
#define IP_sendto lpfnsendto
#define IP_setsockopt lpfnsetsockopt
#ifdef HL_IPV6
#define IP_getaddrinfo lpfngetaddrinfo
#define IP_getnameinfo lpfngetnameinfo
#define IP_getsockname lpfngetsockname
#define IP_freeaddrinfo lpfnfreeaddrinfo
#endif

#define m_ip_socket socket
#define m_ip_closesocket closesocket
#define m_ip_bind bind
#define m_ip_htons htons
#define m_ip_getnameinfo getnameinfo
#define m_ip_getsockname getsockname
#define m_ip_freeaddrinfo freeaddrinfo
#define m_ip_wsawaitm WSAWaitForMultipleEvents
#define m_ip_wsa_enum_net_events WSAEnumNetworkEvents
#define m_ip_wsaevent WSACreateEvent
#define m_ip_recvfrom recvfrom
#define m_ip_sendto sendto
#define m_ip_wsaglerr WSAGetLastError

/*+-------------------------------------------------------------------+*/
/*| Function Calls definitions.                                       |*/
/*+-------------------------------------------------------------------+*/

#ifdef B110210
extern void m_get_perf_data( struct dsd_perf_data * );
#endif
#ifdef B100731
/* routine to do close and connect again                               */
extern "C" void m_aux_conn( void *, char * );
#endif
/* routine to do close and connect again                               */
extern "C" BOOL m_aux_conn( void *, struct dsd_target_ineta_1 *, int );
#ifdef B110210
extern "C" BOOL m_start_monitor_thread( void );
#endif

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

#ifdef HL_IPV6
extern BOOL   bog_ipv6 = FALSE;             /* set if IP Version 6     */
#endif
#ifdef TRACEHL_090912_01
extern BOOL   bog_trace_v1 = FALSE;         /* variable for debugging  */
#endif
#ifdef TRACEHLA
static BOOL bos_error = FALSE;
#endif
static BOOL bos_mem_log = FALSE;
#ifdef TRACEHL1
static void m_trac_exit( void );
#endif
static void WINAPI ServiceMain( DWORD, LPTSTR * );
#ifdef B080407
static htfunc1_t TCPAThread( LPVOID );
static htfunc1_t TCPMThread( LPVOID );
#endif
#ifdef OLD_1112
static htfunc1_t UTILThread( LPVOID );
#endif
#ifdef B060628
static htfunc1_t WORKThread( LPVOID );
#endif
#ifdef B070930
static void * m_proc_alloc( void );
static void m_proc_free( void * );
#endif
static void m_act_thread_1( class clconn1 * );
static void m_act_thread_2( class clconn1 * );
static void m_proc_clconn1( struct dsd_hco_wothr *, void *, void *, void * );
static void m_timeout_conn( struct dsd_timer_ele * );
static void m_free_session_b( struct dsd_timer_ele * );
static void m_timeout_free_memory( struct dsd_timer_ele * );
#ifdef XYZ1
static struct dsd_tich2_ele * m_tich2_alloc( void );
static void m_tich2_free( struct dsd_tich2_ele * );
#endif
static void m_prep_conn_1( class clconn1 *, struct dsd_wspat3_conn * );
static struct dsd_targfi_1 * m_get_session_targfi( char **, class clconn1 * );
static BOOL m_check_conn_sstp_channel_binding( class clconn1 *, char *, int );
#ifdef D_HPPPT1_1
static void m_ppp_auth_radius_compl( struct dsd_radius_control_1 *, int );
static void m_radius_mppe_calc_1( class clconn1 *, struct dsd_radius_control_1 *, char *, int );
#endif
static BOOL m_check_target_multiconn( class clconn1 *, struct dsd_targfi_1 *, struct dsd_unicode_string *, struct dsd_target_ineta_1 *, int );
static void m_lbal_udp_start( class clconn1 * );
static void m_lbal_udp_cb_recv( struct dsd_udp_multiw_1 *, struct dsd_sdh_control_1 * );
#ifdef B130808
#ifdef D_HPPPT1_1
static struct dsd_ineta_raws_1 * m_prepare_htun_ineta( struct sockaddr_storage *, socklen_t *,
                                                       class clconn1 *, struct dsd_hco_wothr *, enum ied_ineta_raws_def );
#ifdef B120206
static BOOL m_prepare_htun_ineta( struct dsd_ineta_raws_1 *, struct sockaddr_storage *, socklen_t *,
                                  class clconn1 *, struct dsd_hco_wothr *, enum ied_ineta_raws_def );
#endif
static void m_cleanup_htun_ineta( struct dsd_ineta_raws_1 * );
static int m_cmp_ineta_n_ipv4( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static int m_cmp_ineta_n_ipv6( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static int m_cmp_ineta_user_ipv4( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static int m_cmp_ineta_user_ipv6( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
#endif
#endif
#ifdef D_INCL_HOB_TUN
static struct dsd_ineta_raws_1 * m_prepare_htun_ineta_htcp( class clconn1 *, struct dsd_hco_wothr *, enum ied_ineta_raws_def );
static BOOL m_update_htun_ineta( struct dsd_ineta_raws_1 *, class clconn1 *, struct dsd_hco_wothr *, enum ied_ineta_raws_def iep_irs_def, struct dsd_config_ineta_1 * );
static void m_cleanup_htun_ineta( struct dsd_ineta_raws_1 * );
static int m_cmp_ineta_n_ipv4( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static int m_cmp_ineta_n_ipv6( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static int m_cmp_ineta_user_ipv4( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static int m_cmp_ineta_user_ipv6( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
#endif
static void m_edit_sci_two( char *, HL_LONGLONG );
static void m_edit_sci_dec( char *, HL_LONGLONG );
#ifdef NEW_REPORT_1501
static void m_time_fingerprint( dsd_time_1 *, dsd_time_1 * );
#endif
static inline void * m_clconn1_dcl_tcp_r_c( void * );
static inline WCHAR * m_clconn1_gatename( void * );
static inline int m_clconn1_sno( void * );
static inline char * m_clconn1_chrc_ineta( void * );
static inline void m_clconn1_critsect_enter( void * );
static inline void m_clconn1_critsect_leave( void * );
#ifndef B120121
static inline void m_clconn1_naeg1( void * );
#endif
static inline BOOL m_clconn1_act_thread_x( void * );
static inline void m_clconn1_act_thread_1( void * );
static inline BOOL m_clconn1_rec_complete( void *, class cl_tcp_r *,
                                           struct dsd_sdh_control_1 *, int );
static inline BOOL m_clconn1_check_client( void *, class cl_tcp_r * );
static inline char ** m_clconn1_get_addr_reason_end( void * );
static inline void m_clconn1_mark_work_area( void *, struct dsd_sdh_control_1 * );
#ifdef B130223
static inline void m_clconn1_check_end_l2tp( void * );
#endif
static inline void m_clconn1_check_end_server( void *, class cl_tcp_r * );
#ifdef TRACEHL_STOR_USAGE
static inline class clconn1 * m_clconn1_get_conn( void * );
static inline struct dsd_sdh_control_1 * m_clconn1_get_sdhc1_chain( void * );
#endif
static inline int m_clconn1_get_trace_level( void * );
static inline void m_clconn1_clear_recv_packets( void * );
static inline BOOL m_sel_server_socks5_1( void *, struct dsd_user_entry *, struct dsd_user_group *,
                                          struct dsd_unicode_string *, enum ied_scp_def, char *, int );
static inline int m_conn_get_no_servent( void *, ied_scp_def, char *, int );
static HL_WCHAR * m_conn_get_servent_by_no( void *, int, ied_scp_def, char *, int );
static inline int m_conn_get_no_user_servent( void *, struct dsd_user_entry *, struct dsd_user_group *,
                                              enum ied_scp_def, char *, int );
static HL_WCHAR * m_conn_get_user_servent_by_no( void *, struct dsd_user_entry *, struct dsd_user_group *, int,
                                                 enum ied_scp_def, char *, int );
static inline ied_set_def m_conn_get_set( void *, BOOL );
static void m_ssl_conn_cl_compl_se( struct dsd_hl_ssl_ccb_1 * );  // Connect Callback
static void m_ssl_conn_cl_compl_cl( struct dsd_hl_ssl_ccb_1 * );  // Connect Callback
static inline void m_garb_coll_1( class clconn1 * );  /* do garbage collect */
static inline BOOL m_garb_coll_2( class clconn1 *, struct dsd_sdh_control_1 * );  /* do garbage collect */
static BOOL m_do_send_server( struct dsd_hco_wothr *, class clconn1 * );
static BOOL m_ext_send_server( struct dsd_hco_wothr *, class clconn1 *, struct dsd_sdh_control_1 * );
static void m_pd_plain_http( struct dsd_pd_work * );
static void m_pd_auth1( struct dsd_pd_work * );
static void m_auth_radius_req_compl( struct dsd_radius_control_1 *, int );
static inline void m_auth_get_input( struct dsd_gather_i_1 *, char *, char *, char * );
static void m_pd_auth_start_pttd( struct dsd_pd_work *, struct dsd_conn_pttd_thr * );  /* connect PTTD thread */
static void m_auth_delete( struct dsd_pd_work *, struct dsd_wsp_auth_1 * );
static void m_pd_loadbal1( struct dsd_pd_work * );
#ifdef TRACEHL_STOR_USAGE
static void m_proc_mark_1( void *ap1, char *achp_pos );
static void m_proc_trac_1( void *ap1, char *achp_trac );
extern "C" void * m_get_stack( void );
#endif
static void m_pd_do_sdh_frse( struct dsd_pd_work * );
static void m_pd_do_sdh_tose( struct dsd_pd_work * );
static void m_pd_do_cs_ssl( struct dsd_pd_work * );
static void m_pd_close_cs_ssl( struct dsd_pd_work * );
#ifdef TRACE_HL_SESS_01
static void m_clconn1_last_action( void *, int );  /* last action      */
#endif  /* TRACE_HL_SESS_01 */
#ifdef TRACEHLC
static void m_check_aclconn1( void *, int );
#endif
static BOOL m_proc_conf( BOOL );
static BOOL m_startprog( struct dsd_wsp_startprog * );
#ifdef D_INCL_HOB_TUN
static void m_gw_start_htun( struct dsd_raw_packet_if_conf * );
#endif
#ifdef D_FILL_LOG                           /* 24.04.08 KB             */
static void m_test_fill_log( void );
#endif
static void m_wothr_start_inj( struct dsd_hco_wothr *, int );
static int m_cmp_session_id( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static void m_loconf_reset( struct dsd_loconf_1 * );
#ifndef B080322
static void m_radius_udp_recv_compl( struct dsd_udp_multiw_1 *, struct dsd_sdh_control_1 * );
#endif
#ifdef OLD_1112
static void m_radius_send( class dsd_radius_query *, char *, int, BOOL );
static void m_radius_remove( class dsd_radius_query * );
static void m_radius_aux_delete( struct dsd_auxf_1 * );
static struct dsd_radius_entry * m_radius_get_str_raent( void *, int );
#endif
static htfunc1_t m_conn_pttd_thread( void * );
static htfunc1_t m_serial_thread( void * );
static htfunc1_t m_wsp_trace_thread( void * );
static void m_wsp_trace_bin_1( struct dsd_wsp_tr_intern_1 *, struct dsd_wsp_trace_record * );
static void m_dump_cma_01( void * vpp_userfld, struct dsd_cma_dump_01 *adsp_cm01 );
static void m_wsp_trace_ascii_1( struct dsd_wsp_tr_intern_1 *, char *, int );
inline dsd_user_entry ** m_get_addr_user_entry( void * );
inline dsd_user_group ** m_get_addr_user_group( void * );
static ied_chid_ret m_auth_user( struct dsd_user_entry **, struct dsd_user_group **,
                                 void *,
                                 struct dsd_unicode_string *, struct dsd_unicode_string *,
                                 BOOL, BOOL );
static void * m_get_certificate( void * );
//static BOOL m_aux_get_ident_set_1( void *, struct dsd_sdh_ident_set_1 * );
static int m_ocsp_start( void * vpp_userfld, struct dsd_hl_ocsp_d_1 * );  // OCSP start
static int m_ocsp_send( void * vpp_userfld, char *achp_buf, int inp_len );  // OCSP send
static struct dsd_hl_ocsp_rec * m_ocsp_recv( void * vpp_userfld );  // OCSP receive
static void m_ocsp_stop( void * vpp_userfld );  // OCSP stop
static void m_ocsp_cleanup( class clconn1 *, struct dsd_auxf_1 * );
#ifndef B150121
static inline void m_conn1_set_timer_1( class clconn1 * );
#endif
static BOOL m_secondary_aux( void *, int, void *, int );
static void m_aux_radius_req_compl( struct dsd_radius_control_1 *, int );
static void m_read_diskfile( struct dsd_hco_wothr *, int, int, int, struct dsd_hl_aux_diskfile_1 * );
#ifdef B130314
static void m_aux_timer_new( class clconn1 *, ied_src_func, void *, int );
static void m_aux_timer_del( class clconn1 *, ied_src_func, void * );
static BOOL m_aux_timer_check( class clconn1 *, ied_src_func, void * );
#endif
static void m_aux_timer_new( class clconn1 *, struct dsd_cid *, int, enum ied_auxt_usage );
static void m_aux_timer_del( class clconn1 *, struct dsd_cid * );
static BOOL m_aux_timer_check( class clconn1 *, struct dsd_cid * );
#ifndef B140620
static void m_sdh_cleanup( struct dsd_aux_cf1 *, struct dsd_cid * );  /* cleanup resources of Server-Data-Hook */
#endif
#ifdef CHECK_PROB_070113
static void m_check_chain_aux( void * );
#endif
static int m_ret_signal( struct dsd_aux_cf1 * );
#ifdef B130314
static void * m_check_sdh_signal( struct dsd_aux_cf1 * );
#endif
static struct dsd_cid * m_check_sdh_signal( struct dsd_aux_cf1 * );
static void m_set_wothr_blocking( void * );
static void m_set_wothr_active( void * );
static BOOL m_mark_work_area( void *, char *, int );
static BOOL m_proc_service_query( void *, struct dsd_aux_service_query_1 * );
static BOOL m_aux_sdh_obj_1( void *, struct dsd_get_sdh_object_1 * );
static BOOL m_aux_session_conf_1( void *, struct dsd_aux_session_conf_1 * );
static BOOL m_aux_admin_1( void *, struct dsd_aux_admin_1 * );
static BOOL m_aux_set_ident_1( void *, struct dsd_aux_set_ident_1 * );
static BOOL m_aux_get_ident_1( class clconn1 *, struct dsd_sdh_ident_set_1 * );
static void m_aux_get_duia_1( class clconn1 *, struct dsd_aux_get_duia_1 * );
static BOOL m_aux_secure_xor( struct dsd_aux_secure_xor_1 * );
static BOOL m_aux_webso_conn( void *, struct dsd_aux_webso_conn_1 * );
static void m_close_webso_conn( void * );
static BOOL m_aux_pipe_manage( void *, struct dsd_aux_pipe_req_1 * );
static void m_aux_pipe_listen_cleanup( class clconn1 *, struct dsd_auxf_1 * );
static void m_aux_pipe_conn_cleanup( class clconn1 *, struct dsd_auxf_1 * );
static int m_cmp_aux_pipe_listen( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static BOOL m_aux_util_thread_cmd( void *, struct dsd_aux_util_thread_call_1 * );
static htfunc1_t m_aux_util_thread_execute( void * );
static void m_swap_stor_open( void );
static void m_swap_stor_update( void );
static BOOL m_aux_swap_stor_req_1( void *, struct dsd_aux_swap_stor_req_1 * );
static BOOL m_swap_stor_file_write( struct dsd_hco_wothr *, int, void * );
static BOOL m_swap_stor_file_read( struct dsd_hco_wothr *, int, void * );
static BOOL m_swap_stor_file_mark_free( int, BOOL );
static char * m_swap_stor_acq_mem( BOOL );
static struct dsd_swap_stor_chain * m_swap_stor_acq_ss_ch( void );
static void m_aux_swap_stor_cleanup( struct dsd_hco_wothr *, class clconn1 *, struct dsd_auxf_1 * );
static BOOL m_aux_dyn_lib_req_1( void *, struct dsd_aux_dyn_lib_req_1 * );
static void m_aux_dyn_lib_cleanup( class clconn1 *, struct dsd_auxf_1 * );
static BOOL m_aux_get_domain_info_1( void *, struct dsd_aux_get_domain_info_1 * );
static BOOL m_aux_file_io_req_1( void *, struct dsd_aux_file_io_req_1 *, int, int );
static BOOL m_aux_sdh_reload_call( void *, struct dsd_hl_aux_manage_sdh_reload * );
static void m_sdh_reload_old_resources( class clconn1 *, struct dsd_cid *, struct dsd_sdh_reload_saved * );
static void m_sdh_reload_new_resources( void *, struct dsd_sdh_reload_saved * );
static void m_sdh_reload_old_end( struct dsd_aux_cf1 *, struct dsd_auxf_1 * );
#ifdef WAS_BEFORE_1501
static void m_sdh_reload_do( void *, int );
static void m_sdh_reload_timeout( struct dsd_timer_ele * );
#endif
static void m_sdh_reload_client_ended( class clconn1 * );
static int m_cmp_aux_sdh_reload( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );
static void m_end_proc( void );
static void m_wait_conn( void *, int );     /* wait till activated     */
static void m_post_conn( void * );          /* post waiting thread     */
static void m_act_conn( void * );           /* activate thread         */
#ifdef TRY_120306_01                        /* flow-control send       */
#ifndef B120313
static inline BOOL m_clconn1_check_act_conn( void * );
static inline void m_clconn1_set_act_conn( void * );
static inline void m_clconn1_do_act_conn( void * );
#endif
#endif
static void m_display_conn( void *, char * );  /* display for connection */
#ifdef B120915
static void m_session_new_params( class clconn1 * );
#endif
static void m_start_ip( void );
static void LoadWinSockFunctions( void );
#ifdef HL_IPV6
static BOOL loadws_IPV6_functions( void );
#endif

static void m_errorcallback( dsd_nblock_acc *, void *, char *, int, int );  // Error callback function.
static void m_acceptcallback( dsd_nblock_acc *, void *, int, struct sockaddr *, int );
static void m_cb_tcpc_conn_err( dsd_tcpcomp *, void *, struct sockaddr *, socklen_t, int, int, int );
#ifdef B121120
static void m_cb_tcpc_connect( dsd_tcpcomp *, void *, struct sockaddr *, socklen_t, int );
#else
static void m_cb_tcpc_connect( dsd_tcpcomp *, void *, struct dsd_target_ineta_1 *, void *, struct sockaddr *, socklen_t, int );
#endif
static void m_cb_tcpc_send( dsd_tcpcomp *, void * );  /* send callback function */
static int m_cb_tcpc_getbuf( dsd_tcpcomp *, void *, void **, char **, int ** ); // get receive buffer callback function
static int m_cb_tcpc_recv( dsd_tcpcomp *, void *, void * );        // receive callback function
static void m_cb_tcpc_error( dsd_tcpcomp *, void *, char *, int, int ); // error callback function
static void m_cb_tcpc_cleanup( dsd_tcpcomp *, void * );
#ifdef B121120
static void m_cb_tcpc_free_target_ineta( dsd_tcpcomp *, void *, const struct dsd_target_ineta_1 * );
#endif

static void HLGW_set_timer( void *, int );
static void HLGW_sendto_LB( void *, char *, int );
static int HLGW_start_conn( void *, struct sockaddr * );
static int HLGW_check_name( void *, char *, int, char *, int );
static void HLGW_set_abend( void * );
#ifndef B140704
static void m_free_seco1( struct dsd_timer_ele * );
#endif
static int m_hlgw_printf( void *, char *, ... );

static HL_LONGLONG m_get_epoch_ms( void );
//static HL_LONGLONG m_get_epoch_microsec( void );
#ifdef B140914
static void m_display( char * );
#endif
//static int m_get_random_number( int );
static void m_lock_blade_control( void );   /* lock resource           */
static void m_unlock_blade_control( void );  /* unlock resource        */
#ifdef B080324
static void m_blade_control_send( UNSIG_MED );
static htfunc1_t m_blade_twin_rec_thread( LPVOID );
#endif

#ifdef B080322
static htfunc1_t m_radius_proc_thread( LPVOID );
#endif

#ifdef B060514
static int HL2_printf( BOOL bopcons, char *aptext, ... );
#endif
#ifdef XYZ2
static int m_hlnew_printf( int, char *aptext, ... );
#endif

extern "C" void m_hl_lock_inc_1( int * );
extern "C" void m_hl_lock_dec_1( int * );

#ifdef TRACEHL_CO_OUT
extern "C" void m_console_out( char *achp_buff, int implength );
#endif
#ifdef DEBUG_HOB_TUN_1407
static void m_debug_hob_tun_1407_start( void );
static void m_debug_hob_tun_1407_proc( struct dsd_hco_wothr *adsp_hco_wothr,
                                       void *ap_param_1, void *ap_param_2, void *ap_param_3 );
#endif

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

static char   *adss_path_param = NULL;      /* path of param - xml file */
static HINSTANCE hInstWinsockDll;           /* load normal library     */
#ifdef B080407
static class clconn1 *aconn1a = NULL;       /* anchor for chain        */
#endif
#ifdef B140913
static dsd_time_1 i_timer_set = 0;          /* timer clconn1           */
#ifdef B120208
static dsd_time_1 ips_timer_set = 0;        /* timer radius            */
#endif
static class clutilth *a_clutil_a = NULL;   /* anchor for chain        */
static struct DAUTHLIB1 *adauthlib1_anchor = NULL;  /* anchor of chain */
#endif
static HL_LONGLONG ils_freq = 0;            /* QueryPerformanceFrequency() */
static HL_LONGLONG ils_perform_start;       /* performance counter at start of WSP */
static HL_LONGLONG ils_epoch_start;         /* epoch microseconds at start of WSP */
static struct dsd_diskfile_1 *adss_df1_anchor = NULL;  /* diskfile in memory */
static int    ins_session_no = 0;           /* session no              */
extern struct dsd_hco_main dsg_hco_main;    /* work threads            */
static int    ims_priority_process;         /* priority of process     */
#ifdef B080407
static struct DWAITT *as_dwaitt_free = 0;   /* chain of free elements  */
static struct DWAITT *as_dwaitt_proc_first = 0; /* chain to process    */
static struct DWAITT *as_dwaitt_proc_last;  /* last to process         */
#endif
/* event handle main and event when configuration file changed         */
static HANDLE dsrs_heve_main[2] = { INVALID_HANDLE_VALUE, INVALID_HANDLE_VALUE };
static CRITICAL_SECTION d_clconn_critsect;  /* critical section clconn */
static CRITICAL_SECTION d_clutil_critsect;  /* critical section clutil */
static CRITICAL_SECTION d_clwork_critsect;  /* critical section clwork */
static class dsd_hcla_critsect_1 dss_critsect_aux;  /* critical section aux */
static class dsd_hcla_critsect_1 dss_critsect_slow;  /* critical section slow actions */
       class dsd_hcla_critsect_1 dsg_global_lock;  /* global lock      */
static class dsd_hcla_critsect_1 dss_trace_lock;  /* lock for WSP-trace */
static unsigned char ucs_random_01 = 0;
#ifdef TRACE_PRINTF
static CRITICAL_SECTION dss_critsect_printf;  /* critical section printf */
#endif
static struct dsd_perf_data dss_perf_data;  /* performance data        */
static CRITICAL_SECTION dsalloc_dcritsect;  /* for alloc / free        */
static void *asrecbuf = NULL;               /* receive buffer          */
static int is_count_free = 0;               /* count free              */
#ifdef TRACEHL_P_COUNT
static int    ins_count_memory = 0;
static int    ins_count_buf_in_use = 0;
static int    ins_count_buf_max = 0;
#endif
#ifdef TRACEHL_STOR_USAGE
static struct dsd_tr_stor_usage_01 *adss_tr_stor_usage_01_anchor = NULL;
#endif
#ifdef TRACEHL_WA_COUNT
static int    ims_count_wa_inc = 0;         /* work area increment     */
static int    ims_count_wa_dec = 0;         /* work area decrement     */
#endif
#ifdef TRACEHL1
static int    ims_cdaux = 0;                /* count call m_cdaux()    */
#endif
#ifdef TRACEHL_P_050118
static int    ims_p_050118 = 0;             /* variable for trace      */
#endif
#ifdef TRACEHL_TCP_BLOCK                    /* 18.07.07 KB count TCP blocking */
static int    ims_trace_block_send = 0;
static int    ims_trace_block_may = 0;
static int    ims_trace_block_retry = 0;
static int    ims_trace_block_call_tcpthr = 0;
#endif /* TRACEHL_TCP_BLOCK                    18.07.07 KB count TCP blocking */
#ifdef TRACEHL_SDH_01
static int    ims_sdhc_alloc_no = 0;        /* number of allocates     */
#endif
#ifdef DEBUG_120206_01                      /* 06.02.12 KB check storage in use - sdhc1 */
static int    ims_debug_sdhc1_c = 0;        /* counter display sdhc1 per session */
#endif
/* anchor of previously loaded XML configurations                      */
static struct dsd_see_cd_plain_xml *adss_see_cd_plain_xml_anchor = NULL;  /* see in core dump plain XML configuration */
/* anchor of loaded configurations                                     */
static struct dsd_loconf_1 *adss_loconf_1_anchor;
/* loaded configurations that are filled now                           */
static struct dsd_loconf_1 *adss_loconf_1_fill;
/* loaded configurations that are in use now                           */
extern "C" struct dsd_loconf_1 *adsg_loconf_1_inuse = NULL;

static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_conn;

static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_ineta_ipv4;
static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_ineta_ipv6;
static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_user_i_ipv4;
static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_user_i_ipv6;

static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_aux_pipe_listen;

static struct dsd_htree1_avl_cntl dss_htree1_avl_cntl_aux_sdh_reload;

static struct dsd_swap_stor_ctrl dss_swap_stor_ctrl = { 0 };  /* swap storage control */

static struct dsd_cluster_ineta_this *adss_cluster_ineta_this = NULL;  /* chain save INETA this cluster member */
static int ims_cluster_ineta_sequ = 0;      /* sequence number cluster queries */

static struct dsd_dyn_lib_ctrl *adss_dyn_lib_ctrl_ch = NULL;  /* chain dynamic library control */

#ifdef WAS_BEFORE_1501
static struct dsd_sdh_reload_saved *adss_sdh_reload_saved_ch = NULL;  /* chain SDHs, saved for reload */
#endif

#ifndef TJ_B171019
static HL_LONGLONG ils_d_sent=0;            /* data sent to client network */
static HL_LONGLONG ils_d_recv=0;            /* data received from client network */
#endif

static struct dsd_acccallback dss_acccb;

#ifdef B121120
static struct dsd_tcpcallback dss_tcpcomp_cb1 = {
#ifdef XYZ1
   &m_cb_tcpc_connect,
#endif
   &m_cb_tcpc_conn_err,                     /* connect error callback function */
   &m_cb_tcpc_connect,                      /* connect callback function */
   &m_cb_tcpc_send,
   &m_cb_tcpc_getbuf,
   &m_cb_tcpc_recv,
   &m_cb_tcpc_error,
   &m_cb_tcpc_cleanup,
   &m_get_random_number,
};
#else
static struct dsd_tcpcallback dss_tcpcomp_cb1 = {
   &m_cb_tcpc_conn_err,                     /* connect error callback function */
   &m_cb_tcpc_connect,                      /* connect callback function */
   &m_cb_tcpc_send,
   &m_cb_tcpc_getbuf,
   &m_cb_tcpc_recv,
   &m_cb_tcpc_error,
   &m_cb_tcpc_cleanup,
   &m_get_random_number
};
#endif

#ifdef B080324
static struct dd_blade_control {
   BOOL boc_blade_active;                   /* blade functions active  */
   BOOL boc_twin_active;                    /* twin is active          */
   CRITICAL_SECTION dc_critsect;            /* critical section        */
   int imc_sign_on_time;                    /* seconds sign on time    */
   struct d_blade_twin *adc_blatw_anchor;   /* anchor of twins         */
   int imc_socket;                          /* socket for UDP          */
#ifdef OLD01
   class cThreads dcthrecv;                 /* thread recvfrom tr twin */
#endif
   class dsd_hcthread dcthrecv;             /* thread recvfrom tr twin */
} ds_blade_control;
#endif

#ifdef OLD01
static struct dsd_radius_control {
   struct dsd_radius_entry *adsc_raent_anchor;  /* chain radius entr   */
   struct dsd_radius_thread *adsc_rathr_anchor;  /* chain radius threa */
   CRITICAL_SECTION dsc_critsect;           /* critical section        */
   int        imc_port_wol;                 /* port for wake-on-lan    */
   UNSIG_MED  umc_wol_r_ineta;              /* IP-addr wol relay       */
   struct dsd_conn_pttd_socket *adsc_cpttdso;  /* chain of sockets     */
} dsg_radius_control;
#endif

struct dsd_radius_control dsg_radius_control;  /* control radius       */

struct dsd_cdaux_control dsg_cdaux_control;  /* control m_cdaux        */

#ifdef D_INCL_HOB_TUN
// to-do 13.09.22 KB - maybe bug, initializes only first field
static struct dsd_tun_ctrl dss_tun_ctrl = {0};  /* HOB-TUN control area */
#endif

static const int imrs_priority[] = {
   IDLE_PRIORITY_CLASS,
// BELOW_NORMAL_PRIORITY_CLASS,
   0X00004000,
   NORMAL_PRIORITY_CLASS,
// ABOVE_NORMAL_PRIORITY_CLASS,
   0X00008000,
   HIGH_PRIORITY_CLASS
};

static const char chrs_query_main[] = MSG_QUERY MSG_CPU_TYPE __DATE__;

#ifdef NEW_REPORT_1501
static struct dsd_bandwidth_client_ctrl dss_bc_ctrl = { 0 };  /* measure bandwidth with clients - control */
#endif

static struct dsd_extra_thread_stat dss_ets_pttd = {  /* statistics about extra threads - pass-thru-to-desktop */
   0,                                       /* int imc_no_started - number of instances started */
   0,                                       /* int imc_no_current - number of instances currently executing */
   0,                                       /* int imc_no_denied - number of start requests denied */
   0,                                       /* HL_LONGLONG ilc_sum_time_ms - summery time executed in milliseconds */
   NULL                                     /* struct dsd_extra_thread_entry *adsc_ete_ch - chain extra thread entries */
};

static struct dsd_extra_thread_stat dss_ets_ut = {  /* statistics about extra threads - utility threads */
   0,                                       /* int imc_no_started - number of instances started */
   0,                                       /* int imc_no_current - number of instances currently executing */
   0,                                       /* int imc_no_denied - number of start requests denied */
   0,                                       /* HL_LONGLONG ilc_sum_time_ms - summery time executed in milliseconds */
   NULL                                     /* struct dsd_extra_thread_entry *adsc_ete_ch - chain extra thread entries */
};

static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

static const char chrs_crlf[] = { 0X0D, 0X0A };

#ifdef TRACEHL_050412
static const unsigned char chrs_trace_050412[] = {
   0X15, 0X03, 0X01, 0X00, 0X16, 0X01, 0X00
};
#endif

/*+-------------------------------------------------------------------+*/
/*| Internal used classes.                                            |*/
/*+-------------------------------------------------------------------+*/

class clfilerin1 {                          /* class read input file   */
   public:
     inline BOOL readfile( WCHAR *apname,
                           char **aapbuffer, ULONG *aulpfilelen,
                           DWORD *adwperror ) {
       HANDLE hufi1;                        /* handle for file         */
       BOOL   bcl1;
       BOOL   bcl2;
       ULONG ulcl1;

       *aapbuffer = 0;
       *aulpfilelen = 0;
       *adwperror = 0;
       hufi1 = CreateFileW( apname, GENERIC_READ, FILE_SHARE_READ, 0,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
       if (hufi1 == INVALID_HANDLE_VALUE) {
         *adwperror = GetLastError();
         return FALSE;
       }
       *aulpfilelen = GetFileSize( hufi1, NULL );
       if (*aulpfilelen == 0XFFFFFFFF) {
         *adwperror = GetLastError();
         CloseHandle( hufi1 );
         return FALSE;
       }
       *aapbuffer = (char *) malloc( *aulpfilelen );
       bcl1 = ReadFile( hufi1, *aapbuffer, *aulpfilelen, &ulcl1, 0 );
       if (bcl1 == FALSE) {
         *adwperror = GetLastError();
       }
       bcl2 = CloseHandle( hufi1 );
       if ((bcl1) && (bcl2)) return TRUE;
       if ((bcl1) && (bcl2 == FALSE)) {
         *adwperror = GetLastError();
       }
       free( *aapbuffer );
       return FALSE;
     }
};

struct dsd_co_sort {                        /* for connection sort    */
   struct dsd_htree1_avl_entry dsc_sort_1;  /* entry for sorting       */
   int        imc_sno;                      /* session number          */
};

class cl_tcp_r {                            /* class TCP/IP receive    */
   private:
#ifdef TRACEHL6
   public:
#endif
#ifdef TRACEHLA
   public:
#endif
#ifdef TRACEHLD
   public:
#endif
     int     icl_receive;                   /* receive is active       */
     BOOL    bo_error_rec;                  /* receive with error      */
#ifndef B120121
     BOOL     boc_naeg1_disa;               /* naegle algorithm disabled */
#endif
#ifdef B080407
     struct DMULTMSG dmultmsg;
#endif
#ifndef B080407
#ifdef DEBUG_100908_01
   public:
#endif
     class dsd_tcpcomp dsc_tcpco1;          /* connection object       */
     volatile BOOL boc_tcpc_act;            /* TCPCOMP active          */
#endif
     int      imc_conn_state;               /* state of the connection */
       /* -1  means connected                                          */
       /* -2  means connection ended                                   */
       /* 0   means currently trying connect                           */
       /* >0  means return code from connect - TCPCOMP                 */
     struct dsd_netw_post_1 *adsc_netw_post_1;  /* structure to post from network callback */
   public:
#ifdef TRY_120306_01                        /* flow-control send       */
     BOOL     boc_act_conn_send;            /* activate connection after send */
#endif
     static HANDLE hws2mod;                 /* Handle to ws2_32.dll    */
     static CRITICAL_SECTION dclcritsectth;  /* critical section thr   */
     static int ( FAR __stdcall *amc_wsasend )( SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE );
     static WSAEVENT( FAR __stdcall *afunc_wsaevent )();
     static int( FAR __stdcall *afunc_wsa_e_select )( SOCKET, WSAEVENT, long );
     static BOOL( FAR __stdcall *afunc_wsa_close_event )( WSAEVENT );
     static BOOL( FAR __stdcall *afunc_wsa_set_event )( WSAEVENT );
     static int( FAR __stdcall *afunc_wsa_enum_net_events )( SOCKET, WSAEVENT, LPWSANETWORKEVENTS );
     static DWORD( FAR __stdcall *afunc_wsawaitm )( DWORD, const WSAEVENT FAR *, BOOL, DWORD, BOOL );
     static int( FAR __stdcall *afunc_wsaglerr )();
     static int progsta( void );
     int     iclsocket;                     /* socket for connection   */
     struct sockaddr_storage dsc_soa;       /* address information session */
     void    *aclconn1;                     /* address of calling      */
#ifdef B100827
// 15.08.10 KB remove boTCPIPconn and use imc_conn_state
     BOOL    boTCPIPconn;                   /* TCP/IP connection       */
#endif
     int     im_may_recv;                   /* recv is possible        */
#ifdef OLD_120121_01
     volatile BOOL boc_recthr;              /* status in receive thr   */
#endif
//   struct dsd_sdh_control_1 *adsc_sdhc1_send;  /* chain to send      */ // 28.02.07 KB
     volatile struct dsd_sdh_control_1 *adsc_sdhc1_send;  /* chain to send */
#ifdef TEST050130
     /* added 30.01.05 KB */
     BOOL     boc_recv_close;               /* received close          */
#endif
#ifdef TRACEHL_SEND
     int      inc_trace_end;
     int      inc_trace_all;
#endif

     inline void m_send_gather( struct dsd_sdh_control_1 *adsp_sdhc1_send, BOOL bop_tcp_thr ) {  /* send TCP/IP gather */
       BOOL   bol1;                         /* working variable        */
       BOOL   bol_cont;                     /* continue to send        */
       BOOL   bol_notify;                   /* send not complete       */
       int    iml1, iml2, iml3, iml4;       /* working variables       */
       int    iml_rc;                       /* return code             */
       int    iml_gai1;                     /* count send buffers      */
//     unsigned int uml_wsabuf;             /* number of WSABUF        */
       unsigned int uml_sent;               /* bytes sent              */
#ifdef NEW_REPORT_1501
       dsd_time_1 dsl_time_cur;             /* current time            */
#endif
       char   *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
       struct dsd_sdh_control_1 *adsl_sdhc1_send;  /* chain to send    */
       struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable   */
       struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable   */
       struct dsd_gather_i_1 *adsl_gai1_w1;  /* working variable       */
       struct dsd_gather_i_1 *adsl_gai1_w2;  /* working variable       */
       struct dsd_wsp_trace_1 *adsl_wt1_w1;  /* WSP trace control record */
       struct dsd_wsp_trace_1 *adsl_wt1_w2;  /* WSP trace control record */
       struct dsd_wsp_trace_1 *adsl_wt1_w3;  /* WSP trace control record */
       struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record  */
       struct dsd_send_gai1_1 dsrl_send_gai1_1[ DEF_SEND_WSASEND ];  /* block passed to TCPCOMP m_send_gather() */

#ifdef TRACEHL_STOR_USAGE
       {
         char chrh_msg[64];
         struct dsd_sdh_control_1 *adsl_sdhc1_h1;
         adsl_sdhc1_h1 = m_clconn1_get_sdhc1_chain( aclconn1 );  /* get chain    */
         while (adsl_sdhc1_h1) {
           sprintf( chrh_msg, "IBIPGW08-l%05d m_send_gather start", __LINE__ );
           m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
           adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
         }
       }
#endif
       adsl_sdhc1_send = adsp_sdhc1_send;   /* chain to send           */

#ifdef TRACE_HL_SESS_01
       iml1 = 30;
       if (bop_tcp_thr) iml1 = 31;
       m_clconn1_last_action( aclconn1, iml1 );  /* last action        */
#endif  /* TRACE_HL_SESS_01 */
#ifdef TRACEHL_SEND
       iml1 = 0;                            /* clear count             */
       adsl_sdhc1_w1 = adsl_sdhc1_send;     /* get chain to send       */
       do {                                 /* loop over chain sdhc1   */
         adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
//       do {                               /* loop over chain gai1    */
//         iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
//         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
//       } while (adsl_gai1_w1);
         while (adsl_gai1_w1) {             /* loop over chain gai1    */
           iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
           adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
         }
         adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
       } while (adsl_sdhc1_w1);
       if (bop_tcp_thr == FALSE) {
         inc_trace_end += iml1;
       }
       m_hlnew_printf( HLOG_XYZ1, "IBIPGW08 l%05d cl_tcp_r=%p m_send_gather() bop_tcp_thr=%d this->adsc_sdhc1_send=%p new=%d inc_trace_end=%d inc_trace_all=%d",
                       __LINE__, this, bop_tcp_thr, this->adsc_sdhc1_send, iml1, inc_trace_end, inc_trace_all );
#endif
       bol_notify = FALSE;                  /* send not complete       */

       psend10:
// 15.08.10 KB remove boTCPIPconn and use imc_conn_state
#ifdef B100827
       if (boTCPIPconn == FALSE) {          /* TCP/IP connection closed */
#ifdef FORKEDIT
       }
#endif
#endif
       if (imc_conn_state != -1) {          /* state of the connection not connected */
         char *achl_w1 = "client";
         if (this != m_clconn1_dcl_tcp_r_c( aclconn1 )) achl_w1 = "server";
         m_hlnew_printf( HLOG_XYZ1, "HWSPS017W GATE=%(ux)s SNO=%08d INETA=%s %s TCP/IP send data after socket closed",
                     m_clconn1_gatename( aclconn1 ),
                     m_clconn1_sno( aclconn1 ),
                     m_clconn1_chrc_ineta( aclconn1 ),
                     achl_w1 );
         /* free buffers                                               */
         while (adsl_sdhc1_send) {          /* loop over all buffers   */
           adsl_sdhc1_w1 = adsl_sdhc1_send;  /* save this buffer       */
           adsl_sdhc1_send = adsl_sdhc1_send->adsc_next;  /* get next in chain */
           if (adsl_sdhc1_w1->imc_usage_count == 0) {  /* not in use   */
             m_proc_free( adsl_sdhc1_w1 );  /* free this buffer        */
           } else {                         /* work area still in use  */
             m_clconn1_mark_work_area( aclconn1, adsl_sdhc1_w1 );
           }
         }
#ifdef TRACE_HL_SESS_01
         iml1 = 32;
         if (bop_tcp_thr) iml1 = 33;
         m_clconn1_last_action( aclconn1, iml1 );  /* last action        */
#endif  /* TRACE_HL_SESS_01 */
         return;
       }
       if (   (bop_tcp_thr == FALSE)        /* not from TCP thread     */
           && (this->adsc_sdhc1_send)) {    /* already send chain      */
         m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxW GATE=%(ux)s SNO=%08d INETA=%s m_send_gather() logic error send already active",
                         m_clconn1_gatename( aclconn1 ),
                         m_clconn1_sno( aclconn1 ),
                         m_clconn1_chrc_ineta( aclconn1 ) );
         /* free send buffers                                          */
         adsl_sdhc1_w1 = adsl_sdhc1_send;   /* get chain to send       */
#ifdef B141114
         do {                               /* loop over chain sdhc1   */
           if (adsl_sdhc1_w1->imc_usage_count == 0) {  /* not in use   */
             m_proc_free( adsl_sdhc1_w1 );  /* free this buffer        */
           } else {                         /* work area still in use  */
             m_clconn1_mark_work_area( aclconn1, adsl_sdhc1_w1 );
           }
           adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
         } while (adsl_sdhc1_w1);
#endif
#ifndef B141114
         do {                               /* loop over chain sdhc1   */
           adsl_sdhc1_w2 = adsl_sdhc1_w1;   /* save this entry         */
           adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
           if (adsl_sdhc1_w2->imc_usage_count == 0) {  /* not in use   */
             m_proc_free( adsl_sdhc1_w2 );  /* free this buffer        */
           } else {                         /* work area still in use  */
             m_clconn1_mark_work_area( aclconn1, adsl_sdhc1_w2 );
           }
         } while (adsl_sdhc1_w1);
#endif
#ifdef TRACE_HL_SESS_01
         iml1 = 34;
         if (bop_tcp_thr) iml1 = 35;
         m_clconn1_last_action( aclconn1, iml1 );  /* last action        */
#endif  /* TRACE_HL_SESS_01 */
         return;
#ifdef B090615
// to-do 12.05.09 KB - data may be lost - prevent sending in xiipgw08-pd-main.cpp
         m_clconn1_critsect_enter( aclconn1 );
#ifdef B080407
         if (bo_may_send) {
           m_clconn1_critsect_leave( aclconn1 );
           goto psend10;                    /* try again               */
         }
#endif
#ifdef B090512
         if (this->adsc_sdhc1_send) {       /* already chain to send   */
           adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) this->adsc_sdhc1_send;  /* get start of chain */
         }
#endif
         adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) this->adsc_sdhc1_send;  /* get start of chain */
         if (adsl_sdhc1_w1) {               /* already chain to send   */
           do {                             /* loop over all old buffers */
             adsl_sdhc1_w2 = adsl_sdhc1_w1;  /* save last entry        */
             adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
           } while (adsl_sdhc1_w1);
           adsl_sdhc1_w2->adsc_next = adsl_sdhc1_send;  /* append new buffers to chain */
           m_clconn1_critsect_leave( aclconn1 );
#ifdef TRACEHL_SEND
           m_hlnew_printf( HLOG_XYZ1, "IBIPGW08 l%05d cl_tcp_r=%p m_send_gather() bop_tcp_thr=%d this->adsc_sdhc1_send=%p append to chain",
                           __LINE__, this, bop_tcp_thr, this->adsc_sdhc1_send );
#endif
           return;
         }
         m_clconn1_critsect_leave( aclconn1 );
#endif
       }
#ifdef TRACE_091013_01
       if (this == m_clconn1_dcl_tcp_r_c( aclconn1 )) {
         int imh2 = 0;                      /* count gather            */
         iml1 = 0;                          /* clear length to send    */
         adsl_sdhc1_w1 = adsl_sdhc1_send;   /* get chain to send       */
         do {                               /* loop over all data to send */
           adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
           while (adsl_gai1_w1) {           /* loop over chain gai1    */
             iml1 += adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
             imh2++;                        /* count gather            */
             adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
           }
           adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
         } while (adsl_sdhc1_w1);
         m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxW GATE=%(ux)s SNO=%08d INETA=%s count m_send_gather() to client gather=%d length=%d/0X%08X.",
                         m_clconn1_gatename( aclconn1 ),
                         m_clconn1_sno( aclconn1 ),
                         m_clconn1_chrc_ineta( aclconn1 ),
                         imh2, iml1, iml1 );
       }
#endif
#ifndef TJ_B171005 
       // In case of session end, data may be sent by work-thread although sending
       // data from TCPCOMP thread is active / scheduled
       if (bop_tcp_thr) {                   /* from TCP thread         */
          m_clconn1_critsect_enter( aclconn1 );
       }
#endif  //TJ_B171005
       do {                                 /* loop till all sent      */
         bol_cont = FALSE;                  /* reset continue to send  */
         iml_gai1 = 0;                      /* number of buffers       */
         adsl_sdhc1_w1 = adsl_sdhc1_send;   /* get chain to send       */
#ifdef TRY_110805_01
         iml1 = TRY_110805_01;
#endif
         do {                               /* loop over chain sdhc1   */
           adsl_gai1_w1 = adsl_sdhc1_w1->adsc_gather_i_1_i;  /* get chain to send */
#ifndef PROB070717
           do {                             /* loop over chain gai1    */
#else
           while (adsl_gai1_w1) {           /* loop over chain gai1    */
#endif
             /* check if not already sent before                       */
             adsl_sdhc1_w2 = adsl_sdhc1_send;  /* get chain to send    */
             adsl_gai1_w2 = NULL;           /* not found till now      */
             while (TRUE) {                 /* loop till this element found */
               if (adsl_sdhc1_w2 == adsl_sdhc1_w1) break;  /* this element found */
               adsl_gai1_w2 = adsl_sdhc1_w2->adsc_gather_i_1_i;  /* get chain to send */
               while (adsl_gai1_w2) {       /* loop over all gather structures */
                 if (adsl_gai1_w2 == adsl_gai1_w1) break;  /* same element sent before */
                 adsl_gai1_w2 = adsl_gai1_w2->adsc_next;  /* get next in chain */
               }
               if (adsl_gai1_w2) break;     /* element sent before     */
               adsl_sdhc1_w2 = adsl_sdhc1_w2->adsc_next;  /* get next in chain */
               if (adsl_sdhc1_w2 == NULL) {
                 m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxW GATE=%(ux)s SNO=%08d INETA=%s m_send_gather() logic error or chain corrupted",
                                 m_clconn1_gatename( aclconn1 ),
                                 m_clconn1_sno( aclconn1 ),
                                 m_clconn1_chrc_ineta( aclconn1 ) );
                 break;
               }
             }
             if (adsl_gai1_w2 == NULL) {    /* this gather structure not sent before */
#ifndef TRY_110805_01
               if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
#ifdef TRACE_091121_01
                 {
                   unsigned char ucrh_cmp_01[] = { 0X03, 0X00, 0X00, 0X7A };
                   if (!memcmp( adsl_gai1_w1->achc_ginp_cur, ucrh_cmp_01, sizeof(ucrh_cmp_01) )) {
                     m_hlnew_printf( HLOG_XYZ1, "l%05d m_send_gather() iml_gai1=%d achc_ginp_cur=%p achc_ginp_end=%p len=%d/0X%p.",
                                     __LINE__, iml_gai1,
                                     adsl_gai1_w1->achc_ginp_cur,
                                     adsl_gai1_w1->achc_ginp_end,
                                     adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur,
                                     adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur );
                   }
                 }
#endif
#ifdef TRY_090429_01
                 if (iml_gai1 >= DEF_SEND_WSASEND) {
                   bol_cont = TRUE;         /* continue processing     */
                   break;
                 }
#endif
#ifdef TRACEHL_090429_01
                 m_hlnew_printf( HLOG_XYZ1, "l%05d m_send_gather() iml_gai1=%d achc_ginp_cur=%p achc_ginp_end=%p len=%d/0X%p.",
                                 __LINE__, iml_gai1,
                                 adsl_gai1_w1->achc_ginp_cur,
                                 adsl_gai1_w1->achc_ginp_end,
                                 adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur,
                                 adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur );
#endif
                 /* data to send found                                 */
                 dsrl_send_gai1_1[ iml_gai1 ].dsc_gai1_send.achc_ginp_cur
                   = adsl_gai1_w1->achc_ginp_cur;
                 dsrl_send_gai1_1[ iml_gai1 ].dsc_gai1_send.achc_ginp_end
                   = adsl_gai1_w1->achc_ginp_end;
                 dsrl_send_gai1_1[ iml_gai1 ].dsc_gai1_send.adsc_next
                   = &dsrl_send_gai1_1[ iml_gai1 + 1 ].dsc_gai1_send;
                 dsrl_send_gai1_1[ iml_gai1 ].adsc_gai1_org = adsl_gai1_w1;  /* gather input data origin */
                 iml_gai1++;                /* next WSABUF             */
#ifndef TRY_090429_01
                 if (iml_gai1 >= DEF_SEND_WSASEND) break;
#endif
               }
#endif
#ifdef TRY_110805_01
               iml2 = adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur;
               if (iml2 > 0) {              /* we have data to send    */
                 if (iml1 <= 0) {           /* no more length          */
                   bol_cont = TRUE;         /* continue processing     */
                   break;
                 }
                 if (iml2 > iml1) {
                   iml2 = iml1;
                   bol_cont = TRUE;         /* continue processing     */
                 }
                 iml1 -= iml2;
#ifdef TRACE_091121_01
                 {
                   unsigned char ucrh_cmp_01[] = { 0X03, 0X00, 0X00, 0X7A };
                   if (!memcmp( adsl_gai1_w1->achc_ginp_cur, ucrh_cmp_01, sizeof(ucrh_cmp_01) )) {
                     m_hlnew_printf( HLOG_XYZ1, "l%05d m_send_gather() iml_gai1=%d achc_ginp_cur=%p achc_ginp_end=%p len=%d/0X%p.",
                                     __LINE__, iml_gai1,
                                     adsl_gai1_w1->achc_ginp_cur,
                                     adsl_gai1_w1->achc_ginp_end,
                                     adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur,
                                     adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur );
                   }
                 }
#endif
#ifdef TRY_090429_01
                 if (iml_gai1 >= DEF_SEND_WSASEND) {
                   bol_cont = TRUE;         /* continue processing     */
                   break;
                 }
#endif
#ifdef TRACEHL_090429_01
                 m_hlnew_printf( HLOG_XYZ1, "l%05d m_send_gather() iml_gai1=%d achc_ginp_cur=%p achc_ginp_end=%p len=%d/0X%p.",
                                 __LINE__, iml_gai1,
                                 adsl_gai1_w1->achc_ginp_cur,
                                 adsl_gai1_w1->achc_ginp_end,
                                 adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur,
                                 adsl_gai1_w1->achc_ginp_end - adsl_gai1_w1->achc_ginp_cur );
#endif
                 /* data to send found                                 */
                 dsrl_send_gai1_1[ iml_gai1 ].dsc_gai1_send.achc_ginp_cur
                   = adsl_gai1_w1->achc_ginp_cur;
                 dsrl_send_gai1_1[ iml_gai1 ].dsc_gai1_send.achc_ginp_end
                   = adsl_gai1_w1->achc_ginp_cur + iml2;
                 dsrl_send_gai1_1[ iml_gai1 ].dsc_gai1_send.adsc_next
                   = &dsrl_send_gai1_1[ iml_gai1 + 1 ].dsc_gai1_send;
                 dsrl_send_gai1_1[ iml_gai1 ].adsc_gai1_org = adsl_gai1_w1;  /* gather input data origin */
                 iml_gai1++;                /* next WSABUF             */
#ifndef TRY_090429_01
                 if (iml_gai1 >= DEF_SEND_WSASEND) break;
#endif
               }
#endif
             }
             adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
#ifndef PROB070717
           } while (adsl_gai1_w1);
#else
           }
#endif
           if (adsl_gai1_w1) break;         /* has to send immediately */
           adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
         } while (adsl_sdhc1_w1);
         /* when no data to send found, we still have to free the buffers */
         uml_sent = 0;                      /* no data sent yet        */
         iml_rc = 0;                        /* did not send something  */
         if (iml_gai1) {                    /* data to send found      */
           dsrl_send_gai1_1[ iml_gai1 - 1 ].dsc_gai1_send.adsc_next = NULL;
#ifdef XYZ1
           iml_rc = amc_wsasend( iclsocket, dsrl_wsabuf, uml_wsabuf,
                                 (LPDWORD) &uml_sent, 0, NULL, NULL );
#endif
           iml_rc = dsc_tcpco1.m_send_gather( &dsrl_send_gai1_1[ 0 ].dsc_gai1_send, &adsl_gai1_w1 );
#ifdef TRACE_091013_01
           if (this == m_clconn1_dcl_tcp_r_c( aclconn1 )) {
             m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxW GATE=%(ux)s SNO=%08d INETA=%s m_send_gather() to client length=%d/0X%08X.",
                             m_clconn1_gatename( aclconn1 ),
                             m_clconn1_sno( aclconn1 ),
                             m_clconn1_chrc_ineta( aclconn1 ),
                             iml_rc, iml_rc );
           }
#endif
#ifdef NEW_REPORT_1501
           if (   (iml_rc > 0)              /* data sent               */
               && (this == m_clconn1_dcl_tcp_r_c( aclconn1 ))) {  /* on client side */
             if (dss_bc_ctrl.adsrc_bc1[ 0 ] != NULL) {  /* with report */
               dsl_time_cur = m_get_time();  /* current time           */
               dss_bc_ctrl.dsc_critsect.m_enter();  /* critical section */
               iml1 = (int) dsl_time_cur - (int) dss_bc_ctrl.adsrc_bc1[ 0 ]->dsc_time_start;
               if (iml1 < 0) iml1 = 0;
               iml1 /= DEF_BANDWIDTH_CLIENT_SECS;  /* compute slot     */
               iml2 = dss_bc_ctrl.adsrc_bc1[ 0 ]->imc_no_entries;  /* number of entries */
               if (iml1 >= iml2) {          /* check if at end         */
                 iml1 = iml2 - 1;           /* last entry              */
               }
               (*(dss_bc_ctrl.adsrc_bc1[ 0 ]->aimc_p_sent + iml1))++;  /* number of packets sent */
               *(dss_bc_ctrl.adsrc_bc1[ 0 ]->ailc_d_sent + iml1) += iml_rc;  /* count bytes data sent */
               dss_bc_ctrl.dsc_critsect.m_leave();  /* critical section */
             }
           }
#endif
           if (m_clconn1_get_trace_level( aclconn1 ) & HL_WT_SESS_NETW) {  /* generate WSP trace record */
             achl_w1 = "SNESENCL";
             achl_w2 = "client";
             if (this != m_clconn1_dcl_tcp_r_c( aclconn1 )) {
               achl_w1 = "SNESENSE";
               achl_w2 = "server";
             }
             adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
#ifdef B110427
             memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
             adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
             adsl_wt1_w1->ilc_epoch = m_get_epoch_ms();  /* time trace record recorded */
             adsl_wt1_w1->achc_text = (char *) (adsl_wt1_w1 + 1);  /* address of text this record */
             adsl_wt1_w1->imc_len_text              /* length of text this record */
               = sprintf( (char *) (adsl_wt1_w1 + 1),
                          "SNO=%08d data sent to %s returned %d.",
                          m_clconn1_sno( aclconn1 ), achl_w1, iml_rc );
#endif
             memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
             adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
             adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
             memcpy( adsl_wt1_w1->chrc_wtrt_id, achl_w1, sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
             adsl_wt1_w1->imc_wtrt_sno = m_clconn1_sno( aclconn1 );  /* WSP session number */
             adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id       */
             achl_w3 = "";
             if (adsl_gai1_w1) achl_w3 = "not all data sent this chunk / ";
             iml1 = sprintf( (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record),
                             "data sent to %s returned %d/0X%X - %sboc_act_conn_send %d.",
                             achl_w2, iml_rc, iml_rc,
                             achl_w3, this->boc_act_conn_send );
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
             ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed    */
             ADSL_WTR_G1->achc_content      /* content of text / data  */
               = (char *) adsl_wt1_w1 + sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record);
             ADSL_WTR_G1->imc_length = iml1;  /* length of text / data */
             adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
             if (   (iml_rc > 0)
                 && (m_clconn1_get_trace_level( aclconn1 ) & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
               achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
               iml1 = iml_rc;               /* length of data sent     */
               iml2 = 0;                    /* in this buffer          */
               achl_w3 = dsrl_send_gai1_1[ 0 ].adsc_gai1_org->achc_ginp_cur;  /* start of data */
               adsl_wt1_w2 = adsl_wt1_w1;   /* in this piece of memory */
               adsl_wtr_w1 = ADSL_WTR_G1;   /* set last in chain       */
               bol1 = FALSE;                /* reset more flag         */
               do {                         /* loop always with new struct dsd_wsp_trace_record */
                 achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
                 if ((achl_w1 + sizeof(struct dsd_wsp_trace_record)) >= achl_w2) {
                   adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
                   memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
                   adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
                   adsl_wt1_w2 = adsl_wt1_w3;  /* this is current network */
                   achl_w1 = (char *) (adsl_wt1_w2 + 1);
                   achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
                 }
                 memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
                 ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
                 achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
                 ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
#ifdef B120709
                 if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
                   adsl_wtr_w1->boc_more = TRUE;  /* more data to follow */
                 }
#endif
                 adsl_wtr_w1->boc_more = bol1;  /* more data to follow */
                 bol1 = TRUE;               /* set more flag           */
                 adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain */
                 adsl_wtr_w1 = ADSL_WTR_G2;  /* this is last in chain now */
                 while (TRUE) {             /* loop over data sent     */
                   iml3 = dsrl_send_gai1_1[ iml2 ].adsc_gai1_org->achc_ginp_end - achl_w3;
                   if (iml3 > iml1) iml3 = iml1;
                   iml4 = achl_w2 - achl_w4;
                   if (iml4 > iml3) iml4 = iml3;
                   memcpy( achl_w4, achl_w3, iml4 );
                   achl_w4 += iml4;
                   achl_w3 += iml4;
                   ADSL_WTR_G2->imc_length += iml4;  /* length of text / data */
                   iml1 -= iml4;            /* length to be copied     */
                   if (iml1 <= 0) break;
                   if (achl_w3 < dsrl_send_gai1_1[ iml2 ].adsc_gai1_org->achc_ginp_end) break;
                   iml2++;                  /* next part to be copied  */
                   achl_w3 = dsrl_send_gai1_1[ iml2 ].adsc_gai1_org->achc_ginp_cur;  /* start of data */
                   if (achl_w4 >= achl_w2) break;
                 }
                 achl_w1 = achl_w2;         /* set end of this area    */
               } while (iml1 > 0);
             }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
             m_wsp_trace_out( adsl_wt1_w1 );  /* output of WSP trace record */
           }
           /* mark buffers sent                                        */
           iml1 = 0;
           do {                             /* loop over all buffers sent */
             dsrl_send_gai1_1[ iml1 ].adsc_gai1_org->achc_ginp_cur
               = dsrl_send_gai1_1[ iml1 ].dsc_gai1_send.achc_ginp_cur;
             if (dsrl_send_gai1_1[ iml1 ].adsc_gai1_org->achc_ginp_cur
                   < dsrl_send_gai1_1[ iml1 ].adsc_gai1_org->achc_ginp_end) {
               bol_notify = TRUE;           /* send not complete       */
             }
             iml1++;                        /* take next buffer        */
           } while (iml1 < iml_gai1);
           uml_sent = 0;
           if (iml_rc > 0) uml_sent = iml_rc;
#ifdef TRACEHL1
           m_hlnew_printf( HLOG_TRACE1, "IBIPGW08 l%05d WSASend completed / sent iml_rc=%d uml_sent=%d iclsocket=%d time-sec=%d",
                           __LINE__, iml_rc, uml_sent, iclsocket, m_get_time() );
#endif
#ifdef TRACEHL_SEND
           inc_trace_all += uml_sent;
#endif
         }
         /* mark buffers that data have been sent                      */
         do {                               /* loop over chain sdhc1   */
           adsl_gai1_w1 = adsl_sdhc1_send->adsc_gather_i_1_i;  /* get chain to send */
#ifndef PROB070717
           do {                             /* loop over chain gai1    */
#else
           while (adsl_gai1_w1) {           /* loop over chain gai1    */
#endif
#ifndef TRY_090429_01
             if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) break;
#else
             if (adsl_gai1_w1->achc_ginp_cur < adsl_gai1_w1->achc_ginp_end) {
               bol_cont = TRUE;             /* continue processing     */
               break;
             }
#endif
             adsl_gai1_w1 = adsl_gai1_w1->adsc_next;  /* get next in chain */
#ifndef PROB070717
           } while (adsl_gai1_w1);
#else
           }
#endif
           if (adsl_gai1_w1) break;         /* has to send immediately */
           adsl_sdhc1_w1 = adsl_sdhc1_send;  /* save buffer for free   */
           adsl_sdhc1_send = adsl_sdhc1_send->adsc_next;  /* get next in chain */
           if (   (adsl_sdhc1_w1->imc_usage_count == 0)  /* not in use */
               && (this == m_clconn1_dcl_tcp_r_c( aclconn1 ))) {  /* send to client */
             m_proc_free( adsl_sdhc1_w1 );  /* free this buffer        */
           } else {                         /* work area still in use  */
             m_clconn1_mark_work_area( aclconn1, adsl_sdhc1_w1 );
           }
         } while (adsl_sdhc1_send);
         if (bol_notify) {                  /* send not complete       */
           this->adsc_sdhc1_send = adsl_sdhc1_send;  /* set chain to send later */
#ifndef TJ_B171005
           if (bop_tcp_thr) {                   /* from TCP thread         */
             m_clconn1_critsect_leave( aclconn1 );
           }
#endif //TJ_B171005
#ifdef TRACEHL_090429_01
           m_hlnew_printf( HLOG_XYZ1, "l%05d m_send_gather() call dsc_tcpco1.m_sendnotify();",
                           __LINE__ );
#endif
           dsc_tcpco1.m_sendnotify();
#ifdef TRACEHL_SEND
           m_hlnew_printf( HLOG_XYZ1, "IBIPGW08 l%05d cl_tcp_r=%p m_send_gather() bop_tcp_thr=%d this->adsc_sdhc1_send=%p bol_notify return",
                           __LINE__, this, bop_tcp_thr, this->adsc_sdhc1_send );
#endif
           return;                          /* all done                */
         }
#ifdef TRACEHL_090429_01
         m_hlnew_printf( HLOG_XYZ1, "l%05d m_send_gather() bol_cont=%d iml_rc=%d adsl_sdhc1_send=%p.",
                         __LINE__, bol_cont, iml_rc, adsl_sdhc1_send );
#endif
       } while (bol_cont && (iml_rc > 0));  /* till all sent           */
#ifdef TRACEHL_090429_01
       m_hlnew_printf( HLOG_XYZ1, "l%05d m_send_gather() bol_cont=%d iml_rc=%d adsl_sdhc1_send=%p.",
                       __LINE__, bol_cont, iml_rc, adsl_sdhc1_send );
#endif
// to-do 12.05.09 KB - data may be lost - prevent sending in xiipgw08-pd-main.cpp
#ifdef TJ_B171005
       if (bop_tcp_thr) {                   /* from TCP thread         */
         m_clconn1_critsect_enter( aclconn1 );
       }
#endif //TJ_B171005
       /* free buffers                                                 */
       while (adsl_sdhc1_send) {            /* loop over all buffers   */
         adsl_sdhc1_w1 = adsl_sdhc1_send;   /* save this buffer        */
         adsl_sdhc1_send = adsl_sdhc1_send->adsc_next;  /* get next in chain */
         if (   (adsl_sdhc1_w1->imc_usage_count == 0)  /* not in use   */
             && (this == m_clconn1_dcl_tcp_r_c( aclconn1 ))) {  /* send to client */
           m_proc_free( adsl_sdhc1_w1 );    /* free this buffer        */
         } else {                           /* work area still in use  */
           m_clconn1_mark_work_area( aclconn1, adsl_sdhc1_w1 );
         }
       }
#ifdef TRACEHL_SEND
       m_hlnew_printf( HLOG_XYZ1, "IBIPGW08 l%05d cl_tcp_r=%p m_send_gather() bop_tcp_thr=%d this->adsc_sdhc1_send=%p return normal and act",
                       __LINE__, this, bop_tcp_thr, this->adsc_sdhc1_send );
#endif
#ifdef TRACEHL_090429_01
       m_hlnew_printf( HLOG_XYZ1, "IBIPGW08 l%05d cl_tcp_r=%p m_send_gather() bop_tcp_thr=%d this->adsc_sdhc1_send=%p aclconn1=%p return normal and act",
                       __LINE__, this, bop_tcp_thr, this->adsc_sdhc1_send, aclconn1 );
#endif
#ifdef TRACE_HL_SESS_01
       iml1 = 38;
       if (bop_tcp_thr) iml1 = 39;
       m_clconn1_last_action( aclconn1, iml1 );  /* last action        */
#endif  /* TRACE_HL_SESS_01 */
#ifdef TRACEHL_STOR_USAGE
       {
         char chrh_msg[64];
         struct dsd_sdh_control_1 *adsl_sdhc1_h1;
         adsl_sdhc1_h1 = m_clconn1_get_sdhc1_chain( aclconn1 );  /* get chain    */
         while (adsl_sdhc1_h1) {
           sprintf( chrh_msg, "IBIPGW08-l%05d m_send_gather end", __LINE__ );
           m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
           adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
         }
       }
#endif
       /* for HOB-PPP-T1 and other tunnel, clear received packets      */
       if (this == m_clconn1_dcl_tcp_r_c( aclconn1 )) {  /* was send to client */
         m_clconn1_clear_recv_packets( aclconn1 );  /* clear received packets */
       }
       if (bop_tcp_thr == FALSE) return;    /* not from TCP thread     */
       this->adsc_sdhc1_send = NULL;        /* all has been sent       */
#ifndef TRY_120306_01                       /* flow-control send       */
       m_clconn1_critsect_leave( aclconn1 );
       m_post_netw_post_1( DEF_NETW_POST_1_TCPCOMP_SEND_COMPL );
       m_act_conn( aclconn1 );              /* activate work-thread    */
       return;                              /* all done                */
#endif
#ifdef TRY_120306_01                        /* flow-control send       */
#ifdef B120313
       m_clconn1_critsect_leave( aclconn1 );
       m_post_netw_post_1( DEF_NETW_POST_1_TCPCOMP_SEND_COMPL );
#ifdef TRY_120306_01                        /* flow-control send       */
#define NOT_DEF_120308
#ifdef NOT_DEF_120308
       if (this->boc_act_conn_send == FALSE) return;  /* activate connection after send */
#endif
#else
#endif
       m_act_conn( aclconn1 );              /* activate work-thread    */
       return;                              /* all done                */
#endif
#ifndef B120313
#ifdef DEBUG_140803_01                      /* problems boc_act_conn_send */
       this->boc_act_conn_send = TRUE;      /* activate connection after send */
#endif
       bol_cont = FALSE;                    /* do not activate work thread */
       if (   (this->boc_act_conn_send)     /* activate connection after send */
           && (m_clconn1_check_act_conn( this->aclconn1 ) == FALSE)) {
         bol_cont = TRUE;                   /* do activate work thread */
         m_clconn1_set_act_conn( this->aclconn1 );
       }
       m_clconn1_critsect_leave( this->aclconn1 );
       m_post_netw_post_1( DEF_NETW_POST_1_TCPCOMP_SEND_COMPL );
       if (bol_cont == FALSE) return;       /* do not activate work thread */
       m_clconn1_do_act_conn( this->aclconn1 );
       return;                              /* all done                */
#endif
#endif
     } /* end m_send_gather()                                          */

     inline BOOL m_check_send_act() {       /* check send TCP/IP active */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "inline class cl_tcp_r.m_check_send_act() l%05d adsc_sdhc1_send=%p",
                       __LINE__, this->adsc_sdhc1_send );
#endif
       if (this->adsc_sdhc1_send) return TRUE;  /* send in progress    */
       return FALSE;                        /* no send active          */
     } /* end m_check_send_act()                                       */

#ifdef NOT_NEEDED_100827
     inline BOOL m_is_connected() {         /* check TCP session is connected */
     } /* end m_is_connected()                                         */
#endif

#ifdef TRACEHLX
     inline static void report_thread_mrecv() {
       struct DTHRR *audthrr_1;

       audthrr_1 = adthrr_a;                /* get anchor              */
       while (audthrr_1) {
         m_hlnew_printf( HLOG_XYZ1, "report_thread_mrecv %p iactive=%d", audthrr_1, audthrr_1->iactive );
         audthrr_1 = audthrr_1->next;       /* get next in chain       */
       }
     }

#endif
     inline static void loaddll() {
       hws2mod = LoadLibraryA( "WS2_32" );
       if ((HINSTANCE) hws2mod <= (HINSTANCE) HINSTANCE_ERROR) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPIP040W Library WS2_32 not available. RC: %d", hws2mod );
         hws2mod = NULL;
         return;
       }
#ifdef TRACEHL2
       hws2mod = NULL;
       return;
#endif
#ifdef DEF_NO_WSOCK2                        /* 11.05.06 KB             */
       hws2mod = NULL;
       return;
#endif
       m_hlnew_printf( HLOG_XYZ1, "HWSPIP041I Library WS2_32 loaded" );
       amc_wsasend = (int( FAR __stdcall * )( SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE ))
                       GetProcAddress( (struct HINSTANCE__ *) hws2mod, "WSASend" );
       if (amc_wsasend == NULL) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPIP057W Function WSASend could not be located. RC: %d", GetLastError() );
       }
       afunc_wsaevent = (WSAEVENT( FAR __stdcall * )())GetProcAddress( (struct HINSTANCE__ *) hws2mod, "WSACreateEvent" );
       if (afunc_wsaevent == NULL) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPIP050W Function WSACreateEvent could not be located. RC: %d", GetLastError() );
       }
       afunc_wsa_close_event = (BOOL( FAR __stdcall * )( WSAEVENT ))GetProcAddress( (struct HINSTANCE__ *) hws2mod, "WSACloseEvent" );
       if (afunc_wsa_close_event == NULL) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPIP051W Function WSACloseEvent could not be located. RC: %d", GetLastError() );
       }
       afunc_wsa_set_event = (BOOL( FAR __stdcall * )( WSAEVENT ))GetProcAddress( (struct HINSTANCE__ *) hws2mod, "WSASetEvent" );
       if (afunc_wsa_set_event == NULL) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPIP052W Function WSASetEvent could not be located. RC: %d", GetLastError() );
       }
       afunc_wsa_e_select = (int( FAR __stdcall * )( SOCKET, WSAEVENT, long ))GetProcAddress( (struct HINSTANCE__ *) hws2mod, "WSAEventSelect" );
       if (afunc_wsa_e_select == NULL) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPIP053W Function WSAEventSelect could not be located. RC: %d", GetLastError() );
       }
       afunc_wsa_enum_net_events = (int( FAR __stdcall * )( SOCKET, WSAEVENT, LPWSANETWORKEVENTS ))GetProcAddress( (struct HINSTANCE__ *) hws2mod, "WSAEnumNetworkEvents" );
       if (afunc_wsa_enum_net_events == NULL) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPIP054W Function WSAEnumNetworkEvents could not be located. RC: %d", GetLastError() );
       }
       afunc_wsawaitm = (DWORD( FAR __stdcall * )( DWORD, const WSAEVENT FAR *, BOOL, DWORD, BOOL ))GetProcAddress( (struct HINSTANCE__ *) hws2mod, "WSAWaitForMultipleEvents" );
       if (afunc_wsawaitm == NULL) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPIP055W Function WSAWaitForMultipleEvents could not be located. RC: %d", GetLastError() );
       }
       afunc_wsaglerr = ( int ( FAR __stdcall * )())GetProcAddress( (struct HINSTANCE__ *)hws2mod, "WSAGetLastError" );
       if (afunc_wsaglerr == NULL) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPIP056W Function WSAGetLastError could not be located. RC: %d", GetLastError() );
       }
       InitializeCriticalSection( &dclcritsectth );
     }

     /* start this TCP session thru connect()                          */
     inline BOOL m_connect_1( class clconn1 *adsl_conn1,
                              struct dsd_bind_ineta_1 *adsp_bind_ineta,
                              struct dsd_target_ineta_1 *adsp_target_ineta,
#ifndef B121120
                              void * ap_free_ti1,  /* INETA to free    */
#endif
                              unsigned short usp_port,
                              BOOL bop_round_robin,
                              struct dsd_netw_post_1 *adsp_netw_post_1 ) {  /* structure to post from network callback */
       int    iml_rc;                       /* return code             */
       aclconn1 = adsl_conn1;               /* set connection          */
       this->adsc_sdhc1_send = NULL;        /* buffer to send          */
// 15.08.10 KB remove boTCPIPconn and use imc_conn_state
#ifdef OLD_120121_01
       boc_recthr = FALSE;                  /* status in receive thr   */
#endif
#ifndef B120121
       this->boc_naeg1_disa = FALSE;        /* naegle algorithm disabled */
#endif
       icl_receive = 0;                     /* receive not active      */
       bo_error_rec = FALSE;                /* no receive error        */
       imc_conn_state = 0;                  /* currently trying connect */
#ifdef TEST050130
       /* added 30.01.05 KB */
       boc_recv_close = FALSE;              /* received close          */
#endif
#ifdef TRACEHL_SEND
       inc_trace_end = 0;
       inc_trace_all = 0;
#endif
       memset( &dsc_tcpco1, 0, sizeof(class dsd_tcpcomp) );
       adsc_netw_post_1 = adsp_netw_post_1;  /* structure to post from network callback */
       boc_tcpc_act = TRUE;                 /* TCPCOMP is active       */
       iml_rc = dsc_tcpco1.m_startco_mh(
                  &dss_tcpcomp_cb1,
                  this,
                  adsp_bind_ineta,          /* for bind multihomed     */
                  adsp_target_ineta,        /* target INETA            */
#ifndef B121120
                  ap_free_ti1,              /* INETA to free           */
#endif
                  usp_port,                 /* port of target          */
                  bop_round_robin );        /* do round-robin          */
       if (iml_rc == 0) return TRUE;        /* no error occured        */
       boc_tcpc_act = FALSE;                /* TCPCOMP not active      */
#ifndef B140926
// Stefan Martin, but does it really make sense ???
       imc_conn_state = -2;                 /* state of the connection no more connected */
#endif
       m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW IBIPGW08 l%05d m_startco_mh() failed %d.",
                       __LINE__, iml_rc );
    //   goto p_conn_80;                        /* close session to client */
    // 29.09.07 KB - to-do
       return FALSE;                        /* error occured           */
     } /* end m_connect_1()                                            */

     inline void m_did_conn_1( void ) {
       imc_conn_state = -1;                 /* connected               */
// 15.08.10 KB remove boTCPIPconn and use imc_conn_state
#ifdef B100827
       boTCPIPconn = TRUE;                  /* TCP/IP connection       */
//     icl_receive++;                       /* receive now active      */
#endif
     } /* end m_did_conn_1()                                           */

#ifdef XYZ1
     /* wait till this TCP session has send all                        */
     inline BOOL m_wait_send_compl( struct dsd_netw_post_1 *adsp_netw_post_1 ) {  /* structure to post from network callback */
       if (this->adsc_sdhc1_send == NULL) return FALSE;  /* no send chain */
       adsc_netw_post_1 = adsp_netw_post_1;  /* structure to post from network callback */
       return TRUE;                         /* needs to wait for send complete */
     }
#endif

     inline void m_set_conn_error( int imp_error ) {
       imc_conn_state = imp_error;          /* set connect error       */
     } /* end m_set_conn_error()                                       */

     inline int m_get_conn_error( void ) {
       if (this->imc_conn_state <= 0) return 0;
       return this->imc_conn_state;         /* return connect error    */
     } /* end m_get_conn_error()                                       */

     inline void start1( class clconn1 *apclconn1,
                         struct sockaddr *adsp_soa, int imp_soa_len,  /* address information session */
                         int ipsocket ) {
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "inline class cl_tcp_r.start1 ipsocket=%d.", ipsocket );
#endif
       aclconn1 = apclconn1;                /* set calling class       */
       memcpy( &dsc_soa, adsp_soa, imp_soa_len );
       iclsocket = ipsocket;
// 15.08.10 KB remove boTCPIPconn and use imc_conn_state
#ifdef B100827
       boTCPIPconn = TRUE;                  /* TCP/IP connection       */
#endif
       imc_conn_state = -1;                 /* connected               */
       icl_receive = 0;                     /* receive not active      */
       bo_error_rec = FALSE;                /* no receive error        */
#ifdef B110524
       this->adsc_sdhc1_send = NULL;        /* buffer to send          */
#endif
#ifndef B111116
       this->adsc_sdhc1_send = NULL;        /* buffer to send          */
#endif
       im_may_recv = 0;                     /* recv is not possible    */
#ifdef OLD_120121_01
       boc_recthr = FALSE;                  /* status in receive thr   */
#endif
#ifndef B120121
       this->boc_naeg1_disa = FALSE;        /* naegle algorithm disabled */
#endif
       adsc_netw_post_1 = NULL;             /* structure to post from network callback */
#ifdef TEST050130
       /* added 30.01.05 KB */
       boc_recv_close = FALSE;              /* received close          */
#endif
#ifdef TRACEHL_SEND
       inc_trace_end = 0;
       inc_trace_all = 0;
#endif
#ifdef TRACEHLA
       m_hlnew_printf( HLOG_XYZ1, "start1 %p clconn1=%p socket=%d", this, aclconn1, iclsocket );
#endif
     } /* end start1()                                                 */

     inline void start2( void ) {
#ifdef B080407
       int    iml1;                         /* working-variable        */
       int    iml_ip_err;                   /* IP error                */
       char ** aachl_re;                    /* address field reason end */
#endif
#ifndef B080407
       int    iml_rc;                       /* return code             */
#endif

#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T start2 clconn1=%p SNO=%08d this=%p &dsc_tcpco1=%p.",
                       __LINE__, aclconn1, m_clconn1_sno( aclconn1 ), this, &dsc_tcpco1 );
#endif
#ifndef B110524
       this->adsc_sdhc1_send = NULL;        /* buffer to send          */
#endif
       iml_rc = dsc_tcpco1.m_startco_fb(
                  iclsocket,
                  &dss_tcpcomp_cb1,
                  this );
       if (iml_rc) {                        /* error occured           */
         m_hlnew_printf( HLOG_XYZ1, "HWSPM212W GATE=%(ux)s SNO=%08d INETA=%s TCPCOMP m_startco_fb() failed socket=%d Error %d.",
                         m_clconn1_gatename( aclconn1 ),
                         m_clconn1_sno( aclconn1 ),
                         m_clconn1_chrc_ineta( aclconn1 ),
                         iclsocket, iml_rc );
         D_TCP_CLOSE( iclsocket );
         return;                            /* all done                */
       }
       this->boc_tcpc_act = TRUE;           /* TCPCOMP active          */
     } /* end start2()                                                 */

     inline void start3( void ) {
#ifdef DEBUG_100830_02
#ifdef TRY_DEBUG_100830_02
       m_hlnew_printf( HLOG_XYZ1, "l%05d start3()", __LINE__ );
#endif
#endif
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T start3 clconn1=%p SNO=%08d this=%p &dsc_tcpco1=%p.",
                       __LINE__, aclconn1, m_clconn1_sno( aclconn1 ), this, &dsc_tcpco1 );
#endif
       if (adsg_loconf_1_inuse->imc_tcp_sndbuf) {  /* set TCP SNDBUF   */
         dsc_tcpco1.mc_set_sndbuf( adsg_loconf_1_inuse->imc_tcp_sndbuf );
       }
       if (adsg_loconf_1_inuse->imc_tcp_rcvbuf) {  /* set TCP RCVBUF   */
         dsc_tcpco1.mc_set_rcvbuf( adsg_loconf_1_inuse->imc_tcp_rcvbuf );
       }
       if (adsg_loconf_1_inuse->boc_tcp_keepalive) {  /* set TCP KEEPALIVE */
         dsc_tcpco1.mc_set_keepalive( TRUE );
       }
#ifndef B120121
       m_clconn1_naeg1( this->aclconn1 );   /* disable naegle algorithm */
#endif
       icl_receive++;                       /* receive now active      */
       dsc_tcpco1.m_recv();                 /* start receiving         */
     } /* end start3()                                                 */

     inline void m_set_netw_post_1( struct dsd_netw_post_1 *adsp_netw_post_1 ) {
       adsc_netw_post_1 = adsp_netw_post_1;  /* structure to post from network callback */
     } /* end m_set_netw_post_1()                                      */

     inline void m_post_netw_post_1( int imp_select ) {
       int    iml_rc;                       /* return code             */
       int    iml_error;                    /* error code              */
       struct dsd_netw_post_1 *adsl_netw_post_1;  /* structure to post from network callback */

       adsl_netw_post_1 = adsc_netw_post_1;  /* get structure to post from network callback */
       if (adsl_netw_post_1 == NULL) return;  /* nothing to do         */
       if ((imp_select & adsl_netw_post_1->imc_select) == 0) return;  /* not selected */
       adsc_netw_post_1 = NULL;             /* remove structure to post from network callback */
       adsl_netw_post_1->boc_posted = TRUE;  /* event has been posted  */
       iml_rc = adsl_netw_post_1->adsc_event->m_post( &iml_error );  /* event for posted */
       if (iml_rc < 0) {                     /* error occured           */
         m_hl1_printf( "xxxxxxxr-%05d-W m_set_netw_post_1() m_post Return Code %d Error %d.",
                       __LINE__, iml_rc, iml_error );
       }
     }; /* end m_post_netw_post_1()                                    */

     inline void m_cleanup_1( void ) {      /* cleanup structure       */
       boc_tcpc_act = FALSE;                /* TCPCOMP not active      */
#ifdef B130223
       m_clconn1_check_end_l2tp( aclconn1 );  /* check end L2TP        */
#endif
       m_clconn1_check_end_server( aclconn1, this );  /* check end server */
       m_clconn1_act_thread_1( aclconn1 );  /* active thread           */
     } /* end m_cleanup_1()                                            */

     inline void m_wait_cleanup( void ) {   /* wait for cleanup        */
       int    iml_count;

       iml_count = 10;
       do {                                 /* loop wait for cleanup   */
         if (boc_tcpc_act == FALSE) return;  /* TCPCOMP not active     */
         Sleep( 100 );                      /* wait some time          */
         iml_count--;                       /* decrement loop counter  */
       } while (iml_count > 0);
       m_hlnew_printf( HLOG_WARN1, "HWSPM213W GATE=%(ux)s SNO=%08d INETA=%s TCPCOMP wait cleanup timeout socket=%d.",
                       m_clconn1_gatename( aclconn1 ),
                       m_clconn1_sno( aclconn1 ),
                       m_clconn1_chrc_ineta( aclconn1 ),
                       iclsocket );
       return;
     } /* end m_wait_cleanup()                                         */

#ifdef B110316
     inline int m_get_socket( void ) {      /* return the TCP socket   */
       return iclsocket;
     }
#endif

     inline void * m_get_ineta( void ) {    /* return the INETA        */
#ifndef B080407
// to-do 30.04.09 KB IPV6 and HTCP
//     return NULL;
       return &dsc_soa;
#endif
#ifdef B080407
#ifndef HL_IPV6
       return &dclient1;
#else
       return &uncl1;
#endif
#endif
     }

     inline void newreceive( void ) {       /* new receive             */
// 15.08.10 KB remove boTCPIPconn and use imc_conn_state
//     if (boTCPIPconn == FALSE) return;    /* TCP/IP connection stat  */
       if (imc_conn_state != -1) return;    /* state of the connection */
       dsc_tcpco1.m_recv();                 /* continue receiving      */
       return;
     }

     inline void setnor( BOOL boplock ) {   /* set status no receive   */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "cl_tcp_r <%p> ::setnor()", this );
#endif
       if (boplock) {
         m_clconn1_critsect_enter( aclconn1 );
       }
       icl_receive--;                       /* reset receive status    */
       if (boplock) {
         m_clconn1_critsect_leave( aclconn1 );
       }
     }

     inline BOOL checkrec() {
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "cl_tcp_r <%p> ::checkrec() %d", this, icl_receive );
#endif
       return (BOOL) icl_receive;           /* return what set         */
     }

     inline BOOL getstc() {                 /* get status connection   */
#ifdef TEST050130
       /* added 30.01.05 KB */
       if (boc_recv_close) return FALSE;    /* received close          */
#endif
// 15.08.10 KB remove boTCPIPconn and use imc_conn_state
//     return boTCPIPconn;                  /* TCP/IP connection stat  */
#ifdef B140131
       return (imc_conn_state == -1);       /* state of the connection */
#else
       return this->boc_tcpc_act;           /* TCPCOMP active          */
#endif
     }

     inline BOOL getstr() {                 /* get status receive      */
       return (icl_receive != 0);           /* return receive status   */
     }

#ifdef OLD_120121_01
     inline BOOL getrecthr() {              /* get status rec-thread   */
       if (hws2mod == NULL) {               /* normal thread receive   */
         return (icl_receive != 0);         /* return receive status   */
       } else {
         return boc_recthr;                 /* return rec thr status   */
       }
     }
#endif

     inline void set_error_rec() {          /* set receive error       */
       bo_error_rec = TRUE;                 /* set status flag         */
     }

     inline BOOL get_error_rec() {          /* get status error rec    */
       return bo_error_rec;                 /* return error status     */
     }

#ifdef B131117
     inline void close1() {                 /* close part one          */
       int rc_sock;
       BOOL bol1;
#ifdef TRACEHLX
       BOOL boh1 = FALSE;
       int ihsavesocket = iclsocket;
#endif
#ifdef TRACEHLD
       m_hlnew_printf( HLOG_XYZ1, "cl_tcp_r::close1() socket=%d boTCPIPconn=%d boc_recthr=%d icl_receive=%d im_may_recv=%08X",
                       iclsocket, boTCPIPconn, boc_recthr, icl_receive, im_may_recv );
#endif
#ifdef PROB_061016                          /* timed out sessions do not close */
       m_hlnew_printf( HLOG_XYZ1, "l%05d cl_tcp_r::close1() socket=%d boTCPIPconn=%d boc_recthr=%d icl_receive=%d im_may_recv=%08X",
                       __LINE__, iclsocket, boTCPIPconn, boc_recthr, icl_receive, im_may_recv );
#endif  /* PROB_061016                         timed out sessions do not close */
// 15.08.10 KB remove boTCPIPconn and use imc_conn_state
#ifdef B100827
       if (boTCPIPconn) {                   /* TCP/IP connection       */
         boTCPIPconn = FALSE;               /* TCP/IP connection stat  */
#ifdef FORKEDIT
       }
#endif
#endif
       if (imc_conn_state == -1) {          /* state of the connection connected */
         imc_conn_state = -2;               /* state of the connection no more connected */
#ifdef TRY_090617
         IP_closesocket( iclsocket );
#endif
#ifdef TRACEHL5
         m_hlnew_printf( HLOG_XYZ1, "IP_shutdown socket %d", iclsocket );
#endif
#ifdef PROB_061016                          /* timed out sessions do not close */
         m_hlnew_printf( HLOG_XYZ1, "l%05d IP_shutdown socket %d", __LINE__, iclsocket );
#endif  /* PROB_061016                         timed out sessions do not close */
#ifndef B080407
#ifdef B090623
         dsc_tcpco1.m_end_session();        /* close TCP session       */
#else
         if (boc_tcpc_act) {                /* TCPCOMP active          */
#ifdef TRACE_090506
           m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T close1 clconn1=%p SNO=%08d this=%p &dsc_tcpco1=%p.",
                           __LINE__, aclconn1, m_clconn1_sno( aclconn1 ), this, &dsc_tcpco1 );
#endif
           dsc_tcpco1.m_end_session();      /* close TCP session       */
         }
#endif
#endif
#ifdef B080407
         rc_sock = IP_shutdown( iclsocket, 2 );
         if (rc_sock != 0) {
#ifdef TRACEHLX
           boh1 = TRUE;
#endif
           if (cl_tcp_r::hws2mod != NULL) {  /* functions loaded       */
             rc_sock = cl_tcp_r::afunc_wsaglerr();  /* get error code  */
           }
           m_hlnew_printf( HLOG_XYZ1, "shutdown() socket=%d Error %d", iclsocket, rc_sock );
         }
#ifdef TRACEHLA
         m_hlnew_printf( HLOG_XYZ1, "IP_closesocket %d", iclsocket );
#endif
#ifdef PROB_061016                          /* timed out sessions do not close */
         m_hlnew_printf( HLOG_XYZ1, "l%05d IP_closesocket %d", __LINE__, iclsocket );
#endif  /* PROB_061016                         timed out sessions do not close */
         rc_sock = IP_closesocket( iclsocket );
         if (rc_sock != 0) {
#ifdef TRACEHLX
           boh1 = TRUE;
#endif
           if (cl_tcp_r::hws2mod != NULL) {  /* functions loaded       */
             rc_sock = cl_tcp_r::afunc_wsaglerr();  /* get error code  */
           }
           m_hlnew_printf( HLOG_XYZ1, "closesocket() socket=%d Error %d", iclsocket, rc_sock );
         }
#ifdef PROB_061016                          /* timed out sessions do not close */
         m_hlnew_printf( HLOG_XYZ1, "l%05d after IP_closesocket %d boc_recthr=%d",
                         __LINE__, iclsocket, boc_recthr );
#endif  /* PROB_061016                         timed out sessions do not close */
         if (   (cl_tcp_r::hws2mod != NULL)  /* functions loaded       */
             && (boc_recthr)) {
#ifdef PROB_061016                          /* timed out sessions do not close */
           m_hlnew_printf( HLOG_XYZ1, "l%05d afunc_wsa_set_event", __LINE__ );
#endif  /* PROB_061016                         timed out sessions do not close */
           bol1 = cl_tcp_r::afunc_wsa_set_event( dclevent );
           if (bol1 == FALSE) {
             m_hlnew_printf( HLOG_XYZ1, "WSASetEvent() socket=%d Error %d",
                             iclsocket, cl_tcp_r::afunc_wsaglerr() );
           }
         }
#endif
       }
#ifdef TRACEHLX
       if (boh1) {                          /* error occured           */
         m_hlnew_printf( HLOG_XYZ1, "close1 %p clconn1=%p error socket=%d sock-save=%d",
                     this, aclconn1, iclsocket, ihsavesocket );
       }
#endif
#ifdef PROB_061016                          /* timed out sessions do not close */
       m_hlnew_printf( HLOG_XYZ1, "l%05d close1() returns", __LINE__ );
#endif  /* PROB_061016                         timed out sessions do not close */
     }
#endif
#ifndef B131117
// to-do 17.11.13 KB - better solution with post like in Unix - name m_close_1()
     inline void close1() {                 /* close TCP connection    */
#ifdef TRACEHLD
       m_hlnew_printf( HLOG_TRACE1, "cl_tcp_r::close1() socket=%d boTCPIPconn=%d boc_recthr=%d icl_receive=%d im_may_recv=%08X",
                       iclsocket, boTCPIPconn, boc_recthr, icl_receive, im_may_recv );
#endif
#ifdef PROB_061016                          /* timed out sessions do not close */
       m_hlnew_printf( HLOG_TRACE1, "l%05d cl_tcp_r::close1() socket=%d boTCPIPconn=%d boc_recthr=%d icl_receive=%d im_may_recv=%08X",
                       __LINE__, iclsocket, boTCPIPconn, boc_recthr, icl_receive, im_may_recv );
#endif  /* PROB_061016                         timed out sessions do not close */
// 15.08.10 KB remove boTCPIPconn and use imc_conn_state
#ifdef B140924
       if (imc_conn_state == -1) {          /* state of the connection connected */
#ifdef FORKEDIT
       }
#endif
#else
       if (imc_conn_state >= -1) {          /* state of the connection connected */
#endif
         imc_conn_state = -2;               /* state of the connection no more connected */
         if (boc_tcpc_act) {                /* TCPCOMP active          */
#ifdef TRACE_090506
           m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T close1 clconn1=%p SNO=%08d this=%p &dsc_tcpco1=%p.",
                           __LINE__, aclconn1, m_clconn1_sno( aclconn1 ), this, &dsc_tcpco1 );
#endif
           dsc_tcpco1.m_end_session();      /* close TCP session       */
         }
       }
     }
#endif

     inline int m_get_socket( void ) {      /* retrieve the TCP socket */
       return dsc_tcpco1.mc_getsocket();
     } /* end m_get_socket()                                           */

     inline void mc_naeg1_disa( BOOL bop_naeg1_disa ) {  /* disable naegle algorithm */
       if (bop_naeg1_disa == this->boc_naeg1_disa) return;
       this->boc_naeg1_disa = bop_naeg1_disa;
       dsc_tcpco1.mc_set_nodelay( (int) this->boc_naeg1_disa );
     } /* end mc_naeg1_disa()                                          */
};

enum ied_servcotype_def {                   /* type of server connection */
   ied_servcotype_none = 0,                 /* no server connection    */
   ied_servcotype_ended,                    /* server connection ended */
   ied_servcotype_normal_tcp,               /* normal TCP              */
   ied_servcotype_htun,                     /* HTUN                    */
   ied_servcotype_l2tp                      /* L2TP                    */
};

class clconn1 {                             /* active connection       */
#ifdef B080407
   private:
     class clconn1 *next;                   /* chain for connections   */
#endif
   public:
     struct dsd_co_sort dsc_co_sort;        /* for connection sort    */
     struct dsd_gate_1 *adsc_gate1;         /* which gateway           */
     struct dsd_gate_listen_1 *adsc_gate_listen_1;  /* listen part of gateway */
     struct dsd_server_conf_1 *adsc_server_conf_1;  /* configuration server */
#ifdef B080924
     struct dsd_send_server_1 *adsc_send_server_1_ch;  /* chain for send to server */
#endif
     class dsd_lbal_gw_1 *adsc_lbal_gw_1;   /* class load balancing GW */
#ifdef OLD_1112
     class dsd_radius_query *adsc_radqu;    /* class Radius Query      */
#else
     struct dsd_wsp_auth_1 *adsc_wsp_auth_1;  /* structure for authentication */
#endif
     struct dsd_int_webso_conn_1 *adsc_int_webso_conn_1;  /* connect for WebSocket applications - internal */
     struct dsd_conn_pttd_thr *adsc_cpttdt;  /* connect PTTD thread    */
     struct dsd_wts_udp_1 *adsc_wtsudp1;    /* WTS UDP                 */
#ifdef WORK051119
     class cl_wsat1 *dcl_wsat1_1;           /* class authentication    */
#endif
     enum ied_servcotype_def iec_servcotype;  /* type of server connection */
     class cl_tcp_r dcl_tcp_r_c;            /* class to receive client */
     union {
       struct {                             /* for TCPCOMP             */
         class cl_tcp_r dcl_tcp_r_s;        /* class to receive server */
#ifdef B120821
         struct dsd_netw_post_1 dsc_netw_post_1;  /* structure to post from network callback */
#endif
       };
#ifdef D_INCL_HOB_TUN
       struct {                             /* for HOB-TUN             */
         volatile dsd_htun_h dsc_htun_h;    /* handle for HOB-TUN      */
         struct dsd_tun_contr_conn dsc_tun_contr_conn;  /* HOB-TUN control area connection */
         struct sockaddr_storage dsc_soa_htcp_server;  /* address information for connected */
         struct dsd_sdh_control_1 *adsc_sdhc1_htun_sch;  /* chain of buffers to send over HOB-TUN */
         int    imc_send_window;            /* number of bytes to be sent */
         int    imc_ppp_state;              /* PPP state               */
         struct dsd_netw_post_1 *adsc_ppp_netw_post_1;  /* structure to post from network callback */
       };
#endif
       struct {                             /* for L2TP                */
         struct dsd_l2tp_session dsc_l2tp_session;  /* L2TP connection session */
         struct dsd_sdh_control_1 *adsc_sdhc1_l2tp_sch;  /* chain of buffers to send over L2TP */
       };
     };
     CRITICAL_SECTION d_act_critsect;       /* critical section act    */
     struct dsd_hl_ssl_s_3 dsc_hlse03s;     /* structure for SSL       */
     struct dsd_timer_ele dsc_timer;        /* timer for wait          */
     int      imc_timeout_set;              /* timeout set in seconds  */
     HL_LONGLONG ilc_timeout;               /* save end-time timeout   */
     struct dsd_auxf_1 *adsc_aux_timer_ch;  /* chain auxiliary timer   */
     struct dsd_auxf_1 *adsc_aux_ldap;      /* auxiliary LDAP field    */
     struct dsd_ineta_raws_1 *adsc_ineta_raws_1;  /* INETA in use      */
#ifndef HL_IPV6
     char     chrc_ineta[16];               /* internet-address char   */
#else
     char     chrc_ineta[ LEN_DISP_INETA ];  /* internet-address char  */
#endif
     char     chrc_priv[ (DEF_PERS_PRIV_LEN + 8 - 1) / 8 ];  /* privileges */
     union {
       struct dsd_sdh_session_1 dsc_sdh_s_1;  /* work area server data hook per session */
       struct dsd_sdh_session_1 *adsrc_sdh_s_1;   /* array work area server data hook per session */
     };
//   void **  avprc_sdh;                    /* address array serv-d-ho */
     struct dsd_auxf_1 *adsc_auxf_1;        /* chain auxiliary ext fields */
     struct dsd_sdh_control_1 *adsc_sdhc1_frcl;  /* chain of buffers from client (SSL encrypted) */
     struct dsd_sdh_control_1 *adsc_sdhc1_chain;  /* chain of buffers input output */
     struct dsd_sdh_control_1 *adsc_sdhc1_inuse;  /* chain of buffers in use */
     struct dsd_sdh_control_1 *adsc_sdhc1_extra;  /* chain of buffers extra */
     struct dsd_csssl_oper_1 *adsc_csssl_oper_1;  /* operation of client-side SSL */
     struct dsd_user_group *adsc_user_group;  /* structure user group  */
     struct dsd_user_entry *adsc_user_entry;  /* structure user entry  */
     struct dsd_radius_group *adsc_radius_group;  /* active Radius group */
     struct dsd_krb5_kdc_1 *adsc_krb5_kdc_1;  /* active Kerberos 5 KDC */
     struct dsd_ldap_group *adsc_ldap_group;  /* active LDAP group     */
#ifdef INCL_TEST_RPC
     struct dsd_rpc_group *adsc_rpc_group;  /* active RPC group        */
#endif
     struct dsd_pd_http_ctrl *adsc_pd_http_ctrl;  /* process data HTTP control */
     struct dsd_util_thread_ctrl *adsc_util_thread_ctrl;  /* utility thread control */
#ifdef B100702
     UNSIG_MED umc_ineta_ppp_ipv4;          /* INETA PPP IPV4          */
     UNSIG_MED umc_ineta_appl_ipv4;         /* INETA appl IPV4         */
#endif
#ifdef TRACEHL_P_COUNT
     int      inc_aux_mem_cur;              /* current memory size     */
     int      inc_aux_mem_max;              /* maximum memory size     */
#endif
     enum     ied_state_server {
       ied_ses_reset,
       ied_ses_auth,                        /* status authentication   */
       ied_ses_do_lbal,                     /* status do load-balancing */
       ied_ses_prep_server,                 /* prepare connect to server */
       ied_ses_wait_conn_s_static,          /* wait for static connect to server */
       ied_ses_wait_conn_s_dynamic,         /* wait for dynamic connect to server */
#ifdef XYZ1
       ied_ses_wait_conn_s_pttd,            /* wait for connect to server, pass-thru-to-desktop */
#endif
       ied_ses_do_cpttdt,                   /* connect pass thru to desktop */
#ifdef B101125
       ied_ses_compl_cpttdt,                /* connect pass thru to desktop completed */
#endif
       ied_ses_start_server_1,              /* start connection to server part one */
#ifdef X101214_XX
       ied_ses_start_dyn_serv_1,            /* start connection to server part one dynamic */
#endif
       ied_ses_wait_csssl,                  /* wait for client-side SSL */
#ifdef X101214_XX
       ied_ses_wait_dyn_csssl,              /* wait for client-side SSL dynamic connect */
#endif
       ied_ses_start_server_2,              /* start connection to server part two */
#ifdef X101214_XX
       ied_ses_start_dyn_serv_2,            /* start connection to server part two dynamic */
#endif
       ied_ses_start_sdh,                   /* start Server-Data-Hooks */
       ied_ses_conn,                        /* server is connected     */
       ied_ses_error_conn,                  /* error connect to server */
       ied_ses_error_co_dyn,                /* error connect to server dynamic */
#ifdef B130909
       ied_ses_close,                       /* close is active         */
#endif
#ifndef B130813
       ied_ses_rec_close,                   /* received close          */
#endif
       ied_ses_abend                        /* abnormal end of session */
     };
     enum ied_state_server iec_st_ses;      /* status server           */
#ifndef B090419
     enum     ied_state_client {
       ied_cls_normal,                      /* normal processing       */
       ied_cls_wait_start,                  /* wait for start message  */
       ied_cls_start_02,                    /* process start messages  */
       ied_cls_proc_ssl,                    /* process data as SSL input */
       ied_cls_normal_http,                 /* process normal HTTP     */
       ied_cls_closed                       /* client connection closed */
     };
     enum ied_state_client iec_st_cls;      /* status client           */
#endif
     BOOL     boc_st_act;                   /* util-thread active      */
     BOOL bo_st_open;                       /* connection open         */
     BOOL     boc_st_sslc;                  /* ssl handshake complete  */
#ifndef B101214
     BOOL     boc_sdh_started;              /* Server-Data-Hooks have been started */
#endif
#ifndef B130314
     BOOL     boc_signal_set;               /* signal for component set */
#endif
#ifdef B060325
     BOOL bo_no_timeout;                    /* do not timeout          */
#endif
#ifdef B120211
     BOOL     boc_hunt_end;                 /* do hunt end             */
#endif
     BOOL     boc_exa_so_01;                /* set if display to come  */
     BOOL     boc_survive;                  /* survive E-O-F client    */
     int      imc_trace_level;              /* trace level set         */
#ifdef D_INCL_HOB_TUN
     int      imc_references;               /* references to this session */
#endif
#ifdef B060628
#ifdef B060415
     class clworkth *adsc_workth;           /* this thread works       */
#endif
#else
#ifdef B060415
     struct dsd_hco_wothr *adsc_hco_wothr;  /* this thread works       */
#endif
#endif
     struct dsd_aux_cf1 *adsc_aux_cf1_cur;  /* current auxiliary control structure */

     char     *achc_reason_end;             /* reason end session      */
     struct dsd_sdh_control_1 *adsc_sdhc1_c1;  /* receive buffer client 1 */
     struct dsd_sdh_control_1 *adsc_sdhc1_c2;  /* receive buffer client 2 */
     struct dsd_sdh_control_1 *adsc_sdhc1_s1;  /* receive buffer server 1 */
     struct dsd_sdh_control_1 *adsc_sdhc1_s2;  /* receive buffer server 2 */
//   int      inc_session_no;               /* session number          */
     int      imc_time_start;               /* time session started    */
     int      inc_c_ns_rece_c;              /* count receive client    */
     int      inc_c_ns_send_c;              /* count send client       */
     int      inc_c_ns_rece_s;              /* count receive server    */
     int      inc_c_ns_send_s;              /* count send server       */
     int      inc_c_ns_rece_e;              /* count encrypted from cl */
     int      inc_c_ns_send_e;              /* count encrypted to clie */
     LONGLONG ilc_d_ns_rece_c;              /* data receive client     */
     LONGLONG ilc_d_ns_send_c;              /* data send client        */
     LONGLONG ilc_d_ns_rece_s;              /* data receive server     */
     LONGLONG ilc_d_ns_send_s;              /* data send server        */
     LONGLONG ilc_d_ns_rece_e;              /* data receive encyrpted  */
     LONGLONG ilc_d_ns_send_e;              /* data send encrypted     */
     char     chrc_server_error[ LEN_SERVER_ERROR ];  /* display server error */
#ifdef TRACE_HL_SESS_01
     int  i_last_action;                    /* last action             */
     int  i_prev_action;                    /* previous action         */
#define DEF_LEN_LAST_ACTION 64
     int  ir_last_action[ DEF_LEN_LAST_ACTION ];
#endif  /* TRACE_HL_SESS_01 */
#ifdef TRACEHLC
     int  im_check_no;
#define DEF_CHECK_ACLCONN1_NO 129
#endif
#ifdef EXAMINE_SIGN_ON_01                   /* 10.08.11 KB examine sign on time */
     LARGE_INTEGER ilc_exa_so_01;           /* time at accept          */
#endif

     /* constructor                                                    */
#ifndef B080407
     inline clconn1( struct dsd_gate_1 *,
                     struct dsd_gate_listen_1 *,
                     struct sockaddr *, int, int,
                     int );
#endif
#ifdef B080407
     inline clconn1( struct dsd_gate_1 *,
#ifndef HL_IPV6
                     struct sockaddr_in *,
#else
                     union un_soaddr_1 *,
                     int,
#endif
                     int, int );
#endif

     /* connect to server                                              */
#ifdef OLD_1112
#ifndef B060628
#ifdef B060415
     inline int conn_server( struct dsd_hco_wothr *, UNSIG_MED, int );
#endif
     inline int conn_server( struct dsd_aux_cf1 *, UNSIG_MED, int );
#else
     inline int conn_server( class clworkth *, UNSIG_MED, int );
#endif
#endif
#ifndef OLD_1112
     inline int mc_conn_server( struct dsd_aux_cf1 *, struct sockaddr * );
#endif

     /* receive complete                                               */
     inline BOOL rec_complete( class cl_tcp_r *, struct dsd_sdh_control_1 *, int );

#ifndef TRACEHLD
     inline void m_proc_data( struct dsd_hco_wothr * );  /* process data */
#else
     inline void m_proc_data( struct dsd_hco_wothr *, int *, int * );  /* process data */
#endif

     inline void m_start_rec_server( struct dsd_pd_work * );  /* start receiving server */

#ifdef TRACEHL_T_050131
     inline void m_chain_sdhc1( void );     /* display chain           */
#endif
#ifdef OLD_1112
     inline void proc_UDP( void );          /* process UDP             */
#endif

#ifdef B080407
     inline class clconn1 * getnext( void ) {  /* get next in chain    */
       return next;
     }
#endif

     inline void m_end_server( void );      /* the server has ended    */

     /* cleanup all resources at shutdown of class instance            */
     inline void cleanup( struct dsd_pd_work * );  /* cleanup          */

     inline void close1( struct dsd_pd_work *adsp_pd_work ) {  /* close everything */
       int    iml1, iml2, iml3, iml4, iml5;  /* working variables      */
       BOOL   bol1;                         /* working variable        */
       char   *achl1, *achl2;               /* working variables       */
       struct dsd_recudp1 *adsl_recudp1_w1;  /* chain of data received */
       class clconn1 *auconn11;             /* position in chain       */
       class clconn1 *auconn12;             /* position in chain       */
       struct dsd_auxf_1 *adsl_auxf_1_1;    /* auxiliary extension field */
       struct dsd_auxf_1 *adsl_auxf_1_w2;   /* auxiliary extension field */
       struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* chain of buffers   */
       struct dsd_sdh_control_1 **aadsl_sdhc1_adr;  /* address chain of buffers */
       struct dsd_hco_wothr *adsl_workth_1;  /* working variable       */
       struct dsd_bgt_contr_1 *adsl_bgt_contr_1;  /* definition background-task control */
       struct dsd_bgt_function_1 *adsl_bgt_function_1;  /* chain background-task functions */
       struct dsd_wsp_trace_1 *adsl_wt1_w1;  /* WSP trace control record */
       char   *achl_avl_error;              /* error code AVL tree     */
#ifndef B170127
       struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* configuration server temporary */
#endif
       struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
#ifdef D_INCL_HOB_TUN
       struct dsd_ineta_raws_1 *adsl_ineta_raws_1_w1;
       struct dsd_netw_post_1 dsl_netw_post_1;  /* structure to post from network callback */
#endif
       int    iml_c_udp_rece;               /* count receive UDP       */
       int    iml_c_udp_send;               /* count send UDP          */
       LONGLONG ill_d_udp_rece;             /* data receive UDP        */
       LONGLONG ill_d_udp_send;             /* data send UDP           */
#ifdef XYZ1
       struct dsd_aux_cf1 dsl_aux_cf1;      /* auxiliary control structure */
#endif
       struct dsd_bgt_call_1 dsl_bgt_call_1;  /* Background-Task Call  */
       char   chrl_ns_1[320];               /* for network-statistic   */
       char   chrl_ns_num[16];              /* for number              */

#define ADSL_AUX_CF1 (&adsp_pd_work->dsc_aux_cf1)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#ifdef TRACEHL1
       int iu1 = 0;
       if (   (iec_st_ses == ied_ses_conn)  /* status server           */
           && (iec_servcotype == ied_servcotype_normal_tcp)) {  /* normal TCP */
         iu1 = dcl_tcp_r_s.iclsocket;
       }
       m_hlnew_printf( HLOG_XYZ1, "IBIPGW08 l%05d destructor clconn1() close1 step 1 / dhlse02.inc_return = %d / so_cl = %d / so_se = %d",
                       __LINE__, dsc_hlse03s.inc_return, dcl_tcp_r_c.iclsocket, iu1 );
#endif
#ifdef DEBUG_140118_01                      /* load-balancing problem  */
       m_hlnew_printf( HLOG_TRACE1, "::close1() start - l%05d ADSL_CONN1_G=%p ADSL_CONN1_G->adsc_wtsudp1=%p.",
                       __LINE__, ADSL_CONN1_G, ADSL_CONN1_G->adsc_wtsudp1 );
#endif
       bo_st_open = FALSE;                  /* connection not open     */
#ifndef B140213
       if (dsc_timer.vpc_chain_2) {         /* timer still set         */
         m_time_rel( &dsc_timer );          /* release timer           */
       }
       if (this->adsc_cpttdt) {             /* connect PTTD thread     */
         this->adsc_cpttdt->adsc_conn1 = NULL;  /* no more connected   */
       }
#endif
#ifdef WAS_BEFORE_1501
#ifndef B140621
       /* check if SDH reload active                                   */
       do {                                 /* loop for multiple entries SDH reload */
         adsl_auxf_1_1 = this->adsc_auxf_1;  /* get chain auxiliary ext fields */
         while (adsl_auxf_1_1) {            /* loop over all entries   */
           if (adsl_auxf_1_1->iec_auxf_def == ied_auxf_sdh_reload) {  /* SDH reload */
             m_sdh_reload_old_end( ADSL_AUX_CF1, adsl_auxf_1_1 );
             break;
           }
           adsl_auxf_1_1 = adsl_auxf_1_1->adsc_next;  /* get next in chain */
         }
       } while (adsl_auxf_1_1);
#endif
#endif
       /* check if SDH reload active                                   */
       adsl_auxf_1_1 = this->adsc_auxf_1;   /* get chain auxiliary ext fields */
       while (adsl_auxf_1_1) {              /* loop over all entries   */
         if (adsl_auxf_1_1->iec_auxf_def == ied_auxf_sdh_reload) {  /* SDH reload */
           m_sdh_reload_old_end( ADSL_AUX_CF1, adsl_auxf_1_1 );
         }
         adsl_auxf_1_1 = adsl_auxf_1_1->adsc_next;  /* get next in chain */
       }
// to-do 24.08.10 KB - use newer mechanism with post
       iml1 = 0;                            /* clear count loop        */
       while (dcl_tcp_r_c.m_check_send_act()) {  /* still data to send */
         iml1++;                            /* increment count loop    */
#ifdef TRACEHL1
         m_hlnew_printf( HLOG_TRACE1, "IBIPGW08 l%05d destructor clconn1() close1 client still data to send",
                         __LINE__, iml1 );
         m_console_out( (char *) &dcl_tcp_r_c, sizeof(class cl_tcp_r) );
#endif
/* added 25.01.07 KB */
         if (iml1 >= 10) break;
         Sleep( 500 );
       }
       dcl_tcp_r_c.close1();                /* class to receive client */
       if (ADSL_CONN1_G->adsc_csssl_oper_1) {  /* with client-side SSL */
         m_pd_close_cs_ssl( adsp_pd_work );
       }
       aadsl_sdhc1_adr = NULL;              /* address chain of buffers */
#ifdef B140314
       if (iec_st_ses == ied_ses_conn) {    /* status server           */
#endif
         switch (iec_servcotype) {          /* type of server connection */
           case ied_servcotype_normal_tcp:  /* normal TCP              */
             iml1 = 0;                      /* clear count loop        */
             while (dcl_tcp_r_s.m_check_send_act()) {  /* still data to send */
               iml1++;                      /* increment count loop    */
#ifdef TRACEHL1
               m_hlnew_printf( HLOG_XYZ1, "IBIPGW08 l%05d destructor clconn1() close1 server still data to send",
                               __LINE__, iml1 );
               m_console_out( (char *) &dcl_tcp_r_s, sizeof(class cl_tcp_r) );
#endif
               if (iml1 >= 10) break;       /* do not wait any longer  */
               Sleep( 500 );
             }
             dcl_tcp_r_s.close1();          /* class to receive server */
             aadsl_sdhc1_adr = (struct dsd_sdh_control_1 **) &dcl_tcp_r_s.adsc_sdhc1_send;  /* address chain of buffers */
             break;
#ifdef D_INCL_HOB_TUN
           case ied_servcotype_htun:        /* HOB-TUN                 */
// abend adsc_ineta_raws_1 == 0 12.03.12
#ifndef B120313
             if (adsc_ineta_raws_1 == NULL) break;
#endif
             memset( &dsl_netw_post_1, 0, sizeof(struct dsd_netw_post_1) );  /* structure to post from network callback */
             dsl_netw_post_1.adsc_event = &ADSL_AUX_CF1->adsc_hco_wothr->dsc_event;  /* event to be posted */
             dsl_netw_post_1.imc_select = DEF_NETW_POST_1_HTUN_SESS_END;  /* posted for HTUN HTCP session end */
             adsc_ineta_raws_1->adsc_netw_post_1 = &dsl_netw_post_1;  /* structure to post from network callback */
             if (adsc_ineta_raws_1->imc_state
                   & (DEF_STATE_HTUN_SESS_END  /* done HOB-TUN HTCP session end */
                        | DEF_STATE_HTUN_ERR_SESS_END)) {  /* done HOB-TUN HTCP session end was with error */
               dsl_netw_post_1.boc_posted = TRUE;  /* as if event has been posted */
             }
#ifndef NEW_HOB_TUN_1103
             m_htun_sess_close( adsc_ineta_raws_1->dsc_htun_h );
#else
             m_htun_sess_close( dsc_htun_h );
#endif
             while (dsl_netw_post_1.boc_posted == FALSE) {  /* event has not been posted */
               m_hco_wothr_wait( ADSL_AUX_CF1->adsc_hco_wothr );  /* wait for an event */
             }
             aadsl_sdhc1_adr = &adsc_sdhc1_htun_sch;  /* address chain of buffers */
             break;
#endif
           case ied_servcotype_l2tp:        /* L2TP                    */
#ifndef B130223
             m_l2tp_client_end( &this->dsc_l2tp_session );  /* call function of L2TP */
#endif
             m_l2tp_close( &dsc_l2tp_session );
             aadsl_sdhc1_adr = &adsc_sdhc1_l2tp_sch;  /* address chain of buffers */
             break;
         }
#ifdef B140314
       }
#endif
#ifdef TRACEHLC
       m_check_aclconn1( this, 180 );
#endif
#ifdef B060325
       if (dtime1_e.bo_timer_set) {         /* with timeout set        */
         sub_time_rel( this );              /* no more in chain        */
       }
#endif
#ifdef TRACEHLC
       m_check_aclconn1( this, 181 );
#endif
       if (adsc_wtsudp1) {                  /* WTS UDP active          */
#ifdef B060616
         if (adsc_wtsudp1->imc_udp_socket >= 0) {  /* socket open           */
           adsc_wtsudp1->boc_udp_close_active = TRUE;
           IP_closesocket( adsc_wtsudp1->imc_udp_socket );
           adsc_wtsudp1->imc_udp_socket = -1;
         }
#endif
#ifdef OLD_1112
         while (   (ADSL_CONN1_G->adsc_wtsudp1->boc_started == FALSE)  /* UDP not yet started */
                && (ADSL_CONN1_G->adsc_wtsudp1->boc_udp_closed == FALSE)) {  /* UDP socket not closed */
           Sleep( 500 );                    /* wait some time          */
         }
         if (adsc_wtsudp1->boc_udp_closed == FALSE) {  /* UDP socket not closed */
           adsc_wtsudp1->boc_udp_close_active = TRUE;
           IP_closesocket( adsc_wtsudp1->imc_udp_socket );
           adsc_wtsudp1->boc_udp_closed = TRUE;  /* UDP socket closed  */
         }
         while (adsc_wtsudp1->adsc_recudp1) {
           adsl_recudp1_w1 = adsc_wtsudp1->adsc_recudp1;  /* get first in chain  */
           adsc_wtsudp1->adsc_recudp1 = adsc_wtsudp1->adsc_recudp1->adsc_next;
           free( adsl_recudp1_w1 );
         }
#endif
// to-do 03.01.12 KB
       }
       cleanup( adsp_pd_work );
#ifdef TRACEHL6
       EnterCriticalSection( &adsc_gate1->dcritsect );
       adsc_gate1->i_session_cur++;         /* count later correct     */
       LeaveCriticalSection( &adsc_gate1->dcritsect );
       if (iec_st_ses != ied_ses_conn) {    /* status server           */
         m_hlnew_printf( HLOG_XYZ1, "Session-End iec_st_ses != ied_ses_conn / %d.", iec_st_ses );
       }
#endif
       EnterCriticalSection( &adsc_gate1->dcritsect );
       adsc_gate1->i_session_cur--;         /* count current session   */
       LeaveCriticalSection( &adsc_gate1->dcritsect );
#ifdef TRACEHLA
       m_hlnew_printf( HLOG_TRACE1, "--- connection ended auconn11 / this = %08X i_last_action = %d i_prev_action = %d",
                       this, i_last_action, i_prev_action );
#ifdef TRACEHL_ABEND
       bos_error = TRUE;                    /* do nothing more         */
       {
         int imh1, imh2, imh3;
         imh1 = 0;
         imh2 = imh1;
         imh3 = imh2;
         imh2 = 4;
         imh1 = imh2 / imh3;                /* divide by zero          */
//       printf( "abend %d\n", imh1 );
         *((void **) imh3) = 0;             /* access forbidden        */
       }
#endif
#endif
       achl1 = "logic-error";
       if (achc_reason_end) {               /* reason end session      */
         achl1 = achc_reason_end;           /* set text                */
       }
       achl2 = "";
       if (   (adsc_gate1->adsc_loconf_1->inc_network_stat)  /* give network statistic */
           || (imc_trace_level)) {
         iml2 = m_get_time() - imc_time_start;
         iml3 = iml2 / 3600;
         iml5 = iml2 - iml3 * 3600;
         iml4 = iml5 / 60;
         iml5 -= iml4 * 60;
         iml1 = sprintf( chrl_ns_1, " / duration: %d h %d min %d sec", iml3, iml4, iml5 );
         achl2 = m_edit_dec_int( chrl_ns_num, inc_c_ns_rece_c );
         iml1 += sprintf( chrl_ns_1 + iml1, " / client: rec %s", achl2 );
         achl2 = m_edit_dec_long( chrl_ns_num, ilc_d_ns_rece_c );
         iml1 += sprintf( chrl_ns_1 + iml1, " - %s bytes", achl2 );
         achl2 = m_edit_dec_int( chrl_ns_num, inc_c_ns_send_c );
         iml1 += sprintf( chrl_ns_1 + iml1, " + send %s", achl2 );
         achl2 = m_edit_dec_long( chrl_ns_num, ilc_d_ns_send_c );
         iml1 += sprintf( chrl_ns_1 + iml1, " - %s bytes", achl2 );
         achl2 = m_edit_dec_int( chrl_ns_num, inc_c_ns_rece_s );
         iml1 += sprintf( chrl_ns_1 + iml1, " / server: rec %s", achl2 );
         achl2 = m_edit_dec_long( chrl_ns_num, ilc_d_ns_rece_s );
         iml1 += sprintf( chrl_ns_1 + iml1, " - %s bytes", achl2 );
         achl2 = m_edit_dec_int( chrl_ns_num, inc_c_ns_send_s );
         iml1 += sprintf( chrl_ns_1 + iml1, " + send %s", achl2 );
         achl2 = m_edit_dec_long( chrl_ns_num, ilc_d_ns_send_s );
         iml1 += sprintf( chrl_ns_1 + iml1, " - %s bytes", achl2 );
         achl2 = m_edit_dec_int( chrl_ns_num, inc_c_ns_rece_e );
         iml1 += sprintf( chrl_ns_1 + iml1, " / encrypted: rec %s", achl2 );
         achl2 = m_edit_dec_long( chrl_ns_num, ilc_d_ns_rece_e );
         iml1 += sprintf( chrl_ns_1 + iml1, " - %s bytes", achl2 );
         achl2 = m_edit_dec_int( chrl_ns_num, inc_c_ns_send_e );
         iml1 += sprintf( chrl_ns_1 + iml1, " + send %s", achl2 );
         achl2 = m_edit_dec_long( chrl_ns_num, ilc_d_ns_send_e );
         iml1 += sprintf( chrl_ns_1 + iml1, " - %s bytes", achl2 );
         achl2 = "";
         if (adsc_gate1->adsc_loconf_1->inc_network_stat) {  /* give network statistic */
           achl2 = chrl_ns_1;
         }
       }
       m_hlnew_printf( HLOG_INFO1, "HWSPS004I GATE=%(ux)s SNO=%08d INETA=%s connection ended - %s%s",
                       adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, achl1, achl2 );
       if (imc_trace_level) {
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "SSESSEN1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_sno = dsc_co_sort.imc_sno;  /* WSP session number */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         iml1 = m_hlsnprintf( (char *) (ADSL_WTR_G1 + 1), 256, ied_chs_ansi_819,
                              "connection ended - %s%s",
                              achl1, chrl_ns_1 );
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed        */
         ADSL_WTR_G1->achc_content          /* content of text / data  */
           = (char *) (ADSL_WTR_G1 + 1);
         ADSL_WTR_G1->imc_length = iml1;    /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
       if (   (adsc_gate1->adsc_loconf_1->inc_network_stat >= 4)  /* give network statistic */
           || (imc_trace_level)) {
         adsl_auxf_1_1 = adsc_auxf_1;       /* get chain auxiliary ext field */
         while (adsl_auxf_1_1) {            /* loop over all entries   */
           if (adsl_auxf_1_1->iec_auxf_def == ied_auxf_gate_udp) {  /* UDP-gate entry */
             m_aux_gate_udp_counter( (char *) (adsl_auxf_1_1 + 1) + sizeof(struct dsd_auxf_ext_1),
                                     &iml_c_udp_rece,  /* count receive UDP */
                                     &iml_c_udp_send,  /* count send UDP */
                                     &ill_d_udp_rece,  /* data receive UDP */
                                     &ill_d_udp_send );  /* data send UDP */
             achl2 = m_edit_dec_long( chrl_ns_num, ill_d_udp_rece );
             iml1 = sprintf( chrl_ns_1, "received packets %d - %s bytes", iml_c_udp_rece, achl2 );
             achl2 = m_edit_dec_long( chrl_ns_num, ill_d_udp_send );
             iml1 += sprintf( chrl_ns_1 + iml1, " + sent packets %d - %s bytes", iml_c_udp_send, achl2 );
             if (adsc_gate1->adsc_loconf_1->inc_network_stat >= 4) {  /* give network statistic */
               m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnI GATE=%(ux)s SNO=%08d INETA=%s connection ended - UDP-gate %s",
                               adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, chrl_ns_1 );
             }
             if (imc_trace_level) {
               adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
               memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
               adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
               adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
               memcpy( adsl_wt1_w1->chrc_wtrt_id, "SSESSEN2", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
               adsl_wt1_w1->imc_wtrt_sno = dsc_co_sort.imc_sno;  /* WSP session number */
               adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id     */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
               iml1 = m_hlsnprintf( (char *) (ADSL_WTR_G1 + 1), 256, ied_chs_ansi_819,
                                    "connection ended - UDP-gate %s",
                                    chrl_ns_1 );
               ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed  */
               ADSL_WTR_G1->achc_content    /* content of text / data  */
                 = (char *) (ADSL_WTR_G1 + 1);
               ADSL_WTR_G1->imc_length = iml1;  /* length of text / data */
               adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
               m_wsp_trace_out( adsl_wt1_w1 );  /* output of WSP trace record */
             }
           }
           adsl_auxf_1_1 = adsl_auxf_1_1->adsc_next;  /* get next in chain */
         }
       }
       adsl_bgt_contr_1 = adsg_loconf_1_inuse->adsc_bgt_contr_1;  /* chain background-task control */
       while (adsl_bgt_contr_1) {           /* loop over background-tasks */
         adsl_bgt_function_1 = adsl_bgt_contr_1->adsc_bgt_function_1;  /* chain background-task functions */
         do {                               /* loop over background-task functions */
           if (adsl_bgt_function_1->iec_bgtf == ied_bgtf_end_session) {  /* called at end of session */
#ifdef XYZ1
             memset( &dsl_aux_cf1, 0, sizeof(struct dsd_aux_cf1) );  /* auxiliary control structure */
             dsl_aux_cf1.adsc_conn = this;  /* set connection          */
             dsl_aux_cf1.adsc_hco_wothr = adsp_hco_wothr;  /* pointer on work-thread */
             dsl_aux_cf1.iec_src_func = ied_src_fu_bgt_end_session;  /* background-task at end of session */
             this->adsc_aux_cf1_cur = &dsl_aux_cf1;  /* current auxiliary control structure */
#endif
#ifdef B130314
             adsp_pd_work->dsc_aux_cf1.iec_src_func = ied_src_fu_bgt_end_session;  /* background-task at end of session */
#endif
             adsp_pd_work->dsc_aux_cf1.dsc_cid.iec_src_func = ied_src_fu_bgt_end_session;  /* background-task at end of session */
             memset( &dsl_bgt_call_1, 0, sizeof(struct dsd_bgt_call_1) );  /* Background-Task Call */
             dsl_bgt_call_1.imc_func = DEF_IFUNC_CONT;  /* process data as specified */
             dsl_bgt_call_1.ac_conf = adsl_bgt_contr_1->ac_conf;  /* data from configuration */
#ifdef XYZ1
             dsl_bgt_call_1.vpc_userfld = &dsl_aux_cf1;  /* auxiliary control structure */
#endif
             dsl_bgt_call_1.vpc_userfld = &adsp_pd_work->dsc_aux_cf1;  /* auxiliary control structure */
             dsl_bgt_call_1.amc_aux = &m_cdaux;  /* subroutine         */
             dsl_bgt_call_1.adsc_bgt_function_1 = adsl_bgt_function_1;  /* called for background-task function */
             dsl_bgt_call_1.imc_sno = dsc_co_sort.imc_sno;  /* session number */
             adsl_bgt_contr_1->adsc_ext_lib1->amc_bgt_entry( &dsl_bgt_call_1 );
           }
           adsl_bgt_function_1 = adsl_bgt_function_1->adsc_next;  /* get next in chain */
         } while (adsl_bgt_function_1);
         adsl_bgt_contr_1 = adsl_bgt_contr_1->adsc_next;  /* get next in chain */
       }
#ifdef TRACEHLC
       m_check_aclconn1( this, 186 );
#endif
#ifdef OLD_120121_01
       iml1 = 4;                            /* set upper limit         */
       iml2 = 0;                            /* zero count              */
       while (dcl_tcp_r_c.getrecthr()) {
         iml2++;
         if (iml2 == iml1) {
           m_hlnew_printf( HLOG_WARN1, "HWSPS005W GATE=%(ux)s SNO=%08d INETA=%s client socket does not close",
                           adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta );
#ifdef TRACEHLD
           m_hlnew_printf( HLOG_XYZ1, "boTCPIPconn=%d boc_recthr=%d icl_receive=%d im_may_recv=%08X",
                           dcl_tcp_r_c.boTCPIPconn,
                           dcl_tcp_r_c.boc_recthr,
                           dcl_tcp_r_c.icl_receive,
                           dcl_tcp_r_c.im_may_recv );
#endif
           iml1 += iml1;                    /* double old value        */
           iml2 = 0;                        /* start counting new      */
         }
#ifdef B060628
         ADSL_AUX_CF1->adsc_workth->m_set_block();  /* mark thread blocking */
         Sleep( 200 );
         ADSL_AUX_CF1->adsc_workth->m_set_active();  /* mark thread active */
#endif
         m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
         Sleep( 200 );
         m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
       }
       if (   (iec_st_ses == ied_ses_conn)  /* status server           */
           && (iec_servcotype == ied_servcotype_normal_tcp)) {  /* normal TCP */
         iml1 = 4;                          /* set upper limit         */
         iml2 = 0;                          /* zero count              */
         while (dcl_tcp_r_s.getrecthr()) {
           iml2++;
           if (iml2 == iml1) {
             m_hlnew_printf( HLOG_WARN1, "HWSPS006W GATE=%(ux)s SNO=%08d INETA=%s server socket does not close",
                             adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta );
             iml1 += iml1;                  /* double old value        */
             iml2 = 0;                      /* start counting new      */
           }
           m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
           Sleep( 200 );
           m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
         }
       }
#endif
#ifdef B170127
#ifndef B060925
       if (adsc_server_conf_1) {            /* with server             */
#ifdef B101208
         if (adsc_server_conf_1->boc_dynamic) {  /* dynamicly allocated */
           free( adsc_server_conf_1 );      /* free server entry       */
         }
#else
         if (adsc_server_conf_1->adsc_seco1_previous) {  /* configuration server previous */
           free( adsc_server_conf_1 );      /* free server entry       */
         }
#endif
       }
#endif
#endif
#ifndef B170127
/**
 * change by Stefan Martin,
 * but should not have any effect
 * since the field this->adsc_server_conf_1
 * should no more get accessed.
 * SM161111_SSLERR
 */
       if (adsc_server_conf_1) {            /* with server             */
         if (adsc_server_conf_1->adsc_seco1_previous) {  /* configuration server previous */
           adsl_server_conf_1_w1 = this->adsc_server_conf_1;  /* configuration server temporary */
           this->adsc_server_conf_1 = adsl_server_conf_1_w1->adsc_seco1_previous;  /* insert default server entry */
           free( adsl_server_conf_1_w1 );   /* free server entry       */
         }
       }
#endif
       if (dsc_timer.vpc_chain_2) {         /* timer still set         */
         m_time_rel( &dsc_timer );          /* release timer           */
       }
       achl_avl_error = NULL;               /* clear error code AVL tree */
       EnterCriticalSection( &d_clconn_critsect );
       do {                                 /* pseudo-loop             */
         bol1 = m_htree1_avl_search( NULL, &dss_htree1_avl_cntl_conn,
                                     &dsl_htree1_work, &dsc_co_sort.dsc_sort_1 );
         if (bol1 == FALSE) {               /* error occured           */
           achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
           break;                           /* do not continue         */
         }
         if (dsl_htree1_work.adsc_found == NULL) {  /* not found in tree */
           achl_avl_error = "m_htree1_avl_search() session-id not found in tree";  /* error code AVL tree */
           break;                           /* do not continue         */
         }
         bol1 = m_htree1_avl_delete( NULL, &dss_htree1_avl_cntl_conn,
                                     &dsl_htree1_work );
         if (bol1 == FALSE) {               /* error occured           */
           achl_avl_error = "m_htree1_avl_delete() failed";  /* error code AVL tree */
           break;                           /* do not continue         */
         }
       } while (FALSE);
       LeaveCriticalSection( &d_clconn_critsect );
       if (achl_avl_error) {                    /* error occured           */
         m_hlnew_printf( HLOG_WARN1, "HWSPS111W GATE=%(ux)s SNO=%08d INETA=%s remove sno error %s",
                         adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, achl_avl_error );
       }
#ifdef TRACEHLC
       m_check_aclconn1( this, 187 );
#endif
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "destructor clconn1() step 2 / dhlse02.inc_return = %d",
                       dsc_hlse03s.inc_return );
#endif
       m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
       Sleep( 1000 );                       /* multi-threaded          */
       m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "destructor clconn1() step 3 / dhlse02.inc_return = %d",
                       dsc_hlse03s.inc_return );
#endif
#ifdef TRACEHLC
       m_check_aclconn1( this, 188 );
#endif
#ifdef B090617
       DeleteCriticalSection( &d_act_critsect );  /* critical section  */
#endif
       if (adsc_sdhc1_c1) m_proc_free( adsc_sdhc1_c1 );
       if (adsc_sdhc1_c2) m_proc_free( adsc_sdhc1_c2 );
       if (adsc_sdhc1_s1) m_proc_free( adsc_sdhc1_s1 );
       if (adsc_sdhc1_s2) m_proc_free( adsc_sdhc1_s2 );
       while (dcl_tcp_r_c.adsc_sdhc1_send) {  /* loop over all buffers */
         adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) dcl_tcp_r_c.adsc_sdhc1_send;  /* save this buffer */
         dcl_tcp_r_c.adsc_sdhc1_send = dcl_tcp_r_c.adsc_sdhc1_send->adsc_next;  /* get next in chain */
         m_proc_free( adsl_sdhc1_w1 );      /* free this buffer        */
       }
       if (aadsl_sdhc1_adr) {               /* address chain of buffers set */
         while (*aadsl_sdhc1_adr) {         /* loop over all buffers   */
           adsl_sdhc1_w1 = *aadsl_sdhc1_adr;  /* save this buffer      */
           *aadsl_sdhc1_adr = (*aadsl_sdhc1_adr)->adsc_next;  /* get next in chain */
           m_proc_free( adsl_sdhc1_w1 );    /* free this buffer        */
         }
       }
       if (this->adsc_wsp_auth_1) {         /* structure for authentication */
         m_auth_delete( adsp_pd_work, this->adsc_wsp_auth_1 );
#ifndef B120719
         this->adsc_wsp_auth_1 = NULL;
#endif
       }
       if (this->adsc_int_webso_conn_1) {   /* connect for WebSocket applications - internal */
         m_close_webso_conn( ADSL_AUX_CF1 );
       }
// to-do 03.02.14 KB
// possible memory-leak
// check fields of struct dsd_pd_work - struct dsd_sdh_control_1 *
//       m_auth_delete( adsp_pd_work, this->adsc_wsp_auth_1 );
// acquires work-area, this is not freed
// ADSL_AUX_CF1->adsc_sdhc1_chain
#ifdef DEBUG_140203_01                      /* memory-leak authentication-library m_auth_delete() */
       if (ADSL_AUX_CF1->adsc_sdhc1_chain) {
         m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W DEBUG_140203_01 possible memory-leak ADSL_AUX_CF1->adsc_sdhc1_chain=%p.",
                         __LINE__, ADSL_AUX_CF1->adsc_sdhc1_chain );
       }
#endif
       if (this->adsc_wtsudp1) {
#ifdef DEBUG_140118_01                      /* load-balancing problem  */
         m_hlnew_printf( HLOG_TRACE1, "::close1() free all - l%05d ADSL_CONN1_G=%p ADSL_CONN1_G->adsc_wtsudp1=%p &dsc_wln_ipv4.dsc_udp_multiw_1=%p dsc_wln_ipv6.dsc_udp_multiw_1=%p.",
                         __LINE__, ADSL_CONN1_G, ADSL_CONN1_G->adsc_wtsudp1,
                         &this->adsc_wtsudp1->dsc_wln_ipv4.dsc_udp_multiw_1, &this->adsc_wtsudp1->dsc_wln_ipv6.dsc_udp_multiw_1 );
#endif
         if (this->adsc_wtsudp1->dsc_wln_ipv4.adsc_wsp_udp_1) {  /* WTS UDP - also means in use */
           m_close_udp_multiw_1( &this->adsc_wtsudp1->dsc_wln_ipv4.dsc_udp_multiw_1 );  /* structure for multiple wait */
         }
         if (this->adsc_wtsudp1->dsc_wln_ipv6.adsc_wsp_udp_1) {  /* WTS UDP - also means in use */
           m_close_udp_multiw_1( &this->adsc_wtsudp1->dsc_wln_ipv6.dsc_udp_multiw_1 );  /* structure for multiple wait */
         }
         m_hco_wothr_blocking( ADSL_AUX_CF1->adsc_hco_wothr );  /* mark thread blocking */
         Sleep( 200 );
         m_hco_wothr_active( ADSL_AUX_CF1->adsc_hco_wothr, FALSE );  /* mark thread active */
         while (ADSL_CONN1_G->adsc_wtsudp1->adsc_sdhc1_rec) {  /* received UDP packets */
           adsl_sdhc1_w1 = ADSL_CONN1_G->adsc_wtsudp1->adsc_sdhc1_rec;  /* get first in chain */
           ADSL_CONN1_G->adsc_wtsudp1->adsc_sdhc1_rec = adsl_sdhc1_w1->adsc_next;  /* set new chain */
           m_proc_free( adsl_sdhc1_w1 );    /* free memory             */
         }
#ifdef DEBUG_140118_01                      /* load-balancing problem  */
         m_hlnew_printf( HLOG_TRACE1, "::close1() free memory - l%05d ADSL_CONN1_G=%p ADSL_CONN1_G->adsc_wtsudp1=%p.",
                         __LINE__, ADSL_CONN1_G, ADSL_CONN1_G->adsc_wtsudp1 );
#endif
         free( adsc_wtsudp1 );
       }
#ifdef B080924
       adsl_send_server_1_w1 = adsc_send_server_1_ch;  /* chain send server */
       while (adsl_send_server_1_w1) {      /* loop over all send server */
         m_htun_ppp_close( ((struct dsd_conn_hpppt1_ss *)
                             ((char *) adsl_send_server_1_w1
                               - offsetof( struct dsd_conn_hpppt1_ss, dsc_send_server_1 )))
                             ->dsc_tun_ppp_h );
         adsl_sdhc1_w1 = adsl_send_server_1_w1->adsc_sdhc1_send;  /* send buffers */
         while (adsl_send_server_1_w1->adsc_sdhc1_send) {  /* loop to free all send buffers */
           adsl_sdhc1_w1 = adsl_send_server_1_w1->adsc_sdhc1_send;  /* send buffers */
           adsl_send_server_1_w1->adsc_sdhc1_send = adsl_send_server_1_w1->adsc_sdhc1_send->adsc_next;
           m_proc_free( adsl_sdhc1_w1 );    /* free the buffer         */
         }
         adsl_send_server_1_w1 = adsl_send_server_1_w1->adsc_next;  /* get next in chain */
       }
#endif
/*
   to-do 21.06.14 KB
   call m_sdh_cleanup( ADSL_AUX_CF1, NULL );
*/
       while (this->adsc_auxf_1) {          /* chain auxiliary extension fields */
#ifdef TRACEHL_P_DISP
         m_hlnew_printf( HLOG_XYZ1, "chain auxiliary ext field not empty / addr=%p iec_auxf_def=%d",
                         adsc_auxf_1, adsc_auxf_1->iec_auxf_def );
#endif
#ifdef TRACEHL_081125
         m_hlnew_printf( HLOG_XYZ1, "TRACEHL_081125 close1() l%05d addr=%p iec_auxf_def=%d.",
                         __LINE__, adsc_auxf_1, adsc_auxf_1->iec_auxf_def );
#endif
         adsl_auxf_1_1 = adsc_auxf_1;       /* save old field          */
         adsc_auxf_1 = adsc_auxf_1->adsc_next;  /* get next in chain   */
         switch (adsl_auxf_1_1->iec_auxf_def) {
           case ied_auxf_defstor:           /* predefined storage      */
             m_proc_free( adsl_auxf_1_1 );  /* put in chain of unused  */
             adsl_auxf_1_1 = NULL;          /* no memory to free       */
             break;
           case ied_auxf_normstor:          /* normal storage          */
             break;                         /* free memory             */
           case ied_auxf_timer:             /* timer                   */
             break;                         /* free memory             */
           case ied_auxf_certname:          /* name from certificate = DN */
             break;                         /* free memory             */
           case ied_auxf_certificate:       /* certificate             */
             break;                         /* free memory             */
           case ied_auxf_radqu:             /* Radius query            */
#ifndef B141110
#ifndef XYZ1_XXX
#define ADSL_RC1 ((struct dsd_radius_control_1 *) (adsl_auxf_1_1 + 1))
             m_radius_cleanup( ADSL_RC1 );  /* Radius request no more needed */
#undef ADSL_RC1
#endif
#endif
             break;                         /* free memory             */
           case ied_auxf_ocsp:              /* OCSP entry              */
#ifdef TRACEHL_P_DISP
             m_hlnew_printf( HLOG_TRACE1, "chain auxiliary ext field OCSP found" );
#endif
             m_ocsp_cleanup( this, adsl_auxf_1_1 );
             break;
#ifdef B130911
           case ied_auxf_radqu:             /* Radius query            */
#ifdef OLD_1112
             m_radius_aux_delete( adsl_auxf_1_1 );
             adsl_auxf_1_1 = NULL;          /* no memory to free       */
#endif
#ifndef OLD_1112
// 08.02.12 KB m_radius_cleanup() not needed
#ifdef B120208
             m_radius_cleanup( (struct dsd_radius_control_1 *) (adsl_auxf_1_1 + 1) );
             adsl_auxf_1_1 = NULL;          /* no memory to free       */
#endif
#ifndef B141029
             m_radius_cleanup( (struct dsd_radius_control_1 *) (adsl_auxf_1_1 + 1) );
#endif
#endif
             break;
#endif
           case ied_auxf_diskfile:          /* link to disk file       */
             time( (time_t *) &(*((struct dsd_diskfile_1 **) (adsl_auxf_1_1 + 1)))->ipc_time_last_acc );  /* get current time */
             dss_critsect_aux.m_enter();
             (*((struct dsd_diskfile_1 **) (adsl_auxf_1_1 + 1)))->inc_usage_count--;  /* usage-count */
             dss_critsect_aux.m_leave();
             break;
           case ied_auxf_cma1:              /* common memory area      */
             /* activate all work threads that are waiting             */
#ifdef B060628
             while (((struct dsd_wsp_cma_lock_1 *) (adsl_auxf_1_1 + 1))->adsc_workth) {
               adsl_workth_1 = ((struct dsd_wsp_cma_lock_1 *) (adsl_auxf_1_1 + 1))->adsc_workth;
               ((struct dsd_wsp_cma_lock_1 *) (adsl_auxf_1_1 + 1))->adsc_workth
                 = (struct dsd_hco_wothr *) adsl_workth_1->vpc_lock_1;
               bol1 = SetEvent( adsl_workth_1->hevework );
               if (bol1 == FALSE) {
                 m_hlnew_printf( HLOG_XYZ1, "HWSPM060W clconn1::close1() SetEvent WORK Error %d",
                                 GetLastError() );
               }
             }
#endif
#ifdef B060709
             if (((struct dsd_wsp_cma_lock_1 *) (adsl_auxf_1_1 + 1))->adsc_hco_wothr) {
               m_hlnew_printf( HLOG_XYZ1, "HWSPM060W l%05d UUUU lock 28.06.06 KB",
                               __LINE__ );
             }
#endif
             m_hco_wothr_unlock( ADSL_AUX_CF1->adsc_hco_wothr,
                                 (struct dsd_hco_lock_1 *) (adsl_auxf_1_1 + 1) );
             break;
           case ied_auxf_q_gather:          /* query gather            */
             break;                         /* free memory             */
           case ied_auxf_sess_stor:         /* Session Storage         */
             break;                         /* free memory             */
           case ied_auxf_service_query_1:   /* service query 1         */
#ifdef B131224
             ((struct dsd_service_aux_1 *) ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_1 + 1)) + 1)->amc_service_close
                                            ( ADSL_AUX_CF1, (char *) (adsl_auxf_1_1 + 1) + sizeof(struct dsd_auxf_ext_1) );
#endif
             ((struct dsd_service_aux_1 *) ((char *) (adsl_auxf_1_1 + 1) + sizeof(struct dsd_auxf_ext_1)))->amc_service_close
                                            ( ADSL_AUX_CF1, (char *) (adsl_auxf_1_1 + 1) + sizeof(struct dsd_auxf_ext_1) );
             break;
           case ied_auxf_ldap:              /* LDAP service            */
             m_ldap_free( (class dsd_ldap_cl *) (adsl_auxf_1_1 + 1) );
             break;
           case ied_auxf_sip:               /* SIP request             */
             m_aux_sip_cleanup( this, (char *) (adsl_auxf_1_1 + 1) + sizeof(struct dsd_auxf_ext_1) );
             break;
           case ied_auxf_udp:               /* UDP request             */
             m_aux_udp_cleanup( this, (char *) (adsl_auxf_1_1 + 1) + sizeof(struct dsd_auxf_ext_1) );
             break;
           case ied_auxf_gate_udp:          /* UDP-gate entry          */
             m_aux_gate_udp_cleanup( this, (char *) (adsl_auxf_1_1 + 1) + sizeof(struct dsd_auxf_ext_1) );
             break;
           case ied_auxf_sessco1:           /* session configuration   */
             break;                         /* free memory             */
//         case ied_auxf_sessco1:           /* session configuration   */
//           break;
           case ied_auxf_admin:             /* admin command           */
             while (((struct dsd_auxf_admin1 *) ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_1 + 1) + 1))->adsc_sdhc1_1) {  /* buffers from previous calls */
               adsl_sdhc1_w1 = ((struct dsd_auxf_admin1 *) ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_1 + 1) + 1))->adsc_sdhc1_1;
               ((struct dsd_auxf_admin1 *) ((struct dsd_auxf_ext_1 *) (adsl_auxf_1_1 + 1) + 1))->adsc_sdhc1_1
                 = adsl_sdhc1_w1->adsc_next;  /* remove from chain     */
               m_proc_free( adsl_sdhc1_w1 );  /* free the buffer       */
             }
             break;
           case ied_auxf_ident:             /* ident - userid and user-group */
#ifdef B130808
             if (adsc_ineta_raws_1 == NULL) break;  /* auxiliary field for HOB-TUN */
// to-do 17.03.13 KB - other solution
             adsc_ineta_raws_1->adsc_auxf_1_ident = adsl_auxf_1_1;  /* store ident to free */
             adsl_auxf_1_1 = NULL;          /* do not free memory      */
#endif
             break;
           case ied_auxf_pipe_listen:       /* aux-pipe create with name */
             m_aux_pipe_listen_cleanup( this, adsl_auxf_1_1 );
             break;
           case ied_auxf_pipe_conn:         /* aux-pipe established connection */
             m_aux_pipe_conn_cleanup( this, adsl_auxf_1_1 );
             break;
           case ied_auxf_util_thread:       /* utility thread          */
#define ADSL_UTC_G ((struct dsd_util_thread_ctrl *) (adsl_auxf_1_1 + 1))
             /* set signal to terminate the utility thread             */
             ADSL_UTC_G->dsc_utp1.imc_signal |= HL_AUX_SIGNAL_CANCEL;
             dss_critsect_aux.m_enter();    /* critical section        */
             /* connection to session has ended                        */
             ADSL_UTC_G->dsc_ete.ac_conn1 = NULL;  /* clear connection */
             /* check if utility thread is still running               */
             if (ADSL_UTC_G->boc_thread_ended == FALSE) {  /* thread has not yet ended */
               /* utility thread will free all resources               */
               adsl_auxf_1_1 = NULL;        /* do not free memory now  */
             }
             dss_critsect_aux.m_leave();    /* critical section        */
             if (adsl_auxf_1_1) {           /* memory to free          */
               while (ADSL_UTC_G->adsc_auxf_1) {  /* chain auxiliary extension fields */
                 adsl_auxf_1_w2 = ADSL_UTC_G->adsc_auxf_1;  /* get first in chain auxiliary extension fields */
                 ADSL_UTC_G->adsc_auxf_1 = adsl_auxf_1_w2->adsc_next;  /* remove from chain */
                 if (adsl_auxf_1_w2->iec_auxf_def == ied_auxf_normstor) {  /* normal storage */
                   free( adsl_auxf_1_w2 );  /* free memory             */
                 } else {                   /* other type              */
                   m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s ied_auxf_util_thread l%05d cannot free resource %p iec_auxf_def %d.",
                                   this->adsc_gate1 + 1, this->dsc_co_sort.imc_sno, this->chrc_ineta,
                                   __LINE__, adsl_auxf_1_w2, adsl_auxf_1_w2->iec_auxf_def );
                 }
               }
             }
             break;
#undef ADSL_UTC_G
           case ied_auxf_swap_stor:         /* swap storage            */
             m_aux_swap_stor_cleanup( ADSL_AUX_CF1->adsc_hco_wothr, this, adsl_auxf_1_1 );
             break;
           case ied_auxf_dyn_lib:           /* dynamic library         */
             m_aux_dyn_lib_cleanup( this, adsl_auxf_1_1 );
             break;
           case ied_auxf_sdh_reload:        /* SDH reload              */
             break;                         /* nothing to do, already processed before */
           case ied_auxf_mppe_keys:         /* SSTP - HLAK             */
             break;
           default:
             m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s close1() l%05d cannot free resource %p iec_auxf_def %d.",
                             this->adsc_gate1 + 1, this->dsc_co_sort.imc_sno, this->chrc_ineta,
                             __LINE__, adsl_auxf_1_1, adsl_auxf_1_1->iec_auxf_def );
             break;
         }
         if (adsl_auxf_1_1) {               /* memory to free          */
           free( adsl_auxf_1_1 );           /* free memory extension   */
         }
       }
#ifdef B130808
#ifdef D_INCL_HOB_TUN
       adsl_ineta_raws_1_w1 = adsc_ineta_raws_1;  /* get auxiliary field for HOB-TUN */
       while (adsl_ineta_raws_1_w1) {       /* auxiliary field for HOB-TUN */
         adsl_ineta_raws_1_w1->ac_conn1 = NULL;  /* for this connection */
#ifndef NEW_HOB_TUN_1103
         if (adsl_ineta_raws_1_w1->dsc_htun_h) break;  /* handle for HOB-TUN */
#else
         if (dsc_htun_h) break;             /* handle for HOB-TUN      */
#endif
         if (adsl_ineta_raws_1_w1->imc_state & DEF_STATE_HTUN_FREE_R_2) break;  /* done HOB-TUN free resources */
         m_cleanup_htun_ineta( adsl_ineta_raws_1_w1 );
         if (adsl_ineta_raws_1_w1->adsc_auxf_1_ident) {  /* store ident to free */
           free( adsl_ineta_raws_1_w1->adsc_auxf_1_ident );  /* free ident */
         }
         free( adsl_ineta_raws_1_w1 );      /* free the memory         */
         adsc_ineta_raws_1 = NULL;          /* clear auxiliary field for HOB-TUN */
         break;
       }
#endif
#endif
       /* free data received from client                     */
       while (adsc_sdhc1_frcl) {            /* chain of buffers from client (SSL encrypted) */
         adsl_sdhc1_w1 = adsc_sdhc1_frcl;   /* get chain               */
         adsc_sdhc1_frcl = adsl_sdhc1_w1->adsc_next;  /* remove from chain */
         m_proc_free( adsl_sdhc1_w1 );      /* free this buffer        */
       }
#ifdef TRACEHL_T_050130
       m_hlnew_printf( HLOG_XYZ1, "clconn1::close1() adsc_sdhc1_chain=%p",
                       adsc_sdhc1_chain );
#endif
#ifdef TRACEHL_P_COUNT
       iml1 = iml2 = iml3 = 0;              /* count buffers           */
#endif
       while (adsc_sdhc1_chain) {           /* free all buffers        */
#ifdef TRACEHL_P_COUNT
         iml1++;                            /* count buffers           */
#endif
         adsl_sdhc1_w1 = adsc_sdhc1_chain;  /* this is buffer          */
         adsc_sdhc1_chain = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
         m_proc_free( adsl_sdhc1_w1 );      /* free buffer             */
       }
       while (adsc_sdhc1_inuse) {           /* free all buffers        */
#ifdef TRACEHL_P_COUNT
         iml2++;                            /* count buffers           */
#endif
         adsl_sdhc1_w1 = adsc_sdhc1_inuse;  /* this is buffer          */
         adsc_sdhc1_inuse = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
         m_proc_free( adsl_sdhc1_w1 );      /* free buffer             */
       }
       while (adsc_sdhc1_extra) {           /* free all buffers        */
#ifdef TRACEHL_P_COUNT
         iml3++;                            /* count buffers           */
#endif
         adsl_sdhc1_w1 = adsc_sdhc1_extra;  /* this is buffer          */
         adsc_sdhc1_extra = adsl_sdhc1_w1->adsc_next;  /* get next in chain */
         m_proc_free( adsl_sdhc1_w1 );      /* free buffer             */
       }
#ifdef TRACEHL_P_COUNT
       if (iml1 || iml2 || iml3) {
         m_hlnew_printf( HLOG_XYZ1, "l%05d leak struct dsd_sdh_control_1 count=%d/%d/%d.", __LINE__, iml1, iml2, iml3 );
       }
       m_hlnew_printf( HLOG_XYZ1, "current memory size inc_aux_mem_cur = %d/0X%08X.",
                       inc_aux_mem_cur, inc_aux_mem_cur );
       m_hlnew_printf( HLOG_XYZ1, "maximum memory size inc_aux_mem_max = %d/0X%08X.",
                       inc_aux_mem_max, inc_aux_mem_max );
#endif
#ifdef TRACEHL_P_COUNT
       m_hlnew_printf( HLOG_XYZ1, "ins_count_buf_in_use=%d ins_count_buf_max=%d ins_count_memory=%d.",
                       ins_count_buf_in_use, ins_count_buf_max, ins_count_memory );
#ifdef B060628
       m_hlnew_printf( HLOG_XYZ1, "HWSPR001I Report session-end / number of Work Threads %d - scheduled %d - busy %d - longest queue %d.",
                       ims_workthr_alloc, ims_workthr_sched, ims_workthr_active,
                       ims_workque_max_no );
#endif
#endif
#ifdef TRACEHL_WA_COUNT                     /* 17.09.09 KB count work area inc / dec */
       m_hlnew_printf( HLOG_XYZ1, "l%05d work area inc=%d dec=%d diff=%d.",
                       __LINE__, ims_count_wa_inc, ims_count_wa_dec, ims_count_wa_inc - ims_count_wa_dec );
#endif
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "HWSPR001I Report session-end / number of Work Threads %d - scheduled %d - busy %d - longest queue %d",
                       dsg_hco_main.imc_workthr_alloc, dsg_hco_main.imc_workthr_sched,
                       dsg_hco_main.imc_workthr_active,
                       dsg_hco_main.imc_workque_max_no );
#endif
#ifdef TRACEHLC
       m_check_aclconn1( this, 189 );
#endif
#ifdef TRACEHL6
       EnterCriticalSection( &adsc_gate1->dcritsect );
       adsc_gate1->i_session_cur--;         /* count current session   */
       LeaveCriticalSection( &adsc_gate1->dcritsect );
       memset( this, 0, sizeof(class clconn1) );
       {
         struct DTHRR *audthrr_1;
         audthrr_1 = cl_tcp_r::adthrr_a;    /* get anchor              */
         while (audthrr_1) {
           SetEvent( audthrr_1->dhandthr[0] );
           audthrr_1 = audthrr_1->next;     /* get next in chain       */
         }
       }
#endif
#ifdef TRACEHLX
       int iu1 = iec_st_ses;
#endif
#ifdef TRACEHL_050427
       while (dcl_tcp_r_c.boTCPIPconn) {    /* TCP/IP connection not closed */
         m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504271 clconn1::close1() Thread=%d SNO=%08d client-socket not closed",
                         GetCurrentThreadId(), dsc_co_sort.imc_sno );
         Sleep( 1000 );
       }
       if (iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
         while (dcl_tcp_r_s.boTCPIPconn) {  /* TCP/IP connection not closed */
           m_hlnew_printf( HLOG_XYZ1, "HWSPMTRAC0504271 clconn1::close1() Thread=%d SNO=%08d server-socket not closed",
                           GetCurrentThreadId(), dsc_co_sort.imc_sno );
           Sleep( 1000 );
         }
       }
#endif
#ifndef B080407
       if (iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
         dcl_tcp_r_s.m_wait_cleanup();      /* wait for cleanup server */
       }
       dcl_tcp_r_c.m_wait_cleanup();        /* wait for cleanup client */
#endif
#ifdef TRACE_090506
       m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T destructor clconn1() %p SNO=%08d before Sleep()", __LINE__, this, dsc_co_sort.imc_sno );
       Sleep( 10000 );
       m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T destructor clconn1() %p SNO=%08d after  Sleep()", __LINE__, this, dsc_co_sort.imc_sno );
#endif
#ifdef B101122
#ifndef B090617
       DeleteCriticalSection( &d_act_critsect );  /* critical section  */
#endif
#endif
#ifdef XYZ1
       delete this;
#endif
       dsc_timer.amc_compl = &m_free_session_b;  /* set routine for free after timer */
       dsc_timer.ilcwaitmsec = DEF_TIMER_FREE_SESSION_B;  /* delay in milliseconds before freeing the session block */
       m_time_set( &dsc_timer, FALSE );     /* set timer now           */
#ifdef TRACEHLX
       m_hlnew_printf( HLOG_XYZ1, "destructor clconn1() end %p iec_st_ses=%d", this, iu1 );
#endif
#ifdef TRACEHLC
       m_check_aclconn1( NULL, 200 );
#endif
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
     }
};

#ifdef TRACEHL_STOR_USAGE
#define D_NO_TSU_NO 8
struct dsd_tr_stor_usage_01 {
   struct dsd_tr_stor_usage_01 *adsc_next;
   void *     ac_stack;
   char       chrc_pos[ 64 ];
   char       chrc_trac[ D_NO_TSU_NO * 64 ];
   int        imc_ind_trac;
};
#endif

#include "XSBSTR01.hpp"
#include "XSLBGW01.hpp"
#ifdef D_FUNC01
#include "XSACES01.hpp"
#include "XSSWEC01.hpp"
#endif
#ifdef OLD_1112
#include "xsradiq1.hpp"
#endif

/*+-------------------------------------------------------------------+*/
/*| Internal used classes.                                            |*/
/*+-------------------------------------------------------------------+*/

   HANDLE cl_tcp_r::hws2mod = NULL;         /* Handle to ws2_32.dll    */
   CRITICAL_SECTION cl_tcp_r::dclcritsectth;  /* critical section thr  */
#ifdef B080407
   struct DTHRR *cl_tcp_r::adthrr_a = NULL;  /* anchor for threads     */
#endif
   int ( FAR __stdcall *cl_tcp_r::amc_wsasend )( SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE );
   WSAEVENT( FAR __stdcall *cl_tcp_r::afunc_wsaevent )();
   BOOL( FAR __stdcall *cl_tcp_r::afunc_wsa_close_event )( WSAEVENT );
   BOOL( FAR __stdcall *cl_tcp_r::afunc_wsa_set_event )( WSAEVENT );
   int( FAR __stdcall *cl_tcp_r::afunc_wsa_e_select )( SOCKET, WSAEVENT, long );
   int( FAR __stdcall *cl_tcp_r::afunc_wsa_enum_net_events )( SOCKET, WSAEVENT, LPWSANETWORKEVENTS );
   DWORD( FAR __stdcall *cl_tcp_r::afunc_wsawaitm )( DWORD, const WSAEVENT FAR*, BOOL, DWORD, BOOL );
   int( FAR __stdcall *cl_tcp_r::afunc_wsaglerr )();

   class dcl_blasetr_1 * dcl_blasetr_1::adss_blasetr_1_anchor = NULL;  /* anchor */
   class dcl_blasetr_1 * dcl_blasetr_1::adss_blasetr_1_free = NULL;  /* anchor free */

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

static BOOL boisservice;                    /* started as service      */
static BOOL   bos_end_proc = FALSE;         /* signal end of processing */
static SERVICE_STATUS_HANDLE   dclhsrvstat;
static SERVICE_STATUS          dclasrvstat;
#ifdef XYZ1
static char *strsrvname = "";               // pointer to service name
#endif
extern "C" BOOL bog_not_aus_start = FALSE;  /* stop immediately        */
extern "C" BOOL bog_log = FALSE;            /* no event log yet        */
extern "C" BOOL bog_event_log_out = FALSE;  /* something written to event log */
static WCHAR  *awcs_rev_source = L"";       /* service-name            */
static BOOL   bos_error_event_log = FALSE;  /* no error in event-log yet */
static int isargc = 0;                      // Number of parameters
static char **asargv=0;                     // Pointer to array of parameters
static char *aparams=0;                     // parameter array
static struct dsd_loconf_1 dss_loconf_1_first;  /* first load config   */
static BOOL   bos_disk_file = FALSE;        /* did not access disk file yet */
static struct dsd_wsp_tr_ineta_ctrl *adss_wtic_active = NULL;  /* WSP trace client with INETA control */
#ifdef DEBUG_100809
static void * as_debug_100809_01 = NULL;
#endif
#ifdef DEBUG_110315_01
static BOOL   bos_debug_110315_01 = FALSE;
static void * as_debug_110315_01;
#endif

static unsigned char ucrs_cr_lf[ 2 ] = { CHAR_CR, CHAR_LF };

#ifdef D_HPPPT1_1
static unsigned char ucrs_wsp_ident[] = {
   'H', 'O', 'B', '-', 'W', 'S', 'P', '-', 'V', '2', '.', '3'
};

static unsigned char ucrs_mscv2_magic1[ 39 ] = {  /* length 39         */
   0X4D, 0X61, 0X67, 0X69, 0X63, 0X20, 0X73, 0X65, 0X72, 0X76,
   0X65, 0X72, 0X20, 0X74, 0X6F, 0X20, 0X63, 0X6C, 0X69, 0X65,
   0X6E, 0X74, 0X20, 0X73, 0X69, 0X67, 0X6E, 0X69, 0X6E, 0X67,
   0X20, 0X63, 0X6F, 0X6E, 0X73, 0X74, 0X61, 0X6E, 0X74
};

static unsigned char ucrs_mscv2_magic2[ 41 ] = {  /* length 41         */
   0X50, 0X61, 0X64, 0X20, 0X74, 0X6F, 0X20, 0X6D, 0X61, 0X6B,
   0X65, 0X20, 0X69, 0X74, 0X20, 0X64, 0X6F, 0X20, 0X6D, 0X6F,
   0X72, 0X65, 0X20, 0X74, 0X68, 0X61, 0X6E, 0X20, 0X6F, 0X6E,
   0X65, 0X20, 0X69, 0X74, 0X65, 0X72, 0X61, 0X74, 0X69, 0X6F,
   0X6E
};

static unsigned char ucrs_send_avp_ms_01[ 6 ] = {
   0X1A, 0X00,
   0X00, 0X00, 0X01, 0X37
};

static unsigned char ucrs_mscv2_failed_p1[] = {  /* MS-CHAP-V2 failure part one */
   0X04, 0X00, 0X00, 0X34,                  /* header                  */
   0X45, 0X3D, 0X36, 0X39, 0X31, 0X20,      /* E=691                   */
   0X52, 0X3D, 0X31, 0X20, 0X43, 0X3D       /* R=1 C=                  */
};

static unsigned char ucrs_mscv2_failed_p2[] = {  /* MS-CHAP-V2 failure part two */
   0X20, 0X56, 0X3D, 0X33                   /*  V=3                    */
};

static unsigned char ucrs_vendor_s_ms_numbers[ 3 ] = {
   'E', 'R', 'V'
};

/* Constants defined in RFC 3079 - MPPE                                */
static const unsigned char ucrs_mppe_magic1[27] =
        { 0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74,
          0x68, 0x65, 0x20, 0x4d, 0x50, 0x50, 0x45, 0x20, 0x4d,
          0x61, 0x73, 0x74, 0x65, 0x72, 0x20, 0x4b, 0x65, 0x79 };
      /* "On the client side, this is the send key; "
         "on the server side, it is the receive key." */
static const unsigned char ucrs_mppe_magic2[84] =
        { 0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
          0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
          0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
          0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20, 0x6b, 0x65, 0x79,
          0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x73,
          0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73, 0x69, 0x64, 0x65,
          0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
          0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
          0x6b, 0x65, 0x79, 0x2e };
      /* "On the client side, this is the receive key; "
         "on the server side, it is the send key." */
static const unsigned char ucrs_mppe_magic3[84] =
        { 0x4f, 0x6e, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x69,
          0x65, 0x6e, 0x74, 0x20, 0x73, 0x69, 0x64, 0x65, 0x2c, 0x20,
          0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x74, 0x68,
          0x65, 0x20, 0x72, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x20,
          0x6b, 0x65, 0x79, 0x3b, 0x20, 0x6f, 0x6e, 0x20, 0x74, 0x68,
          0x65, 0x20, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x20, 0x73,
          0x69, 0x64, 0x65, 0x2c, 0x20, 0x69, 0x74, 0x20, 0x69, 0x73,
          0x20, 0x74, 0x68, 0x65, 0x20, 0x73, 0x65, 0x6e, 0x64, 0x20,
          0x6b, 0x65, 0x79, 0x2e };

static const unsigned char ucrs_mppe_shspad1[40] =
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

static const unsigned char ucrs_mppe_shspad2[40] =
        { 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
          0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
          0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2,
          0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2, 0xf2 };
#endif

/* for windows core dump                                               */
struct dsd_wcord1 dsg_wcord1 = { NULL, NULL, NULL, NULL, NULL, NULL };

#ifdef XYZ1
static int imrs_sha1_security_token[ SHA_ARRAY_SIZE ];  /* for hash security-token */
#endif
static HL_LONGLONG ilrs_sha384_security_token[ SHA384_ARRAY_SIZE ];  /* for hash security-token */

extern struct dsd_sdh_lib1 *adsg_sdhl_anchor = NULL;  /* anchor of cha */
extern struct dsd_hlwspat2_lib1 *adsg_hlwspat2l_anchor = NULL;  /* anchor chain authentication library */
extern struct dsd_this_server dsg_this_server = { 0 };  /* data about this server */
extern struct dsd_sys_state_1 dsg_sys_state_1 = {  /* system state     */
   FALSE,     /* boc_load_balancing_started load-balancing has been started */
   -1,        /* imc_load_balancing_value   last value returned by load-balancing */
   0,         /* imc_load_balancing_epoch   time last load-balancing query was done */
   FALSE,     /* boc_htun_started           HTUN has been started      */
   FALSE,     /* boc_htun_start_failed      start of HTUN has failed   */
   FALSE,     /* boc_listen_active          listen is currently active */
   FALSE,     /* boc_listen_ended           listen has already ended   */
   0          /* imc_epoch_listen_act       epoch until which listen keeps active */
};

static struct dsd_sysaddr dss_sysaddr = {   /* structure with System Addresses */
   sizeof(struct dsd_sysaddr),              /* length of structure     */
#ifdef B100815
   (void *) &m_aux_conn,                    /* address routine m_aux_conn() */
#endif
   (void *) &m_tcp_dynamic_conn,            /* address routine m_tcp_dynamic_conn() - connect TCP */
   &dsg_hco_main,                           /* work threads            */
   &dss_loconf_1_first,                     /* load configuration      */
   (void *) &m_set_wothr_blocking,
   (void *) &m_set_wothr_active
};

static struct dsd_ser_thr_ctrl {            /* control serial thread   */
   struct dsd_ser_thr_task *adsc_sth_work;  /* work as task for serial thread */
   struct dsd_ser_thr_task *adsc_sth_free;  /* chain of free structures */
   class dsd_hcthread dsc_thread;           /* serial thread           */
   class dsd_hcla_event_1 dsc_event_thr;    /* event of thread         */
   UNSIG_MED  umc_index_if_arp;             /* holds index of compatible IF for ARP */
   UNSIG_MED  umc_index_if_route;           /* holds index of compatible IF for routes */
} dss_ser_thr_ctrl;

static struct dsd_wsp_trace_thr_ctrl {      /* control WSP trace thread */
   struct dsd_wsp_trace_1 *adsc_wt1_anchor;  /* WSP trace record anchor */
   struct dsd_wsp_trace_1 *adsc_wt1_last;   /* WSP trace record last in chain */
   BOOL       boc_tread_running;            /* WSP trace thread is running */
   enum ied_wsp_trace_target iec_wtt;       /* WSP Trace target        */
   BOOL       boc_cma_dump;                 /* make CMA dump           */
   class dsd_hcthread dsc_thread;           /* serial thread           */
   class dsd_hcla_event_1 dsc_event_thr;    /* event of thread         */
} dss_wsp_trace_thr_ctrl;

extern "C" int img_wsp_trace_core_flags1 = 0;  /* WSP trace core flags */

#ifdef B100702
/* 26.11.08 KB - only valid till replaced by configurable parameters   */
/* attention Alan Duca                                                 */
static struct dsd_wsptun_conf_1 dss_wsptun_conf_1 = {
   TRUE,
   FALSE,
   { 172, 22, 0, 1 },
   { 0, 0, 0, 0 },
   { 172, 22, 0, 1 },
   { 0, 0, 0, 0 },
   { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
   { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
   { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
   { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
};
#endif

static char   chs_zero = 0;                 /* memory with zero        */
static void * vps_ones = (void *) ((long long int) -1);  /* memory with all bits set */

#ifdef EXAMINE_SIGN_ON_01                   /* 10.08.11 KB examine sign on time */
static HL_LONGLONG ils_freq;
#endif

#ifdef TRACEHL1
/*+-------------------------------------------------------------------+*/
/*| Subroutine for Tracing                                            |*/
/*+-------------------------------------------------------------------+*/

static void m_trac_exit( void ) {
   m_hlnew_printf( HLOG_XYZ1, "m_trac_exit l%05d called",
                   __LINE__ );
   ExitProcess( 2 );  /* UUUU 07.10.05 KB */
}
#endif
/*+-------------------------------------------------------------------+*/
/*| Subroutine for Output to Console.                                 |*/
/*+-------------------------------------------------------------------+*/

/** write message to the console and to all configured logs            */
extern PTYPE int m_hlnew_printf( int imp_type, char *aptext, ... ) {
   va_list    dsl_argptr;
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3;             /* working-variables       */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   WCHAR      *awcl_w1;                     /* working-variable        */
   HANDLE     dsl_hlog;                     /* Handle to appl log      */
   const WCHAR *awcrl_logs[2];              // String pointer for writing into log file
   WCHAR      wcrl_timebuf[9];              // buffer to receive current time
   HL_WCHAR   wcrl_out1[ 512 * sizeof(HL_WCHAR) ];  /* buffer          */

   va_start( dsl_argptr, aptext );
   iml1 = m_hlvsnprintf( wcrl_out1, sizeof(wcrl_out1) - 2, ied_chs_ansi_819, aptext, dsl_argptr );
#ifdef XYZ1
   printf( "%s\n", wcrl_out1 );
#endif
#ifdef B120830
   if (iml1 > 0) {
     *((char *) wcrl_out1 + iml1 + 0) = '\n';
     *((char *) wcrl_out1 + iml1 + 1) = 0;
   }
   cout << (char *) wcrl_out1;
#else
   if (iml1 == 0) return 0;                 /* empty input             */
   iml2 = sizeof(wcrl_out1) - 2;            /* maximum length output   */
   if (iml1 > 0) {
     iml2 = iml1 + 1;                       /* length of string        */
   }
   *((char *) wcrl_out1 + iml2 - 1) = '\n';
   std::cout.write( (char *) wcrl_out1, iml2 );
#ifdef LOG_INSURE_01
   *((char *) wcrl_out1 + iml2 - 1) = 0;    /* make zero-terminated    */
   _Insure_trace_enable( 1 );
   _Insure_trace_annotate( 1, "%s\n", wcrl_out1 );
   _Insure_trace_enable( 0 );
#endif
#endif
#ifdef TRACEHL1
   fflush( stdout );
#endif
#ifdef TRACEHL_FLUSH
   fflush( stdout );
#endif
   if (   (img_wsp_trace_core_flags1 & HL_WT_CORE_CONSOLE)  /* messages written to the console */
       && (dss_wsp_trace_thr_ctrl.iec_wtt != ied_wtt_console)) {  /* not print on console */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CCONSOLE", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "write to console length %d/0X%X.",
                     iml1, iml1 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2)) {  /* generate WSP trace record */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml2 = iml1;                         /* length of data displayed */
       achl_w3 = (char *) wcrl_out1;        /* start of data           */
       adsl_wt1_w2 = adsl_wt1_w1;           /* in this piece of memory */
       adsl_wtr_w1 = ADSL_WTR_G1;           /* set last in chain       */
       bol1 = FALSE;                        /* reset more flag         */
       do {                                 /* loop always with new struct dsd_wsp_trace_record */
         achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         if ((achl_w1 + sizeof(struct dsd_wsp_trace_record)) >= achl_w2) {
           adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
           adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
           adsl_wt1_w2 = adsl_wt1_w3;       /* this is current network */
           achl_w1 = (char *) (adsl_wt1_w2 + 1);
           achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         }
         memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
#ifdef B110706
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
#endif
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed        */
         achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
         ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
#ifdef B110706
         if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
           adsl_wtr_w1->boc_more = TRUE;    /* more data to follow     */
         }
#endif
         adsl_wtr_w1->boc_more = bol1;      /* more data to follow     */
         bol1 = TRUE;                       /* set more flag           */
         adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain     */
         adsl_wtr_w1 = ADSL_WTR_G2;         /* this is last in chain now */
         iml3 = achl_w2 - achl_w4;
         if (iml3 > iml2) iml3 = iml2;
         memcpy( achl_w4, achl_w3, iml3 );
         achl_w4 += iml3;
         achl_w3 += iml3;
         ADSL_WTR_G2->imc_length = iml2;    /* length of text / data   */
         iml2 -= iml3;                      /* length to be copied     */
         achl_w1 = achl_w2;                 /* set end of this area    */
       } while (iml2 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (bos_mem_log) {                       /* write to memory log     */
     iml2 = m_hlvsnprintf( wcrl_out1, sizeof(wcrl_out1), ied_chs_utf_8,
                           aptext, dsl_argptr );
     m_write_log( imp_type, (char *) wcrl_out1, iml2 );
   }
   if (imp_type == HLOG_EMER1) {
     /* write line with program version first, if event log not yet opened */
     if (bog_event_log_out == FALSE) {      /* nothing written to event log yet */
       bog_event_log_out = TRUE;            /* something written to event log */
       awcl_w1 = adsg_loconf_1_inuse->awcc_rev_source;
       if (awcl_w1 == NULL) awcl_w1 = awcs_rev_source;
       dsl_hlog = RegisterEventSourceW( adsg_loconf_1_inuse->awcc_rev_server, awcl_w1 );
       if (dsl_hlog == NULL) {              /* function did not succeed */
         va_end( dsl_argptr );
         return iml1;
       }
       swprintf( (WCHAR *) wcrl_out1, L"%S", MSG_CONS_P1 MSG_CPU_TYPE __DATE__ MSG_CONS_P2 );
       _wstrtime( wcrl_timebuf );
       awcrl_logs[0] = (WCHAR *) wcrl_out1;
       awcrl_logs[1] = NULL;
       ReportEventW( dsl_hlog, EVENTLOG_INFORMATION_TYPE,
                     0, HOB_INFO_001, 0, 1, 8, awcrl_logs, wcrl_timebuf );
       DeregisterEventSource( dsl_hlog );
     }
   } else if (bog_log == FALSE) {           /* do not write to log     */
     va_end( dsl_argptr );
     return iml1;
   }
   awcl_w1 = adsg_loconf_1_inuse->awcc_rev_source;
   if (awcl_w1 == NULL) awcl_w1 = awcs_rev_source;
   dsl_hlog = RegisterEventSourceW( adsg_loconf_1_inuse->awcc_rev_server, awcl_w1 );
   if (dsl_hlog == NULL) {                  /* function did not succeed */
     if (bos_error_event_log == FALSE) {
       sprintf( (char *) wcrl_out1, "HWSPxyz RegisterEventSourceW() returned Error %d\n",
                GetLastError() );
       cout << (char *) wcrl_out1;
       bos_error_event_log = TRUE;
     }
     va_end( dsl_argptr );
     return iml1;
   }
   iml2 = m_hlvsnprintf( wcrl_out1, sizeof(wcrl_out1) / sizeof(HL_WCHAR), ied_chs_utf_16,
                         aptext, dsl_argptr );
   va_end( dsl_argptr );
   _wstrtime( wcrl_timebuf );
   awcrl_logs[0] = (WCHAR *) wcrl_out1;
   awcrl_logs[1] = NULL;
   ReportEventW( dsl_hlog, EVENTLOG_INFORMATION_TYPE,
                 0, HOB_INFO_001, 0, 1, 8, awcrl_logs, wcrl_timebuf );
   DeregisterEventSource( dsl_hlog );
   bog_event_log_out = TRUE;                /* something written to event log */
   return iml1;
} /* end m_hlnew_printf()                                              */

extern "C" int m_hl1_printf( char *aptext, ... ) {
   va_list    dsl_argptr;
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3;             /* working-variables       */
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */
   WCHAR      *awcl_w1;                     /* working-variable        */
   HANDLE     dsl_hlog;                     /* Handle to appl log      */
   const WCHAR *awcrl_logs[2];              // String pointer for writing into log file
   WCHAR      wcrl_timebuf[9];              // buffer to receive current time
   HL_WCHAR   wcrl_out1[ 512 * sizeof(HL_WCHAR) ];  /* buffer          */

   va_start( dsl_argptr, aptext );
   iml1 = m_hlvsnprintf( wcrl_out1, sizeof(wcrl_out1), ied_chs_ansi_819, aptext, dsl_argptr );
#ifdef XYZ1
   printf( "%s\n", wcrl_out1 );
#endif
   if (iml1 > 0) {
     *((char *) wcrl_out1 + iml1 + 0) = '\n';
     *((char *) wcrl_out1 + iml1 + 1) = 0;
   }
   cout << (char *) wcrl_out1;
#ifdef TRACEHL1
   fflush( stdout );
#endif
   if (   (img_wsp_trace_core_flags1 & HL_WT_CORE_CONSOLE)  /* messages written to the console */
       && (dss_wsp_trace_thr_ctrl.iec_wtt != ied_wtt_console)) {  /* not print on console */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CCONSOLE", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "write to console length %d/0X%X.",
                     iml1, iml1 );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (img_wsp_trace_core_flags1 & (HL_WT_CORE_DATA1 | HL_WT_CORE_DATA2)) {  /* generate WSP trace record */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml2 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml2 = iml1;                         /* length of data displayed */
       achl_w3 = (char *) wcrl_out1;        /* start of data           */
       adsl_wt1_w2 = adsl_wt1_w1;           /* in this piece of memory */
       adsl_wtr_w1 = ADSL_WTR_G1;           /* set last in chain       */
       bol1 = FALSE;                        /* reset more flag         */
       do {                                 /* loop always with new struct dsd_wsp_trace_record */
         achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         if ((achl_w1 + sizeof(struct dsd_wsp_trace_record)) >= achl_w2) {
           adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
           adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
           adsl_wt1_w2 = adsl_wt1_w3;       /* this is current network */
           achl_w1 = (char *) (adsl_wt1_w2 + 1);
           achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         }
         memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
#ifdef B110706
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
#endif
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_text;  /* text passed        */
         achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
         ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
#ifdef B110706
         if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
           adsl_wtr_w1->boc_more = TRUE;    /* more data to follow     */
         }
#endif
         adsl_wtr_w1->boc_more = bol1;      /* more data to follow     */
         bol1 = TRUE;                       /* set more flag           */
         adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain     */
         adsl_wtr_w1 = ADSL_WTR_G2;         /* this is last in chain now */
         iml3 = achl_w2 - achl_w4;
         if (iml3 > iml2) iml3 = iml2;
         memcpy( achl_w4, achl_w3, iml3 );
         achl_w4 += iml3;
         achl_w3 += iml3;
         ADSL_WTR_G2->imc_length = iml2;    /* length of text / data   */
         iml2 -= iml3;                      /* length to be copied     */
         achl_w1 = achl_w2;                 /* set end of this area    */
       } while (iml2 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (bos_mem_log) {                       /* write to memory log     */
     iml2 = m_hlvsnprintf( wcrl_out1, sizeof(wcrl_out1), ied_chs_utf_8,
                           aptext, dsl_argptr );
     m_write_log( HLOG_WARN1, (char *) wcrl_out1, iml2 );
   }
   if (bog_log == FALSE) {                  /* do not write to log     */
     va_end( dsl_argptr );
     return iml1;
   }
   awcl_w1 = adsg_loconf_1_inuse->awcc_rev_source;
   if (awcl_w1 == NULL) awcl_w1 = awcs_rev_source;
   dsl_hlog = RegisterEventSourceW( adsg_loconf_1_inuse->awcc_rev_server, awcl_w1 );
   if (dsl_hlog == NULL) {                  /* function did not succeed */
     if (bos_error_event_log == FALSE) {
       sprintf( (char *) wcrl_out1, "HWSPxyz RegisterEventSourceW() returned Error %d.\n",
                GetLastError() );
       cout << (char *) wcrl_out1;
       bos_error_event_log = TRUE;
     }
     va_end( dsl_argptr );
     return iml1;
   }
   iml2 = m_hlvsnprintf( wcrl_out1, sizeof(wcrl_out1) / sizeof(HL_WCHAR), ied_chs_utf_16,
                         aptext, dsl_argptr );
   va_end( dsl_argptr );
   _wstrtime( wcrl_timebuf );
   awcrl_logs[0] = (WCHAR *) wcrl_out1;
   awcrl_logs[1] = NULL;
   ReportEventW( dsl_hlog, EVENTLOG_INFORMATION_TYPE,
                 0, HOB_INFO_001, 0, 1, 8, awcrl_logs, wcrl_timebuf );
   DeregisterEventSource( dsl_hlog );
   bog_event_log_out = TRUE;                /* something written to event log */
   return iml1;
} /* end m_hl1_printf()                                                */

/*+-------------------------------------------------------------------+*/
/*| Main control procedure.                                           |*/
/*+-------------------------------------------------------------------+*/

int main( int argc, char *argv[] ) {
   BOOL     bou1;
   SERVICE_TABLE_ENTRY st[] = {
     { (LPSTR) DEF_APPL_NAME, ServiceMain },
     { NULL, NULL }
   };
   /* 04.08.04 KB + Joachim Frank */
   char       byrl_cout[512];

// printf( MSG_CONS_P1 MSG_CPU_TYPE __DATE__ MSG_CONS_P2 "\n" );
   sprintf( byrl_cout, MSG_CONS_P1 MSG_CPU_TYPE __DATE__ MSG_CONS_P2 );
#ifndef TRACE_PRINTF
   cout << byrl_cout << endl;
#else
   InitializeCriticalSection( &dss_critsect_printf );  /* critical section printf */
   EnterCriticalSection( &dss_critsect_printf );
   printf( "%s\n", (char *) byrl_cout );
   LeaveCriticalSection( &dss_critsect_printf );
#endif

#ifdef TRACEHL1
#ifndef D_NO_SERVICE
#define D_NO_SERVICE
#endif
#endif
#ifdef D_NO_SERVICE
   /* 24.04.09 KB - from Mr. Galea                                     */
   setbuf( stdout, 0 );
   m_hlnew_printf( HLOG_XYZ1, "start without service" );
   boisservice = FALSE;
   isargc = argc;                         // copy command line parameters
   asargv = argv;
   ServiceMain( 0, NULL );
   if (boisservice == FALSE) return 0;
#endif

   boisservice = TRUE;

   bou1 = StartServiceCtrlDispatcher( st );
   if (bou1 == FALSE) {
//   printf( "Service dispatcher could not be started. Error: %d\n", GetLastError() );
     sprintf( byrl_cout, "HWSPM002I Service dispatcher could not be started. Error: %d", GetLastError() );
#ifndef TRACE_PRINTF
     cout << byrl_cout << endl;
#else
     EnterCriticalSection( &dss_critsect_printf );
     printf( "%s\n", (char *) byrl_cout );
     LeaveCriticalSection( &dss_critsect_printf );
#endif
     boisservice = FALSE;                   // then start it as non-service application
     isargc = argc;                         // copy command line parameters
     asargv = argv;
     ServiceMain( 0, NULL );
   }
   return 0;
}

static void WINAPI srventry01( DWORD ictrl )
{
   struct dsd_gate_1 *audgate1;             /* gateway                 */
#ifdef B080407
   class clconn1 *auclconn11;               /* connection              */
#endif
   BOOL     bou1;

   switch (ictrl) {
     case SERVICE_CONTROL_SHUTDOWN:
     case SERVICE_CONTROL_STOP:
       dclasrvstat.dwCurrentState = SERVICE_STOP_PENDING;
       SetServiceStatus( dclhsrvstat, &dclasrvstat );  // set state service closing down
       bos_end_proc = TRUE;                 /* signal end of processing */
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "SERVICE_CONTROL_STOP - SetEvent" );
#endif
#ifdef B080407
       audgate1 = adsg_loconf_1_inuse->adsc_gate_anchor;  /* get anchor gate */
       while (audgate1) {                   /* loop over all gates     */
         IP_closesocket( audgate1->inc_listen_socket );
         audgate1 = audgate1->adsc_next;    /* get next gate in chain  */
       }
#endif
#ifdef B080407
       auclconn11 = aconn1a;                /* get anchor              */
       while (auclconn11) {                 /* loop over all conn      */
         auclconn11->dcl_tcp_r_c.close1();
         if (auclconn11->iec_st_ses == clconn1::ied_ses_conn)  /* server */
           auclconn11->dcl_tcp_r_s.close1();
         auclconn11 = auclconn11->getnext();  /* get next in chain     */
       }
#endif
/* to-do 08.04.08 KB */
       bou1 = SetEvent( dsrs_heve_main[0] );
       if (bou1 == FALSE) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPM005W Service-Entry SetEvent Error %d", GetLastError() );
       }
       break;
     case SERVICE_INTERROGATE:
       SetServiceStatus( dclhsrvstat, &dclasrvstat );  // report current state
       break;
   }
}

static void WINAPI ServiceMain( DWORD dwArgc, LPTSTR *lpszArgv ) // Main function of service
{
   /* service variables - start                                        */
   HKEY hkini;                 // Handle to registry entry
   long regrc;                 // return code of registry methods
   DWORD ireglen , iregtyp;    // length and type of entry
   char *inextparam;           // pointer to next parameter
   char *icurparam;            // pointer to current parameter
   int iindex;                 // index to parameter array;
   int imode;                  // search mode 0 = start of parameter
                               //             1 = search end with blank
                               //             2 = search end with "
   char strkeyname[ MAX_PATH ];// Registry key name
   /* service variables - end                                          */
   int      rcu;
// int      iu1;
#ifdef NEW_REPORT_1501
   int        iml_rc;                       /* return code             */
#endif
#ifndef NEW_REPORT_1501
   int        iml1, iml2;                   /* working variables       */
   LONGLONG   ill1, ill2;                   /* working variables       */
#endif
#ifdef NEW_REPORT_1501
   int        iml_diff_report;              /* time difference report  */
   int        iml1, iml2, iml3, iml4, iml5;  /* working variables      */
   HL_LONGLONG ill_w1, ill_w2, ill_w3, ill_w4;  /* working variables   */
#endif
   char       *achl1, *achl2, *achl3;       /* working variables       */
   WCHAR      *awcl1;                       /* working-variable        */
// BOOL     bou1;
// char     *au1;                           /* working variable        */
#ifdef NEW_REPORT_1501
   struct dsd_bandwidth_client_1 *adsl_bc1_report;  /* measure bandwidth with clients */
   struct dsd_bandwidth_client_1 *adsl_bc1_free;  /* memory to get freed */
   struct dsd_bandwidth_client_1 *adsl_bc1_w1,  *adsl_bc1_w2;  /* working variables */
#endif
   int      imrl_sha1[ SHA_ARRAY_SIZE ];    /* for hash                */
#ifndef NEW_REPORT_1501
   char     byarruwork1[512];               /* working variable        */
   char     byarruwork2[ MAX_PATH ];        /* working variable        */
   char     byarruwork3[ MAX_PATH ];        /* working variable        */
#endif
#ifdef NEW_REPORT_1501
#ifdef XYZ1
   struct tm  *adsl_tm_w1;                  /* working variable        */
   struct tm  dsl_tm_l1;                    /* working variable        */
   struct tm  dsl_tm_l2;                    /* working variable        */
#endif
   char       chrl_disp_fp[ DEF_LEN_FINGERPRINT * 2 + DEF_LEN_FINGERPRINT / 2 - 1 ];
   char       chrl_work1[ 512 ];            /* work area               */
   char       chrl_work2[ MAX_PATH ];       /* work area               */
   char       chrl_work3[ MAX_PATH ];       /* work area               */
#endif
   DWORD    dwu1;                           /* working variable        */
   DWORD      dwl1;                         /* working variable        */
   DWORD      dwl_wait;                     /* how long to wait        */
#ifndef B080407
   struct dsd_gate_1 *adsl_gate_1_w1;       /* for start listen        */
#endif
//#ifdef B080407
   struct dsd_gate_1 *audgate1;                 /* for thread-start        */
//#endif
   HANDLE   huth;                           /* Thread handle           */
   DWORD    tidu1;                          /* Thread id               */
   time_t     dsl_time_1;                   /* for time                */
   time_t     dsl_time_last_report;         /* time of last report     */
   time_t     dsl_time_read_conf;           /* time to read configuration */
   time_t     dsl_time_cma_check;           /* time to check CMA entries */
#ifdef NEW_REPORT_1501
   time_t     dsl_time_fingerprint;         /* time to print fingerprint in report */
#endif
// class clworkth *audclworkth1;
   struct dsd_extra_thread_entry *adsl_ete_w1;  /* extra thread entries */
   struct dsd_loconf_1 *adsl_loconf_1_1;    /* working var loaded conf */
   BOOL       bol1;                         /* working variable        */
#ifdef NEW_REPORT_1501
   BOOL       bol_fingerprint;              /* print fingerprint in report */
#endif
   char       *adsl_path_fn;                /* pointer to filename     */
   WIN32_FILE_ATTRIBUTE_DATA dsl_fi_c;      /* file data               */
   FILETIME   dsl_ft_lastmod;               /* time last modified (cf) */
   struct dsd_diskfile_1 *adsl_df1_1;       /* diskfile in memory      */
   struct dsd_bgt_contr_1 *adsl_bgt_contr_1;  /* definition background-task control */
   struct dsd_bgt_function_1 *adsl_bgt_function_1;  /* chain background-task functions */
   bool                       recognizeNEL = false;
   char                       localeStr[64];
   struct dsd_aux_cf1 dsl_aux_cf1;          /* auxiliary control structure */
   struct dsd_bgt_call_1 dsl_bgt_call_1;    /* Background-Task Call    */
   struct dsd_cluster_report dsl_cluster_report;  /* cluster report structure */
   char       chrl_ns_num[16];              /* for number              */
   /* 04.08.04 KB + Joachim Frank */
   char       byrl_cout[512];
#ifdef D_INCL_HOB_TUN
   BOOL       bol_rc;                       /* return code             */
   struct dsd_ser_thr_task *adsl_ser_thr_task_w1;  /* task for serial thread */
   struct dsd_ser_thr_task *adsl_ser_thr_task_w2;  /* task for serial thread */
   unsigned short int usl_ineta_length;     /* length of INETA         */
   BOOL       bol_route_del;                /* delete the route        */
   BOOL       bol_first;
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */
   char       chrl_cmp_ineta[ 16 ];         /* compare INETA           */
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "ServiceMain started" );
#endif
#ifdef XYZ1
   if (dwArgc > 0) {                        /* arguments found         */
     strsrvname = lpszArgv[0];
   } else {
     strsrvname = DEF_APPL_NAME;
   }
#endif
   if (dwArgc > 0) {                        /* arguments found         */
     achl1 = lpszArgv[0];
   } else {
     achl1 = DEF_APPL_NAME;
   }
   awcs_rev_source = (WCHAR *) malloc( (strlen( achl1 ) + 1) * sizeof(WCHAR) );
   awcl1 = awcs_rev_source;
   while (*achl1) {
     *awcl1++ = (WCHAR) *achl1++;
   }
   *awcl1 = 0;                              /* make zero-terminated    */
   if (boisservice) {
     dclasrvstat.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
     dclasrvstat.dwCurrentState = SERVICE_RUNNING;
     dclasrvstat.dwControlsAccepted = SERVICE_ACCEPT_STOP || SERVICE_ACCEPT_SHUTDOWN;
     dclasrvstat.dwWin32ExitCode = NO_ERROR;
     dclasrvstat.dwServiceSpecificExitCode = 0;
     dclasrvstat.dwCheckPoint = 0;
     dclasrvstat.dwWaitHint = 0;
     dclhsrvstat = RegisterServiceCtrlHandler( DEF_APPL_NAME, srventry01 ); // Register handler
     SetServiceStatus( dclhsrvstat, &dclasrvstat );         // set state
      // Now build parameter array from registry entry
#ifdef XYZ1
      sprintf( strkeyname , "System\\CurrentControlSet\\Services\\%s\\Parameters" , strsrvname );
#endif
      sprintf( strkeyname, "System\\CurrentControlSet\\Services\\%S\\Parameters", awcs_rev_source );

      regrc = RegOpenKeyEx( HKEY_LOCAL_MACHINE ,
                            strkeyname,
                            0 ,
                            KEY_QUERY_VALUE ,
                            &hkini );
      if( regrc == ERROR_SUCCESS )
      {
         ireglen = 0;
         regrc = RegQueryValueEx( hkini,
                                  "Parameters" ,
                                  0 ,
                                  &iregtyp ,
                                  0 ,
                                  &ireglen );
         if( regrc == ERROR_SUCCESS && ireglen > 0 )    // parameter found
         {
            aparams = new char[ ireglen + 1 ];          // reserve storage for entry
            RegQueryValueEx( hkini,                     // read parameters
                             "Parameters" ,
                             0 ,
                             &iregtyp ,
                             ((unsigned char *)aparams)+1,
                             &ireglen );
            isargc = 1;
            icurparam = aparams + 1;
            imode = 0;                    // search for parameter start
            while( *icurparam != 0 )
            {
               if( imode == 0 )
               {
                  if( *icurparam == ' ' )    // single blank
                  {
                     icurparam++;
                     continue;
                  }
                  else
                  {
                     if( *icurparam == '"' ) // Parameter starting with "
                     {
                        icurparam++;            // start of parameter
                        inextparam = icurparam;
                        imode = 2;           // search for "
                     }
                     else
                     {
                        imode = 1;           // search for blank
                     }
                  }
               }
               else if( imode == 1 )         // search for next blank
               {
                  inextparam = strchr( icurparam , ' ' );
                  isargc++;
                  if( inextparam != 0 )
                  {
                     icurparam = inextparam + 1;
                     imode = 0;
                  }
                  else
                  {
                     break;
                  }
               }
               else if( imode == 2 )         // search for next "
               {
                  inextparam = strchr( inextparam , '"' );
                  if( inextparam == 0 )      // no ending bracket
                  {
                     isargc++;
                     break;
                  }
                  else
                  {
                     if( *(inextparam+1) == ' ' )  // is ending bracket
                     {
                        isargc++;
                        icurparam = inextparam + 2;
                        imode = 0;                  // start new search
                     }
                     else if( *(inextparam+1) == 0 )  // bracket at end
                     {
                        isargc++;
                        break;
                     }
                     else
                     {
                        inextparam += 2;
                     }
                  }
               }
            }
            asargv = new char*[ isargc ];        // create array of argument pointers

            iindex = 0;
            asargv[ iindex ] = aparams;          // Set first parameter
            *aparams = 0;

            icurparam = aparams + 1;
            imode = 0;                    // search for parameter start
            while( *icurparam != 0 )
            {
               if( imode == 0 )
               {
                  if( *icurparam == ' ' )    // single blank
                  {
                     icurparam++;
                     continue;
                  }
                  else
                  {
                     if( *icurparam == '"' ) // Parameter starting with "
                     {
                        icurparam++;
                        inextparam = icurparam;
                        imode = 2;           // search for "
                     }
                     else
                     {
                        imode = 1;           // search for blank
                     }
                  }
               }
               else if( imode == 1 )         // search for next blank
               {
                  inextparam = strchr( icurparam , ' ' );
                  iindex++;
                  asargv[ iindex ] = icurparam;
                  if( inextparam != 0 )
                  {
                     *inextparam = 0;
                     icurparam = inextparam + 1;
                     imode = 0;
                  }
                  else
                  {
                     break;
                  }
               }
               else if( imode == 2 )         // search for next "
               {
                  inextparam = strchr( inextparam , '"' );
                  if( inextparam == 0 )      // no ending bracket
                  {
                     iindex++;
                     asargv[ iindex ] = icurparam;
                     break;
                  }
                  else
                  {
                     if( *(inextparam+1) == ' ' )  // is ending bracket
                     {
                        iindex++;
                        asargv[ iindex ] = icurparam;
                        *inextparam = 0;
                        icurparam = inextparam + 2;
                        imode = 0;                  // start new search
                     }
                     else if( *(inextparam+1) == 0 )  // bracket at end
                     {
                        iindex++;
                        asargv[ iindex ] = icurparam;
                        *inextparam = 0;
                        break;
                     }
                     else
                     {
                        if(  *(inextparam+1) == '"' ) // double " remove one of it
                        {
                           memmove( inextparam+1 , inextparam + 2 , aparams + ireglen - inextparam - 1 );
                           inextparam += 1;
                        }
                        else
                        {
                           inextparam += 2;
                        }
                     }
                  }
               }
            }
         }
      }
      else
      {
         /* 04.08.04 KB + Joachim Frank */
//       printf( "Read registry error. regrc = %d\n", regrc );
         sprintf( byrl_cout, "HWSPM006W Read registry error. regrc = %d", regrc );
#ifndef TRACE_PRINTF
         cout << byrl_cout << endl;
#else
         EnterCriticalSection( &dss_critsect_printf );
         printf( "%s\n", (char *) byrl_cout );
         LeaveCriticalSection( &dss_critsect_printf );
#endif
      }
   } else {
//   printf( "IBIPGW08 started as non-service application.\n" );
#ifndef TRACE_PRINTF
     cout << "HWSPM003I IBIPGW08 started as non-service application.\n";
#else
     EnterCriticalSection( &dss_critsect_printf );
     printf( "HWSPM003I IBIPGW08 started as non-service application.\n" );
     LeaveCriticalSection( &dss_critsect_printf );
#endif
   }

   if (isargc != 2) {
     /* 04.08.04 KB + Joachim Frank */
//   printf( "Number of parameters invalid (*.xml)\n" );
#ifndef TRACE_PRINTF
     cout << "HWSPM004E Number of parameters invalid (*.xml)\n";
#else
     EnterCriticalSection( &dss_critsect_printf );
     printf( "HWSPM004E Number of parameters invalid (*.xml)\n" );
     LeaveCriticalSection( &dss_critsect_printf );
#endif
     if (boisservice) {
       dclasrvstat.dwCurrentState = SERVICE_STOPPED;  /* service clos  */
       SetServiceStatus( dclhsrvstat, &dclasrvstat );  /* set state    */
     }
     return;
   }
#ifdef TRACEHLA
   m_hlnew_printf( HLOG_XYZ1, "FD_READ = %d / FD_WRITE = %d / FD_CLOSE = %d",
                   FD_READ, FD_WRITE, FD_CLOSE );
   m_hlnew_printf( HLOG_XYZ1, "PTYPE:" PTYPE " ???" );
   iml1 = (int) time( NULL );
   ill1 = m_get_epoch_ms();
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_get_epoch_ms=%lld time=%d diff=%d.",
                   __LINE__, ill1, iml1, ill1 - iml1 * 1000 );
#endif
#ifdef TRACE_091013_01
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T dcl_tcp_r_c=%p dcl_tcp_r_s=%p.",
                   __LINE__,
                   offsetof( class clconn1, dcl_tcp_r_c ),
                   offsetof( class clconn1, dcl_tcp_r_s ) );
#endif
   /* prepare for time / epoch in microseconds                         */
   do {                                     /* pseudo-loop             */
     bol_rc = QueryPerformanceFrequency( (LARGE_INTEGER *) &ils_freq );
     if (bol_rc == FALSE) {                 /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d error QueryPerformanceFrequency() %d.",
                       __LINE__, GetLastError() );
       break;
     }
     bol_rc = QueryPerformanceCounter( (LARGE_INTEGER *) &ils_perform_start );  /* performance counter at start of WSP */
     if (bol_rc == FALSE) {                 /* error occured           */
       m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d error QueryPerformanceCounter() %d.",
                       __LINE__, GetLastError() );
       ils_freq = 0;                        /* do not use QueryPerformanceFrequency() */
     }
   } while (FALSE);
   /* fill data about this server                                      */
   dsg_this_server.ilc_epoch_started = m_get_epoch_ms();
   if (ils_freq != 0) {                     /* do use QueryPerformanceFrequency() */
     ils_epoch_start = dsg_this_server.ilc_epoch_started * 1000 + 500;  /* epoch microseconds at start of WSP */
   }
#ifndef B140819
   /* initialize random generator                                      */
   srand( (unsigned int) (m_get_epoch_ms() >> 7) );
#endif
#ifndef NEW_REPORT_1501
   dwl1 = sizeof(byarruwork1) / sizeof(WCHAR);
   bol1 = GetComputerNameExW( ComputerNameNetBIOS, (WCHAR *) byarruwork1, &dwl1 );
   if (bol1) {                              /* without error           */
     dsg_this_server.imc_len_server_name
       = m_cpy_vx_vx( dsg_this_server.chrc_server_name,
                      sizeof(dsg_this_server.chrc_server_name),
                      ied_chs_utf_8,
                      byarruwork1, dwl1, ied_chs_utf_16 );
   } else {                                 /* API returned error      */
     m_hlnew_printf( HLOG_WARN1, "HWSPM012W l%05d error GetComputerNameExW() %d.",
                     __LINE__, GetLastError() );
     dsg_this_server.imc_len_server_name = -1;
   }
#endif
#ifdef NEW_REPORT_1501
   dwl1 = sizeof(chrl_work1) / sizeof(WCHAR);
   bol1 = GetComputerNameExW( ComputerNameNetBIOS, (WCHAR *) chrl_work1, &dwl1 );
   if (bol1) {                              /* without error           */
     dsg_this_server.imc_len_server_name
       = m_cpy_vx_vx( dsg_this_server.chrc_server_name,
                      sizeof(dsg_this_server.chrc_server_name),
                      ied_chs_utf_8,
                      chrl_work1, dwl1, ied_chs_utf_16 );
   } else {                                 /* API returned error      */
     m_hlnew_printf( HLOG_WARN1, "HWSPM012W l%05d error GetComputerNameExW() %d.",
                     __LINE__, GetLastError() );
     dsg_this_server.imc_len_server_name = -1;
   }
#endif
   if (dsg_this_server.imc_len_server_name <= 0) {  /* no valid server name */
     strcpy( dsg_this_server.chrc_server_name, "???" );
     dsg_this_server.imc_len_server_name = 3;
   }
   dsg_this_server.imc_pid = GetCurrentProcessId();
   dsg_this_server.boc_endian_big = FALSE;  /* Windows - CPU is not big endian */
   dsg_this_server.imc_aligment = sizeof(void *);  /* aligment         */
   /* compute fingerprint / hash                                       */
   SHA1_Init( imrl_sha1 );
   SHA1_Update( imrl_sha1, dsg_this_server.chrc_server_name, 0, dsg_this_server.imc_len_server_name );
   SHA1_Update( imrl_sha1, (char *) &dsg_this_server.imc_pid, 0, sizeof(dsg_this_server.imc_pid) );
   SHA1_Update( imrl_sha1, (char *) &dsg_this_server.ilc_epoch_started, 0, sizeof(dsg_this_server.ilc_epoch_started) );
   iml1 = m_get_random_number( 0X010000 );
   SHA1_Update( imrl_sha1, (char *) &iml1, 0, sizeof(iml1) );
   SHA1_Final( imrl_sha1, dsg_this_server.chrc_fingerprint, 0 );
#ifdef EXAMINE_SIGN_ON_01                   /* 10.08.11 KB examine sign on time */
   ils_freq = 0;
   bol1 = QueryPerformanceFrequency( (LARGE_INTEGER *) &ils_freq );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPM IBIPGW08-l%05d-W error QueryPerformanceFrequency() error %d.",
                     __LINE__, GetLastError() );
   }
#endif
   /* priority of process                                              */
   ims_priority_process = DEF_PRIO_DEFAULT;
   memset( &dss_ser_thr_ctrl, 0, sizeof(dss_ser_thr_ctrl) );  /* control serial thread */
   memset( &dss_wsp_trace_thr_ctrl, 0, sizeof(dss_wsp_trace_thr_ctrl) );  /* control WSP trace thread */
#ifdef B080324
   ds_blade_control.boc_blade_active = FALSE;  /* blade funct not act  */
#endif
   memset( &dss_loconf_1_first, 0, sizeof(struct dsd_loconf_1) );
   /* anchor of loaded configurations                                  */
   adss_loconf_1_anchor = &dss_loconf_1_first;
   /* loaded configurations that are filled now                        */
   adss_loconf_1_fill = &dss_loconf_1_first;
   /* loaded configurations that are in use now                        */
   adsg_loconf_1_inuse = &dss_loconf_1_first;
   // Initialize the XML4C system
   memset( localeStr, 0, sizeof localeStr );
    try
    {
        if (strlen(localeStr))
        {
            XMLPlatformUtils::Initialize(localeStr);
        }
        else
        {
            XMLPlatformUtils::Initialize();
        }

        if (recognizeNEL)
        {
            XMLPlatformUtils::recognizeNEL(recognizeNEL);
        }
    }

    catch (const XMLException& toCatch)
    {
      m_hlnew_printf( HLOG_EMER1, "HWSPM010W Error during XERCES-initialization: %s",
                      toCatch.getMessage() );
      m_hlnew_printf( HLOG_EMER1, "HWSPM011E Gateway could not start because exception in XERCES initialization" );
      if (boisservice) {
        dclasrvstat.dwCurrentState = SERVICE_STOPPED;  /* service clos  */
        SetServiceStatus( dclhsrvstat, &dclasrvstat );  /* set state    */
      }
      return;
    }

   iml1 = GetFullPathNameA( asargv[1], 0, NULL, NULL );
   if (iml1 == 0) {
     m_hlnew_printf( HLOG_EMER1, "HWSPM020W error GetFullPathName( %s ) 1 : %d - abend",
                     asargv[1], GetLastError() );
     m_end_proc();
     return;
   }
   adss_path_param = (char *) malloc( iml1 );
   iml2 = GetFullPathNameA( asargv[1], iml1, adss_path_param, &adsl_path_fn );
   if (iml2 == 0) {
     m_hlnew_printf( HLOG_EMER1, "HWSPM021W error GetFullPathName( %s ) 2 : %d - abend",
                     asargv[1], GetLastError() );
     m_end_proc();
     return;
   }
   if (iml2 >= iml1) {
     m_hlnew_printf( HLOG_EMER1, "HWSPM022W error GetFullPathName( %s ) 3 : %d / %d - abend",
                     asargv[1], iml1, iml2 );
     m_end_proc();
     return;
   }
   bol1 = GetFileAttributesExA( adss_path_param, GetFileExInfoStandard, &dsl_fi_c );
   if (bol1 == FALSE) {
     dwl1 = GetLastError();
     if (dwl1 == ERROR_FILE_NOT_FOUND) {
       m_hlnew_printf( HLOG_EMER1, "HWSPM025W error file \"%s\" not found - abend",
                       adss_path_param );
     } else {                               /* other error             */
       m_hlnew_printf( HLOG_EMER1, "HWSPM023W error GetFileAttributesExA( %s ) : %d - abend",
                       adss_path_param, dwl1 );
     }
     m_end_proc();
     return;
   }
   /* save time last written - last modified                           */
   memcpy( &dsl_ft_lastmod, &dsl_fi_c.ftLastWriteTime, sizeof(dsl_ft_lastmod) );
   /* process the configuration                                        */
   bol1 = m_proc_conf( TRUE );              /* process the configuration */
   if (bol1 == FALSE) {
     m_hlnew_printf( HLOG_EMER1, "HWSPM024W could not process the configuration ( %s ) - abend",
                     asargv[1] );
     m_end_proc();
     return;
   }
#ifdef TRY_HSM_1007
#ifndef NEW_REPORT_1501
   int iml_rc, iml_error;
#endif
#ifdef NEW_REPORT_1501
   int iml_error;
#endif
   iml_rc = dss_ser_thr_ctrl.dsc_event_thr.m_create( &iml_error );  /* event for serial thread */
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d event serial m_create Return Code %d Error %d.",
                     __LINE__, iml_rc, iml_error );
   }
   iml_rc = dss_ser_thr_ctrl.dsc_thread.mc_create( &m_serial_thread, NULL );
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d CreateThread Serial Error", __LINE__ );
   }
#endif

   if (dss_loconf_1_first.adsc_gate_anchor == NULL) {  /* anchor for chain gates */
     m_hlnew_printf( HLOG_EMER1, "HWSPM030W Gateway not started because no connections in configuration file" );
     m_end_proc();
     return;
   }
#ifdef NEW_REPORT_1501
   iml1 = adsg_loconf_1_inuse->inc_report_intv;
   if (iml1 == 0) {
     goto pmt_bc_80;                        /* end of bandwidth client */
   }
   /* number of entries                                                */
   iml2 = (iml1 + DEF_BANDWIDTH_CLIENT_SECS - 1) / DEF_BANDWIDTH_CLIENT_SECS;
   iml_rc = dss_bc_ctrl.dsc_critsect.m_create();
   if (iml_rc < 0) {                        /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_bc_ctrl.dsc_critsect m_create Return Code %d",
                     __LINE__, iml_rc );
   }
   dss_bc_ctrl.adsrc_bc1[ 0 ]
     = (struct dsd_bandwidth_client_1 *) malloc( 2 * (sizeof(struct dsd_bandwidth_client_1)
                                                        + 2 * iml2 * sizeof(int)
                                                        + 2 * iml2 * sizeof(HL_LONGLONG)) );
   dss_bc_ctrl.adsrc_bc1[ 0 ]->dsc_time_start = m_get_time();  /* current time */
   dss_bc_ctrl.adsrc_bc1[ 0 ]->imc_no_entries = iml2;  /* number of entries */
   dss_bc_ctrl.adsrc_bc1[ 0 ]->aimc_p_sent  /* number of packets sent  */
     = (int *) (dss_bc_ctrl.adsrc_bc1[ 0 ] + 1);
   dss_bc_ctrl.adsrc_bc1[ 0 ]->aimc_p_recv  /* number of packets received */
     = (int *) (dss_bc_ctrl.adsrc_bc1[ 0 ] + 1) + iml2;
   dss_bc_ctrl.adsrc_bc1[ 0 ]->ailc_d_sent  /* count bytes data sent   */
     = (HL_LONGLONG *) ((char *) dss_bc_ctrl.adsrc_bc1[ 0 ]
                          + sizeof(struct dsd_bandwidth_client_1)
                          + 2 * iml2 * sizeof(int));
   dss_bc_ctrl.adsrc_bc1[ 0 ]->ailc_d_recv  /* count bytes data received */
     = (HL_LONGLONG *) ((char *) dss_bc_ctrl.adsrc_bc1[ 0 ]
                          + sizeof(struct dsd_bandwidth_client_1)
                          + 2 * iml2 * sizeof(int)
                          + iml2 * sizeof(HL_LONGLONG));
   memset( dss_bc_ctrl.adsrc_bc1[ 0 ] + 1,
           0,
           2 * iml2 * sizeof(int)
             + 2 * iml2 * sizeof(HL_LONGLONG) );
   dss_bc_ctrl.adsrc_bc1[ 1 ]
     = (struct dsd_bandwidth_client_1 *) ((char *) dss_bc_ctrl.adsrc_bc1[ 0 ]
                                            + sizeof(struct dsd_bandwidth_client_1)
                                            + 2 * iml2 * sizeof(int)
                                            + 2 * iml2 * sizeof(HL_LONGLONG));
   dss_bc_ctrl.adsrc_bc1[ 1 ]->imc_no_entries = iml2;  /* number of entries */
   dss_bc_ctrl.adsrc_bc1[ 1 ]->aimc_p_sent  /* number of packets sent  */
     = (int *) (dss_bc_ctrl.adsrc_bc1[ 1 ] + 1);
   dss_bc_ctrl.adsrc_bc1[ 1 ]->aimc_p_recv  /* number of packets received */
     = (int *) (dss_bc_ctrl.adsrc_bc1[ 1 ] + 1) + iml2;
   dss_bc_ctrl.adsrc_bc1[ 1 ]->ailc_d_sent  /* count bytes data sent   */
     = (HL_LONGLONG *) ((char *) dss_bc_ctrl.adsrc_bc1[ 1 ]
                          + sizeof(struct dsd_bandwidth_client_1)
                          + 2 * iml2 * sizeof(int));
   dss_bc_ctrl.adsrc_bc1[ 1 ]->ailc_d_recv  /* count bytes data received */
     = (HL_LONGLONG *) ((char *) dss_bc_ctrl.adsrc_bc1[ 1 ]
                          + sizeof(struct dsd_bandwidth_client_1)
                          + 2 * iml2 * sizeof(int)
                          + iml2 * sizeof(HL_LONGLONG));
   /* save values for reload of configuration                          */
   dss_bc_ctrl.adsc_bc1_mem = dss_bc_ctrl.adsrc_bc1[ 0 ];  /* measure bandwidth with clients */
   dss_bc_ctrl.imc_report_intv = iml1;      /* saved interval in seconds */
   dss_bc_ctrl.boc_critsect_init = TRUE;    /* critical section has been initialized */

   pmt_bc_80:                               /* end of bandwidth client */
#endif

   if (dss_loconf_1_first.boc_reload_conf) {  /* with reload configuration */
     achl1 = adss_path_param;               /* address source          */
#ifndef NEW_REPORT_1501
     achl2 = byarruwork1;                   /* address target          */
#endif
#ifdef NEW_REPORT_1501
     achl2 = chrl_work1;                    /* address target          */
#endif
     achl3 = NULL;                          /* no separator yet        */
     while (TRUE) {                         /* loop over input data    */
#ifndef NEW_REPORT_1501
       if (achl2 == (byarruwork1 + sizeof(byarruwork1) - 1)) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPM031W Path Configuration File too long" );
         *achl2 = 0;                        /* make zero-terminated    */
         break;
       }
#endif
#ifdef NEW_REPORT_1501
       if (achl2 == (chrl_work1 + sizeof(chrl_work1) - 1)) {
         m_hlnew_printf( HLOG_WARN1, "HWSPM031W Path Configuration File too long" );
         *achl2 = 0;                        /* make zero-terminated    */
         break;
       }
#endif
       *achl2 = *achl1;                     /* copy character          */
       if (*achl1 == 0) break;              /* at end of input         */
       if (*achl2 == '\\') {                /* at separator            */
         achl3 = achl2;                     /* save position separator */
       }
       achl1++;                             /* increment input         */
       achl2++;                             /* increment output        */
     }
     if (achl3) *achl3 = 0;                 /* end at last separator   */
#ifndef NEW_REPORT_1501
     dsrs_heve_main[1] = FindFirstChangeNotificationA( byarruwork1,
                                                       FALSE,
                                                       FILE_NOTIFY_CHANGE_LAST_WRITE |
                                                       FILE_NOTIFY_CHANGE_SIZE |
                                                       FILE_NOTIFY_CHANGE_FILE_NAME
                                                     );
#endif
#ifdef NEW_REPORT_1501
     dsrs_heve_main[1] = FindFirstChangeNotificationA( chrl_work1,
                                                       FALSE,
                                                       FILE_NOTIFY_CHANGE_LAST_WRITE |
                                                       FILE_NOTIFY_CHANGE_SIZE |
                                                       FILE_NOTIFY_CHANGE_FILE_NAME
                                                     );
#endif
     if (dsrs_heve_main[1] == INVALID_HANDLE_VALUE) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPM032W FindFirstChangeNotification() returned %d", GetLastError());
     }
   }

   m_gw_udp_update( &dss_loconf_1_first );
#ifdef D_INCL_HOB_TUN
   m_gw_start_htun( dss_loconf_1_first.adsc_raw_packet_if_conf );
#endif
#ifndef PROBLEM_140406_01
   bol1 = m_start_monitor_thread();
   if (bol1 == FALSE) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM181W l%05d start monitor performance parameter failed", __LINE__ );
   }
#endif
#ifdef WSP_CLUSTER_DISP_LOAD
   if (dss_loconf_1_first.adsc_cluster) {
     dss_loconf_1_first.adsc_cluster->boc_display_load = TRUE;  /* display load every time calculated */
   }
#endif
   m_cluster_start( dss_loconf_1_first.adsc_cluster );
#ifdef INCL_TEST_RPC
// m_rpc_start();
#endif
   adsl_gate_1_w1 = dss_loconf_1_first.adsc_gate_anchor;  /* get anchor gate */
   while (adsl_gate_1_w1) {                 /* loop over all gates     */
     m_start_listen( adsl_gate_1_w1 );      /* start listen            */
     adsl_gate_1_w1 = adsl_gate_1_w1->adsc_next;
   }
   dsg_sys_state_1.boc_listen_active = TRUE;  /* listen is currently active */
   m_hlnew_printf( HLOG_INFO1, "HWSPM180I l%05d WebSecureProxy initialization done", __LINE__ );

   /* start timer thread                                               */
#ifdef B060628
   rcu = dss_thread_timer.mc_create( &m_timer_thr, NULL );
   if (rcu < 0) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM034W l%05d CreateThread Timer Error", __LINE__ );
   }
#endif
   time( &dsl_time_1 );                     /* get current time        */
   dsl_time_last_report = dsl_time_1;       /* set time of last report */
   dsl_time_read_conf = 0;                  /* time to read configuration */
   dsl_time_cma_check = dsl_time_1 + DEF_TIME_CMA_CHECK;  /* time to check CMA entries */
//#ifdef XYZ1
#ifdef NEW_REPORT_1501
   dsl_time_fingerprint = 0;                /* time to print fingerprint in report */
#endif
//#endif

   /* wait for program to be ended                                     */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "wait for dsrs_heve_main[0] - start" );
#endif

   pmtend20:                                /* loop report + config + end */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d pmtend20: time cur=%lld cma_check=%lld fingerprint=%lld read_conf=%lld.",
                   __LINE__,
                   (HL_LONGLONG) dsl_time_1,
                   (HL_LONGLONG) dsl_time_cma_check,
                   (HL_LONGLONG) dsl_time_fingerprint,
                   (HL_LONGLONG) dsl_time_read_conf );
   dwl1 = 0;
#endif
   dwl_wait = (dsl_time_cma_check - dsl_time_1) * 1000;
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d pmtend20: after cma         dwl_wait=%d dwl1=%d.",
                   __LINE__, dwl_wait, dwl1 );
#endif
   if (adsg_loconf_1_inuse->inc_report_intv > 0) {
     dwl1 = ((dsl_time_last_report + adsg_loconf_1_inuse->inc_report_intv) - dsl_time_1) * 1000;
     if (dwl_wait > dwl1) {
       dwl_wait = dwl1;                     /* set wait time report    */
     }
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d pmtend20: after report-intv dwl_wait=%d dwl1=%d.",
                   __LINE__, dwl_wait, dwl1 );
#endif
#ifdef NEW_REPORT_1501
#ifdef XYZ1
   if (dsl_time_fingerprint) {              /* time to print fingerprint in report */
     dwl1 = (dsl_time_fingerprint - dsl_time_1) * 1000;
     if (dwl_wait > dwl1) {
       dwl_wait = dwl1;                     /* set wait time report    */
     }
   }
#endif
   dsl_time_fingerprint = 0;                /* time to print fingerprint in report */
   if (adsg_loconf_1_inuse->imc_tod_mark_log) {  /* <time-of-day-mark-log> seconds from midnight, +1 */
     m_time_fingerprint( &dsl_time_fingerprint, &dsl_time_1 );
     dwl1 = (dsl_time_fingerprint - dsl_time_1) * 1000;
     if (dwl_wait > dwl1) {
       dwl_wait = dwl1;                     /* set wait time report    */
     }
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d pmtend20: after fingerprint dwl_wait=%d dwl1=%d.",
                   __LINE__, dwl_wait, dwl1 );
#endif
#endif
   if (dsl_time_read_conf) {                /* time set to reload configuration */
     dwl1 = (dsl_time_read_conf - dsl_time_1) * 1000;
     if (dwl_wait > dwl1) {
       dwl_wait = dwl1;                     /* set wait time reload conf */
     }
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "l%05d pmtend20: after read-conf   dwl_wait=%d dwl1=%d.",
                   __LINE__, dwl_wait, dwl1 );
#endif
#ifdef TRACEHLD
   m_hlnew_printf( HLOG_XYZ1, "Report-Intv %d dwl_wait %08X", adsg_loconf_1_inuse->inc_report_intv, dwl_wait );
#endif

   /* wait for end or timer                                            */
   iml1 = 1;                                /* only posted when end program */
   if (dsrs_heve_main[1] != INVALID_HANDLE_VALUE) {
     iml1 = 2;                              /* get notified when file changed */
   }
   dwl1 = WaitForMultipleObjects( iml1, dsrs_heve_main, FALSE, dwl_wait );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "wait for dsrs_heve_main[0] - end dwl1=%d", dwl1 );
#endif
   time( &dsl_time_1 );                     /* get current time        */
   if (dsl_time_1 >= dsl_time_cma_check) {  /* time now for CMA check  */
     m_cma1_free_old_e();                   /* remove old entries      */
     dsl_time_cma_check = dsl_time_1 + DEF_TIME_CMA_CHECK;  /* time to check CMA entries */
   }
   if (dwl1 != (WAIT_OBJECT_0 + 1)) goto pmtend40;  /* file did not change */
   dwl1 = WAIT_OBJECT_0 + 0;                /* no error message later  */
   bol1 = FindNextChangeNotification( dsrs_heve_main[1] );  /* reset wait condition */
   if (bol1 == FALSE) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM035W error FindNextChangeNotification() : %d - ignore",
                     GetLastError() );
   }
   /* check if configuration file has changed                          */
   bol1 = GetFileAttributesExA( adss_path_param, GetFileExInfoStandard, &dsl_fi_c );
   if (bol1 == FALSE) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM036W error GetFileAttributesExA( %s ) : %d - ignore",
                     adss_path_param, GetLastError() );
     dsl_time_read_conf = 0;                /* do not read configuration file */
     goto pmtend60;                         /* do not reload configuration file */
   }
   if (!memcmp( &dsl_ft_lastmod, &dsl_fi_c.ftLastWriteTime, sizeof(dsl_ft_lastmod) )) {
     /* file did not change                                            */
     goto pmtend40;                         /* check reload configuration file */
   }
   /* save time last written - last modified                           */
   memcpy( &dsl_ft_lastmod, &dsl_fi_c.ftLastWriteTime, sizeof(dsl_ft_lastmod) );
   dsl_time_read_conf = dsl_time_1 + DEF_DELAY_RELOAD_CONF_FILE;  /* add delay in seconds */

   pmtend40:                                /* check reload configuration file */
   if ((dwl1 != WAIT_TIMEOUT) && (dwl1 != WAIT_OBJECT_0)) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM037W error main() WaitForMultipleObjects() Return %d Error %d.", dwl1, GetLastError() );
   }
   if (   (dsl_time_read_conf == 0)
       || (dsl_time_read_conf > dsl_time_1)) {
     goto pmtend60;                         /* do not reload configuration file */
   }
   /* reload configuration file now                                    */
   m_hlnew_printf( HLOG_INFO1, "HWSPM038I reload configuration file in progress" );
   dsl_time_read_conf = 0;                  /* file has been loaded    */
   if (   (adsg_loconf_1_inuse->boc_reload_conf == FALSE)  /* without reload configuration */
       && (dsrs_heve_main[1] != INVALID_HANDLE_VALUE)) {
     bol1 = FindCloseChangeNotification( dsrs_heve_main[1] );  /* close wait condition */
     if (bol1 == FALSE) {
       m_hlnew_printf( HLOG_WARN1, "HWSPM039W error FindCloseChangeNotification() : %d - ignore",
                       GetLastError() );
     }
     dsrs_heve_main[1] = INVALID_HANDLE_VALUE;
   }
   m_loconf_reset( adsg_loconf_1_inuse );   /* close listen sockets    */
   adss_loconf_1_fill = (struct dsd_loconf_1 *) malloc( sizeof(struct dsd_loconf_1) );
   memset( adss_loconf_1_fill, 0, sizeof(struct dsd_loconf_1) );
   bol1 = m_proc_conf( FALSE );             /* process the configuration */
   if (bol1 == FALSE) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM024W could not process the configuration ( %s ) - ignored",
                     asargv[1] );
     adss_loconf_1_fill->adsc_gate_anchor = NULL;  /* no more chain gates */
     goto pmtend60;                         /* all done with reload configuration file */
   }
   m_gw_udp_update( adss_loconf_1_fill );
#ifdef B130828
#ifdef D_INCL_HOB_TUN
#ifdef B130825
   m_gw_start_htun( adss_loconf_1_fill->adsc_raw_packet_if_conf );
#else
   m_gw_start_htun( adss_loconf_1_fill->adsc_raw_packet_if_conf, iml_tun_instance );
#endif
#endif
#endif
   adsg_loconf_1_inuse = adss_loconf_1_fill;  /* used filled configuration now */
   adsg_loconf_1_inuse->adsc_next = adss_loconf_1_anchor;  /* get old chain */
   adss_loconf_1_anchor = adsg_loconf_1_inuse;  /* set new anchor      */

   bos_mem_log = m_create_log( adsg_loconf_1_inuse->ilc_mem_ls );

#ifndef DEBUG_HOB_TUN_1407
#ifdef D_INCL_HOB_TUN
   m_gw_start_htun( adsg_loconf_1_inuse->adsc_raw_packet_if_conf );
#endif
#endif

   m_admin_reload_conf();

   if (adsg_loconf_1_inuse->adsc_gate_anchor == NULL) {  /* anchor for chain gates */
     m_hlnew_printf( HLOG_WARN1, "HWSPM063W Gateway does not take sessions because no connections in configuration file" );
   } else {
#ifdef WSP_CLUSTER_DISP_LOAD
     if (adsg_loconf_1_inuse->adsc_cluster) {
       adsg_loconf_1_inuse->adsc_cluster->boc_display_load = TRUE;  /* display load every time calculated */
     }
#endif
     m_cluster_start( adsg_loconf_1_inuse->adsc_cluster );

     /* start SWAP-STOR                                                */
     m_swap_stor_open();

#ifdef B080407
     audgate1 = adsg_loconf_1_inuse->adsc_gate_anchor;  /* get anchor gate */
     while (audgate1) {                     /* loop over all gates     */
#ifdef OLD01
       rcu = audgate1->clthaccept.Create( &TCPAThread, audgate1 );
#endif
       rcu = audgate1->clthaccept.mc_create( &TCPAThread, audgate1 );
       if (rcu < 0) {
         m_hlnew_printf( HLOG_WARN1, "HWSPM064W CreateThread TCPA Error" );
       }
       audgate1 = audgate1->adsc_next;
     }
#endif
#ifdef B101102
/* Mr. Jakobs 02.11.10 - reload configuration does not open all ports for listen */
     iml1 = m_start_all_listen( dsg_sys_state_1.boc_listen_active );
#else
     iml1 = m_start_all_listen( FALSE );
#endif
     m_hlnew_printf( HLOG_INFO1, "HWSPM068I reload configuration listen started ports %d.",
                     iml1 );
   }

   pmtend60:                                /* end or report           */
   if (   (   (adsg_loconf_1_inuse->inc_report_intv == 0)
           || ((dsl_time_last_report + adsg_loconf_1_inuse->inc_report_intv) > dsl_time_1))
#ifdef NEW_REPORT_1501
       && (   (dsl_time_fingerprint == 0)
           || (dsl_time_fingerprint > dsl_time_1))
#endif
       && (bos_end_proc == FALSE)) {
     goto pmtend20;                         /* do not display report   */
   }
#ifndef NEW_REPORT_1501
   dsl_time_last_report = dsl_time_1;       /* set time of last report */
   strftime( byarruwork1, sizeof(byarruwork1),
             "%a %B %d %Y %H:%M:%S %Z",
             localtime( &dsl_time_1 ) );
   byarruwork2[0] = 0;                      /* no text queue           */
   if (dsg_hco_main.imc_workque_max_no) {   /* work queue maximum      */
     memcpy( byarruwork2, " at time: ", 10 );
     strftime( byarruwork2 + 10, sizeof(byarruwork2) - 10,
               "%a %B %d %Y %H:%M:%S %Z",
               localtime( &dsg_hco_main.dsc_workque_max_time ) );
   }
   m_hlnew_printf( HLOG_INFO1, "HWSPR001I Report %s / number of Work Threads %d - scheduled %d - busy %d - current queue %d - longest queue %d%s",
                   byarruwork1,
                   dsg_hco_main.imc_workthr_alloc, dsg_hco_main.imc_workthr_sched,
                   dsg_hco_main.imc_workthr_active,
                   dsg_hco_main.imc_workque_sched,
                   dsg_hco_main.imc_workque_max_no, byarruwork2 );
#ifdef TRACEHLD
   {
     int ih1 = 0;                           /* count threads           */
     audclworkth1 = adss_workth_1_anchor;   /* get anchor of chain     */
     while (audclworkth1) {                 /* loop over all threads   */
       m_hlnew_printf( HLOG_XYZ1, "+++ check thread thrid=%d no=%d / %08X clconn1=%p act=%p time=%08X",
                         audclworkth1->getthrid(),
                         ih1 + 1, audclworkth1,
                         audclworkth1->ad_clconn1,
                         audclworkth1->trace_act, audclworkth1->trace_time );
       ih1++;
       audclworkth1 = audclworkth1->getnext();  /* get next in chain   */
     }
   }
#endif
#ifdef TRACEHLX
   cl_tcp_r::report_thread_mrecv();         /* display receive thr     */
#endif
   m_get_perf_data( &dss_perf_data );
   m_edit_sci_two( byarruwork1, dss_perf_data.ulc_memory );
   m_edit_sci_dec( byarruwork2, dss_perf_data.ulc_io_total_ops );
   m_edit_sci_two( byarruwork3, dss_perf_data.ulc_io_total_bytes );
   m_hlnew_printf( HLOG_INFO1, "HWSPR002I Report Performance / elapsed CPU time %d sec / virt-stor %sB / I-O %s %sB.",
                   (int) ((dss_perf_data.ulc_cpu_total_time + 500) / 1000), byarruwork1, byarruwork2, byarruwork3 );
   if (bos_disk_file) {                     /* did access disk file    */
     iml1 = iml2 = ill1 = 0;                /* reset counters          */
     adsl_df1_1 = adss_df1_anchor;          /* get anchor of files     */
     while (adsl_df1_1) {                   /* loop over all files in cache */
       iml1++;                              /* count the files         */
       if (adsl_df1_1->dsc_int_df1.achc_filecont_start) {  /* file in memory */
         iml2++;                            /* count the files         */
         /* add size of this file  */
         ill1 += adsl_df1_1->dsc_int_df1.achc_filecont_end
                   - adsl_df1_1->dsc_int_df1.achc_filecont_start;
       }
       adsl_df1_1 = adsl_df1_1->adsc_next;  /* get next in chain       */
     }
     m_edit_sci_two( byarruwork1, ill1 );
     m_hlnew_printf( HLOG_INFO1, "HWSPR005I Report cached disk files number %d / %d with data - size in memory: %sB.",
                     iml1, iml2, byarruwork1 );
   }
   m_cma1_statistics( &iml1, &ill1 );       /* get statistics          */
   if (iml1) {                              /* entries in CMA          */
     m_edit_sci_two( byarruwork1, ill1 );
     m_hlnew_printf( HLOG_INFO1, "HWSPR006I Report CMA common memory area %d entries - size in memory: %sB.",
                     iml1, byarruwork1 );
   }
   m_cluster_report( &dsl_cluster_report );  /* cluster report structure */
   if (dsl_cluster_report.boc_cluster_active) {  /* cluster is active  */
     achl1 = "active";
     if (dsg_sys_state_1.boc_listen_active == FALSE) {
       achl1 = "closed";
     }
     m_hlnew_printf( HLOG_INFO1, "HWSPR008I Report Cluster active connections %d - this group %d - listen %s.",
                     dsl_cluster_report.imc_no_cluster_active,  /* number of active cluster connections */
                     dsl_cluster_report.imc_no_same_group,  /* number of active cluster connections same group */
                     achl1 );
   }
   if (dss_ets_pttd.imc_no_started > 0) {   /* pass-thru-to-desktop - number of instances started */
     ill1 = dss_ets_pttd.ilc_sum_time_ms;   /* summary time executed in milliseconds */
     if (dss_ets_pttd.adsc_ete_ch) {        /* chain extra thread entries */
       adsl_ete_w1 = dss_ets_pttd.adsc_ete_ch;  /* chain extra thread entries */
       ill2 = m_get_epoch_ms();             /* get current time        */
       while (adsl_ete_w1) {                /* loop over chain extra thread entries */
         ill1 += ill2 - adsl_ete_w1->ilc_time_started_ms;  /* time / epoch started in milliseconds */
         adsl_ete_w1 = adsl_ete_w1->adsc_next;  /* get next in chain   */
       }
     }
     achl1 = m_edit_dec_long( chrl_ns_num, ill1 );
     m_hlnew_printf( HLOG_INFO1, "HWSPR010I Report extra threads - desktop-on-demand - currently-running=%d started=%d start-denied=%d time-running-milliseconds=%s.",
                     dss_ets_pttd.imc_no_current,  /* number of instances currently executing */
                     dss_ets_pttd.imc_no_started,  /* number of instances started */
                     dss_ets_pttd.imc_no_denied,   /* number of start requests denied */
                     achl1 );
   }
   if (dss_ets_ut.imc_no_started > 0) {     /* utility threads - number of instances started */
     ill1 = dss_ets_ut.ilc_sum_time_ms;     /* summary time executed in milliseconds */
     if (dss_ets_ut.adsc_ete_ch) {          /* chain extra thread entries */
       adsl_ete_w1 = dss_ets_ut.adsc_ete_ch;  /* chain extra thread entries */
       ill2 = m_get_epoch_ms();             /* get current time        */
       while (adsl_ete_w1) {                /* loop over chain extra thread entries */
         ill1 += ill2 - adsl_ete_w1->ilc_time_started_ms;  /* time / epoch started in milliseconds */
         adsl_ete_w1 = adsl_ete_w1->adsc_next;  /* get next in chain   */
       }
     }
     achl1 = m_edit_dec_long( chrl_ns_num, ill1 );
     m_hlnew_printf( HLOG_INFO1, "HWSPR011I Report extra threads - utility threads   - currently-running=%d started=%d start-denied=%d time-running-milliseconds=%s.",
                     dss_ets_ut.imc_no_current,  /* number of instances currently executing */
                     dss_ets_ut.imc_no_started,  /* number of instances started */
                     dss_ets_ut.imc_no_denied,   /* number of start requests denied */
                     achl1 );
   }
   adsl_loconf_1_1 = adss_loconf_1_anchor;  /* get anchor loaded conf  */
   do {
     m_hlnew_printf( HLOG_INFO1, "HWSPR003I configuration loaded %s", adsl_loconf_1_1->byrc_time );
     audgate1 = adsl_loconf_1_1->adsc_gate_anchor;  /* get anchor gate */
     while (audgate1) {
       byarruwork1[0] = 0;                  /* make zero string        */
       if (audgate1->i_session_max) {
         sprintf( byarruwork1, " max-session-conf=%d max-session-exceeded=%d",
                  audgate1->i_session_max, audgate1->i_session_exc );
       }
       m_hlnew_printf( HLOG_INFO1, "HWSPR004I GATE=%(ux)s report - current sessions=%d start session requests=%d number of session maximum reached=%d%s.",
                       audgate1 + 1,
                       audgate1->i_session_cur, audgate1->i_session_cos, audgate1->i_session_mre,
                       byarruwork1 );
       audgate1 = audgate1->adsc_next;
     }
     adsl_loconf_1_1 = adsl_loconf_1_1->adsc_next;  /* get next in chain */
   } while (adsl_loconf_1_1);               /* over all configurations */
   /* background-task statistics                                       */
   adsl_bgt_contr_1 = adsg_loconf_1_inuse->adsc_bgt_contr_1;  /* chain background-task control */
   while (adsl_bgt_contr_1) {               /* loop over background-tasks */
     adsl_bgt_function_1 = adsl_bgt_contr_1->adsc_bgt_function_1;  /* chain background-task functions */
     do {                                   /* loop over background-task functions */
       if (adsl_bgt_function_1->iec_bgtf == ied_bgtf_stat) {  /* called for statistic */
         memset( &dsl_aux_cf1, 0, sizeof(struct dsd_aux_cf1) );  /* auxiliary control structure */
#ifdef B130314
         dsl_aux_cf1.iec_src_func = ied_src_fu_bgt_stat;  /* background-task for statistic */
#endif
         dsl_aux_cf1.dsc_cid.iec_src_func = ied_src_fu_bgt_stat;  /* background-task for statistic */
         memset( &dsl_bgt_call_1, 0, sizeof(struct dsd_bgt_call_1) );  /* Background-Task Call */
         dsl_bgt_call_1.imc_func = DEF_IFUNC_CONT;  /* process data as specified */
         dsl_bgt_call_1.ac_conf = adsl_bgt_contr_1->ac_conf;  /* data from configuration */
         dsl_bgt_call_1.vpc_userfld = &dsl_aux_cf1;  /* auxiliary control structure */
         dsl_bgt_call_1.amc_aux = &m_cdaux;  /* subroutine             */
         dsl_bgt_call_1.adsc_bgt_function_1 = adsl_bgt_function_1;  /* called for background-task function */
         adsl_bgt_contr_1->adsc_ext_lib1->amc_bgt_entry( &dsl_bgt_call_1 );
       }
       adsl_bgt_function_1 = adsl_bgt_function_1->adsc_next;  /* get next in chain */
     } while (adsl_bgt_function_1);
     adsl_bgt_contr_1 = adsl_bgt_contr_1->adsc_next;  /* get next in chain */
   }
#ifdef TRACEHL_P_COUNT
   {
     adsl_df1_1 = adss_df1_anchor;          /* get anchor of files     */
     while (adsl_df1_1) {                   /* loop over all files in cache */
       m_hlnew_printf( HLOG_XYZ1, "disk-file adsl_df1_1=%p inc_usage_count=%d boc_superseeded=%d"
                   " iec_difi_def=%d ipc_time_last_acc=%d/%08X ipc_time_last_checked=%d/%08X"
                   " achc_filecont_start=%p name=%S",
                   adsl_df1_1,
                   adsl_df1_1->inc_usage_count,
                   adsl_df1_1->boc_superseeded,
                   adsl_df1_1->iec_difi_def,
                   adsl_df1_1->ipc_time_last_acc,
                   adsl_df1_1->ipc_time_last_acc,
                   adsl_df1_1->ipc_time_last_checked,
                   adsl_df1_1->ipc_time_last_checked,
                   adsl_df1_1->dsc_int_df1.achc_filecont_start,
                   adsl_df1_1->dsc_int_df1.awcc_name );
       adsl_df1_1 = adsl_df1_1->adsc_next;    /* get next in chain       */
     }
   }
#endif
//ifdef TRACEHL_P_DISP
#ifdef TRACEHL_P_COUNT
   m_hlnew_printf( HLOG_XYZ1, "ins_count_buf_in_use=%d ins_count_buf_max=%d ins_count_memory=%d.",
                   ins_count_buf_in_use, ins_count_buf_max, ins_count_memory );
#endif
#ifdef TRACEHL_P_050118
   m_hlnew_printf( HLOG_XYZ1, "ims_p_050118 = %d.", ims_p_050118 );
#endif
#ifdef TRACEHL_WA_COUNT                     /* 17.09.09 KB count work area inc / dec */
   m_hlnew_printf( HLOG_XYZ1, "l%05d work area inc=%d dec=%d diff=%d.",
                   __LINE__, ims_count_wa_inc, ims_count_wa_dec, ims_count_wa_inc - ims_count_wa_dec );
#endif
#ifdef TRACEHL_TCP_BLOCK                    /* 18.07.07 KB count TCP blocking */
   m_hlnew_printf( HLOG_XYZ1, "Report l%05d ims_trace_block_send=%d ims_trace_block_may=%d ims_trace_block_retry=%d.",
                   __LINE__,
                   ims_trace_block_send, ims_trace_block_may, ims_trace_block_retry );
#endif /* TRACEHL_TCP_BLOCK                    18.07.07 KB count TCP blocking */
#ifdef TRACEHL_STOR_USAGE
   {
     int imh1, imh2;
     struct dsd_tr_stor_usage_01 *adsl_tr_stor_usage_01_h1;
     EnterCriticalSection( &dsalloc_dcritsect );
     adsl_tr_stor_usage_01_h1 = adss_tr_stor_usage_01_anchor;
     while (adsl_tr_stor_usage_01_h1) {
#define ADSL_SDHC1_G ((struct dsd_sdh_control_1 *) (adsl_tr_stor_usage_01_h1 + 1))
       m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-STOR-USAGE-l%05d stor=%p stack=%p chrc_pos=%s adsc_next=%p adsc_gather_i_1_i=%p inc_function=%p inc_position=%p boc_ready_t_p=%p imc_usage_count=%p.",
                       __LINE__, adsl_tr_stor_usage_01_h1, adsl_tr_stor_usage_01_h1->ac_stack, adsl_tr_stor_usage_01_h1->chrc_pos,
                       ADSL_SDHC1_G->adsc_next,  /* field for chaining */
                       ADSL_SDHC1_G->adsc_gather_i_1_i,  /* gather input data */
                       ADSL_SDHC1_G->inc_function,  /* function of SDH */
                       ADSL_SDHC1_G->inc_position,  /* position of SDH */
                       ADSL_SDHC1_G->boc_ready_t_p,  /* ready to process */
                       ADSL_SDHC1_G->imc_usage_count );  /* usage count */
#undef ADSL_SDHC1_G
       imh1 = adsl_tr_stor_usage_01_h1->imc_ind_trac;
       imh2 = 0;
       do {
         imh2++;
         m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-STOR-USAGE-l%05d stor=%p no=%d trac=%s.",
                         __LINE__, adsl_tr_stor_usage_01_h1, imh2,
                         &adsl_tr_stor_usage_01_h1->chrc_trac[ imh1 * (sizeof(adsl_tr_stor_usage_01_h1->chrc_trac) / D_NO_TSU_NO) ] );
         imh1++;
         if (imh1 == D_NO_TSU_NO) imh1 = 0;
       } while (imh1 != adsl_tr_stor_usage_01_h1->imc_ind_trac);
       adsl_tr_stor_usage_01_h1 = adsl_tr_stor_usage_01_h1->adsc_next;
     }
     LeaveCriticalSection( &dsalloc_dcritsect );
   }
#endif
#ifdef TRACE_HL_SESS_01
   {
     BOOL     boh_first = TRUE;
     int      imh1, imh2, imh3, imh4, imh5;
     int      imh_gather;                   /* count gather            */
     int      imh_data;                     /* count data              */
     char     *achh2;
     char     *achh_avl_error = NULL;       /* clear error code AVL tree */
     struct dsd_sdh_control_1 *adsh_sdhc1_cur_1;  /* current location 1 */
     struct dsd_gather_i_1 *adsh_gai1_w1;   /* working variable        */
     struct dsd_htree1_avl_work dsh_htree1_work;  /* work-area for AVL-Tree */
     char     chrl_ns_1[320];               /* for network-statistic   */
     char     chrl_ns_num[16];              /* for number              */
     EnterCriticalSection( &d_clconn_critsect );
     while (TRUE) {                         /* loop for sequential retrieval */
       bol1 = m_htree1_avl_getnext( NULL, &dss_htree1_avl_cntl_conn,
                                    &dsh_htree1_work, boh_first );
       if (bol1 == FALSE) {                 /* error occured           */
         achh_avl_error = "m_htree1_avl_getnext() failed";  /* error code AVL tree */
         break;                             /* do not continue         */
       }
       if (dsh_htree1_work.adsc_found == NULL) break;  /* reached end of tree */
#define ADSL_CONN1_G ((class clconn1 *) (dsh_htree1_work.adsc_found))
       boh_first = FALSE;
       m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-l%05d GATE=%(ux)s SNO=%08d INETA=%s adsc_server_conf_1=%p.",
                       __LINE__,
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta,
                       ADSL_CONN1_G->adsc_server_conf_1 );
       chrl_ns_1[0] = 0;                    /* for network-statistic   */
       imh2 = m_get_time() - ADSL_CONN1_G->imc_time_start;
       imh3 = imh2 / 3600;
       imh5 = imh2 - imh3 * 3600;
       imh4 = imh5 / 60;
       imh5 -= imh4 * 60;
       imh1 = sprintf( chrl_ns_1, "duration: %d h %d min %d sec", imh3, imh4, imh5 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_rece_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " / client: rec %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_rece_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_send_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " + send %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_send_c );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_rece_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " / server: rec %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_rece_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_send_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " + send %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_send_s );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_rece_e );
       imh1 += sprintf( chrl_ns_1 + imh1, " / encrypted: rec %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_rece_e );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       achh2 = m_edit_dec_int( chrl_ns_num, ADSL_CONN1_G->inc_c_ns_send_e );
       imh1 += sprintf( chrl_ns_1 + imh1, " + send %s", achh2 );
       achh2 = m_edit_dec_long( chrl_ns_num, ADSL_CONN1_G->ilc_d_ns_send_e );
       imh1 += sprintf( chrl_ns_1 + imh1, " - %s bytes", achh2 );
       m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-l%05d %s.",
                       __LINE__, chrl_ns_1 );
       imh1 = 0;
       adsh_sdhc1_cur_1 = ADSL_CONN1_G->adsc_sdhc1_chain;  /* get chain */
       while (adsh_sdhc1_cur_1) {           /* loop over all buffers   */
         adsh_gai1_w1 = adsh_sdhc1_cur_1->adsc_gather_i_1_i;  /* get chain to send */
         imh_gather = 0;                    /* clear count gather      */
         imh_data = 0;                      /* clear count data        */
         while (adsh_gai1_w1) {             /* loop over data to send  */
           imh_gather++;                    /* increment count gather  */
           imh2 = adsh_gai1_w1->achc_ginp_end - adsh_gai1_w1->achc_ginp_cur;
           imh_data += imh2;
           adsh_gai1_w1 = adsh_gai1_w1->adsc_next;  /* get next in chain */
         }
         m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-l%05d adsh_sdhc1_cur_1=%p function=%d position=%d imc_usage_count=%d gather=%d data=%d",
                         __LINE__, adsh_sdhc1_cur_1,
                         adsh_sdhc1_cur_1->inc_function, adsh_sdhc1_cur_1->inc_position, adsh_sdhc1_cur_1->imc_usage_count,
                         imh_gather, imh_data );
         imh1++;
         adsh_sdhc1_cur_1 = adsh_sdhc1_cur_1->adsc_next;  /* get next in chain */
       }
       m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-l%05d i_last_action=%05d i_prev_action=%05d adsc_sdhc1_chain=%p no-e=%d dcl_tcp_r_c.adsc_sdhc1_send=%p dcl_tcp_r_s.adsc_sdhc1_send=%p.",
                       __LINE__,
                       ADSL_CONN1_G->i_last_action, ADSL_CONN1_G->i_prev_action,
                       ADSL_CONN1_G->adsc_sdhc1_chain, imh1,
                       ADSL_CONN1_G->dcl_tcp_r_c.adsc_sdhc1_send,
                       ADSL_CONN1_G->dcl_tcp_r_s.adsc_sdhc1_send );
       imh1 = 0;
       do {
         m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-l%05d ir_last_action[ %d ... ] = %05d %05d %05d %05d %05d %05d %05d %05d.",
                         __LINE__, imh1,
                         ADSL_CONN1_G->ir_last_action[ imh1 + 0 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 1 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 2 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 3 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 4 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 5 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 6 ],
                         ADSL_CONN1_G->ir_last_action[ imh1 + 7 ] );
         imh1 += 8;
       } while (imh1 < DEF_LEN_LAST_ACTION);
#undef ADSL_CONN1_G
     }
     LeaveCriticalSection( &d_clconn_critsect );
     if (achh_avl_error) {                    /* error occured           */
       m_hlnew_printf( HLOG_XYZ1, "HWSP-TRACE-l%05d AVL error %s.",
                       __LINE__, achh_avl_error );
     }
   }
#endif  /* TRACE_HL_SESS_01 */
#endif
#ifdef NEW_REPORT_1501
#include "xiipgw08-report.cpp"
#endif
   if (bos_end_proc == FALSE) goto pmtend20;
   m_loconf_reset( adsg_loconf_1_inuse );   /* close listen sockets    */
   m_cluster_end();                         /* close cluster           */
#ifdef D_INCL_HOB_TUN
   usl_ineta_length = 4;                    /* length of INETA         */
   iml2 = 0;                                /* count number of delete route */
   bol_first = TRUE;                        /* start at beginning of AVL tree */
   dsg_global_lock.m_enter();
   while (TRUE) {                           /* loop over all INETAs in the AVL tree */
     bol1 = m_htree1_avl_getnext( NULL, &dss_htree1_avl_cntl_ineta_ipv4,
                                  &dsl_htree1_work, bol_first );
     if (bol1 == FALSE) {                   /* error occured           */
//     achh_avl_error = "m_htree1_avl_getnext() failed";  /* error code AVL tree */
       break;                               /* do not continue         */
     }
     if (dsl_htree1_work.adsc_found == NULL) break;  /* reached end of tree */
#ifdef B130808
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_ineta_raws_1, dsc_sort_ineta )))
#endif
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) dsl_htree1_work.adsc_found - offsetof( struct dsd_ineta_raws_1, dsc_sort_ineta_ipv4 )))
     bol_route_del = TRUE;                  /* delete the route        */
#ifdef B130808
     if (   (bol_first == FALSE)            /* do not start at beginning of AVL tree */
         && (!memcmp( chrl_cmp_ineta, ADSL_INETA_RAWS_1_G + 1, usl_ineta_length ))) {  /* compare INETA */
       bol_route_del = FALSE;               /* do not delete the route */
     }
#endif
     if (   (bol_first == FALSE)            /* do not start at beginning of AVL tree */
         && (!memcmp( chrl_cmp_ineta, &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_G->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr, usl_ineta_length ))) {  /* compare INETA */
       bol_route_del = FALSE;               /* do not delete the route */
     }
     bol_first = FALSE;                     /* do not start at beginning of AVL tree */
     if (bol_route_del) {                   /* delete the route        */
       iml2 += 20;                          /* count number of delete route - time needed */
#ifdef B130808
       memcpy( chrl_cmp_ineta, ADSL_INETA_RAWS_1_G + 1, usl_ineta_length );  /* fill compare INETA */
#endif
       memcpy( chrl_cmp_ineta, &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_G->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr, usl_ineta_length );  /* fill compare INETA */
       /* give work to serialisation thread to delete the a route      */
       adsl_ser_thr_task_w1 = dss_ser_thr_ctrl.adsc_sth_free;  /* chain of free structures */
       if (adsl_ser_thr_task_w1 == NULL) {  /* we need more entries    */
         adsl_ser_thr_task_w1
           = (struct dsd_ser_thr_task *) malloc( DEF_SERIAL_FREE_POOL * sizeof(struct dsd_ser_thr_task) );
         adsl_ser_thr_task_w1->adsc_next = adsl_ser_thr_task_w1 + DEF_SERIAL_FREE_POOL - 1;
         adsl_ser_thr_task_w2 = adsl_ser_thr_task_w1 + 1;
         adsl_ser_thr_task_w2->adsc_next = NULL;
         iml1 = DEF_SERIAL_FREE_POOL - 2;
         do {
           adsl_ser_thr_task_w2++;          /* next entry in pool      */
           adsl_ser_thr_task_w2->adsc_next = adsl_ser_thr_task_w2 - 1;
           iml1--;                          /* decrement index         */
         } while (iml1 > 0);
       }
       dss_ser_thr_ctrl.adsc_sth_free = adsl_ser_thr_task_w1->adsc_next;
       memset( adsl_ser_thr_task_w1, 0, sizeof(struct dsd_ser_thr_task) );  /* task for serial thread */
// to-do 03.07.10 KB attention IPV6
       adsl_ser_thr_task_w1->iec_sth = ied_sth_route_ipv4_del;  /* delete a route IPV4 */
#ifdef B130808
       memcpy( adsl_ser_thr_task_w1->chrc_ineta, ADSL_INETA_RAWS_1_G + 1, usl_ineta_length );
       adsl_ser_thr_task_w1->umc_index_if_arp = ADSL_INETA_RAWS_1_G->umc_index_if_arp;  /* holds index of compatible IF for ARP */
       adsl_ser_thr_task_w1->umc_index_if_route = ADSL_INETA_RAWS_1_G->umc_index_if_route;  /* holds index of compatible IF for routes */
       adsl_ser_thr_task_w1->umc_taif_ineta = ADSL_INETA_RAWS_1_G->umc_taif_ineta;  /* <TUN-adapter-use-interface-ineta> */
#endif
       memcpy( adsl_ser_thr_task_w1->chrc_ineta, &((struct sockaddr_in *) &ADSL_INETA_RAWS_1_G->dsc_tun_contr_ineta.dsc_soa_local_ipv4)->sin_addr, 4 );
       adsl_ser_thr_task_w1->umc_index_if_arp = ADSL_INETA_RAWS_1_G->umc_index_if_arp_ipv4;  /* holds index of compatible IF for ARP */
       adsl_ser_thr_task_w1->umc_index_if_route = ADSL_INETA_RAWS_1_G->umc_index_if_route_ipv4;  /* holds index of compatible IF for routes */
       adsl_ser_thr_task_w1->umc_taif_ineta = ADSL_INETA_RAWS_1_G->umc_taif_ineta_ipv4;  /* <TUN-adapter-use-interface-ineta> */
       /* append at end of chain to process                            */
       if (dss_ser_thr_ctrl.adsc_sth_work == NULL) {  /* work as task for serial thread */
         dss_ser_thr_ctrl.adsc_sth_work = adsl_ser_thr_task_w1;  /* work as task for serial thread */
         iml_rc = dss_ser_thr_ctrl.dsc_event_thr.m_post( &iml_error );  /* event for serial thread */
         if (iml_rc < 0) {                  /* error occured           */
// to-do 21.12.10 KB error number
           m_hlnew_printf( HLOG_XYZ1, "HWSPMxxxW l%05d cleanup HOB-TUN INETA event serial m_post Return Code %d Error %d.",
                           __LINE__, iml_rc, iml_error );
         }
       } else {
         adsl_ser_thr_task_w2 = dss_ser_thr_ctrl.adsc_sth_work;  /* get chain */
         while (adsl_ser_thr_task_w2->adsc_next) adsl_ser_thr_task_w2 = adsl_ser_thr_task_w2->adsc_next;
         adsl_ser_thr_task_w2->adsc_next = adsl_ser_thr_task_w1;
       }
     }
   }
#undef ADSL_INETA_RAWS_1_G
   dsg_global_lock.m_leave();
#ifndef B130828
   m_htun_end( dss_loconf_1_first.adsc_raw_packet_if_conf, &dss_tun_ctrl );
#endif
   Sleep( 500 + iml2 );                     /* wait some time          */
#else
   Sleep( 500 );                            /* wait some time          */
#endif
   if (boisservice) {
     dclasrvstat.dwCurrentState = SERVICE_STOPPED;  /* service clos    */
     SetServiceStatus( dclhsrvstat, &dclasrvstat );  /* set state      */
     m_hlnew_printf( HLOG_XYZ1, "now ServiceStatus is set to SERVICE_STOPPED" );
   }
} /* end ServiceMain()                                                 */

/* get string with name and version of the WSP                         */
extern "C" const char * m_get_query_main( void ) {
   return chrs_query_main;
} /* end m_get_chrs_query_main()                                       */

#ifdef B080407
static htfunc1_t TCPAThread( LPVOID ulThreadArg ) {
#define audg1 ((struct dsd_gate_1 *) ulThreadArg)
   int        rc_sock;                      /* return code             */
   int        itr1sock;                     /* socket for receive 1    */
   int        iml1;                         /* working variable        */
   int        inl_session_no;               /* session no              */
#ifndef HL_IPV6
   struct sockaddr_in dclient1;             /* client address informat */
#else
   union un_soaddr_1 unu1;                  /* client address informat */
#endif
   int        iunamelen;                    /* length of client name   */
   struct sockaddr_in duclient;             /* client address informat */
   BOOL       bou1;
   class clconn1 *adsl_conn1;               /* class created           */
#ifdef D_NAEGLE_ALGOR_OFF
   int ioptval;
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "Start TCPAThread %d", audg1->igateport );
#endif
#ifndef OLD01
   InitializeCriticalSection( &audg1->dcritsect );
#else
#ifdef HL_IPV6
   if (bog_ipv6) {                           /* was listen with IPV6    */
     InitializeCriticalSection( &audg1->dcritsect );
     goto ptawait10;                        /* loop for incomming acce */
   }
#endif
   /* Get a socket for accepting connections.                          */
   audg1->inc_listen_socket = IP_socket( AF_INET, SOCK_STREAM, 0 );
   if (audg1->inc_listen_socket < 0) {
     iml1 = audg1->inc_listen_socket;
     if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
       iml1 = cl_tcp_r::afunc_wsaglerr();   /* get error code          */
     }
     m_hlnew_printf( HLOG_XYZ1, "HWSPM100W GATE=%(ux)s Socket() Error %d/%d",
                 (WCHAR *) (audg1 + 1), audg1->inc_listen_socket, iml1 );
     return;
   }

   /* Bind the socket to the server address.                           */
   memset( (char *) &duclient, 0, sizeof(struct sockaddr_in) );
   duclient.sin_family = AF_INET;
   duclient.sin_port   = IP_htons( audg1->igateport );
   duclient.sin_addr.s_addr = audg1->ul_in_ineta;

   rc_sock = IP_bind( audg1->inc_listen_socket,
                      (struct sockaddr *) &duclient,
                      sizeof(duclient) );
   if (rc_sock != 0) {
     iml1 = rc_sock;
     if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
       iml1 = cl_tcp_r::afunc_wsaglerr();   /* get error code          */
     }
     m_hlnew_printf( HLOG_XYZ1, "HWSPM101W GATE=%(ux)s Bind() port=%d Error %d/%d",
                 (WCHAR *) (audg1 + 1), audg1->igateport, rc_sock, iml1 );
     IP_closesocket( audg1->inc_listen_socket );
     return;
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nach Bind" );
#endif
   InitializeCriticalSection( &audg1->dcritsect );

   /* Listen for connections. Specify the backlog.                     */
   rc_sock = IP_listen( audg1->inc_listen_socket, audg1->ibacklog );
   if (   (rc_sock != 0)                    /* error occured           */
       || (audg1->boc_gate_close)) {        /* gate is closed          */
     if (audg1->boc_gate_close == FALSE) {  /* gate not closed         */
       iml1 = rc_sock;
       if (cl_tcp_r::hws2mod != NULL) {     /* functions loaded        */
         iml1 = cl_tcp_r::afunc_wsaglerr();  /* get error code         */
       }
       m_hlnew_printf( HLOG_XYZ1, "HWSPM102W GATE=%(ux)s Listen() Error %d/%d",
                   (WCHAR *) (audg1 + 1), rc_sock, iml1 );
     } else {
       m_hlnew_printf( HLOG_XYZ1, "HWSPM103I GATE=%(ux)s Listen() ended",
                   (WCHAR *) (audg1 + 1) );
     }
     IP_closesocket( audg1->inc_listen_socket );
     DeleteCriticalSection( &audg1->dcritsect );
     return;
   }
#endif

   /* Accept a connection.                                             */
   ptawait10:                               /* loop for incomming acce */
#ifndef HL_IPV6
   memset( (char *) &dclient1, 0, sizeof(struct sockaddr_in) );
   iunamelen = sizeof(dclient1);
#else
   if (bog_ipv6 == FALSE) {
     memset( (char *) &unu1.dsoad1, 0, sizeof(struct sockaddr_in) );
     iunamelen = sizeof(unu1.dsoad1);
   } else {
     memset( (char *) &unu1.dsost1, 0, sizeof(SOCKADDR_STORAGE) );
     iunamelen = sizeof(unu1.dsost1);
   }
#endif
   itr1sock = IP_accept( audg1->inc_listen_socket,
#ifndef HL_IPV6
                         (struct sockaddr *) &dclient1,
#else
                         (struct sockaddr *) &unu1,
#endif
                         &iunamelen );
   if (   (itr1sock < 0)                    /* error occured           */
       || (audg1->boc_gate_close)) {        /* gate is closed          */
     if (audg1->boc_gate_close == FALSE) {  /* gate not closed         */
       iml1 = itr1sock;
       if (cl_tcp_r::hws2mod != NULL) {     /* functions loaded        */
         iml1 = cl_tcp_r::afunc_wsaglerr();  /* get error code         */
       }
       m_hlnew_printf( HLOG_XYZ1, "HWSPM104W GATE=%(ux)s Accept() Error %d/%d",
                   (WCHAR *) (audg1 + 1), itr1sock, iml1 );
     } else {
       m_hlnew_printf( HLOG_XYZ1, "HWSPM105I GATE=%(ux)s Listen() ended",
                   (WCHAR *) (audg1 + 1) );
     }
     IP_closesocket( audg1->inc_listen_socket );
//   DeleteCriticalSection( &audg1->dcritsect );
#ifdef OLD01
     return;
#endif
     return 0;
   }

#ifdef D_REFUSE_CONNECT_1                   /* 25.06.07 KB             */
   audg1->i_session_max = audg1->i_session_cur = 1;
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nach Accept" );
#endif
   bou1 = TRUE;                             /* session is valid        */
#ifdef D_NAEGLE_ALGOR_OFF
// 13.03.2007, G.Oed
   ioptval = 1;
   if(IP_setsockopt(itr1sock,IPPROTO_TCP,TCP_NODELAY,
		    (const char *) (void *) &ioptval, sizeof(int)) != 0)
     m_hlnew_printf( HLOG_XYZ1, "TCPAThread: failed to set accepted socket TCP_NODELAY!");
   else
     m_hlnew_printf( HLOG_XYZ1, "TCPAThread: accepted socket set to TCP_NODELAY");
#endif // defined NAGLE_ALGOR_OFF
   EnterCriticalSection( &audg1->dcritsect );
   audg1->i_session_cos++;                  /* count start of session  */
   if (   (audg1->i_session_max)
       && (audg1->i_session_cur >= audg1->i_session_max)) {
     bou1 = FALSE;                          /* session not valid       */
     audg1->i_session_exc++;                /* count times exceeded    */
   } else {
     audg1->i_session_cur++;                /* count current session   */
     if (audg1->i_session_cur > audg1->i_session_mre)
       audg1->i_session_mre = audg1->i_session_cur;
     ins_session_no++;                      /* get new session no      */
     inl_session_no = ins_session_no;
   }
/* 19.12.04 KB - session-ID UUUUU */
   LeaveCriticalSection( &audg1->dcritsect );
   if (bou1 == FALSE) {                     /* do not start session    */
     IP_closesocket( itr1sock );
     m_hlnew_printf( HLOG_XYZ1, "HWSPS001W GATE=%(ux)s maximum number of session exceeded",
                     (WCHAR *) (audg1 + 1) );
     goto ptawait10;
   }
#ifndef HL_IPV6
   adsl_conn1 = new clconn1( audg1, &dclient1, itr1sock, inl_session_no );
#else
   adsl_conn1 = new clconn1( audg1, &unu1, iunamelen, itr1sock, inl_session_no );
#endif
   if (adsl_conn1 == NULL) {                /* constructor failed      */
     IP_closesocket( itr1sock );
     m_hlnew_printf( HLOG_XYZ1, "HWSPS002W GATE=%(ux)s SNO=%08d constructor clconn1 failed - short on memory",
                     (WCHAR *) (audg1 + 1), inl_session_no );
   }
   goto ptawait10;

   ptawait40:                               /* never comes here        */
   DeleteCriticalSection( &audg1->dcritsect );
#ifdef OLD01
   return;
#endif
   return 0;
} /* end TCPAThread()                                                  */
#undef audg1
#endif

#ifdef OLD_1112
/* Thread to read from TCP/IP socket-connection (one of many)          */
static htfunc1_t UTILThread( LPVOID ulThreadArg ) {
#define audclutilth ((class clutilth *) ulThreadArg)
   APIRET   rcu;                            /* return code             */
   int      iuread;                         /* lenght read             */
   char     *auread;                        /* block to read           */
   BOOL     bou1;
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* structure receive       */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "Start UTILThread %p", ulThreadArg );
#endif
   goto putilth40;

   putilth20:                               /* wait for more to do     */
   audclutilth->ienum_ac = clutilth::en_ac_idle;
   rcu = WaitForSingleObject( audclutilth->heveutil, INFINITE );

   putilth40:                               /* loop receive data       */
   if (audclutilth->ienum_ac == clutilth::en_ac_UDP) {
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "UTILThread %p before proc_UDP", ulThreadArg );
#endif
     ((class clconn1 *) audclutilth->ad_activity)->proc_UDP();
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "UTILThread %p after proc_UDP", ulThreadArg );
#endif
     goto putilth20;                        /* continue                */
   }
#ifdef B080407
   if (audclutilth->ienum_ac != clutilth::en_ac_receive)
     goto putilth20;                        /* continue                */

   putilthr0:                               /* loop receive data       */
#define audcltcpr1 ((class cl_tcp_r *) audclutilth->ad_activity)
#define ADSL_CONN1_G ((class clconn1 *) (audcltcpr1->aclconn1))
   /* get storage for incomming message                                */
// auread = (char *) m_proc_alloc();
   adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
   /* Receive the message on the connected socket.                     */
   iuread = IP_recv( audcltcpr1->iclsocket,
                     (char *) (((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1)) + 1),
                     LEN_TCP_RECV
                       - sizeof(struct dsd_sdh_control_1)
                       - sizeof(struct dsd_gather_i_1),
                     0 );
#ifdef TRACEHL1
   if (iuread <= 0) {
     m_hlnew_printf( HLOG_XYZ1, "Recv() Error %d", iuread );
   }
#endif
   if (iuread > 0) {
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))
     memset( ADSL_GATHER_I_1_W, 0, sizeof(struct dsd_gather_i_1) );
     ADSL_GATHER_I_1_W->achc_ginp_cur
       = (char *) (ADSL_GATHER_I_1_W + 1);
     ADSL_GATHER_I_1_W->achc_ginp_end
       = ADSL_GATHER_I_1_W->achc_ginp_cur + iuread;
#undef ADSL_GATHER_I_1_W
   }

   /* receive has been completed                                       */
   bou1 = ADSL_CONN1_G->rec_complete( audcltcpr1, adsl_sdhc1_w1, iuread );

   if (iuread <= 0) {                       /* no data received        */
     m_proc_free( adsl_sdhc1_w1 );          /* free buffer again       */
   }
   if (bou1) goto putilthr0;                /* continue receiving      */
   audcltcpr1->setnor( TRUE );
#endif
   goto putilth20;                          /* continue                */

#ifdef B080407
#undef ADSL_CONN1_G
#undef audcltcpr1
#endif
#undef audclutilth
}
#endif

/* constructor clconn1                                                 */
#ifndef B080407
inline clconn1::clconn1( struct dsd_gate_1 *apdg1,
                         struct dsd_gate_listen_1 *adsp_gate_listen_1,  /* listen part of gateway */
                         struct sockaddr *adsp_soa, int imp_len_soa, int imp_socket,
                         int inp_session_no )
#endif
#ifdef B080407
#ifndef HL_IPV6
inline clconn1::clconn1( struct dsd_gate_1 *apdg1,
                         struct sockaddr_in *apclient, int ipsocket,
                         int inp_session_no )
#else
inline clconn1::clconn1( struct dsd_gate_1 *apdg1,
                         union un_soaddr_1 *apun1, int iuaddrlen, int ipsocket,
                         int inp_session_no )
#endif
#endif
{
   int        iml1;                         /* working-variable        */
#ifdef HL_IPV6
   int      rcu;                            /* return code             */
#endif
   BOOL       bol1;                         /* working variable        */
   char       *achl_ineta;                  /* address of INETA        */
   char       *achl_cur;                    /* current INETA pointer   */
   char       *achl_end;                    /* end if INETAs           */
   struct dsd_wsp_tr_ineta_ctrl *adsl_wtic_w1;  /* WSP trace client with INETA control */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */
   char       *achl_avl_error;              /* error code AVL tree     */
   struct dsd_co_sort dsl_co_sort;          /* for connection sort    */
   struct dsd_htree1_avl_work dsl_htree1_work;  /* work-area for AVL-Tree */

#ifdef B080407
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "clconn1::clconn1 ipsocket=%d", ipsocket );
#endif
#endif
#ifdef TRACEHL_050427
   memset( this, 0, sizeof( class clconn1 ) );
#endif
#ifdef EXAMINE_SIGN_ON_01                   /* 10.08.11 KB examine sign on time */
   this->boc_exa_so_01 = TRUE;              /* set if display to come  */
   bol1 = QueryPerformanceCounter( &this->ilc_exa_so_01 );  /* time at accept */
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPM IBIPGW08-l%05d-W GATE=%(ux)s QueryPerformanceCounter() error %d.",
                     __LINE__, apdg1 + 1, GetLastError() );
     this->boc_exa_so_01 = FALSE;           /* reset display to come   */
   }
#endif
#ifdef TRACE_HL_SESS_01
   i_last_action = 0;                       /* last action             */
   i_prev_action = 0;                       /* last action             */
   memset( ir_last_action, 0, sizeof(ir_last_action) );
#endif  /* TRACE_HL_SESS_01 */
#ifdef TRACEHLC
   im_check_no = DEF_CHECK_ACLCONN1_NO;
#endif
#ifdef B080924
   adsc_send_server_1_ch = NULL;            /* chain for send to server */
#endif
   imc_time_start = m_get_time();           /* time session started    */
   dsc_co_sort.imc_sno = inp_session_no;    /* set session no          */
   rcu = getnameinfo( adsp_soa, imp_len_soa,
                      chrc_ineta, sizeof(chrc_ineta), 0, 0, NI_NUMERICHOST );
   if (rcu) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPM062W GATE=%(ux)s getnameinfo() returned %d %d.",
                     apdg1 + 1, rcu, D_TCP_ERROR );
     strcpy( chrc_ineta, "???" );
   }
#ifdef TRY_SNMP_100812
   {
     struct dsd_wsp_snmp_trap_radius_query dsl_wsp_snmp_trap_radius_query;  /* Radius query reported error */
     memset( &dsl_wsp_snmp_trap_radius_query, 0, sizeof(struct dsd_wsp_snmp_trap_radius_query) );
     dsl_wsp_snmp_trap_radius_query.dsc_radius_conf.ac_str = "Test Radius Conf";
     dsl_wsp_snmp_trap_radius_query.dsc_radius_conf.imc_len_str = -1;  /* length string in elements */
     dsl_wsp_snmp_trap_radius_query.dsc_radius_conf.iec_chs_str = ied_chs_ansi_819;  /* character set string */
     dsl_wsp_snmp_trap_radius_query.dsc_error_msg.ac_str = "Error Message 12.08.10 �������";
     dsl_wsp_snmp_trap_radius_query.dsc_error_msg.imc_len_str = -1;  /* length string in elements */
     dsl_wsp_snmp_trap_radius_query.dsc_error_msg.iec_chs_str = ied_chs_ansi_819;  /* character set string */
     m_snmp_trap_1( ied_wsp_snmp_trap_radius_query, &dsl_wsp_snmp_trap_radius_query );  /* send the Trap */
   }
#endif
   m_hlnew_printf( HLOG_XYZ1, "HWSPS003I GATE=%(ux)s SNO=%08d INETA=%s connect in",
                   apdg1 + 1, inp_session_no, chrc_ineta );
   adsc_sdhc1_c1 = NULL;                    /* receive buffer client 1 */
   adsc_sdhc1_c2 = NULL;                    /* receive buffer client 2 */
   adsc_sdhc1_s1 = NULL;                    /* receive buffer server 1 */
   adsc_sdhc1_s2 = NULL;                    /* receive buffer server 1 */
   adsc_gate1 = apdg1;                      /* get gateway             */
   iec_servcotype = ied_servcotype_none;    /* no server connection    */
#ifndef B080407
   adsc_gate_listen_1 = adsp_gate_listen_1;  /* listen part of gateway */
#endif
#ifndef B090419
   iec_st_cls = ied_cls_normal;             /* status client normal processing */
   if (   (adsc_gate1->imc_permmov_from_port > 0)  /* <permanently-moved-from_port> */
       && (((struct sockaddr_in *) &adsc_gate_listen_1->dsc_soa)->sin_port == IP_htons( adsc_gate1->imc_permmov_from_port))) {  /* <permanently-moved-from_port> */
     iec_st_cls = ied_cls_wait_start;       /* status client wait for start message */
   }
#endif
   boc_st_act = TRUE;                       /* util-thread active      */
   boc_st_sslc = FALSE;                     /* ssl handshake complete  */
#ifndef B130314
   this->boc_signal_set = FALSE;            /* signal for component set */
#endif
#ifdef B120211
   boc_hunt_end = FALSE;                    /* clear hunt end          */
#endif
   this->imc_timeout_set = 0;               /* timeout set in seconds  */
   imc_trace_level = 0;                     /* trace level set         */
#ifdef D_INCL_HOB_TUN
   this->imc_references = 0;                /* references to this session */
#endif
   inc_c_ns_rece_c = 0;                     /* count receive client    */
   inc_c_ns_send_c = 0;                     /* count send client       */
   inc_c_ns_rece_s = 0;                     /* count receive server    */
   inc_c_ns_send_s = 0;                     /* count receive server    */
   inc_c_ns_rece_e = 0;                     /* count encrypted from se */
   inc_c_ns_send_e = 0;                     /* count encrypted from se */
   ilc_d_ns_rece_c = 0;                     /* data receive client     */
   ilc_d_ns_send_c = 0;                     /* data send client        */
   ilc_d_ns_rece_s = 0;                     /* data receive server     */
   ilc_d_ns_send_s = 0;                     /* data send server        */
   ilc_d_ns_rece_e = 0;                     /* data receive encyrpted  */
   ilc_d_ns_send_e = 0;                     /* data send encrypted     */
   adsc_lbal_gw_1 = NULL;                   /* class load balancing GW */
   adsc_wtsudp1 = NULL;                     /* no WTS UDP yet          */
   adsc_auxf_1 = NULL;                      /* anchor of extensions    */
   adsc_aux_timer_ch = NULL;                /* no auxiliary timer      */
#ifndef NO_LDAP_071116
   adsc_aux_ldap = NULL;                    /* clear auxiliary LDAP field */
#endif
   adsc_ineta_raws_1 = NULL;                /* auxiliary field for HOB-TUN */
   adsc_sdhc1_frcl = NULL;                  /* chain of buffers from client (SSL encrypted) */
   adsc_sdhc1_chain = NULL;                 /* chain of buffers input output */
   adsc_sdhc1_inuse = NULL;                 /* chain of buffers in use */
   adsc_sdhc1_extra = NULL;                 /* chain of buffers extra  */
#ifdef B100702
   umc_ineta_ppp_ipv4 = 0;                  /* INETA PPP IPV4          */
   umc_ineta_appl_ipv4 = 0;                 /* INETA appl IPV4         */
#endif
#ifdef TRACEHL_P_COUNT
   inc_aux_mem_cur = 0;                     /* current memory size     */
   inc_aux_mem_max = 0;                     /* maximum memory size     */
#endif
#ifdef WORK051119
   dcl_wsat1_1 = NULL;                      /* class authentication    */
#endif
#ifdef OLD_111203
   adsc_radqu = NULL;                       /* class Radius Query      */
#endif
   adsc_wsp_auth_1 = NULL;                  /* structure for authentication */
   adsc_int_webso_conn_1 = NULL;            /* connect for WebSocket applications - internal */
   adsc_cpttdt = NULL;                      /* connect PTTD thread     */
   this->chrc_server_error[ 0 ] = 0;        /* display server error    */
   this->boc_survive = FALSE;               /* survive E-O-F client    */
// to-do 08.12.10 KB - check if imc_trace_level should be set
   adsl_wtic_w1 = adss_wtic_active;         /* WSP trace client with INETA control */
   while (adsl_wtic_w1) {                   /* WSP trace client with INETA control set */
     do {                                   /* pseudo-loop             */
       if (adsl_wtic_w1->boc_trace_ineta_all) {  /* trace all INETAS   */
         imc_trace_level = adsl_wtic_w1->imc_trace_level;  /* trace_level */
         break;
       }
       /* search if INETA set                                            */
       achl_ineta = (char *) &((struct sockaddr_in *) adsp_soa)->sin_addr;
       iml1 = 4;                              /* length of INETA         */
       if (adsp_soa->sa_family == AF_INET6) {  /* IPV6                   */
         achl_ineta = (char *) &((struct sockaddr_in6 *) adsp_soa)->sin6_addr;
         iml1 = 16;                           /* length of INETA         */
       }
       achl_cur = (char *) (adsl_wtic_w1 + 1);  /* here start INETAs     */
       achl_end = (char *) (adsl_wtic_w1 + 1) + adsl_wtic_w1->imc_len_inetas;
#define ADSL_WTIA1_G1 ((struct dsd_wsp_tr_ineta_1 *) achl_cur)
       while (achl_cur < achl_end) {          /* loop over all INETAs    */
         if (   (iml1 == ADSL_WTIA1_G1->usc_length)
             && (!memcmp( ADSL_WTIA1_G1 + 1, achl_ineta, iml1 ))) {
           imc_trace_level = ADSL_WTIA1_G1->imc_trace_level;  /* trace_level */
           break;                             /* all done                */
         }
         achl_cur += sizeof(struct dsd_wsp_tr_ineta_1) + ADSL_WTIA1_G1->usc_length;  /* next INETA */
       }
#undef ADSL_WTIA1_G1
     } while (FALSE);
     if (imc_trace_level == 0) break;
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "SCONNIN1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = inp_session_no;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = m_hlsnprintf( (char *) (ADSL_WTR_G1 + 1), 256, ied_chs_ansi_819,
                          "GATE=%(ux)s INETA=%s connect in",
                          apdg1 + 1, chrc_ineta );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
     break;
   }
#ifdef WSP_TRACE_110309
   imc_trace_level = WSP_TRACE_110309;      /* trace level set         */
#endif
   memset( &dsc_sdh_s_1, 0, sizeof(struct dsd_sdh_session_1) );  /* clear work area server data hook per session */
   adsc_csssl_oper_1 = NULL;                /* operation of client-side SSL */
   adsc_user_group = NULL;                  /* clear structure user group */
   adsc_user_entry = NULL;                  /* clear structure user entry */
#ifdef B100909
   adsc_krb5_kdc_1 = NULL;                  /* clear active Kerberos 5 KDC */
   adsc_ldap_group = NULL;                  /* clear active LDAP group */
#endif
   this->adsc_radius_group = NULL;          /* active Radius group */
   adsc_krb5_kdc_1 = NULL;                  /* active Kerberos 5 KDC   */
   adsc_ldap_group = NULL;                  /* active LDAP group       */
   if (apdg1->imc_no_radius == 1) {         /* check number of radius groups */
     this->adsc_radius_group = *(apdg1->adsrc_radius_group + 0);  /* set active Radius group */
     adsc_ldap_group = this->adsc_radius_group->adsc_ldap_group;  /* set corresponding LDAP group */
   }
   if (apdg1->imc_no_krb5_kdc == 1) {       /* check number of Kerberos 5 KDCs */
     adsc_krb5_kdc_1 = *(apdg1->adsrc_krb5_kdc_1 + 0);  /* set active Kerberos 5 KDC */
     adsc_ldap_group = adsc_krb5_kdc_1->adsc_ldap_group;  /* set corresponding LDAP group */
   }
   if (apdg1->imc_no_ldap_group == 1) {     /* check number of LDAP groups */
     adsc_ldap_group = *(apdg1->adsrc_ldap_group + 0);  /* set active LDAP group */
   }
#ifdef XYZ1
   if (   (apdg1->imc_no_ldap_group == 1)   /* check number of LDAP groups */
       && (adsc_ldap_group == NULL)) {
     adsc_ldap_group = *(apdg1->adsrc_ldap_group + 0);  /* set active LDAP group */
   }
#endif
   this->adsc_pd_http_ctrl = NULL;          /* process data HTTP control */
   this->adsc_util_thread_ctrl = NULL;      /* utility thread control  */
   this->adsc_server_conf_1 = adsc_gate1->adsc_server_conf_1;
   if (   (this->adsc_server_conf_1)
       && (this->adsc_server_conf_1->inc_no_sdh >= 2)) {
     adsrc_sdh_s_1 = (struct dsd_sdh_session_1 *) malloc( this->adsc_server_conf_1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );  /* array work area server data hook per session */
     memset( adsrc_sdh_s_1, 0, this->adsc_server_conf_1->inc_no_sdh * sizeof(struct dsd_sdh_session_1) );
   }
   achc_reason_end = NULL;                  /* reason end session      */
// to-do 31.08.09 KB - still necessary ???
#ifdef XYZ1
#ifndef B100812
   iec_servcotype = ied_servcotype_normal_tcp;  /* normal TCP          */
#endif
   dcl_tcp_r_s.prepare();                   /* prepare server connect  */
#endif
   /* start receiving client                                           */
#ifndef B080407
   dcl_tcp_r_c.start1( this, adsp_soa, imp_len_soa, imp_socket );  /* start client */
#endif
#ifdef B080407
#ifndef HL_IPV6
   dcl_tcp_r_c.start1( this, apclient, ipsocket );  /* start client    */
#else
   dcl_tcp_r_c.start1( this, apun1, ipsocket );  /* start client       */
#endif
#endif

#ifdef B060615
   if (apdg1->ifunction < 0) {
     /* class load balancing GW                                        */
     adsc_lbal_gw_1 = new dsd_lbal_gw_1( this,
                               adsc_server_conf_1->inc_wts_time1, adsc_server_conf_1->inc_wts_time2,
                               adsc_server_conf_1->adsc_wtsg1, adsc_server_conf_1->boc_is_blade_server );
     iec_st_ses = ied_ses_reset;            /* status server           */
   } else {
     iec_st_ses = ied_ses_prep_server;      /* status server prepare   */
   }
#endif
   iec_st_ses = ied_ses_prep_server;        /* status server prepare   */
   if (apdg1->ifunction < 0) {              /* do load-balancing first */
     iec_st_ses = ied_ses_reset;            /* status server           */
   }
#ifndef B101214
   boc_sdh_started = FALSE;                 /* Server-Data-Hooks have been started */
#endif
#ifndef NO_WSP_SOCKS_MODE_01
#ifdef OLD_1112
   if (   (apdg1->adsc_server_conf_1 == NULL)  /* configuration server */
       || (apdg1->inc_no_radius)            /* number of radius server */
       || (apdg1->inc_no_usgro)             /* number of user groups   */
       || (apdg1->inc_no_seli)              /* number of server lists  */
       || (apdg1->adsc_hobwspat3_ext_lib1)) {  /* external library loaded for HOB-WSP-AT3 */
     if (apdg1->ifunction != DEF_FUNC_L2TP) {  /* set function L2TP UDP connection */
       if (   (apdg1->adsc_server_conf_1 == NULL)  /* no server configured yet */
           || (adsc_server_conf_1->boc_sdh_reflect == FALSE)  /* not only Server-Data-Hook */
           || (apdg1->adsc_hobwspat3_ext_lib1)) {  /* external library loaded for HOBWSPAT3 */
         iec_st_ses = ied_ses_auth;         /* status authentication   */
       }
     }
   }
#else
   if (   (this->adsc_server_conf_1 == NULL)  /* configuration server  */
       || (apdg1->imc_no_radius)            /* number of radius server */
       || (apdg1->inc_no_usgro)             /* number of user groups   */
       || (apdg1->inc_no_seli)              /* number of server lists  */
       || (apdg1->adsc_hobwspat3_ext_lib1)) {  /* external library loaded for HOBWSPAT3 */
     if (apdg1->ifunction != DEF_FUNC_L2TP) {  /* set function L2TP UDP connection */
       if (   (this->adsc_server_conf_1 == NULL)  /* no server configured yet */
           || (this->adsc_server_conf_1->boc_sdh_reflect == FALSE)  /* not only Server-Data-Hook */
           || (apdg1->adsc_hobwspat3_ext_lib1)) {  /* external library loaded for HOBWSPAT3 */
         iec_st_ses = ied_ses_auth;         /* status authentication   */
       }
     }
   }
#endif
#endif
   bo_st_open = TRUE;                       /* connection open         */
#ifdef B060524
   boc_st_act = FALSE;                      /* util-thread not active  */
#endif
   InitializeCriticalSection( &d_act_critsect );  /* critical section  */
   achl_avl_error = NULL;                   /* clear error code AVL tree */
   EnterCriticalSection( &d_clconn_critsect );
   do {
     bol1 = m_htree1_avl_search( NULL, &dss_htree1_avl_cntl_conn,
                                 &dsl_htree1_work, &dsc_co_sort.dsc_sort_1 );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "m_htree1_avl_search() failed";  /* error code AVL tree */
       break;                               /* do not continue         */
     }
     if (dsl_htree1_work.adsc_found == NULL) break;  /* not found in tree */
     achl_avl_error = "m_htree1_avl_search() new element succeeded - double or illogic";  /* error code AVL tree */
   } while (FALSE);
   if (achl_avl_error == NULL) {            /* no error before         */
     bol1 = m_htree1_avl_insert( NULL, &dss_htree1_avl_cntl_conn,
                                 &dsl_htree1_work, &dsc_co_sort.dsc_sort_1 );
     if (bol1 == FALSE) {                   /* error occured           */
       achl_avl_error = "m_htree1_avl_insert() failed";  /* error code AVL tree */
     }
   }
   LeaveCriticalSection( &d_clconn_critsect );
   if (achl_avl_error) {                    /* error occured           */
     m_hlnew_printf( HLOG_XYZ1, "HWSPS110W GATE=%(ux)s SNO=%08d INETA=%s insert sno error %s",
                     adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, achl_avl_error );
   }
   /* structure for SSL                                                */
   memset( &dsc_hlse03s, 0, sizeof(dsc_hlse03s) );
   dsc_hlse03s.inc_func = DEF_IFUNC_START;  /* set start mode          */
#ifdef NOTYET050817
   dsc_hlse03s.boc_socket_alive = TRUE;
#endif
   dsc_hlse03s.amc_aux = &m_cdaux;          /* subroutine              */
   dsc_hlse03s.amc_conn_callback = &m_ssl_conn_cl_compl_se;
   dsc_hlse03s.amc_ocsp_start = &m_ocsp_start;
   dsc_hlse03s.amc_ocsp_send = &m_ocsp_send;
   dsc_hlse03s.amc_ocsp_recv = &m_ocsp_recv;
   dsc_hlse03s.amc_ocsp_stop = &m_ocsp_stop;
   dsc_hlse03s.ac_config_id = adsc_gate1->vpc_configid;
   this->dsc_hlse03s.imc_sno = this->dsc_co_sort.imc_sno;  /* session number */
   if (this->imc_trace_level & HL_WT_SESS_SSL_INT) {  /* WSP Trace SSL intern */
     this->dsc_hlse03s.imc_trace_level
       = HL_AUX_WT_ALL                      /* WSP Trace SDH all       */
           | (this->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2));
   }
   bol1 = QueryPerformanceCounter( (LARGE_INTEGER *) &dsc_hlse03s.ilc_entropy );
   this->boc_exa_so_01 = TRUE;              /* set if display to come  */
#ifdef B060415A
   dsc_hlse03s.vpc_userfld = this;          /* set user field = conn   */
#endif
#ifdef B060325
   dtime1_e.iwaitsec = m_se_get_conf_timeout( apdg1->vpc_configid );
   if (dtime1_e.iwaitsec <= 0) dtime1_e.iwaitsec = DEF_SSL_TIMEOUT;
   if (   (apdg1->itimeout > 0)             /* set timeout             */
       && (apdg1->itimeout < dtime1_e.iwaitsec)) {
     dtime1_e.iwaitsec = apdg1->itimeout;   /* get number of seconds   */
   }
   if (dtime1_e.iwaitsec) {
     sub_time_set( this );                  /* set timeout now         */
   }
#endif
   memset( &dsc_timer, 0, sizeof(struct dsd_timer_ele) );
   dsc_timer.amc_compl = &m_timeout_conn;   /* set routine for timeout */
   ilc_timeout = dsc_timer.ilcendtime;      /* clear end-time          */
#ifdef B090623
   iml1 = m_se_get_conf_timeout( apdg1->vpc_configid );
   if (iml1 <= 0) iml1 = DEF_SSL_TIMEOUT;
   if (   (apdg1->itimeout > 0)             /* set timeout             */
       && (apdg1->itimeout < iml1)) {
     iml1 = apdg1->itimeout;                /* get number of seconds   */
   }
   if (iml1) {                              /* time specified          */
     dsc_timer.ilcwaitmsec = iml1 * 1000;   /* wait in milliseconds    */
     m_time_set( &dsc_timer, FALSE );       /* set timeout now         */
     ilc_timeout = dsc_timer.ilcendtime;    /* save end-time           */
   }
#endif
#ifdef TRACEHLC
   m_check_aclconn1( this, 110 );
#endif

#ifdef B060616
   if (apdg1->ifunction < 0) {              /* function WTSGATE        */
     boc_st_act = FALSE;                    /* util-thread not active  */
     adsc_wtsudp1 = (struct dsd_wts_udp_1 *) malloc( sizeof(struct dsd_wts_udp_1) );
#ifndef HL_IPV6
     memcpy( &adsc_wtsudp1->dclientin, apclient, sizeof(struct sockaddr_in) );
#else
     memcpy( &adsc_wtsudp1->dclientin, &apun1->dsoad1, sizeof(struct sockaddr_in) );
#endif
     adsc_wtsudp1->imc_client_socket = ipsocket;
     adsc_wtsudp1->boc_timer_set = FALSE;   /* timer has been set      */
#ifdef OLD01
     adsc_wtsudp1->bo_timer_expired = FALSE;   /* timer has expired       */
#endif
     adsc_wtsudp1->adsc_recudp1 = NULL;     /* chain of data received  */
     adsc_wtsudp1->boc_UDP_close_active = FALSE;  /* UDP socket not close active */
     adsc_wtsudp1->boc_udp_closed = FALSE;  /* UDP socket not closed   */
     clutilth::run_thread( this, clutilth::en_ac_UDP );
     return;
   }
#endif
   /* start SSL subroutine                                             */
#ifdef B060524
   boc_st_act = TRUE;                       /* util-thread active      */
#endif
#ifdef B060628
   clworkth::act_thread( this );
#else
   m_act_thread_2( this );                  /* activate m_proc_data()  */
#endif
} /* end clconn1::clconn1()                                            */

/* receive complete                                                    */
inline BOOL clconn1::rec_complete( class cl_tcp_r *dpcltcpr,
                                   struct dsd_sdh_control_1 *adsp_sdhc1, int iplen ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working-variables       */
   HL_LONGLONG ill1;                        /* working-variable        */
   LARGE_INTEGER ill_exa_so_01;             /* time now                */
   BOOL       bol_rec;                      /* receive more data       */
   BOOL       bol_act;                      /* activate thread         */
   BOOL       bol_err_recv;                 /* error receive           */
#ifdef NEW_REPORT_1501
   dsd_time_1 dsl_time_cur;                 /* current time            */
#endif
   char       *achl_w1, *achl_w2, *achl_w3, *achl_w4;  /* working variables */
   void *     al_free;                      /* buffer to free          */
   char       *achl_cl_se;                  /* client or server        */
   char       *achl_wsp_tr_m;               /* WSP Trace message no    */
#ifdef B150121
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
#endif
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w2;     /* WSP trace control record */
   struct dsd_wsp_trace_1 *adsl_wt1_w3;     /* WSP trace control record */
   struct dsd_wsp_trace_record *adsl_wtr_w1;  /* WSP trace record      */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "clconn1::rec_complete l%05d iplen=%d time-sec=%d",
                   __LINE__, iplen, m_get_time() );
   if (iplen == 50) {
     m_hlnew_printf( HLOG_TRACE1, "clconn1::rec_complete trace boc_st_act=%d this->dcl_tcp_r_c.adsc_sdhc1_send=%p this->dcl_tcp_r_s.adsc_sdhc1_send=%p",
                     boc_st_act, this->dcl_tcp_r_c.adsc_sdhc1_send, this->dcl_tcp_r_s.adsc_sdhc1_send );
   }
#endif
   if (this->boc_exa_so_01) {               /* set if display to come  */
     this->boc_exa_so_01 = FALSE;           /* reset display to come   */
     bol1 = QueryPerformanceCounter( &ill_exa_so_01 );  /* time now    */
     if (bol1 == FALSE) {                   /* error occured           */
       m_hlnew_printf( HLOG_XYZ1, "HWSPM IBIPGW08-l%05d-W GATE=%(ux)s QueryPerformanceCounter() error %d.",
                       __LINE__, adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, GetLastError() );
     } else {
       this->dsc_hlse03s.ilc_entropy = *((HL_LONGLONG *) &ill_exa_so_01) - this->dsc_hlse03s.ilc_entropy;
#ifdef EXAMINE_SIGN_ON_01                   /* 10.08.11 KB examine sign on time */
       char *achh1;                         /* working variable        */
       char chrh_edit[ 32 ];
       *((HL_LONGLONG *) &ill_exa_so_01) -= *((HL_LONGLONG *) &this->ilc_exa_so_01);
       achh1 = m_edit_dec_long( chrh_edit, (HL_LONGLONG) (*((HL_LONGLONG *) &ill_exa_so_01) * 1000000) / ils_freq );
       m_hlnew_printf( HLOG_XYZ1, "HWSPM IBIPGW08-l%05d-T GATE=%(ux)s SNO=%08d INETA=%s interval=0X%016llX/%lld micro-sec=%s.",
                       __LINE__,
                       adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta,
                       ill_exa_so_01, ill_exa_so_01, achh1 );
#endif
     }
   }
#ifdef DEBUG_100830_02
#ifdef TRY_DEBUG_100830_02
   m_hlnew_printf( HLOG_XYZ1, "clconn1::rec_complete l%05d dpcltcpr=%p iplen=%d boc_st_act=%d time-sec=%d.",
                   __LINE__, dpcltcpr, iplen, boc_st_act, m_get_time() );
#endif
#endif
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = this->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "IBIPGW08-l%05d rec_complete start", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
#ifdef TRACE_P_060922                       /* problem received data   */
   if (iplen > 0) {
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (adsp_sdhc1 + 1))
     m_hlnew_printf( HLOG_XYZ1, "clconn1::rec_complete l%05d iplen=%d time-sec=%lld\
 adsp_sdhc1=%p achc_ginp_cur=%p achc_ginp_end=%p data=0X%02X",
                     __LINE__, iplen, m_get_time(),
                     adsp_sdhc1, ADSL_GATHER_I_1_W->achc_ginp_cur, ADSL_GATHER_I_1_W->achc_ginp_end,
                     *((unsigned char *) ADSL_GATHER_I_1_W->achc_ginp_cur) );
#undef ADSL_GATHER_I_1_W
   }
#endif /* TRACE_P_060922                       problem received data   */
#ifdef B061016
   if (dpcltcpr->boTCPIPconn == FALSE) return FALSE;  /* TCP/IP connection stat */
#endif
// 15.08.10 KB remove boTCPIPconn and use imc_conn_state
#ifdef B100827
   if (   (dpcltcpr->boTCPIPconn == FALSE)
       && (achc_reason_end == NULL)) {
#ifndef B080407
     if (adsp_sdhc1) m_proc_free( adsp_sdhc1 );  /* free the buffer    */
#endif
     return FALSE;                          /* TCP/IP connection stat  */
   }
#endif
   if (   (dpcltcpr->getstc() == FALSE)     /* TCP/IP connection status */
       && (achc_reason_end == NULL)) {
// to-do 09.03.11 KB WSP trace
     if (adsp_sdhc1) m_proc_free( adsp_sdhc1 );  /* free the buffer    */
     return FALSE;                          /* TCP/IP connection stat  */
   }
   bol_rec = FALSE;                         /* do not receive more     */
   bol_act = FALSE;                         /* do not activate thread  */
   bol_err_recv = FALSE;                    /* error receive           */
   if (iplen <= 0) {                        /* end connection          */
#ifndef B080407
//   m_proc_free( adsp_sdhc1 );             /* free the buffer         */
#endif
     if (achc_reason_end == NULL) {         /* reason end session      */
       if (dpcltcpr == &this->dcl_tcp_r_c) {  /* is from client        */
#ifdef B150104
         if (iplen == 0) {                  /* normal end              */
           achc_reason_end = "client normal end";
         } else {                           /* abnormal end            */
           achc_reason_end = "client ended with error";
         }
#endif
         if (this->boc_survive == FALSE) {  /* survive E-O-F client    */
           if (iplen == 0) {                /* normal end              */
             this->achc_reason_end = "client normal end";
           } else {                         /* abnormal end            */
             this->achc_reason_end = "client ended with error";
           }
         }
       } else {                             /* is from server          */
#ifdef B140629
         if (iplen == 0) {                  /* normal end              */
           /* do not set when dynamic server                           */
           if (   (this->adsc_server_conf_1 == NULL)
               || (this->adsc_server_conf_1->boc_dynamic == FALSE)) {
#ifdef B120211
             if (this->boc_hunt_end == FALSE) {  /* do not hunt end    */
               achc_reason_end = "server normal end";
             }
#else
             achc_reason_end = "server normal end";
#endif
           }
           sprintf( this->chrc_server_error,  /* display server error  */
                    "TCP normal end" );
         } else {                           /* abnormal end            */
           achc_reason_end = "server ended with error";
// to-do 13.03.14 KB - error number
           sprintf( this->chrc_server_error,  /* display server error */
                    "TCP server ended with error" );
         }
#endif
#ifndef B140629
         adsl_server_conf_1_w1 = this->adsc_server_conf_1;  /* get server connected */
         if (adsl_server_conf_1_w1) {       /* server is connected     */
           if (adsl_server_conf_1_w1->adsc_seco1_previous) adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_seco1_previous;
         }
         if (   (achc_reason_end == NULL)
             && (   (adsl_server_conf_1_w1 == NULL)
                 || (adsl_server_conf_1_w1->inc_no_sdh == 0))) {  /* no server-data-hook */
           if (iplen == 0) {                /* normal end              */
             achc_reason_end = "server normal end";
             sprintf( this->chrc_server_error,  /* display server error */
                      "TCP normal end" );
           } else {                         /* abnormal end            */
             achc_reason_end = "server ended with error";
// to-do 13.03.14 KB - error number
             sprintf( this->chrc_server_error,  /* display server error */
                    "TCP server ended with error" );
           }
         }
#endif
#ifndef B130922
         this->iec_st_ses = ied_ses_rec_close;  /* received close      */
#endif
       }
     }
     dpcltcpr->close1();
#ifdef B120211
     boc_hunt_end = FALSE;                  /* do not more hunt end    */
#endif
   }
#ifdef NEW_REPORT_1501
   if (   (dpcltcpr == &this->dcl_tcp_r_c)  /* is from client          */
       && (iplen > 0)) {                    /* data received           */
     if (dss_bc_ctrl.adsrc_bc1[ 0 ] != NULL) {  /* with report         */
       dsl_time_cur = m_get_time();         /* current time            */
       dss_bc_ctrl.dsc_critsect.m_enter();  /* critical section        */
       iml1 = (int) dsl_time_cur - (int) dss_bc_ctrl.adsrc_bc1[ 0 ]->dsc_time_start;
       if (iml1 < 0) iml1 = 0;
       iml1 /= DEF_BANDWIDTH_CLIENT_SECS;   /* compute slot            */
       iml2 = dss_bc_ctrl.adsrc_bc1[ 0 ]->imc_no_entries;  /* number of entries */
       if (iml1 >= iml2) {                  /* check if at end         */
         iml1 = iml2 - 1;                   /* last entry              */
       }
       (*(dss_bc_ctrl.adsrc_bc1[ 0 ]->aimc_p_recv + iml1))++;  /* number of packets received */
       *(dss_bc_ctrl.adsrc_bc1[ 0 ]->ailc_d_recv + iml1) += iplen;  /* count bytes data received */
       dss_bc_ctrl.dsc_critsect.m_leave();  /* critical section        */
     }
   }
#endif
#ifdef B060325
   bo_no_timeout = TRUE;                    /* do not timeout          */
#endif
   if (this->boc_st_sslc) {                 /* ssl handshake complete  */
     iml1 = this->adsc_gate1->itimeout;     /* from GATE               */
     adsl_server_conf_1_w1 = this->adsc_server_conf_1;  /* get server connected */
     if (adsl_server_conf_1_w1) {           /* server is connected     */
/** to-do 04.03.14 KB
       insure++ reports read-dangling
       other field with first server-conf needed, anchor of chain ???
*/
#ifndef B140629
       if (adsl_server_conf_1_w1->adsc_seco1_previous) adsl_server_conf_1_w1 = adsl_server_conf_1_w1->adsc_seco1_previous;
#endif
       if (adsl_server_conf_1_w1->inc_timeout) {
         if (   (iml1 == 0)
             || (adsl_server_conf_1_w1->inc_timeout < iml1)) {
           iml1 = adsl_server_conf_1_w1->inc_timeout;
         }
       }
     }
#ifndef B130323
     if (this->imc_timeout_set) {           /* timeout set in seconds  */
       iml1 = this->imc_timeout_set;        /* timeout set in seconds  */
     }
#endif
     if (iml1 > 0) {                        /* set timeout             */
       this->ilc_timeout = m_get_epoch_ms() + iml1 * 1000;  /* set new end-time */
     } else {                               /* no timeout              */
       this->ilc_timeout = 0;               /* no end-time             */
     }
   }
#ifdef B150121
   adsl_auxf_1_w1 = this->adsc_aux_timer_ch;  /* get chain auxiliary timer */
   while (adsl_auxf_1_w1) {                 /* loop over all timer entries */
#define ADSL_AUX_T ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))
     if (ADSL_AUX_T->boc_expired == FALSE) break;  /* timer has not yet expired */
#undef ADSL_AUX_T
     adsl_auxf_1_w1 = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->adsc_auxf_next;
   }
   if (   (adsl_auxf_1_w1 == NULL)          /* no auxiliary timer entry not found */
       && (this->ilc_timeout == 0)) {       /* no timeout              */
     if (this->dsc_timer.vpc_chain_2) {     /* timer still set         */
       m_time_rel( &this->dsc_timer );      /* release timer           */
     }
   } else {                                 /* needs timer             */
     ill1 = this->ilc_timeout;              /* get timeout             */
     if (   (adsl_auxf_1_w1)                /* auxiliary timer set     */
         && (   (ill1 == 0)                /* timer not yet set       */
             || (ill1 > ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime))) {
       ill1 = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime;
     }
     if (   (ill1 != this->dsc_timer.ilcendtime)  /* different end-time */
         || (this->dsc_timer.vpc_chain_2 == NULL)) {  /* timer not set */
       if (this->dsc_timer.vpc_chain_2) {   /* timer still set         */
         m_time_rel( &this->dsc_timer );    /* release timer           */
       }
       this->dsc_timer.ilcendtime = ill1;   /* set new end-time        */
       m_time_set( &this->dsc_timer, TRUE );  /* set new timer         */
     }
   }
#endif
#ifndef B150121
   m_conn1_set_timer_1( this );
#endif
   al_free = NULL;                          /* no buffer to free       */
   EnterCriticalSection( &d_act_critsect );  /* critical section act   */
   if (bo_st_open) {                        /* connection is open      */
     if (iplen > 0) {                       /* buffer given            */
#ifndef B080407
       memset( adsp_sdhc1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsp_sdhc1 + 1))
       ADSL_GAI1_W1->achc_ginp_cur = (char *) (ADSL_GAI1_W1 + 1);
       ADSL_GAI1_W1->achc_ginp_end = ADSL_GAI1_W1->achc_ginp_cur + iplen;
#ifndef B080426
       adsp_sdhc1->adsc_gather_i_1_i = ADSL_GAI1_W1;
#endif
#undef ADSL_GAI1_W1
#endif
       if (dpcltcpr == &this->dcl_tcp_r_c) {  /* is from client        */
         if (adsc_sdhc1_c1 == NULL) {       /* receive buffer client 1 */
           adsc_sdhc1_c1 = adsp_sdhc1;      /* get data received first buffer */
           bol_rec = TRUE;                  /* receive more data       */
         } else {                           /* already receive data    */
           if (adsc_sdhc1_c2 == NULL) {     /* second buffer not yet set */
             adsc_sdhc1_c2 = adsp_sdhc1;    /* get data received second buffer */
           } else {                         /* illogic                 */
             bol_err_recv = TRUE;           /* error receive           */
             al_free = adsp_sdhc1;          /* set buffer to free      */
           }
         }
       } else {                             /* is from server          */
         if (adsc_sdhc1_s1 == NULL) {       /* receive buffer server 1 */
           adsc_sdhc1_s1 = adsp_sdhc1;      /* get data received first buffer */
           bol_rec = TRUE;                  /* receive more data       */
         } else {                           /* already receive data    */
           if (adsc_sdhc1_s2 == NULL) {     /* second buffer not yet set */
             adsc_sdhc1_s2 = adsp_sdhc1;    /* get data received second buffer */
           } else {                         /* illogic                 */
             bol_err_recv = TRUE;           /* error receive           */
             al_free = adsp_sdhc1;          /* set buffer to free      */
           }
         }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "clconn1::rec_complete entered Critical Section data from server adsc_sdhc1_s1=%p adsc_sdhc1_s2=%p dcl_tcp_r_s.getstc()=%d",
                   adsc_sdhc1_s1, adsc_sdhc1_s2, dcl_tcp_r_s.getstc() );
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (adsc_sdhc1_s1 + 1))
   if (adsc_sdhc1_s1) {
     m_hlnew_printf( HLOG_XYZ1, "clconn1::rec_complete adsc_sdhc1_s1=%p achc_ginp_cur=%p achc_ginp_end=%p",
                     adsc_sdhc1_s1, ADSL_GATHER_I_1_W->achc_ginp_cur, ADSL_GATHER_I_1_W->achc_ginp_end );
   }
#undef ADSL_GATHER_I_1_W
#define ADSL_GATHER_I_1_W ((struct dsd_gather_i_1 *) (adsc_sdhc1_s2 + 1))
   if (adsc_sdhc1_s2) {
     m_hlnew_printf( HLOG_XYZ1, "clconn1::rec_complete adsc_sdhc1_s2=%p achc_ginp_cur=%p achc_ginp_end=%p",
                     adsc_sdhc1_s2, ADSL_GATHER_I_1_W->achc_ginp_cur, ADSL_GATHER_I_1_W->achc_ginp_end );
   }
#undef ADSL_GATHER_I_1_W
#endif
       }
#ifndef B080407
     } else {
       al_free = adsp_sdhc1;                /* set buffer to free      */
#endif
     }
     while (boc_st_act == FALSE) {          /* util-thread not active  */
       if (dpcltcpr == &this->dcl_tcp_r_c) {  /* is from client        */
         if (   (iec_st_ses == ied_ses_conn)  /* status server         */
             && (adsc_server_conf_1->boc_sdh_reflect == FALSE)) {  /* not only Server-Data-Hook */
           /* wait because of flow control                             */
//         if (dcl_tcp_r_s.m_check_send_act()) break;  /* check server */
           if (   (this->iec_servcotype == ied_servcotype_normal_tcp)  /* normal TCP */
               && (dcl_tcp_r_s.m_check_send_act())) {  /* check server */
#ifdef TRY_120306_01                        /* flow-control send       */
             this->dcl_tcp_r_s.boc_act_conn_send = TRUE;  /* activate connection after send */
#endif
             break;
           }
#ifdef D_INCL_HOB_TUN
           if (   (this->iec_servcotype == ied_servcotype_htun)  /* HOB-TUN */
               && (this->imc_send_window > DEF_HTCP_SEND_WINDOW)) {  /* number of bytes to be sent */
             break;
           }
#endif
         }
       } else {                             /* is from server          */
#ifndef TRY_120306_01                        /* flow-control send       */
         if (dcl_tcp_r_c.m_check_send_act()) break;  /* check flow client */
#else
         if (dcl_tcp_r_c.m_check_send_act()) {  /* check flow client   */
           this->dcl_tcp_r_c.boc_act_conn_send = TRUE;  /* activate connection after send */
           break;
         }
#endif
       }
       boc_st_act = TRUE;                   /* util-thread active now  */
       bol_act = TRUE;                      /* activate thread         */
       break;
     }
   } else {                                 /* connection not open     */
#ifndef B080407
     al_free = adsp_sdhc1;                  /* set buffer to free      */
#endif
#ifdef B080407
     if (iplen > 0) {                       /* buffer given            */
       al_free = adsp_sdhc1;                /* set buffer to free      */
     }
#endif
   }
   LeaveCriticalSection( &d_act_critsect );  /* critical section act   */
#ifdef B110501
   adsl_wt1_w1 = NULL;                      /* no WSP trace record     */
   achl_cl_se = "server";                   /* client or server        */
   if (dpcltcpr == &this->dcl_tcp_r_c) {    /* is from client          */
     achl_cl_se = "client";                 /* client or server        */
   }
   if (imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
     adsl_wt1_w1->achc_text = (char *) (adsl_wt1_w1 + 1);  /* address of text this record */
     adsl_wt1_w1->imc_len_text              /* length of text this record */
       = sprintf( (char *) (adsl_wt1_w1 + 1),
                  "SNO=%08d data received from %s length %d/0X%X bol_rec=%d bol_act=%d.",
                  dsc_co_sort.imc_sno, achl_cl_se, iplen, iplen, bol_rec, bol_act );
   }
   if (adsl_wt1_w1) {                       /* output trace generated  */
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#endif
// to-do 10.02.12 KB maybe read dangling because work-thread could already have freed the block
   achl_cl_se = "server";                   /* client or server        */
   achl_wsp_tr_m = "SNERECSE";              /* WSP Trace message no    */
   if (dpcltcpr == &this->dcl_tcp_r_c) {    /* is from client          */
     achl_cl_se = "client";                 /* client or server        */
     achl_wsp_tr_m = "SNERECCL";            /* WSP Trace message no    */
   }
   if (imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, achl_wsp_tr_m, sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = dsc_co_sort.imc_sno;  /* WSP session number */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "data received from %s length %d/0X%X bol_rec=%d bol_act=%d.",
                     achl_cl_se, iplen, iplen, bol_rec, bol_act );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
     if (   (iplen > 0)                     /* data received           */
         && (imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2))) {  /* generate WSP trace record */
       achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
       iml1 = iplen;                        /* length of data received */
       achl_w3 = (char *) ((struct dsd_gather_i_1 *) (adsp_sdhc1 + 1) + 1);  /* start of data */
       adsl_wt1_w2 = adsl_wt1_w1;           /* in this piece of memory */
       adsl_wtr_w1 = ADSL_WTR_G1;           /* set last in chain       */
       do {                                 /* loop always with new struct dsd_wsp_trace_record */
         achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         if ((achl_w1 + sizeof(struct dsd_wsp_trace_record)) >= achl_w2) {
           adsl_wt1_w3 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
           memset( adsl_wt1_w3, 0, sizeof(struct dsd_wsp_trace_1) );  /* clear WSP trace record */
           adsl_wt1_w2->adsc_cont = adsl_wt1_w3;  /* continue this record */
           adsl_wt1_w2 = adsl_wt1_w3;       /* this is current network */
           achl_w1 = (char *) (adsl_wt1_w2 + 1);
           achl_w2 = (char *) adsl_wt1_w2 + LEN_TCP_RECV;  /* end of this piece of memory */
         }
         memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
         achl_w4 = (char *) (ADSL_WTR_G2 + 1);  /* here starts content */
         ADSL_WTR_G2->achc_content = achl_w4;  /* content of text / data */
         if (adsl_wtr_w1->iec_wtrt == ied_wtrt_data) {  /* binary data passed */
           adsl_wtr_w1->boc_more = TRUE;    /* more data to follow     */
         }
         adsl_wtr_w1->adsc_next = ADSL_WTR_G2;  /* append to chain     */
         adsl_wtr_w1 = ADSL_WTR_G2;         /* this is last in chain now */
         iml2 = achl_w2 - achl_w4;
         if (iml2 > iml1) iml2 = iml1;
         memcpy( achl_w4, achl_w3, iml2 );
         achl_w4 += iml2;
         achl_w3 += iml2;
         ADSL_WTR_G2->imc_length = iml2;    /* length of text / data   */
         iml1 -= iml2;                      /* length to be copied     */
         achl_w1 = achl_w2;                 /* set end of this area    */
       } while (iml1 > 0);
     }
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   if (bol_act) {
#ifdef B060628
     clworkth::act_thread( this );
#else
     m_act_thread_2( this );                /* activate m_proc_data()  */
#endif
   }
   if (al_free) {                           /* buffer to free          */
     m_proc_free( al_free );                /* free memory             */
   }
   if (bol_err_recv) {                      /* error receive           */
// to-do 08.09.10 KB error number
     m_hlnew_printf( HLOG_XYZ1, "HWSPSuuuW GATE=%(ux)s SNO=%08d INETA=%s %s receive illogic",
                     adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, achl_cl_se );
#ifdef DEBUG_100908_01

     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08 l%05d &(class dsd_tcpcomp)=%p.",
                     __LINE__,
                     (char *) dpcltcpr + offsetof( class cl_tcp_r, dsc_tcpco1 ) );
#endif
   }
#ifdef TRACEHL_STOR_USAGE
   {
     char chrh_msg[64];
     struct dsd_sdh_control_1 *adsl_sdhc1_h1;
     adsl_sdhc1_h1 = this->adsc_sdhc1_chain;  /* get chain    */
     while (adsl_sdhc1_h1) {
       sprintf( chrh_msg, "IBIPGW08-l%05d rec_complete end", __LINE__ );
       m_proc_trac_1( adsl_sdhc1_h1, chrh_msg );
       adsl_sdhc1_h1 = adsl_sdhc1_h1->adsc_next;
     }
   }
#endif
   return bol_rec;
} /* end clconn1::rec_complete()                                       */

#ifdef TRACEHL_T_050131
inline void clconn1::m_chain_sdhc1( void ) {  /* display chain         */
   int        inl1;
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   adsl_sdhc1_w1 = adsc_sdhc1_chain;        /* get chain               */
   inl1 = 0;                                /* clear count             */
   while (adsl_sdhc1_w1) {
     m_hlnew_printf( HLOG_XYZ1, "clconn1::m_chain_sdhc1() element=%p inc_function=%d inc_position=%d",
                 adsl_sdhc1_w1, adsl_sdhc1_w1->inc_function, adsl_sdhc1_w1->inc_position );
     inl1++;                                /* count entry             */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
   }
   m_hlnew_printf( HLOG_XYZ1, "clconn1::m_chain_sdhc1() count=%d", inl1 );
}
#endif


#include "xiipgw08-pd-main.cpp"
#include "xiipgw08-pd-http.cpp"
#include "xiipgw08-pd-auth.cpp"

static void m_pd_loadbal1( class clconn1 *adsp_conn, struct dsd_pd_work *adsp_pd_work ) {
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_pd_loadbal1() l%05d started adsp_conn=0X%p adsp_pd_work=0X%p",
                   __LINE__,  adsp_conn, adsp_pd_work );
#endif
} /* end m_pd_loadbal1()                                               */

#include "xiipgw08-pd-sdh.cpp"
#include "xiipgw08-seli.cpp"

/** start receiving from server                                        */
inline void clconn1::m_start_rec_server( struct dsd_pd_work *adsp_pd_work ) {
   BOOL       bol1;                         /* working variable        */
   int        inl1;                         /* working variable        */
#ifdef B121121
   BOOL       bol_next_conn;                /* try next connection     */
#endif
   BOOL       bol_start_sdh;                /* start Server-Data-Hook  */
   char       *achl1, *achl2;               /* working variables       */
   int        rc_sock;
   int        iml_rc;                       /* return code             */
   int        iml_server_socket;            /* socket for server connection */
   int        iml_ind_connect;              /* index of connect, no INETA */
#ifdef D_INCL_HOB_TUN
   int        iml_hob_tun_state;            /* value of HOB-TUN state  */
#endif
   socklen_t  iml_namelen;                  /* length of name          */
   socklen_t  iml_bindlen;                  /* length for bind         */
#ifdef B130808
#ifdef D_INCL_HOB_TUN
   socklen_t  iml_local_namelen;            /* length of name local    */
   enum ied_ineta_raws_def iel_irs_def;     /* type of INETA raw socket */
#ifndef NEW_HOB_TUN_1103
   struct dsd_ineta_raws_1 *adsl_ineta_raws_1_w1;  /* extension field HTUN */
#endif
#endif
#endif
#ifdef D_INCL_HOB_TUN
   socklen_t  iml_local_namelen;            /* length of name local    */
   enum ied_ineta_raws_def iel_irs_def;     /* type of INETA raw socket */
   struct sockaddr *adsl_soa_w1;            /* sockaddr temporary value */
   struct dsd_ineta_raws_1 *adsl_ineta_raws_1_w1;  /* extension field HOB-TUN */
   struct dsd_raw_packet_if_conf *adsl_raw_packet_if_conf;  /* configuration raw-packet-interface */
#endif
   struct sockaddr *adsl_soa_bind;          /* address information for bind */
   struct sockaddr_storage dsl_soa_conn;    /* address information for connect */
   struct sockaddr_in du_gateway_sockaddr;  /* gateway multihomed      */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
   struct dsd_target_ineta_1 *adsl_server_ineta_w1;  /* server INETA   */
#ifndef B121120
   void *     al_free_ti1;                  /* INETA to free           */
#endif
   struct dsd_hl_clib_1 dsl_sdh_l1;         /* HOBLink Copy Library 1  */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_cur_1;  /* current location 1  */
   struct dsd_sdh_control_1 *adsl_sdhc1_last_1;  /* last location 1    */
// char       chrl_ineta_server[ 16 ];      /* for INETA server        */
   char       chrl_ineta_server[ LEN_DISP_INETA ];  /* for INETA server */
#ifdef D_INCL_HOB_TUN
   char       chrl_ineta_local[ LEN_DISP_INETA ];  /* for INETA local  */
   union {
     struct dsd_tun_start_htcp dsl_tun_start_htcp;  /* HOB-TUN start interface HTCP */
     struct dsd_tun_start_ppp dsl_tun_start_ppp;  /* HOB-TUN start interface PPP */
   };
#endif
#ifdef B130808
#ifdef D_HPPPT1_1
   struct dsd_tun_start1 dsl_tun_start1;    /* HTUN start interface    */
#endif
#endif

#define ADSL_AUX_CF1 (&adsp_pd_work->dsc_aux_cf1)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
   if (adsc_server_conf_1 == NULL) return;  /* no server yet           */
#ifndef B140701
   if (ADSL_CONN1_G->iec_st_ses == ied_ses_do_lbal) return;  /* status do load-balancing */
#endif
   bol_start_sdh = FALSE;                   /* start Server-Data-Hook  */
#ifdef DEBUG_100824_01
   m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_start_rec_server() iec_st_ses=%d.",
                   adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, iec_st_ses );
#endif
#ifdef DEBUG_100830_02
#ifdef TRY_DEBUG_100830_02
   m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s m_start_rec_server() iec_st_ses=%d.",
                   adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, iec_st_ses );
#endif
#endif
   /* check connect to receiving server                                */
   if (   (iec_st_ses == ied_ses_prep_server)  /* status server prepare */
       && (boc_st_sslc)                     /* ssl handshake complete  */
#ifdef WORK051119
       && (dcl_wsat1_1 == NULL)             /* auth no more active     */
#endif
#ifdef OLD_1112
       && (   (adsc_radqu == NULL)          /* radius no more active   */
           || (adsc_radqu->boc_connect_active))) {  /* connect active  */
#ifdef FORKEDIT
       } (
#endif
#else
       && (   (this->adsc_wsp_auth_1 == NULL)  /* authentication not active */
           || (this->adsc_wsp_auth_1->boc_connect_active))) {  /* connect active */
#endif
#ifdef TRY_130920_01
// to-do 20.09.13 KB - what to do?
/**
check if direct connection, with server, no reflection,
then connect to server.
this was missing here.
*/
#endif
     if (   (adsc_server_conf_1->iec_scp_def == ied_scp_websocket)  /* protocol WebSocket */
         && (adsc_int_webso_conn_1 == NULL)  /* connect for WebSocket applications - internal */
         && (   (adsc_server_conf_1->boc_sdh_reflect)  /* only Server-Data-Hook */
             || (   (adsc_server_conf_1->inc_function != DEF_FUNC_DIR)  /* set function direct */
                 && (adsc_server_conf_1->inc_function != DEF_FUNC_RDP)  /* set function RDP */
                 && (adsc_server_conf_1->inc_function != DEF_FUNC_ICA)))) {  /* set function ICA */
       iec_st_ses = ied_ses_start_sdh;      /* start Server-Data-Hooks */
       bol_start_sdh = TRUE;                /* start Server-Data-Hook  */
       goto p_strecs_40;                    /* continue start receive server */
     }
     switch (adsc_server_conf_1->inc_function) {
#ifdef B130808
#ifdef D_HPPPT1_1
       case DEF_FUNC_HPPPT1:
         memset( &dsl_tun_start1, 0, sizeof(struct dsd_tun_start1) );  /* HTUN start interface */
         if (adsg_loconf_1_inuse->adsc_raw_packet_if_conf) {  /* configuration raw-packet-interface */
           dsl_tun_start1.adsc_wsptun_conf_1
             = &adsg_loconf_1_inuse->adsc_raw_packet_if_conf->dsc_wsptun_conf_1;  /* TUN PPP INETAs */
         }
         dsl_tun_start1.umc_s_nw_ineta = adsc_server_conf_1->umc_s_nw_ineta;  /* server-network-ineta */
         dsl_tun_start1.umc_s_nw_mask = adsc_server_conf_1->umc_s_nw_mask;  /* server-network-mask */
         goto p_strecs_20;                  /* start HOB-TUN           */
       case DEF_FUNC_SSTP:                  /* set function SSTP Tunnel */
         memset( &dsl_tun_start1, 0, sizeof(struct dsd_tun_start1) );  /* HTUN start interface */
         if (adsg_loconf_1_inuse->adsc_raw_packet_if_conf) {  /* configuration raw-packet-interface */
           dsl_tun_start1.adsc_wsptun_conf_1
             = &adsg_loconf_1_inuse->adsc_raw_packet_if_conf->dsc_wsptun_conf_1;  /* TUN PPP INETAs */
         }
         goto p_strecs_20;                  /* start HOB-TUN           */
#endif
#endif
#ifdef D_INCL_HOB_TUN
       case DEF_FUNC_HPPPT1:
         memset( &ADSL_CONN1_G->dsc_tun_contr_conn, 0, sizeof(struct dsd_tun_contr_conn) );  /* HOB-TUN control area connection */
         ADSL_CONN1_G->dsc_tun_contr_conn.iec_tunc = ied_tunc_ppp;  /* PPP - HOB-PPP-T1 */
#ifndef B150706
         ADSL_CONN1_G->dsc_tun_contr_conn.imc_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* session number */
         ADSL_CONN1_G->dsc_tun_contr_conn.imc_trace_level = ADSL_CONN1_G->imc_trace_level;  /* WSP trace level */
#endif
         memset( &dsl_tun_start_ppp, 0, sizeof(struct dsd_tun_start_ppp) );  /* HOB-TUN start interface PPP */
         dsl_tun_start_ppp.umc_s_nw_ineta_ipv4 = ADSL_CONN1_G->adsc_server_conf_1->umc_s_nw_ineta;  /* server-network-ineta */
         dsl_tun_start_ppp.umc_s_nw_mask_ipv4 = ADSL_CONN1_G->adsc_server_conf_1->umc_s_nw_mask;  /* server-network-mask */
         goto p_strecs_24;                  /* start HOB-TUN           */
       case DEF_FUNC_SSTP:                  /* set function SSTP Tunnel */
         memset( &ADSL_CONN1_G->dsc_tun_contr_conn, 0, sizeof(struct dsd_tun_contr_conn) );  /* HOB-TUN control area connection */
         ADSL_CONN1_G->dsc_tun_contr_conn.iec_tunc = ied_tunc_sstp;  /* SSTP */
#ifndef B150706
         ADSL_CONN1_G->dsc_tun_contr_conn.imc_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* session number */
         ADSL_CONN1_G->dsc_tun_contr_conn.imc_trace_level = ADSL_CONN1_G->imc_trace_level;  /* WSP trace level */
#endif
         memset( &dsl_tun_start_ppp, 0, sizeof(struct dsd_tun_start_ppp) );  /* HOB-TUN start interface PPP */
         goto p_strecs_24;                  /* start HOB-TUN           */
#endif
       case DEF_FUNC_L2TP:                  /* set function L2TP UDP connection */
         iec_servcotype = ied_servcotype_l2tp;  /* L2TP                */
         adsc_sdhc1_l2tp_sch = NULL;        /* no buffers to send      */
         /* start L2TP                                                 */
         m_l2tp_conn( adsc_server_conf_1->adsc_l2tp_conf,
                      &dsc_l2tp_session,
                      adsc_server_conf_1->iec_scp_def,
                      adsc_server_conf_1->umc_s_nw_ineta,
                      adsc_server_conf_1->umc_s_nw_mask );
         iec_st_ses = ied_ses_start_server_1;  /* status server continue */
#ifdef OLD_1112
         if (adsc_radqu) {                  /* radius still active     */
           adsc_radqu->boc_did_connect = TRUE;  /* did connect         */
         }
#endif
#ifndef OLD_1112
         if (this->adsc_wsp_auth_1) {       /* authentication active   */
           this->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
           this->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
         }
#endif
         goto p_strecs_40;                  /* continue start receive server */
     }
     do {                                   /* only for break          */
       if (adsc_server_conf_1->boc_sdh_reflect) {  /* only Server-Data-Hook */
#ifdef OLD_1112
         if (adsc_radqu) break;             /* Radius still active     */
#endif
#ifndef OLD_1112
         if (this->adsc_wsp_auth_1) break;  /* authentication active   */
#endif
         iec_st_ses = ied_ses_start_sdh;    /* start Server-Data-Hooks */
         bol_start_sdh = TRUE;              /* start Server-Data-Hook  */
         break;
       }
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "IBIPGW08.cpp l%05d clconn1::m_start_rec_server() do connect()", __LINE__ );
#endif
       adsl_server_ineta_w1 = adsc_server_conf_1->adsc_server_ineta;  /* server INETA */
#ifndef B121120
       al_free_ti1 = NULL;                  /* INETA to free           */
#endif
       if (adsc_server_conf_1->boc_dns_lookup_before_connect) {  /* needs to solve INETA before connect */
         adsl_server_ineta_w1 = m_get_target_ineta( adsc_server_conf_1->achc_dns_name,  /* address of DNS name */
                                                    adsc_server_conf_1->imc_len_dns_name,  /* length of DNS name */
                                                    ied_chs_ansi_819,
                                                    &adsc_server_conf_1->dsc_bind_out );
         if (adsl_server_ineta_w1 == NULL) {  /* could not resolve INETA */
           m_hlnew_printf( HLOG_WARN1, "HWSPS170W GATE=%(ux)s SNO=%08d INETA=%s configured INETA %.*s could not by resolved by DNS",
                           adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta,
                           adsc_server_conf_1->imc_len_dns_name,  /* length of DNS name */
                           adsc_server_conf_1->achc_dns_name );  /* address of DNS name */
#define DEF_ERR_NO_DNS 124
#ifdef OLD_1112
           if (adsc_radqu) {                /* radius still active     */
             adsc_radqu->imc_connect_error = DEF_ERR_NO_DNS;
             adsc_radqu->boc_did_connect = TRUE;  /* did connect       */
             return;
           }
#endif
#ifndef OLD_1112
           if (this->adsc_wsp_auth_1) {     /* authentication active   */
             this->adsc_wsp_auth_1->imc_connect_error = DEF_ERR_NO_DNS;
             this->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
             this->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
             return;
           }
#endif
           if (this->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
             this->adsc_int_webso_conn_1->imc_connect_error = DEF_ERR_NO_DNS;
             this->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
             this->adsc_int_webso_conn_1->boc_notify = TRUE;  /* notify SDH */
             return;
           }
// to-do 03.07.10 KB we return now, we do not need to start the SDHs
           iec_st_ses = ied_ses_error_conn;  /* status server error     */
           if (adsc_server_conf_1->boc_dynamic == FALSE) return;  /* not dynamicly allocated */
           iec_st_ses = ied_ses_error_co_dyn;  /* status server error  */
           return;
         }
#ifndef B121120
         al_free_ti1 = adsl_server_ineta_w1;  /* INETA to free         */
#endif
       }
#ifdef B130808
#ifdef D_INCL_HOB_TUN
       if (adsc_server_conf_1->boc_use_ineta_appl) {  /* use HTCP      */
         memset( &dsl_tun_start1, 0, sizeof(struct dsd_tun_start1) );  /* HOB-TUN start interface */
         iel_irs_def = ied_ineta_raws_user_ipv4;  /* INETA user IPV4   */
         this->adsc_ineta_raws_1 = m_prepare_htun_ineta( &dsl_tun_start1.dsc_soa_local,
                                                         &iml_local_namelen,
                                                         this,
                                                         ADSL_AUX_CF1->adsc_hco_wothr,
                                                         iel_irs_def );
         if (this->adsc_ineta_raws_1) {     /* INETA found             */
// to-do 03.07.10 KB display INETA
           iml_rc = IP_getnameinfo( (struct sockaddr *) &dsl_tun_start1.dsc_soa_local, iml_local_namelen,
                                    chrl_ineta_local, sizeof(chrl_ineta_local),
                                    0, 0, NI_NUMERICHOST );
           if (iml_rc < 0) {                  /* error occured           */
             if (cl_tcp_r::hws2mod != NULL) {  /* functions loaded       */
               iml_rc = cl_tcp_r::afunc_wsaglerr();  /* get error code   */
             }
             m_hlnew_printf( HLOG_WARN1, "HWSPS171W GATE=%(ux)s SNO=%08d INETA=%s getnameinfo local failed with code %d.",
                             adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, iml_rc );
           } else {
             m_hlnew_printf( HLOG_INFO1, "HWSPS172I GATE=%(ux)s SNO=%08d INETA=%s use ineta-appl %s TCP source port %d.",
                             adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, chrl_ineta_local, this->adsc_ineta_raws_1->usc_appl_port );
           }
#ifdef B120206
           adsc_ineta_raws_1 = adsl_ineta_raws_1_w1;  /* auxiliary field for HOB-TUN */
           adsc_ineta_raws_1->dsc_tun_contr1.iec_tunc = ied_tunc_htcp;  /* HTUN interface type */
#endif
           dsl_tun_start1.adsc_server_ineta = adsl_server_ineta_w1;  /* server INETA */
           dsl_tun_start1.imc_server_port = adsc_server_conf_1->inc_server_port;  /* TCP/IP port connect */
           dsl_tun_start1.boc_connect_round_robin = adsc_server_conf_1->boc_connect_round_robin;  /* do connect round-robin */
           iec_st_ses = ied_ses_wait_conn_s_static;  /* wait for static connect to server */
#ifdef B120208
           goto p_strecs_24;                /* start HTUN              */
#else
           goto p_strecs_20;                /* start HOB-TUN           */
#endif
         }
#ifdef B120206
#ifdef NEW_HOB_TUN_1103
         adsc_ineta_raws_1                  /* auxiliary field for HOB-TUN */
           = (struct dsd_ineta_raws_1 *) malloc( sizeof(struct dsd_ineta_raws_1) + sizeof(UNSIG_MED) );
         iel_irs_def = ied_ineta_raws_user_ipv4;  /* INETA user IPV4   */
         bol1 = m_prepare_htun_ineta( adsc_ineta_raws_1,
                                      &dsl_tun_start1.dsc_soa_local,
                                      &iml_local_namelen,
                                      this,
                                      ADSL_AUX_CF1->adsc_hco_wothr,
                                      iel_irs_def );
         if (bol1) {                        /* INETA found             */
// to-do 03.07.10 KB display INETA
           iml_rc = IP_getnameinfo( (struct sockaddr *) &dsl_tun_start1.dsc_soa_local, iml_local_namelen,
                                    chrl_ineta_local, sizeof(chrl_ineta_local),
                                    0, 0, NI_NUMERICHOST );
           if (iml_rc < 0) {                  /* error occured           */
             if (cl_tcp_r::hws2mod != NULL) {  /* functions loaded       */
               iml_rc = cl_tcp_r::afunc_wsaglerr();  /* get error code   */
             }
             m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s getnameinfo local failed with code %d.",
                             adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, iml_rc );
           } else {
             m_hlnew_printf( HLOG_INFO1, "HWSPSnnnI GATE=%(ux)s SNO=%08d INETA=%s use ineta-appl %s TCP source port %d.",
                             adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, chrl_ineta_local, adsc_ineta_raws_1->usc_appl_port );
           }
           dsc_tun_contr1.iec_tunc = ied_tunc_htcp;  /* HOB-TUN interface type HTCP */
           dsl_tun_start1.adsc_server_ineta = adsl_server_ineta_w1;  /* server INETA */
           dsl_tun_start1.imc_server_port = adsc_server_conf_1->inc_server_port;  /* TCP/IP port connect */
           dsl_tun_start1.boc_connect_round_robin = adsc_server_conf_1->boc_connect_round_robin;  /* do connect round-robin */
           iec_st_ses = ied_ses_wait_conn_s_static;  /* wait for static connect to server */
           adsc_ineta_raws_1->ac_conn1 = this;  /* set connection      */
           goto p_strecs_24;                /* start HOB-TUN           */
         }
         free( adsc_ineta_raws_1 );         /* free HOB-TUN area again */
         adsc_ineta_raws_1 = NULL;          /* no more HOB-TUN area    */
#endif
#endif
         m_hlnew_printf( HLOG_WARN1, "HWSPS173W GATE=%(ux)s SNO=%08d INETA=%s configured use-ineta-appl but no ineta-appl available - use normal TCP",
                         this->adsc_gate1 + 1, this->dsc_co_sort.imc_sno, this->chrc_ineta );
       }
#endif
#endif
#ifdef B130826
       iec_servcotype = ied_servcotype_normal_tcp;  /* normal TCP      */
#ifdef TRY100514$01
#include "xiipgw08-test-ineta-1.cpp"
#endif
//     iec_st_ses = ied_ses_wait_conn_s_pttd;  /* wait for connect to server, pass-thru-to-desktop */
       iec_st_ses = ied_ses_wait_conn_s_static;  /* wait for static connect to server */
       bol1 = dcl_tcp_r_s.m_connect_1( this,
                                       &adsc_server_conf_1->dsc_bind_out,
                                       adsl_server_ineta_w1,  /* server INETA */
#ifndef B121120
                                       al_free_ti1,  /* INETA to free  */
#endif
                                       adsc_server_conf_1->inc_server_port,  /* TCP/IP port connect */
                                       adsc_server_conf_1->boc_connect_round_robin,  /* do connect round-robin */
                                       NULL );  /* structure to post from network callback */
       if (bol1) return;
       m_hlnew_printf( HLOG_WARN1, "HWSPS174W GATE=%(ux)s SNO=%08d INETA=%s m_connect_1() failed",
                       this->adsc_gate1 + 1, this->dsc_co_sort.imc_sno, this->chrc_ineta );
// to-do 13.08.10 KB what to do ???
       return;
#endif
#ifndef B130826
//#ifndef B121121
       iml_rc = m_tcp_static_conn( ADSL_AUX_CF1, FALSE );
       if (iml_rc == 0) return;             /* no error occured        */
#ifdef XYZ1
       ADSL_CONN1_G->dsc_tc1_server.boc_connected = FALSE;  /* TCP session is not connected */
//     boc_tcpc_act = FALSE;                /* TCPCOMP not active      */
#endif
       m_hlnew_printf( HLOG_WARN1, "HWSPS175W GATE=%(ux)s SNO=%08d INETA=%s IBIPGW08 l%05d m_tcp_static_conn() failed %d.",
                       ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta, __LINE__, iml_rc );
// to-do 21.11.12 KB what to do ???
       return;
//#endif
#endif
     } while (FALSE);
#ifdef OLD_1112
     if (adsc_radqu) {                      /* radius still active     */
       adsc_radqu->boc_did_connect = TRUE;  /* did connect             */
     }
#endif
#ifndef OLD_1112
     if (this->adsc_wsp_auth_1) {           /* authentication active   */
       this->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
       this->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
     }
#endif
     if (this->adsc_int_webso_conn_1) {     /* connect for WebSocket applications - internal */
       this->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
       this->adsc_int_webso_conn_1->boc_notify = TRUE;  /* notify SDH */
#ifndef B140701
       ADSL_CONN1_G->boc_signal_set = TRUE;  /* signal for component set */
#endif
     }
   }
#ifdef OLD_1112
   if (adsc_radqu) return;                  /* radius still active     */
#endif
#ifndef OLD_1112
   if (this->adsc_wsp_auth_1) return;       /* authentication active   */
#endif
#ifdef B140701
   if (this->adsc_int_webso_conn_1) return;  /* connect for WebSocket applications - internal */
#endif
   /* check start receiving server                                     */
#ifndef X101214_XX
   if (iec_st_ses == ied_ses_start_server_1) {  /* status server       */
#ifdef FORKEDIT
   }
#endif
#else
   if (   (iec_st_ses == ied_ses_start_server_1)  /* status server      */
       || (iec_st_ses == ied_ses_start_dyn_serv_1)) {  /* start connection to server part one dynamic */
#endif
#ifdef B100731
     iec_st_ses = ied_ses_start_sdh;        /* start Server-Data-Hooks */
     bol_start_sdh = TRUE;                  /* start Server-Data-Hook  */
#endif
#ifndef X101214_XX
#ifndef B100731
     iec_st_ses = ied_ses_start_server_2;   /* start connection to server part two */
#endif
#else
     if (iec_st_ses != ied_ses_start_dyn_serv_1) {  /* start connection to server part one dynamic */
       iec_st_ses = ied_ses_start_server_2;  /* start connection to server part two */
     } else {
       iec_st_ses = ied_ses_start_dyn_serv_2;  /* start connection to server part two dynamic */
     }
#endif
     switch (adsc_server_conf_1->inc_function) {
//#ifdef D_HPPPT1_1
#ifdef D_INCL_HOB_TUN
       case DEF_FUNC_HPPPT1:
//       dsc_tun_contr1.iec_tunc = ied_tunc_ppp;  /* PPP type session  */
//       goto p_strecs_20;                  /* start HTUN              */
         goto p_strecs_40;                  /* continue start receive server */
       case DEF_FUNC_SSTP:                  /* set function SSTP Tunnel */
//       dsc_tun_contr1.iec_tunc = ied_tunc_sstp;  /* SSTP session type */
//       goto p_strecs_20;                  /* start HTUN              */
         goto p_strecs_40;                  /* continue start receive server */
#endif
       case DEF_FUNC_L2TP:                  /* set function L2TP UDP connection */
         iec_servcotype = ied_servcotype_l2tp;  /* L2TP                */
         adsc_sdhc1_l2tp_sch = NULL;        /* no buffers to send      */
         /* start L2TP                                                 */
         m_l2tp_conn( adsc_server_conf_1->adsc_l2tp_conf,
                      &dsc_l2tp_session,
                      adsc_server_conf_1->iec_scp_def,
                      adsc_server_conf_1->umc_s_nw_ineta,
                      adsc_server_conf_1->umc_s_nw_mask );
         goto p_strecs_40;                  /* continue start receive server */
     }
     if (iec_servcotype == ied_servcotype_normal_tcp) {  /* normal TCP */
#ifdef XYZ1
#ifdef TRY_110523_01
       dcl_tcp_r_s.start2();                /* start TCPCOMP           */
#endif
#endif
       dcl_tcp_r_s.start3();                /* receive data now        */
     }
#ifndef B100731
     do {
       if (this->adsc_server_conf_1->boc_use_csssl == FALSE) break;  /* do not use client-side-SSL */
       if (this->adsc_csssl_oper_1) {
         m_hlnew_printf( HLOG_XYZ1, "IBIPGW08 l%05d clconn1::m_start_rec_server() this->adsc_csssl_oper_1 already set",
                         __LINE__ );
         break;
       }
       this->adsc_csssl_oper_1
         = (struct dsd_csssl_oper_1 *) malloc( sizeof(struct dsd_csssl_oper_1)
                                                 + this->adsc_server_conf_1->imc_len_dns_name + 1 );
       memset( this->adsc_csssl_oper_1, 0, sizeof(struct dsd_csssl_oper_1) );
       if (this->adsc_server_conf_1->imc_len_dns_name) {
         memcpy( ADSL_CONN1_G->adsc_csssl_oper_1 + 1,
                 this->adsc_server_conf_1->achc_dns_name,  /* address of DNS name */
                 this->adsc_server_conf_1->imc_len_dns_name );
       }
       *((char *) (ADSL_CONN1_G->adsc_csssl_oper_1 + 1) + this->adsc_server_conf_1->imc_len_dns_name) = 0;  /* make zero-terminated */
       this->adsc_csssl_oper_1->dsc_hlcl01s.amc_aux = &m_cdaux;  /* subroutine */
       this->adsc_csssl_oper_1->dsc_hlcl01s.amc_conn_callback = &m_ssl_conn_cl_compl_cl;
       this->adsc_csssl_oper_1->dsc_hlcl01s.amc_ocsp_start = &m_ocsp_start;
       this->adsc_csssl_oper_1->dsc_hlcl01s.amc_ocsp_send = &m_ocsp_send;
       this->adsc_csssl_oper_1->dsc_hlcl01s.amc_ocsp_recv = &m_ocsp_recv;
       this->adsc_csssl_oper_1->dsc_hlcl01s.amc_ocsp_stop = &m_ocsp_stop;
       this->adsc_csssl_oper_1->dsc_hlcl01s.vpc_config_id = adsg_loconf_1_inuse->vpc_csssl_config_id;
       iec_st_ses = ied_ses_wait_csssl;     /* wait for client-side SSL */
     } while (FALSE);
#endif
#ifdef B100731
     if (adsc_server_conf_1->boc_hc_proxauth) {  /* HOBCOM proxy communic */
#ifdef FORKEDIT
//   }
#endif
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
       memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
       adsl_sdhc1_w1->adsc_gather_i_1_i = (struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1);
       adsl_sdhc1_w1->inc_function = DEF_IFUNC_TOSERVER;
       adsl_sdhc1_w1->inc_position = -1;    /* send direct to server   */
       adsl_sdhc1_w1->boc_ready_t_p = TRUE;  /* ready to process       */
       achl1 = (char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1);  /* start of buffer */
       ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))->achc_ginp_cur
         = (char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1);  /* start of buffer */
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XFA;
       *achl1++ = (char) 0X28;
#ifdef B080407
#ifndef HL_IPV6
       *achl1++ = (char) 0X60;
       achl2 = (char *) &dcl_tcp_r_c.dclient1.sin_addr;
       inl1 = 4;
#else
       *achl1++ = (char) 0X60;
       if (bog_ipv6 == FALSE) {
         achl2 = (char *) &dcl_tcp_r_c.uncl1.dsoad_client1.sin_addr;
         inl1 = 4;
       } else {
         if (dcl_tcp_r_c.uncl1.dsost_client1.ss_family == AF_INET) {
           achl2 = (char *) (&((struct sockaddr_in *) (&dcl_tcp_r_c.uncl1.dsost_client1))->sin_addr);
           inl1 = 4;
         } else if (dcl_tcp_r_c.uncl1.dsost_client1.ss_family == AF_INET6) {
           achl2 = (char *) (&((struct sockaddr_in6 *) (&dcl_tcp_r_c.uncl1.dsost_client1))->sin6_addr);
           inl1 = 16;
         } else {
           achl2 = "";
           inl1 = 1;
         }
       }
#endif
#endif
#ifndef B080407
       *achl1++ = (char) 0X60;
       if (dcl_tcp_r_c.dsc_soa.ss_family == AF_INET) {
         achl2 = (char *) (&((struct sockaddr_in *) (&dcl_tcp_r_c.dsc_soa))->sin_addr);
         inl1 = 4;
       } else if (dcl_tcp_r_c.dsc_soa.ss_family == AF_INET6) {
         achl2 = (char *) (&((struct sockaddr_in6 *) (&dcl_tcp_r_c.dsc_soa))->sin6_addr);
         inl1 = 16;
       } else {
         achl2 = "";
         inl1 = 1;
       }
#endif
       do {
         *achl1++ = *achl2;
         if (*achl2 == (char) 0XFF) *achl1++ = (char) 0XFF;
         achl2++;
         inl1--;
       } while (inl1 > 0);
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XF0;
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XFA;
       *achl1++ = (char) 0X28;
       *achl1++ = (char) 0X61;
       adsl_auxf_1_w1 = adsc_auxf_1;        /* anchor of extensions    */
       inl1 = 0;                            /* no name found           */
       while (adsl_auxf_1_w1) {             /* loop over chain         */
         if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_certname) {
#ifdef B080205
           /* does UTF-8 contain hexa FF?                              */
           inl1 = m_u8l_from_u16l( achl1,
                                   ((char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1)) - 2
                                     - achl1,
                                   (HL_WCHAR *) (((int *) (adsl_auxf_1_w1 + 1)) + 1),
                                   *((int *) (adsl_auxf_1_w1 + 1)) );
           if (inl1 >= 0) achl1 += inl1;    /* add length output       */
           else achl1 += ((char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1)) - 2
                           - achl1;
#else
           inl1 = m_u8l_from_u16l( achl1,
                                   ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - 2)
                                     - achl1,
                                   (HL_WCHAR *) (((int *) (adsl_auxf_1_w1 + 1)) + 1),
                                   *((int *) (adsl_auxf_1_w1 + 1)) );
           if (inl1 > 0) achl1 += inl1;     /* add length output       */
#endif
           break;
         }
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
       }
       /* output name from WSP-Socks-mode if no certificate            */
       if (inl1 <= 0) {                     /* no name from certificate */
#ifdef TRACEHL_USER_080202
         m_hlnew_printf( HLOG_XYZ1, "IBIPGW08 l%05d clconn1::m_start_rec_server() adsc_user_entry=%p.",
                         __LINE__, adsc_user_entry );
#endif
         if (adsc_user_entry) {             /* structure user entry found */
           achl1 += m_cpy_vx_vx( achl1,
                                 ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - 2)
                                   - achl1,
                                 ied_chs_utf_8,
                                 (adsc_user_entry + 1), -1, ied_chs_utf_16 );
         } else achl1 -= 6;                 /* no user name            */
       }
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XF0;
       ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))->achc_ginp_end = achl1;
       /* send to server immediately                                   */
       adsl_sdhc1_cur_1 = adsc_sdhc1_chain;  /* get chain              */
       adsl_sdhc1_last_1 = NULL;            /* clear last in chain found */
       while (adsl_sdhc1_cur_1) {           /* loop over all buffers   */
         if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
             && (adsl_sdhc1_cur_1->inc_position < 0)) {
           break;
         }
         adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* set last in chain found */
         adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
       }
       if (adsl_sdhc1_last_1 == NULL) {     /* insert at start of chain */
         adsc_sdhc1_chain = adsl_sdhc1_w1;
       } else {                             /* insert middle in chain  */
         adsl_sdhc1_last_1->adsc_next = adsl_sdhc1_w1;
       }
     }
#endif
   }
#ifdef D_INCL_HOB_TUN
   goto p_strecs_40;                        /* continue start receive server */

#ifdef B130808
   p_strecs_20:                             /* start HOB-TUN           */
#ifdef B080924
/* 26.04.08 better do subroutine */
   adsl_conn_hpppt1_ss = (struct dsd_conn_hpppt1_ss *) malloc( sizeof(struct dsd_conn_hpppt1_ss) );
   memset( adsl_conn_hpppt1_ss, 0, sizeof(struct dsd_conn_hpppt1_ss) );
   adsl_conn_hpppt1_ss->dsc_send_server_1.iec_tss = ied_tss_hpppt1;
   adsl_conn_hpppt1_ss->adsc_conn1 = this;  /* class connection        */
   adsl_conn_hpppt1_ss->dsc_tun_contr1.iec_tunc = ied_tunc_ppp;                //PPP type session
   adsl_conn_hpppt1_ss->dsc_tun_contr1.dsc_ineta_conf_1.imc_family = AF_INET;  //IPv4 type client
   *((UNSIG_MED *) &adsl_conn_hpppt1_ss->dsc_tun_contr1.dsc_ineta_conf_1.chrc_ineta) = inet_addr( "172.22.61.4" );
   *((UNSIG_MED *) &adsl_conn_hpppt1_ss->dsc_tun_contr1.dsc_ineta_conf_1.chrc_dns_pri) = inet_addr( "172.22.0.1" );
   *((UNSIG_MED *) &adsl_conn_hpppt1_ss->dsc_tun_contr1.dsc_ineta_conf_1.chrc_dns_sec) = inet_addr( "172.22.0.3" );
   *((UNSIG_MED *) &adsl_conn_hpppt1_ss->dsc_tun_contr1.dsc_ineta_conf_1.chrc_wins_pri) = inet_addr( "172.22.0.103" );
   *((UNSIG_MED *) &adsl_conn_hpppt1_ss->dsc_tun_contr1.dsc_ineta_conf_1.chrc_wins_sec) = inet_addr( "172.22.0.107" );
   adsl_conn_hpppt1_ss->dsc_tun_ppp_h = m_htun_new_ppp( &adsl_conn_hpppt1_ss->dsc_tun_contr1 );
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T clconn1::m_start_rec_server() m_htun_new_ppp() returned %p adsl_conn_hpppt1_ss=%p &dsc_tun_contr1=%p.",
                   __LINE__, adsl_conn_hpppt1_ss->dsc_tun_ppp_h, adsl_conn_hpppt1_ss, &adsl_conn_hpppt1_ss->dsc_tun_contr1 );
   adsc_send_server_1_ch = &adsl_conn_hpppt1_ss->dsc_send_server_1;  /* for send to server */
   iec_st_ses = ied_ses_start_server_1;     /* status server continue  */
   if (adsc_radqu) {                        /* radius still active     */
     adsc_radqu->boc_did_connect = TRUE;    /* did connect             */
     return;
   }
#endif
#ifdef B100702
   memset( &dsc_tun_contr1.dsc_soa_local, 0, sizeof(struct sockaddr_storage) );  /* address information INETA to be used locally */
   dsc_tun_contr1.dsc_soa_local.ss_family = AF_INET;  /* IPV4          */
   *((UNSIG_MED *) &((struct sockaddr_in *) &dsc_tun_contr1.dsc_soa_local)->sin_addr)
     = umc_ineta_ppp_ipv4;                  /* INETA PPP IPV4          */
#endif
#ifdef XYZ1
   iel_irs_def = ied_ineta_raws_n_ipv4;     /* INETA IPV4              */
   adsl_ineta_raws_1_w1 = m_prepare_htun_ineta( &dsl_tun_start1.dsc_soa_local,
                                                &iml_local_namelen,
                                                this,
                                                ADSL_AUX_CF1->adsc_hco_wothr,
                                                iel_irs_def );
   if (adsl_ineta_raws_1_w1 == NULL) {      /* no INETA found          */
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s tries to start raw-interface PPP but no ineta-ppp available",
                     adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta );
#define DEF_HTUN_ERR_NO_INETA 123
#ifdef OLD_1112
     if (adsc_radqu) {                      /* radius still active     */
       adsc_radqu->imc_connect_error = DEF_HTUN_ERR_NO_INETA;
       adsc_radqu->boc_did_connect = TRUE;  /* did connect             */
       return;
     }
#endif
#ifndef OLD_1112
     if (this->adsc_wsp_auth_1) {           /* authentication active   */
       this->adsc_wsp_auth_1->imc_connect_error = DEF_HTUN_ERR_NO_INETA;
       this->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
       this->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
       return;
     }
#endif
     if (this->adsc_int_webso_conn_1) {     /* connect for WebSocket applications - internal */
       this->adsc_int_webso_conn_1->imc_connect_error = DEF_HTUN_ERR_NO_INETA;
       this->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
       this->adsc_int_webso_conn_1->boc_notify = TRUE;  /* notify SDH  */
#ifndef B140701
       ADSL_CONN1_G->boc_signal_set = TRUE;  /* signal for component set */
#endif
       return;
     }
// to-do 03.07.10 KB we return now, we do not need to start the SDHs
     iec_st_ses = ied_ses_error_conn;       /* status server error     */
     if (adsc_server_conf_1->boc_dynamic == FALSE) return;  /* not dynamicly allocated */
     iec_st_ses = ied_ses_error_co_dyn;     /* status server error     */
     return;
   }
// to-do 03.07.10 KB display INETA
   iml_rc = IP_getnameinfo( (struct sockaddr *) &dsl_tun_start1.dsc_soa_local, iml_local_namelen,
                            chrl_ineta_local, sizeof(chrl_ineta_local),
                            0, 0, NI_NUMERICHOST );
   if (iml_rc < 0) {                        /* error occured           */
     if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
       iml_rc = cl_tcp_r::afunc_wsaglerr();  /* get error code         */
     }
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s getnameinfo local failed with code %d.",
                     adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, iml_rc );
   } else {
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s use ineta-ppp %s.",
                     adsc_gate1 + 1, dsc_co_sort.imc_sno, chrc_ineta, chrl_ineta_local );
   }
   switch (adsc_server_conf_1->inc_function) {
     case DEF_FUNC_HPPPT1:
       adsl_ineta_raws_1_w1->dsc_tun_contr1.iec_tunc = ied_tunc_ppp;  /* PPP type session */
       break;
     case DEF_FUNC_SSTP:                  /* set function SSTP Tunnel */
       adsl_ineta_raws_1_w1->dsc_tun_contr1.iec_tunc = ied_tunc_sstp;  /* SSTP type session */
       break;
   }
#endif
#ifdef B120206
#ifdef NEW_HOB_TUN_1103
   switch (adsc_server_conf_1->inc_function) {
     case DEF_FUNC_HPPPT1:
       dsc_tun_contr1.iec_tunc = ied_tunc_ppp;  /* PPP type session   */
       break;
     case DEF_FUNC_SSTP:                  /* set function SSTP Tunnel */
       dsc_tun_contr1.iec_tunc = ied_tunc_sstp;  /* SSTP type session */
       break;
   }
#endif
#ifdef B130813
#ifdef B120208

   p_strecs_24:                             /* start TUN - entry HTCP  */
#else
   memset( &this->dsc_tun_contr1, 0, sizeof(struct dsd_tun_contr1) );
   switch (adsc_server_conf_1->inc_function) {
     case DEF_FUNC_HPPPT1:
       this->dsc_tun_contr1.iec_tunc = ied_tunc_ppp;  /* PPP type session */
       break;
     case DEF_FUNC_SSTP:                  /* set function SSTP Tunnel */
       this->dsc_tun_contr1.iec_tunc = ied_tunc_sstp;  /* SSTP type session */
       break;
     default:
       this->dsc_tun_contr1.iec_tunc = ied_tunc_htcp;  /* HOB-TUN interface type HTCP */
       this->adsc_ineta_raws_1->ac_conn1 = this;  /* set connection    */
       break;
   }
#endif
#endif
#endif
   iec_servcotype = ied_servcotype_htun;    /* HOB-TUN                 */
#ifdef XYZ1
   adsc_auxf_1_htun = adsl_auxf_1_htun;     /* auxiliary extension field HTUN */
   adsl_auxf_1_htun->adsc_next = adsc_auxf_1;  /* get old chain auxiliary ext fields */
   adsc_auxf_1 = adsl_auxf_1_htun;          /* set new chain auxiliary ext fields */
#endif
#ifdef B120206
   adsc_ineta_raws_1 = adsl_ineta_raws_1_w1;  /* auxiliary field for HOB-TUN */
#endif
   adsc_sdhc1_htun_sch = NULL;              /* no buffers to send      */
   imc_send_window = 0;                     /* number of bytes to be sent */
#ifdef B120206
   adsl_ineta_raws_1_w1->ac_conn1 = this;   /* set connection          */
   dsl_tun_start1.adsc_htun_h = (dsd_htun_h *) &adsl_ineta_raws_1_w1->dsc_htun_h;  /* where to put the handle created */
   m_htun_new_sess( &dsl_tun_start1, &adsl_ineta_raws_1_w1->dsc_tun_contr1 );
#endif
   dsl_tun_start1.adsc_htun_h = (dsd_htun_h *) &dsc_htun_h;  /* where to put the handle created */
   m_htun_new_sess( &dsl_tun_start1, &dsc_tun_contr1 );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T clconn1::m_start_rec_server() m_htun_new_sess() returned %p &dsc_tun_contr1=%p.",
                   __LINE__, adsl_ineta_raws_1_w1->dsc_htun_h, &adsl_ineta_raws_1_w1->dsc_tun_contr1 );
#endif
#ifdef B120206
   if (adsl_ineta_raws_1_w1->dsc_tun_contr1.iec_tunc == ied_tunc_htcp) {  /* HTCP session type */
     return;                                /* wait till connect complete */
   }
#endif
   if (dsc_tun_contr1.iec_tunc == ied_tunc_htcp) {  /* HTCP session type */
     return;                                /* wait till connect complete */
   }
#ifdef B120206
#ifdef NEW_HOB_TUN_1103
   dsl_tun_start1.adsc_htun_h = (dsd_htun_h *) &dsc_htun_h;  /* where to put the handle created */
   m_htun_new_sess( &dsl_tun_start1, &dsc_tun_contr1 );
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T clconn1::m_start_rec_server() m_htun_new_sess() returned %p &dsc_tun_contr1=%p.",
                   __LINE__, dsc_htun_h, &dsc_tun_contr1 );
#endif
   if (dsc_tun_contr1.iec_tunc == ied_tunc_htcp) {  /* HTCP session type */
     return;                                /* wait till connect complete */
   }
#endif
#endif
   iec_st_ses = ied_ses_start_server_1;     /* status server continue  */
#ifdef OLD_1112
   if (adsc_radqu) {                        /* radius still active     */
     adsc_radqu->boc_did_connect = TRUE;    /* did connect             */
     return;
   }
#endif
#ifndef OLD_1112
   if (this->adsc_wsp_auth_1) {             /* authentication active   */
     this->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
     this->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
     return;
   }
#endif
   if (this->adsc_int_webso_conn_1) {       /* connect for WebSocket applications - internal */
     this->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
     this->adsc_int_webso_conn_1->boc_notify = TRUE;  /* notify SDH    */
     return;
   }
#endif
#ifndef B130813

   p_strecs_24:                             /* start TUN - entry HTCP  */
#endif
   adsl_raw_packet_if_conf = adsg_loconf_1_inuse->adsc_raw_packet_if_conf;  /* configuration raw-packet-interface */
#define DEF_HTUN_ERR_NO_CONF 124
   if (adsl_raw_packet_if_conf == NULL) {  /* cannot start HOB-TUN */
     if (ADSL_CONN1_G->adsc_wsp_auth_1) {  /* authentication active */
// to-do 16.09.12 KB - other error number
       ADSL_CONN1_G->adsc_wsp_auth_1->imc_connect_error = DEF_HTUN_ERR_NO_CONF;
       ADSL_CONN1_G->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
       ADSL_CONN1_G->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
       return;
     }
     ADSL_CONN1_G->iec_st_ses = ied_ses_error_conn;  /* status server error */
     if (ADSL_CONN1_G->adsc_server_conf_1->boc_dynamic == FALSE) return;  /* not dynamicly allocated */
     ADSL_CONN1_G->iec_st_ses = ied_ses_error_co_dyn;  /* status server error */
     return;
   }
#ifdef XYZ1
   if (adsg_loconf_1_inuse->adsc_raw_packet_if_conf) {  /* configuration raw-packet-interface */
     dsl_tun_start1.adsc_wsptun_conf_1
       = &adsg_loconf_1_inuse->adsc_raw_packet_if_conf->dsc_wsptun_conf_1;  /* TUN PPP INETAs */
   }
#endif
   ADSL_CONN1_G->iec_servcotype = ied_servcotype_htun;  /* HOB-TUN     */
#ifndef B140728
   memset( &ADSL_CONN1_G->dsc_soa_htcp_server, 0, sizeof(struct sockaddr_storage) );  /* address information for connected */
#endif
   ADSL_CONN1_G->adsc_sdhc1_htun_sch = NULL;  /* no buffers to send    */
   ADSL_CONN1_G->imc_send_window = 0;       /* number of bytes to be sent */
   ADSL_CONN1_G->imc_ppp_state = 0;         /* PPP state               */
   ADSL_CONN1_G->adsc_ppp_netw_post_1 = NULL;  /* structure to post from network callback */
   dsl_tun_start_ppp.adsc_htun_h = (void **) &ADSL_CONN1_G->dsc_htun_h;  /* where to put the handle created */
   m_htun_new_sess_ppp( &dsl_tun_start_ppp, &ADSL_CONN1_G->dsc_tun_contr_conn );
   ADSL_CONN1_G->iec_st_ses = ied_ses_start_server_1;  /* status server continue */
   if (ADSL_CONN1_G->adsc_wsp_auth_1) {     /* authentication active   */
     ADSL_CONN1_G->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
     ADSL_CONN1_G->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
     return;
   }
#ifdef B140701
   if (ADSL_CONN1_G->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
     ADSL_CONN1_G->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
     ADSL_CONN1_G->adsc_int_webso_conn_1->boc_notify = TRUE;  /* notify SDH */
     return;
   }
#endif
#endif

   p_strecs_40:                             /* continue start receive server */
#ifndef B140701
#ifdef TRY_150220_01                        /* problems DoD WebSocket     */
   if (ADSL_CONN1_G->iec_st_ses != ied_ses_do_cpttdt) {  /* connect pass thru to desktop */
#endif
   if (ADSL_CONN1_G->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
     ADSL_CONN1_G->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
     ADSL_CONN1_G->adsc_int_webso_conn_1->boc_notify = TRUE;  /* notify SDH */
     ADSL_CONN1_G->iec_st_ses = ied_ses_conn;  /* normal state of session */
     ADSL_CONN1_G->boc_signal_set = TRUE;  /* signal for component set */
     return;
   }
#ifdef TRY_150220_01                        /* problems DoD WebSocket     */
   }
#endif
#endif
#ifndef B100731
   if (iec_st_ses == ied_ses_start_server_2) {  /* status server       */
     iec_st_ses = ied_ses_start_sdh;        /* start Server-Data-Hooks */
     bol_start_sdh = TRUE;                  /* start Server-Data-Hook  */
     if (adsc_server_conf_1->boc_hc_proxauth) {  /* HOBCOM proxy communic */
       adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) m_proc_alloc();
       memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
       adsl_sdhc1_w1->adsc_gather_i_1_i = (struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1);
       adsl_sdhc1_w1->inc_function = DEF_IFUNC_TOSERVER;
       adsl_sdhc1_w1->inc_position = -1;    /* send direct to server   */
#ifdef B110904
       adsl_sdhc1_w1->boc_ready_t_p = TRUE;  /* ready to process       */
#endif
       adsl_sdhc1_w1->iec_sdhcs = ied_sdhcs_activate;  /* activate SDH when possible */
       achl1 = (char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1);  /* start of buffer */
       ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))->achc_ginp_cur
         = (char *) adsl_sdhc1_w1 + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1);  /* start of buffer */
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XFA;
       *achl1++ = (char) 0X28;
       *achl1++ = (char) 0X60;
       if (dcl_tcp_r_c.dsc_soa.ss_family == AF_INET) {
         achl2 = (char *) (&((struct sockaddr_in *) (&dcl_tcp_r_c.dsc_soa))->sin_addr);
         inl1 = 4;
       } else if (dcl_tcp_r_c.dsc_soa.ss_family == AF_INET6) {
         achl2 = (char *) (&((struct sockaddr_in6 *) (&dcl_tcp_r_c.dsc_soa))->sin6_addr);
         inl1 = 16;
       } else {
         achl2 = "";
         inl1 = 1;
       }
       do {
         *achl1++ = *achl2;
         if (*achl2 == (char) 0XFF) *achl1++ = (char) 0XFF;
         achl2++;
         inl1--;
       } while (inl1 > 0);
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XF0;
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XFA;
       *achl1++ = (char) 0X28;
       *achl1++ = (char) 0X61;
       adsl_auxf_1_w1 = adsc_auxf_1;        /* anchor of extensions    */
       inl1 = 0;                            /* no name found           */
       while (adsl_auxf_1_w1) {             /* loop over chain         */
         if (adsl_auxf_1_w1->iec_auxf_def == ied_auxf_certname) {
           inl1 = m_u8l_from_u16l( achl1,
                                   ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - 2)
                                     - achl1,
                                   (HL_WCHAR *) (((int *) (adsl_auxf_1_w1 + 1)) + 1),
                                   *((int *) (adsl_auxf_1_w1 + 1)) );
           if (inl1 > 0) achl1 += inl1;       /* add length output       */
           break;
         }
         adsl_auxf_1_w1 = adsl_auxf_1_w1->adsc_next;  /* get next in chain */
       }
       /* output name from WSP-Socks-mode if no certificate              */
       if (inl1 <= 0) {                     /* no name from certificate */
#ifdef TRACEHL_USER_080202
         m_hlnew_printf( HLOG_XYZ1, "IBIPGW08 l%05d clconn1::m_start_rec_server() adsc_user_entry=%p.",
                         __LINE__, adsc_user_entry );
#endif
         if (adsc_user_entry) {             /* structure user entry found */
           achl1 += m_cpy_vx_vx( achl1,
                                 ((char *) adsl_sdhc1_w1 + LEN_TCP_RECV - 2)
                                   - achl1,
                                 ied_chs_utf_8,
                                 (adsc_user_entry + 1), -1, ied_chs_utf_16 );
         } else achl1 -= 6;                 /* no user name            */
       }
       *achl1++ = (char) 0XFF;
       *achl1++ = (char) 0XF0;
       ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))->achc_ginp_end = achl1;
       /* send to server immediately                                   */
       adsl_sdhc1_cur_1 = adsc_sdhc1_chain;  /* get chain              */
       adsl_sdhc1_last_1 = NULL;            /* clear last in chain found */
       while (adsl_sdhc1_cur_1) {           /* loop over all buffers   */
         if (   (adsl_sdhc1_cur_1->inc_function != DEF_IFUNC_FROMSERVER)
             && (adsl_sdhc1_cur_1->inc_position < 0)) {
           break;
         }
         adsl_sdhc1_last_1 = adsl_sdhc1_cur_1;  /* set last in chain found */
         adsl_sdhc1_cur_1 = adsl_sdhc1_cur_1->adsc_next;  /* get next in chain */
       }
       if (adsl_sdhc1_last_1 == NULL) {     /* insert at start of chain */
         adsc_sdhc1_chain = adsl_sdhc1_w1;
       } else {                             /* insert middle in chain  */
         adsl_sdhc1_last_1->adsc_next = adsl_sdhc1_w1;
       }
     }
   }
#endif
   if (bol_start_sdh == FALSE) return;      /* start Server-Data-Hook  */
   if (adsc_int_webso_conn_1) return;       /* connect for WebSocket applications - internal */
// if (adsc_server_conf_1 == NULL) return;  /* no server               */
//#ifdef B100830
   if (adsc_server_conf_1->inc_no_sdh == 0) return;  /* no server-data-hook */
//#endif
#ifdef B100830_XXX
   if (adsc_server_conf_1->inc_no_sdh == 0) {  /* no server-data-hook  */
     iec_st_ses = ied_ses_conn;             /* do not start Server-Data-Hooks */
     return;
   }
#endif
#ifndef X101214_XX
#ifdef B101208
   if (adsc_server_conf_1->boc_dynamic) {   /* dynamicly allocated     */
     iec_st_ses = ied_ses_conn;             /* do not start Server-Data-Hooks */
     return;
   }
#else
#ifdef B101214
   if (adsc_server_conf_1->adsc_seco1_previous) {  /* configuration server previous */
     iec_st_ses = ied_ses_conn;             /* do not start Server-Data-Hooks */
     return;
   }
#ifdef XYZ1
   if (   (adsc_server_conf_1->boc_dynamic)  /* dynamicly allocated    */
       && (ADSL_CONN1_G->iec_servcotype != ied_servcotype_none)) {  /* with server connection */
     iec_st_ses = ied_ses_conn;             /* do not start Server-Data-Hooks */
     return;
   }
#endif
#endif
#endif
#endif
#ifndef B101214
#ifdef B110207_XXX
   iec_st_ses = ied_ses_conn;               /* Server-Data-Hooks have started */
#endif
   if (   (adsc_server_conf_1->adsc_seco1_previous)  /* configuration server previous */
       || (adsc_server_conf_1->inc_no_sdh == 0)  /* no server-data-hook */
       || (boc_sdh_started)) {              /* Server-Data-Hooks have been started */
#ifndef B110207_XXX
     iec_st_ses = ied_ses_conn;             /* do not start Server-Data-Hooks */
#endif
     return;
   }
#ifdef B110211_XXX
   if (iec_servcotype != ied_servcotype_none) {  /* with server connection */
     iec_st_ses = ied_ses_conn;             /* session connected to server */
   }
#endif
   boc_sdh_started = TRUE;                  /* Server-Data-Hooks have been started */
#endif
   inl1 = 0;                                /* count the hooks         */

#ifdef B080609
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (adsc_server_conf_1 + 1) \
                          + inl1 * sizeof(struct dsd_sdh_work_1)))->adsc_sdhl_1
#endif
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (adsc_server_conf_1 + 1) \
                          + inl1 * sizeof(struct dsd_sdh_work_1)))->adsc_ext_lib1
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "before   pstsdh20 adsc_server_conf_1=%p ...(struct)=%p ADSL_SDH_LIB1=%p.",
                   adsc_server_conf_1,
                   ((char *) (adsc_server_conf_1 + 1) + inl1 * sizeof(struct dsd_sdh_work_1)),
                   ADSL_SDH_LIB1 );
#endif

   pstsdh20:                                /* start Server-Data-Hook  */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "at label pstsdh20 adsc_server_conf_1=%p ...(struct)=%p ADSL_SDH_LIB1=%p.",
                   adsc_server_conf_1,
                   ((char *) (adsc_server_conf_1 + 1) + inl1 * sizeof(struct dsd_sdh_work_1)),
                   ADSL_SDH_LIB1 );
#endif
#ifdef DEBUG_120118_01                      /* watch inc_no_sdh        */
   m_hlnew_printf( HLOG_XYZ1, "l%05d at label pstsdh20 adsc_server_conf_1=%p ...&inc_no_sdh<%p>-->%p.",
                   __LINE__, this->adsc_server_conf_1, &this->adsc_server_conf_1->inc_no_sdh, this->adsc_server_conf_1->inc_no_sdh );
#endif
#ifndef B120116
   adsp_pd_work->imc_hookc = inl1;          /* set number of SDH       */
#endif
   memset( &dsl_sdh_l1, 0, sizeof(dsl_sdh_l1) );
#ifdef B120116
   if (adsc_server_conf_1->inc_no_sdh < 2) {
     dsl_sdh_l1.ac_ext = dsc_sdh_s_1.ac_ext;  /* attached buffer pointer */
//   bol1 = ADSL_CONN1_G->dsc_sdh_s_1.boc_ended;  /* processing of this SDH has ended */
   } else {
     dsl_sdh_l1.ac_ext = adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].ac_ext;  /* attached buffer pointer */
//   bol1 = ADSL_CONN1_G->adsrc_sdh_s_1[ adsp_pd_work->imc_hookc ].boc_ended;  /* processing of this SDH has ended */
   }
#endif
#ifndef B120116
#ifdef XYZ1                                 /* not needed              */
   if (adsc_server_conf_1->inc_no_sdh < 2) {
     dsl_sdh_l1.ac_ext = dsc_sdh_s_1.ac_ext;  /* attached buffer pointer */
   } else {
     dsl_sdh_l1.ac_ext = adsrc_sdh_s_1[ inl1 ].ac_ext;  /* attached buffer pointer */
   }
#endif
#endif
   dsl_sdh_l1.inc_func = DEF_IFUNC_START;
   dsl_sdh_l1.vpc_userfld = ADSL_AUX_CF1;   /* pointer to parameter area */
#ifdef B130314
   ADSL_AUX_CF1->iec_src_func = ied_src_fu_sdh;  /* Server-Data-Hook   */
   /* current Server-Data-Hook                                         */
   ADSL_AUX_CF1->ac_sdh
     = (void *) ((char *) (this->adsc_server_conf_1 + 1) + inl1 * sizeof(struct dsd_sdh_work_1));
#endif
   ADSL_AUX_CF1->dsc_cid.iec_src_func = ied_src_fu_sdh;  /* Server-Data-Hook */
   /* current Server-Data-Hook                                         */
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr
     = (void *) ((char *) (this->adsc_server_conf_1 + 1) + inl1 * sizeof(struct dsd_sdh_work_1));
   dsl_sdh_l1.amc_aux = &m_cdaux;           /* subroutine              */
   dsl_sdh_l1.ac_conf = ((struct dsd_sdh_work_1 *) \
                          ((char *) (adsc_server_conf_1 + 1) \
                            + inl1 * sizeof(struct dsd_sdh_work_1)))->ac_conf;
#ifdef OLD_1112
   dsl_sdh_l1.ac_hobwspat2_conf = adsc_gate1->vpc_hlwspat2_conf;  /* data from HOB-WSP-AT2 configuration */
#endif
   dsl_sdh_l1.ac_hobwspat3_conf = adsc_gate1->vpc_hobwspat3_conf;  /* configuration authentication library */
   /* flags of configuration                                           */
   if (adsc_gate1->inc_no_usgro) {          /* user group defined */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_USERLI;
   }
#ifdef OLD_1112
   if (adsc_gate1->inc_no_radius) {         /* radius server defined */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_RADIUS;
   }
#endif
#ifndef OLD_1112
   if (this->adsc_gate1->imc_no_radius) {   /* radius server defined   */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_RADIUS;
     if (this->adsc_gate1->imc_no_radius > 1) {  /* multiple radius server defined */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_RADIUS;
     }
   }
#endif
   if (adsc_gate1->imc_no_krb5_kdc) {       /* number of Kerberos 5 KDCs */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_KRB5;  /* Kerberos 5 KDC defined */
     if (adsc_gate1->imc_no_krb5_kdc > 1) {  /* number of Kerberos 5 KDCs */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_KRB5;  /* dynamic Kerberos 5 KDC defined */
     }
   }
   if (adsc_gate1->imc_no_ldap_group) {     /* number of LDAP groups   */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_LDAP;  /* LDAP group defined */
     if (adsc_gate1->imc_no_ldap_group > 1) {  /* number of LDAP groups */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_LDAP;  /* dynamic LDAP groups defined */
     }
   }
   dsl_sdh_l1.imc_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* session number */
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SDH_INT) {  /* WSP Trace SDH intern */
     dsl_sdh_l1.imc_trace_level
       = HL_AUX_WT_ALL                      /* WSP Trace SDH all       */
           | (ADSL_CONN1_G->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2));
   }
#ifdef TRACEHL1
   {
     void *vph1, *vph2;
     vph1 = ADSL_SDH_LIB1;
     vph2 = ADSL_SDH_LIB1->amc_hlclib01;
     m_hlnew_printf( HLOG_XYZ1, "pstsdh20 addr method1 amc_hlclib01=%p", vph2 );
   }
#endif
#ifdef TRACEHL_P_050118
   {
     struct dsd_gather_i_1 *adsh_gather_i_1_1;  /* gather data         */
     adsh_gather_i_1_1 = dsl_sdh_l1.adsc_gather_i_1_in;
     while (adsh_gather_i_1_1) {
       if (   (adsh_gather_i_1_1->achc_ginp_cur < adsh_gather_i_1_1->achc_ginp_end)
           && (*adsh_gather_i_1_1->achc_ginp_cur >= 0X05)) {
         ims_p_050118++;
       }
       adsh_gather_i_1_1 = adsh_gather_i_1_1->adsc_next;
     }
     adsh_gather_i_1_1 = dsl_sdh_l1.adsc_gather_i_1_out;
     while (adsh_gather_i_1_1) {
       if (   (adsh_gather_i_1_1->achc_ginp_cur < adsh_gather_i_1_1->achc_ginp_end)
           && (*adsh_gather_i_1_1->achc_ginp_cur >= 0X05)) {
         ims_p_050118++;
       }
       adsh_gather_i_1_1 = adsh_gather_i_1_1->adsc_next;
     }
   }
#endif
   ADSL_SDH_LIB1->amc_hlclib01( &dsl_sdh_l1 );
#ifdef TRACEHL_P_050118
   {
     struct dsd_gather_i_1 *adsh_gather_i_1_1;  /* gather data         */
     adsh_gather_i_1_1 = dsl_sdh_l1.adsc_gather_i_1_in;
     while (adsh_gather_i_1_1) {
       if (   (adsh_gather_i_1_1->achc_ginp_cur < adsh_gather_i_1_1->achc_ginp_end)
           && (*adsh_gather_i_1_1->achc_ginp_cur >= 0X05)) {
         ims_p_050118++;
       }
       adsh_gather_i_1_1 = adsh_gather_i_1_1->adsc_next;
     }
     adsh_gather_i_1_1 = dsl_sdh_l1.adsc_gather_i_1_out;
     while (adsh_gather_i_1_1) {
       if (   (adsh_gather_i_1_1->achc_ginp_cur < adsh_gather_i_1_1->achc_ginp_end)
           && (*adsh_gather_i_1_1->achc_ginp_cur >= 0X05)) {
         ims_p_050118++;
       }
       adsh_gather_i_1_1 = adsh_gather_i_1_1->adsc_next;
     }
   }
#endif
   if (adsc_server_conf_1->inc_no_sdh < 2) {
     dsc_sdh_s_1.ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   } else {
     adsrc_sdh_s_1[ inl1 ].ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   }
   if (dsl_sdh_l1.inc_return != DEF_IRET_NORMAL) {
     if (adsc_server_conf_1->inc_no_sdh < 2) {
       dsc_sdh_s_1.boc_ended = TRUE;        /* processing of this SDH has ended */
     } else {
       adsrc_sdh_s_1[ inl1 ].boc_ended = TRUE;  /* processing of this SDH has ended */
     }
#ifdef NOT_YET
     dsl_sdh_l1.boc_callagain = FALSE;      /* do not process last server-data-hook again */
     dsl_sdh_l1.boc_callrevdir = FALSE;     /* not requested to call again in reverse direction */
#endif
   }
#undef ADSL_SDH_LIB1

   /* process next Server-Data-Hook                                    */
   inl1++;                                  /* increment no se-da-hook */
   if (inl1 < adsc_server_conf_1->inc_no_sdh) goto pstsdh20;
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
   return;
} /* end clconn1::m_start_rec_server()                                 */

inline void clconn1::m_end_server( void ) {  /* the server has ended   */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T clconn1::m_end_server() called this=%p.",
                   __LINE__, this );
#endif
#ifdef TRY_140319_01                        /* end TCPCOMP without received end */
   this->iec_servcotype = ied_servcotype_none;  /* no server connection */
   if (this->iec_st_ses == ied_ses_conn) {  /* server is connected     */
     goto p_act_00;                         /* session was active before */
   }
#endif
   if (iec_st_ses != ied_ses_wait_conn_s_static) return;  /* wait for static connect to server */
// to-do 13.08.10 KB where do we get the error number from ???
#ifdef OLD_1112
   if (adsc_radqu) {                        /* radius still active     */
     adsc_radqu->imc_connect_error = 1234;
     adsc_radqu->boc_did_connect = TRUE;    /* did connect             */
     return;
   }
#endif
#ifndef OLD_1112
#ifndef TRY_140319_01                        /* end TCPCOMP without received end */
   this->iec_servcotype = ied_servcotype_none;  /* no server connection */
#endif
   if (this->adsc_wsp_auth_1) {             /* authentication active   */
     this->adsc_wsp_auth_1->imc_connect_error = this->dcl_tcp_r_s.m_get_conn_error();
     this->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect    */
     this->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
     this->iec_st_ses = ied_ses_auth;       /* status authentication   */
     return;
   }
#endif
   if (this->adsc_int_webso_conn_1) {       /* connect for WebSocket applications - internal */
#ifdef DEBUG_150220_01                      /* Dod connect too earl    */
     m_hlnew_printf( HLOG_TRACE1, "DEBUG_150220_01 l%05d clconn1::m_start_rec_server()", __LINE__ );
#endif
     this->adsc_int_webso_conn_1->imc_connect_error = this->dcl_tcp_r_s.m_get_conn_error();
     this->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
     this->adsc_int_webso_conn_1->boc_notify = TRUE;  /* notify SDH    */
     this->iec_st_ses = ied_ses_conn;       /* server is connected     */
     return;
   }
   this->iec_st_ses = ied_ses_error_conn;   /* status server error     */
   if (adsc_server_conf_1->boc_dynamic == FALSE) return;  /* not dynamicly allocated */
   this->iec_st_ses = ied_ses_error_co_dyn;  /* status server error    */
#ifdef TRY_140319_01                        /* end TCPCOMP without received end */
   return;

   p_act_00:                                /* session was active before */
   if (achc_reason_end == NULL) {           /* reason end session      */
     /* do not set when dynamic server                                 */
     if (   (this->adsc_server_conf_1 == NULL)
         || (this->adsc_server_conf_1->boc_dynamic == FALSE)) {
       achc_reason_end = "server TCP end";
     }
   }
   if (this->chrc_server_error[0] == 0) {   /* no error message yet    */
     sprintf( this->chrc_server_error,      /* display server error    */
              "TCP end" );
   }
   this->iec_st_ses = ied_ses_rec_close;    /* received close          */
#endif
} /* end m_end_server()                                                */

inline void clconn1::cleanup( struct dsd_pd_work *adsp_pd_work ) {  /* cleanup */
   int        inl1;                         /* working variable        */
   BOOL       bol1;                         /* working variable        */
   struct dsd_hl_clib_1 dsl_sdh_l1;         /* HOBLink Copy Library 1  */
   struct dsd_server_conf_1 *adsl_server_conf_1_w1;  /* working variable */
#ifndef B140525
   struct dsd_server_conf_1 *adsl_server_conf_1_used;  /* configuration server */
#endif

#define ADSL_AUX_CF1 (&adsp_pd_work->dsc_aux_cf1)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#ifdef B140525
   if (   (iec_st_ses != ied_ses_conn)      /* not connected           */
       && (iec_st_ses != ied_ses_error_co_dyn)) {  /* error connect to server dynamic */
     goto pclsdh80;                         /* do not call Server-Data-Hook */
   }
   if (   (adsc_server_conf_1 == NULL)      /* no server yet           */
       || (adsc_server_conf_1->inc_no_sdh == 0)) {  /* no server-data-hook */
     goto pclsdh80;                         /* do not call Server-Data-Hook */
   }
#endif
#ifndef B140525
   adsl_server_conf_1_used = this->adsc_server_conf_1;  /* configuration server */
   if (adsl_server_conf_1_used == NULL) {   /* no configuration server */
     goto pclsdh80;                         /* do not call Server-Data-Hook */
   }
   if (this->boc_sdh_started == FALSE) {    /* Server-Data-Hooks have been started */
     goto pclsdh80;                         /* do not call Server-Data-Hook */
   }
   if (adsl_server_conf_1_used->adsc_seco1_previous) {  /* configuration server previous */
     adsl_server_conf_1_used = adsl_server_conf_1_used->adsc_seco1_previous;  /* configuration server previous */
   }
   if (adsl_server_conf_1_used->inc_no_sdh == 0) {  /* no server-data-hook */
     goto pclsdh80;                         /* do not call Server-Data-Hook */
   }
#endif
   inl1 = 0;                                /* count the hooks         */

#ifdef B140525
#ifdef B080609
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (adsc_server_conf_1 + 1) \
                          + inl1 * sizeof(struct dsd_sdh_work_1)))->adsc_sdhl_1
#endif
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (adsc_server_conf_1 + 1) \
                          + inl1 * sizeof(struct dsd_sdh_work_1)))->adsc_ext_lib1
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "before pclsdh20 adsc_server_conf_1=%p ...(struct)=%p ADSL_SDH_LIB1=%p",
                   adsc_server_conf_1,
                   ((char *) (adsc_server_conf_1 + 1) + inl1 * sizeof(struct dsd_sdh_work_1)),
                   ADSL_SDH_LIB1 );
#endif
#endif
#ifndef B140525
#define ADSL_SDH_LIB1 ((struct dsd_sdh_work_1 *) \
                        ((char *) (adsl_server_conf_1_used + 1) \
                          + inl1 * sizeof(struct dsd_sdh_work_1)))->adsc_ext_lib1
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "before pclsdh20 adsc_server_conf_1=%p ...(struct)=%p ADSL_SDH_LIB1=%p",
                   adsc_server_conf_1,
                   ((char *) (adsl_server_conf_1_used + 1) + inl1 * sizeof(struct dsd_sdh_work_1)),
                   ADSL_SDH_LIB1 );
#endif
#endif

   pclsdh20:                                /* close Server-Data-Hook  */
   memset( &dsl_sdh_l1, 0, sizeof(dsl_sdh_l1) );
#ifdef B140525
   if (adsc_server_conf_1->inc_no_sdh < 2) {
     dsl_sdh_l1.ac_ext = dsc_sdh_s_1.ac_ext;  /* attached buffer pointer */
     bol1 = dsc_sdh_s_1.boc_ended;          /* processing of this SDH has ended */
   } else {
     dsl_sdh_l1.ac_ext = adsrc_sdh_s_1[ inl1 ].ac_ext;  /* attached buffer pointer */
     bol1 = adsrc_sdh_s_1[ inl1 ].boc_ended;  /* processing of this SDH has ended */
   }
#endif
#ifndef B140525
   if (adsl_server_conf_1_used->inc_no_sdh < 2) {
     dsl_sdh_l1.ac_ext = dsc_sdh_s_1.ac_ext;  /* attached buffer pointer */
     bol1 = dsc_sdh_s_1.boc_ended;          /* processing of this SDH has ended */
   } else {
     dsl_sdh_l1.ac_ext = adsrc_sdh_s_1[ inl1 ].ac_ext;  /* attached buffer pointer */
     bol1 = adsrc_sdh_s_1[ inl1 ].boc_ended;  /* processing of this SDH has ended */
   }
#endif
   if (bol1) goto pclsdh40;                 /* SDH has already ended   */
   dsl_sdh_l1.inc_func = DEF_IFUNC_CLOSE;
   dsl_sdh_l1.vpc_userfld = ADSL_AUX_CF1;   /* pointer to parameter area */
#ifdef B130314
   ADSL_AUX_CF1->iec_src_func = ied_src_fu_sdh;  /* Server-Data-Hook   */
   /* current Server-Data-Hook                                         */
   ADSL_AUX_CF1->ac_sdh
     = (void *) ((char *) (adsc_server_conf_1 + 1) + inl1 * sizeof(struct dsd_sdh_work_1));
#endif
   ADSL_AUX_CF1->dsc_cid.iec_src_func = ied_src_fu_sdh;  /* Server-Data-Hook */
   /* current Server-Data-Hook                                         */
#ifdef B140525
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr
     = (void *) ((char *) (adsc_server_conf_1 + 1) + inl1 * sizeof(struct dsd_sdh_work_1));
   dsl_sdh_l1.amc_aux = &m_cdaux;           /* subroutine              */
   dsl_sdh_l1.ac_conf = ((struct dsd_sdh_work_1 *) \
                          ((char *) (adsc_server_conf_1 + 1) \
                            + inl1 * sizeof(struct dsd_sdh_work_1)))->ac_conf;
#endif
#ifndef B140525
   ADSL_AUX_CF1->dsc_cid.ac_cid_addr
     = (void *) ((char *) (adsl_server_conf_1_used + 1) + inl1 * sizeof(struct dsd_sdh_work_1));
   dsl_sdh_l1.amc_aux = &m_cdaux;           /* subroutine              */
   dsl_sdh_l1.ac_conf = ((struct dsd_sdh_work_1 *) \
                          ((char *) (adsl_server_conf_1_used + 1) \
                            + inl1 * sizeof(struct dsd_sdh_work_1)))->ac_conf;
#endif
#ifdef OLD_1112
   dsl_sdh_l1.ac_hobwspat2_conf = adsc_gate1->vpc_hlwspat2_conf;  /* data from HOB-WSP-AT2 configuration */
#endif
   dsl_sdh_l1.ac_hobwspat3_conf = adsc_gate1->vpc_hobwspat3_conf;  /* configuration authentication library */
   /* flags of configuration                                           */
   if (adsc_gate1->inc_no_usgro) {          /* user group defined      */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_USERLI;
   }
#ifdef OLD_1112
   if (adsc_gate1->inc_no_radius) {         /* radius server defined   */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_RADIUS;
   }
#endif
#ifndef OLD_1112
   if (this->adsc_gate1->imc_no_radius) {   /* radius server defined   */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_RADIUS;
     if (this->adsc_gate1->imc_no_radius > 1) {  /* multiple radius server defined */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_RADIUS;
     }
   }
#endif
   if (adsc_gate1->imc_no_krb5_kdc) {       /* number of Kerberos 5 KDCs */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_KRB5;  /* Kerberos 5 KDC defined */
     if (adsc_gate1->imc_no_krb5_kdc > 1) {  /* number of Kerberos 5 KDCs */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_KRB5;  /* dynamic Kerberos 5 KDC defined */
     }
   }
   if (adsc_gate1->imc_no_ldap_group) {     /* number of LDAP groups   */
     dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_LDAP;  /* LDAP group defined */
     if (adsc_gate1->imc_no_ldap_group > 1) {  /* number of LDAP groups */
       dsl_sdh_l1.imc_flags_1 |= DEF_CLIB1_CONF_DYN_LDAP;  /* dynamic LDAP groups defined */
     }
   }
   dsl_sdh_l1.imc_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* session number */
   if (ADSL_CONN1_G->imc_trace_level & HL_WT_SESS_SDH_INT) {  /* WSP Trace SDH intern */
     dsl_sdh_l1.imc_trace_level
       = HL_AUX_WT_ALL                      /* WSP Trace SDH all       */
           | (ADSL_CONN1_G->imc_trace_level & (HL_WT_SESS_DATA1 | HL_WT_SESS_DATA2));
   }
#ifdef TRACEHL1
   {
     void *vph1, *vph2;
     vph1 = ADSL_SDH_LIB1;
     vph2 = ADSL_SDH_LIB1->amc_hlclib01;
     m_hlnew_printf( HLOG_XYZ1, "pclsdh20 addr method1 amc_hlclib01=%p", vph2 );
   }
#endif
   ADSL_SDH_LIB1->amc_hlclib01( &dsl_sdh_l1 );
#ifdef B140525
   if (adsc_server_conf_1->inc_no_sdh < 2) {
     dsc_sdh_s_1.ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   } else {
     adsrc_sdh_s_1[ inl1 ].ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   }
#endif
#ifndef B140525
   if (adsl_server_conf_1_used->inc_no_sdh < 2) {
     this->dsc_sdh_s_1.ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   } else {
     this->adsrc_sdh_s_1[ inl1 ].ac_ext = dsl_sdh_l1.ac_ext;  /* attached buffer pointer */
   }
#endif
#undef ADSL_SDH_LIB1

   pclsdh40:                                /* process next Server-Data-Hook */
   inl1++;                                  /* increment no se-da-hook */
#ifdef B140525
   if (inl1 < adsc_server_conf_1->inc_no_sdh) goto pclsdh20;
#endif
#ifndef B140525
   if (inl1 < adsl_server_conf_1_used->inc_no_sdh) goto pclsdh20;
#endif

   pclsdh80:                                /* Server-Data-Hook ended  */
   if (adsc_lbal_gw_1) delete adsc_lbal_gw_1;
#ifdef WORK051119
   if (dcl_wsat1_1) {                       /* class authentication    */
     dcl_wsat1_1->HL_AUTH_ABEND();          /* process abend           */
   }
#endif
#ifdef OLD_1112
   if (adsc_radqu) {                        /* Radius Query active     */
/* UUUU 19.11.05 KB - end HLWSPAT2 */
     adsc_radqu->m_delete();                /* delete entry            */
   }
#endif
#ifdef B140213
   if (adsc_cpttdt) {                       /* connect PTTD thread     */
     adsc_cpttdt->adsc_conn1 = NULL;        /* no more connected       */
   }
#endif
#ifdef B140525
   if (   (adsrc_sdh_s_1)                   /* array work area server data hook per session */
       && (this->adsc_server_conf_1)        /* server connected        */
       && (this->adsc_server_conf_1->inc_no_sdh >= 2)) {  /* array needed */
     free( adsrc_sdh_s_1 );                 /* free memory             */
   }
#endif
#ifndef B140525
   if (   (this->adsrc_sdh_s_1)             /* array work area server data hook per session */
       && (adsl_server_conf_1_used)         /* server connected        */
       && (adsl_server_conf_1_used->inc_no_sdh >= 2)) {  /* array needed */
     free( this->adsrc_sdh_s_1 );           /* free memory             */
   }
#endif
#ifdef B060925
   if (adsc_server_conf_1) {                /* with server             */
     if (adsc_server_conf_1->boc_dynamic) {  /* dynamicly allocated    */
       free( adsc_server_conf_1 );          /* free server entry       */
     }
   }
#endif
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end clconn1::cleanup()                                            */

#ifndef TRACEHL_STOR_USAGE
extern PTYPE void * m_proc_alloc( void ) {
   void     *alrecbuf;                      /* receive buffer          */

#ifdef TRACEHL_P_COUNT
   EnterCriticalSection( &dsalloc_dcritsect );
   ins_count_buf_in_use++;
   if (ins_count_buf_in_use > ins_count_buf_max) ins_count_buf_max = ins_count_buf_in_use;
#ifdef D_STOR_ONE_TIME
   ins_count_memory++;
#endif
   LeaveCriticalSection( &dsalloc_dcritsect );
#ifdef D_STOR_ONE_TIME
   alrecbuf = malloc( LEN_TCP_RECV );
#ifdef TRACEHL_SDH_01
   memset( alrecbuf, 0, sizeof(struct dsd_sdh_control_1) );
   ims_sdhc_alloc_no++;                     /* number of allocates     */
   ((struct dsd_sdh_control_1 *) alrecbuf)->imc_line_no[ 0 ] = ims_sdhc_alloc_no;  /* line numbers for debugging */
#endif
#ifdef TRACEHL_P_DISP
   m_hlnew_printf( HLOG_XYZ1, "+S+ proc_alloc new alrecbuf=%p", alrecbuf );
#endif
#ifdef DEBUG_110315_01
   if (bos_debug_110315_01) {
     m_hlnew_printf( HLOG_XYZ1, "+S+ proc_alloc new alrecbuf=%p / DEBUG_110315_01", alrecbuf );
   }
#endif
   return alrecbuf;
#endif
#endif
   pp_alloc_20:                             /* search buffer           */
#ifndef TRACEHL_P_COUNT
#ifndef TRACEHL_SDH_01
#ifdef B170329
   if (asrecbuf == NULL) return malloc( LEN_TCP_RECV );
#endif
#ifndef B170329
   if (asrecbuf == NULL) {
     alrecbuf = malloc( LEN_TCP_RECV );
     if (alrecbuf) return alrecbuf;
     m_hlnew_printf( HLOG_EMER1, "HWSPM027E out of memory - l%05d m_proc_alloc()",
                     __LINE__ );
     return NULL;
   }
#endif
#else
   if (asrecbuf == NULL) {
     alrecbuf = malloc( LEN_TCP_RECV );
     memset( alrecbuf, 0, sizeof(struct dsd_sdh_control_1) );
     ims_sdhc_alloc_no++;                   /* number of allocates     */
     ((struct dsd_sdh_control_1 *) alrecbuf)->imc_line_no[ 0 ] = ims_sdhc_alloc_no;  /* line numbers for debugging */
     return alrecbuf;
   }
#endif
#else
   if (asrecbuf == NULL) {
     ins_count_memory++;
#ifndef TRACEHL3
#ifndef TRACEHL_SDH_01
     return malloc( LEN_TCP_RECV );
#else
     alrecbuf = malloc( LEN_TCP_RECV );
     memset( alrecbuf, 0, sizeof(struct dsd_sdh_control_1) );
     ims_sdhc_alloc_no++;                   /* number of allocates     */
     ((struct dsd_sdh_control_1 *) alrecbuf)->imc_line_no[ 0 ] = ims_sdhc_alloc_no;  /* line numbers for debugging */
     return alrecbuf;
#endif
#else
     alrecbuf = malloc( LEN_TCP_RECV );
#ifdef TRACEHL_SDH_01
     memset( alrecbuf, 0, sizeof(struct dsd_sdh_control_1) );
     ims_sdhc_alloc_no++;                   /* number of allocates     */
     ((struct dsd_sdh_control_1 *) alrecbuf)->imc_line_no[ 0 ] = ims_sdhc_alloc_no;  /* line numbers for debugging */
#endif
     m_hlnew_printf( HLOG_XYZ1, "+S+ proc_alloc new alrecbuf=%p", alrecbuf );
     return alrecbuf;
#endif
   }
#endif
   EnterCriticalSection( &dsalloc_dcritsect );
   alrecbuf = asrecbuf;                     /* get first in chain      */
   if (alrecbuf) {
     asrecbuf = *((void **) alrecbuf);      /* set next in chain       */
   }
   LeaveCriticalSection( &dsalloc_dcritsect );
#ifndef TRACEHL3
#ifndef TRACEHL_SDH_01
   if (alrecbuf) return alrecbuf;
#else
   if (alrecbuf) {
     memset( alrecbuf, 0, sizeof(struct dsd_sdh_control_1) );
     ims_sdhc_alloc_no++;                   /* number of allocates     */
     ((struct dsd_sdh_control_1 *) alrecbuf)->imc_line_no[ 0 ] = ims_sdhc_alloc_no;  /* line numbers for debugging */
     return alrecbuf;
   }
#endif
#else
   if (alrecbuf) {
     m_hlnew_printf( HLOG_XYZ1, "proc_alloc old alrecbuf=%p", alrecbuf );
#ifdef TRACEHL_SDH_01
     memset( alrecbuf, 0, sizeof(struct dsd_sdh_control_1) );
     ims_sdhc_alloc_no++;                   /* number of allocates     */
     ((struct dsd_sdh_control_1 *) alrecbuf)->imc_line_no[ 0 ] = ims_sdhc_alloc_no;  /* line numbers for debugging */
#endif
     return alrecbuf;
   }
#endif
   goto pp_alloc_20;                        /* repeat                  */
}

extern "C" void m_proc_free( void *ap1 ) {

#ifdef DEBUG_100809
   if (ap1 == as_debug_100809_01) {
     m_hlnew_printf( HLOG_XYZ1, "+S+ proc_free ap1=%p / as_debug_100809_01", ap1 );
   }
#endif
#ifdef DEBUG_110315_01
   if (bos_debug_110315_01) {
     m_hlnew_printf( HLOG_XYZ1, "+S+ proc_free ap1=%p / DEBUG_110315_01", ap1 );
     if (ap1 == as_debug_110315_01) {
       m_hlnew_printf( HLOG_XYZ1, "?S? proc_free debug-point reached" );
     }
   }
#endif
#ifdef D_STOR_ONE_TIME
#ifdef TRACEHL_P_DISP
   m_hlnew_printf( HLOG_XYZ1, "+S+ proc_free ap1=%p", ap1 );
#endif
#ifdef TRACEHL_P_COUNT
   EnterCriticalSection( &dsalloc_dcritsect );
   ins_count_buf_in_use--;
   LeaveCriticalSection( &dsalloc_dcritsect );
#endif
   free( ap1 );
   return;
#endif
#ifdef TRACEHL3
   m_hlnew_printf( HLOG_XYZ1, "+S+ proc_free ap1=%p", ap1 );
#endif
   if (adsg_loconf_1_inuse->boc_clear_used_mem) {  /* clear used memory */
     memset( ap1, 0, LEN_TCP_RECV );        /* clear the memory, is more secure */
   }
#ifdef TRACEHL_P_050118
   free( ap1 );
#ifdef TRACEHL_P_COUNT
   EnterCriticalSection( &dsalloc_dcritsect );
   ins_count_buf_in_use--;
   LeaveCriticalSection( &dsalloc_dcritsect );
#endif
   return;
#endif
   EnterCriticalSection( &dsalloc_dcritsect );
#ifdef TRACEHL_P_COUNT
   ins_count_buf_in_use--;
#endif
   if (is_count_free == 0) is_count_free = 10;
   is_count_free--;
   if (is_count_free) {                     /* keep memory in stock    */
     *((void **) ap1) = asrecbuf;           /* get old chain           */
     asrecbuf = ap1;                        /* set new chain           */
     ap1 = NULL;
   }
   LeaveCriticalSection( &dsalloc_dcritsect );
   if (ap1 == NULL) return;                 /* do not free memory      */
   free( ap1 );                             /* free memory             */
} /* end m_proc_free()                                                 */
#endif
#ifdef TRACEHL_STOR_USAGE
extern PTYPE void * m_proc_alloc( void ) {
   void     *alrecbuf;                      /* receive buffer          */
   struct dsd_tr_stor_usage_01 *adsl_tr_stor_usage_01_w1;

   adsl_tr_stor_usage_01_w1 = (struct dsd_tr_stor_usage_01 *) malloc( sizeof(struct dsd_tr_stor_usage_01) + LEN_TCP_RECV );
   memset( adsl_tr_stor_usage_01_w1, 0, sizeof(struct dsd_tr_stor_usage_01) );
   adsl_tr_stor_usage_01_w1->ac_stack = m_get_stack();
   EnterCriticalSection( &dsalloc_dcritsect );
#ifdef TRACEHL_P_COUNT
   ins_count_buf_in_use++;
   if (ins_count_buf_in_use > ins_count_buf_max) ins_count_buf_max = ins_count_buf_in_use;
#ifdef D_STOR_ONE_TIME
   ins_count_memory++;
#endif
#endif
   adsl_tr_stor_usage_01_w1->adsc_next = adss_tr_stor_usage_01_anchor;
   adss_tr_stor_usage_01_anchor = adsl_tr_stor_usage_01_w1;
   LeaveCriticalSection( &dsalloc_dcritsect );
   return adsl_tr_stor_usage_01_w1 + 1;
} /* end m_proc_alloc()                                                */

extern "C" void m_proc_free( void *ap1 ) {
   struct dsd_tr_stor_usage_01 *adsl_tr_stor_usage_01_w1;
   struct dsd_tr_stor_usage_01 *adsl_tr_stor_usage_01_w2;

   adsl_tr_stor_usage_01_w1 = (struct dsd_tr_stor_usage_01 *) ((char *) ap1 - sizeof(struct dsd_tr_stor_usage_01));

   EnterCriticalSection( &dsalloc_dcritsect );
#ifdef D_STOR_ONE_TIME
#ifdef TRACEHL_P_COUNT
   ins_count_buf_in_use--;
#endif
#endif
   if (adsl_tr_stor_usage_01_w1 == adss_tr_stor_usage_01_anchor) {
     adss_tr_stor_usage_01_anchor = adsl_tr_stor_usage_01_w1->adsc_next;
     adsl_tr_stor_usage_01_w2 = adsl_tr_stor_usage_01_w1;  /* only for error message */
   } else {
     adsl_tr_stor_usage_01_w2 = adss_tr_stor_usage_01_anchor;
     while (   (adsl_tr_stor_usage_01_w2)
            && (adsl_tr_stor_usage_01_w2->adsc_next != adsl_tr_stor_usage_01_w1)) {
       adsl_tr_stor_usage_01_w2 = adsl_tr_stor_usage_01_w2->adsc_next;
     }
     if (adsl_tr_stor_usage_01_w2) {
       adsl_tr_stor_usage_01_w2->adsc_next = adsl_tr_stor_usage_01_w1->adsc_next;
     }
   }
   LeaveCriticalSection( &dsalloc_dcritsect );
   free( adsl_tr_stor_usage_01_w1 );
} /* end m_proc_free()                                                 */

static void m_proc_mark_1( void *ap1, char *achp_pos ) {
   int        iml1;                         /* working variable        */
   struct dsd_tr_stor_usage_01 *adsl_tr_stor_usage_01_w1;

   adsl_tr_stor_usage_01_w1 = (struct dsd_tr_stor_usage_01 *) ((char *) ap1 - sizeof(struct dsd_tr_stor_usage_01));
   iml1 = strlen( achp_pos );
   if (iml1 >= sizeof(adsl_tr_stor_usage_01_w1->chrc_pos)) {
     iml1 = sizeof(adsl_tr_stor_usage_01_w1->chrc_pos) - 1;
   }
   memcpy( adsl_tr_stor_usage_01_w1->chrc_pos, achp_pos, iml1 );
   *(adsl_tr_stor_usage_01_w1->chrc_pos + iml1) = 0;
} /* end m_proc_mark_1()                                               */

static void m_proc_trac_1( void *ap1, char *achp_trac ) {
   int        iml1, iml2;                   /* working variables       */
   struct dsd_tr_stor_usage_01 *adsl_tr_stor_usage_01_w1;
   struct dsd_tr_stor_usage_01 *adsl_tr_stor_usage_01_w2;

// return;
#define LEN_TRAC_ENTRY (sizeof(adsl_tr_stor_usage_01_w1->chrc_trac) / D_NO_TSU_NO)
   adsl_tr_stor_usage_01_w1 = (struct dsd_tr_stor_usage_01 *) ((char *) ap1 - sizeof(struct dsd_tr_stor_usage_01));
   iml1 = strlen( achp_trac );
   if (iml1 >= LEN_TRAC_ENTRY) {
     iml1 = LEN_TRAC_ENTRY - 1;
   }
   EnterCriticalSection( &dsalloc_dcritsect );
   iml2 = adsl_tr_stor_usage_01_w1->imc_ind_trac;
   memcpy( &adsl_tr_stor_usage_01_w1->chrc_trac[ iml2 * LEN_TRAC_ENTRY ],
           achp_trac,
           iml1 );
   *(&adsl_tr_stor_usage_01_w1->chrc_trac[ iml2 * LEN_TRAC_ENTRY ] + iml1) = 0;
   iml2++;
   if (iml2 >= D_NO_TSU_NO) {
     iml2 = 0;
   }
   adsl_tr_stor_usage_01_w1->imc_ind_trac = iml2;
   /* check if still in chain of living blocks                         */
   adsl_tr_stor_usage_01_w2 = adss_tr_stor_usage_01_anchor;
   while (adsl_tr_stor_usage_01_w2) {
     if (adsl_tr_stor_usage_01_w2 == adsl_tr_stor_usage_01_w1) break;
     adsl_tr_stor_usage_01_w2 = adsl_tr_stor_usage_01_w2->adsc_next;
   }
   LeaveCriticalSection( &dsalloc_dcritsect );
   if (adsl_tr_stor_usage_01_w2) return;
   memcpy( &adsl_tr_stor_usage_01_w1->chrc_trac[ iml2 * LEN_TRAC_ENTRY ],
           "not-acquired",
           13 );
#undef LEN_TRAC_ENTRY
   iml2++;
   if (iml2 >= D_NO_TSU_NO) {
     iml2 = 0;
   }
   adsl_tr_stor_usage_01_w1->imc_ind_trac = iml2;
} /* end m_proc_trac_1()                                               */
#endif

/* check if session is still active                                    */
extern "C" BOOL m_check_conn_active( class clconn1 *adsp_conn1 ) {
   return adsp_conn1->bo_st_open;
} /* end m_check_conn_active()                                         */

/* return information about connection for WSP trace                   */
extern "C" void m_get_wsp_trace_info_conn1( struct dsd_wsp_trace_info_conn1 *adsp_wtic, void *ap_conn1 ) {
#define ADSL_CONN1_G ((class clconn1 *) ap_conn1)
   memset( adsp_wtic, 0, sizeof(struct dsd_wsp_trace_info_conn1) );
   adsp_wtic->imc_trace_level = ADSL_CONN1_G->imc_trace_level;  /* trace_level */
   adsp_wtic->imc_sno = ADSL_CONN1_G->dsc_co_sort.imc_sno;  /* WSP session number */
#undef ADSL_CONN1_G
} /* end m_get_wsp_trace_info_conn1()                                  */

/* activate work-thread if not already active                          */
static inline void m_act_thread_1( class clconn1 *adsp_conn1 ) {
   BOOL       bol1;                         /* working-variable        */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_act_thread_1 l%05d adsp_conn1=%p",
                   __LINE__, adsp_conn1 );
#endif
   bol1 = FALSE;                            /* not yet set             */
   m_clconn1_critsect_enter( adsp_conn1 );
   if (adsp_conn1->boc_st_act == FALSE) {   /* thread does not run     */
     adsp_conn1->boc_st_act = TRUE;         /* thread will run soon    */
     bol1 = TRUE;                           /* activate thread         */
   }
   m_clconn1_critsect_leave( adsp_conn1 );
   if (bol1 == FALSE) return;
   m_act_thread_2( adsp_conn1 );
   return;
} /* end m_act_thread_1()                                              */

/* activate work-thread                                                */
static inline void m_act_thread_2( class clconn1 *adsp_conn1 ) {
   struct dsd_call_para_1 dsl_call_para_1_w1;  /* call parameters      */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_act_thread_2 l%05d adsp_conn1=%p",
                   __LINE__, adsp_conn1 );
#endif
   memset( &dsl_call_para_1_w1, 0, sizeof(struct dsd_call_para_1) );
   dsl_call_para_1_w1.amc_function = &m_proc_clconn1;
   dsl_call_para_1_w1.ac_param_1 = adsp_conn1;
   m_hco_run_thread( &dsl_call_para_1_w1 );
   return;
} /* end m_act_thread_2()                                              */

static void m_proc_clconn1( struct dsd_hco_wothr *adsp_hco_wothr,
                            void *ap_param_1, void *ap_param_2, void *ap_param_3 ) {
#define ADSL_CONN1_G ((class clconn1 *) ap_param_1)
   ADSL_CONN1_G->m_proc_data( adsp_hco_wothr );  /* call class method  */
#undef ADSL_CONN1_G
} /* end m_proc_clconn1()                                              */

/** routine called by timer thread when a connection timed out         */
static void m_timeout_conn( struct dsd_timer_ele *adsp_timer_ele ) {
   HL_LONGLONG ill1;                        /* working-variable        */
   char       *achl1;                       /* working-variable        */
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_act_conn;                 /* activate connection     */
   struct dsd_auxf_1 *adsl_auxf_1_w1;       /* auxiliary extension fi  */
#ifdef TRACEHL1
   class clconn1 *adsl_clconn1_t1;
#endif
#ifdef HELP_DEBUG                           /* 04.04.06 KB - help in tracing */
   class clconn1 *ADSL_CONN1_G;
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-%05d-T m_timeout_conn( %p )",
                   __LINE__, adsp_timer_ele );
#endif
#ifndef HELP_DEBUG                           /* 04.04.06 KB - help in tracing */
#define ADSL_CONN1_G ((class clconn1 *) ((char *) adsp_timer_ele - offsetof( class clconn1, dsc_timer )))
#else
   ADSL_CONN1_G = ((class clconn1 *) ((char *) adsp_timer_ele - offsetof( class clconn1, dsc_timer )));
#endif
#ifdef TRACEHL1
   adsl_clconn1_t1 = ADSL_CONN1_G;
   m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-%05d-T m_timeout_conn( %p ) clconn1=%p vpc_chain_2=%p",
                   __LINE__, adsp_timer_ele, adsl_clconn1_t1, adsp_timer_ele->vpc_chain_2 );
#endif
   if (   (ADSL_CONN1_G->ilc_timeout == 0)  /* timeout not set         */
       && (ADSL_CONN1_G->adsc_aux_timer_ch == NULL)) {  /* no auxiliary timer */
     return;
   }
   ill1 = m_get_epoch_ms();                 /* get current time        */
   bol_act_conn = FALSE;                    /* reset activate connection */
#ifndef B150121
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_aux_timer_ch;  /* get anchor of chain */
   if (adsl_auxf_1_w1 == NULL) {            /* no timer chain          */
     goto p_timer_20;                       /* part of timer processed */
   }
   EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#endif
   adsl_auxf_1_w1 = ADSL_CONN1_G->adsc_aux_timer_ch;  /* get anchor of chain */
   while (adsl_auxf_1_w1) {                 /* loop over timer entries */
     if (((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime
           > ill1) {
       break;                               /* timer not yet expired   */
     }
#ifdef XYZ1
     if (((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->iec_auxtu == ied_auxtu_sdh_reload) {  /* wait for SDH-reload */
       if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
         ADSL_CONN1_G->achc_reason_end = "timeout reconnect";  /* set text */
       }
       achl1 = "HWSPS034W GATE=%S SNO=%08d INETA=%s waiting for reconnect - timed out";
       goto p_message;                      /* output message and cancel connection */
     }
#endif
     if (((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->boc_expired == FALSE) {
       ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->boc_expired = TRUE;
#ifndef B130314
       ADSL_CONN1_G->boc_signal_set = TRUE;  /* signal for component set */
#endif
       bol_act_conn = TRUE;                 /* activate connection     */
     }
     adsl_auxf_1_w1 = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->adsc_auxf_next;
   }
#ifdef PROB_T_060504                        /* problem with timer      */
#ifdef B060628
   if (adssticha_anchor) {
     if (adssticha_anchor->adsctiele_first == NULL) {
       m_hlnew_printf( HLOG_WARN1, "IBIPGW08 l%05d m_timeout_conn() error PROB_T_060504",
                       __LINE__ );
     }
   }
   m_hlnew_printf( HLOG_TRACE1, "IBIPGW08 l%05d m_timeout_conn() &dsc_timer=%p vpc_chain_2=%p adsl_auxf_1_w1=%p",
                   __LINE__, &ADSL_CONN1_G->dsc_timer, ADSL_CONN1_G->dsc_timer.vpc_chain_2, adsl_auxf_1_w1 );
#endif /* PROB_T_060504                     problem with timer         */
#endif
#ifndef B150121
   LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */

   p_timer_20:                              /* part of timer processed */
#endif
   if (ADSL_CONN1_G->ilc_timeout == 0) {    /* timeout not set         */
     if (adsl_auxf_1_w1) {                  /* with auxiliary timer    */
       ADSL_CONN1_G->dsc_timer.ilcendtime
         = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime;
       m_time_set( &ADSL_CONN1_G->dsc_timer, TRUE );  /* set timer from new */
     }
   } else if (ill1 < ADSL_CONN1_G->ilc_timeout) {  /* did not timeout yet */
     ADSL_CONN1_G->dsc_timer.ilcendtime = ADSL_CONN1_G->ilc_timeout;
     if (   (adsl_auxf_1_w1)
         && (((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime
               < ADSL_CONN1_G->dsc_timer.ilcendtime)) {
       ADSL_CONN1_G->dsc_timer.ilcendtime
         = ((struct dsd_aux_timer *) (adsl_auxf_1_w1 + 1))->ilc_endtime;
     }
     m_time_set( &ADSL_CONN1_G->dsc_timer, TRUE );  /* set timer from new */
   }
   if (bol_act_conn) {                      /* activate connection     */
     m_act_conn( ADSL_CONN1_G );            /* has to process timer    */
   }
   if (ADSL_CONN1_G->ilc_timeout == 0) return;  /* timeout not set     */
   if (ill1 < ADSL_CONN1_G->ilc_timeout) return;  /* did not timeout yet */
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-%05d-T connection %p timed out time-sec=%d",
                   __LINE__, ADSL_CONN1_G, m_get_time() );
#endif
#ifndef B160410
   ADSL_CONN1_G->ilc_timeout = 0;           /* timeout no more set     */
#endif
   if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
     ADSL_CONN1_G->achc_reason_end = "timeout";  /* set text           */
     if (ADSL_CONN1_G->boc_st_sslc == FALSE) {  /* check status SSL    */
       ADSL_CONN1_G->achc_reason_end = "timeout SSL";  /* set text     */
     }
   }
   achl1 = "HWSPS032W GATE=%(ux)s SNO=%08d INETA=%s connection timed out";
   if (ADSL_CONN1_G->boc_st_sslc == FALSE) {  /* check status SSL      */
     achl1 = "HWSPS031W GATE=%(ux)s SNO=%08d INETA=%s connection timed out (SSL)";
   }
#ifdef XYZ1

   p_message:                               /* output message and cancel connection */
#endif
   m_hlnew_printf( HLOG_WARN1, achl1,
                   ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno, ADSL_CONN1_G->chrc_ineta );
   bol1 = FALSE;                            /* not yet closed          */
   if (ADSL_CONN1_G->iec_st_cls != clconn1::ied_cls_closed) {  /* client connection closed */
     ADSL_CONN1_G->dcl_tcp_r_c.close1();
     bol1 = TRUE;                           /* session closed          */
   }
   if (   (ADSL_CONN1_G->iec_st_ses == clconn1::ied_ses_conn)  /* stat server */
       && (ADSL_CONN1_G->iec_servcotype == ied_servcotype_normal_tcp)) {  /* normal TCP */
     ADSL_CONN1_G->dcl_tcp_r_s.close1();
     bol1 = TRUE;                           /* session closed          */
   }
   if (bol1 == FALSE) {                      /* not yet closed          */
     ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_abend;  /* abnormal end of session */
     m_act_conn( ADSL_CONN1_G );            /* session needs to process end */
   }
#ifndef HELP_DEBUG                           /* 04.04.06 KB - help in tracing */
#undef ADSL_CONN1_G
#endif
} /* end m_timeout_conn()                                              */

/**
   end of HOB-TUN,
   call m_cleanup_htun_ineta() and free storage
   the session thread clears ac_conn1
   first imc_state DEF_STATE_HTUN_FREE_R_2 is set  - done HOB-TUN free resources -
   second dsc_htun_h is cleared
   so by checking both variables (1. and 2.) it can be checked if the resource is already freed
*/
/* routine called by timer thread when the block of the connection has to be freed */
static void m_free_session_b( struct dsd_timer_ele *adsp_timer_ele ) {
#define ADSL_CONN1_G ((class clconn1 *) ((char *) adsp_timer_ele - offsetof( class clconn1, dsc_timer )))
#ifdef DEBUG_140118_01                      /* load-balancing problem  */
    m_hlnew_printf( HLOG_TRACE1, "m_free_session_b() free memory - l%05d ADSL_CONN1_G=%p.",
                    __LINE__, ADSL_CONN1_G );
#endif
#ifdef D_INCL_HOB_TUN
#ifdef B130808
#define ADSL_INETA_RAWS_1_G ADSL_CONN1_G->adsc_ineta_raws_1
   while (ADSL_INETA_RAWS_1_G) {            /* auxiliary field for HOB-TUN */
     if ((ADSL_INETA_RAWS_1_G->imc_state & DEF_STATE_HTUN_FREE_R_1) == 0) break;  /* not yet done HTUN free resources */
     if (ADSL_INETA_RAWS_1_G->imc_state & DEF_STATE_HTUN_FREE_R_2) break;  /* done HTUN free resources */
     m_cleanup_htun_ineta( ADSL_INETA_RAWS_1_G );
     if (ADSL_INETA_RAWS_1_G->adsc_auxf_1_ident) {  /* store ident to free */
       free( ADSL_INETA_RAWS_1_G->adsc_auxf_1_ident );  /* free ident  */
     }
     free( ADSL_INETA_RAWS_1_G );           /* free the memory         */
     break;
   }
#undef ADSL_INETA_RAWS_1_G
#endif
   if (ADSL_CONN1_G->imc_references) {      /* references to this session */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T m_free_session_b() ADSL_CONN1_G=%p imc_references=%d - wait again",
                     __LINE__, ADSL_CONN1_G, ADSL_CONN1_G->imc_references );
#endif
     m_time_set( &ADSL_CONN1_G->dsc_timer, FALSE );  /* set timer now  */
     return;                                /* wait once more          */
   }
#endif
   DeleteCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section */
   delete ADSL_CONN1_G;                     /* free the block of the session */
#undef ADSL_CONN1_G
} /* end m_free_session_b()                                            */

/* routine called by timer thread for delayed freeing of memory        */
static void m_timeout_free_memory( struct dsd_timer_ele *adsp_timer_ele ) {
   free( adsp_timer_ele );                  /* free the memory         */
} /* end m_timeout_free_memory()                                       */

#ifdef OLD_1112
static void HLGW_set_timer( void *apparam, int imp_time ) {
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "HLGW_set_timer apparam=%p iptime=%d",
                   apparam, imp_time );
#endif
#define ADSL_CONN1_G ((class clconn1 *) apparam)
   m_aux_timer_new( ADSL_CONN1_G, ied_src_fu_lbal, NULL, imp_time * 1000 );
   ADSL_CONN1_G->adsc_wtsudp1->boc_timer_set = TRUE;
   return;
#undef ADSL_CONN1_G
} /* end HLGW_set_timer()                                              */

#define D_LOAD_BAL_R1                       /* random processing       */
static void HLGW_sendto_LB( void *apparam, char *achp_buf, int imp_sendlen ) {
   int        iml1;                         /* working-variable        */
   struct sockaddr dsl_soa_lbgw1;           /* client address informat */
   struct dsd_wtsg_1 *adsl_wtsg1_w1;        /* for WTSGATE             */
#ifdef D_MAX_LOAD_BAL
   int        inl_load_bal_no;              /* number of load balanced WTS */
   /* table to mark WTS-servers where data have been sent              */
   struct dsd_wtsg_1 *adsrl_wtsg1[ D_MAX_LOAD_BAL ];
#endif
#ifdef D_LOAD_BAL_R1                        /* random processing       */
   char       *achl1;                       /* working-variable        */
   int        iml_lb_rand;                  /* random position         */
   int        iml_lbal_count;               /* number of load balanced WTS */
   char       *achl_lbal_tab;               /* address of array        */
   char       chrl_lbal_tab[ 16 ];          /* array load balanced sent */
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "HLGW_sendto_LB apparam=%p achp_buf=%p imp_sendlen=%d",
                   apparam, achp_buf, imp_sendlen );
#endif
#define ADSL_CONN1_G ((class clconn1 *) apparam)
   if (ADSL_CONN1_G->adsc_wtsudp1->boc_started == FALSE) {  /* UDP not yet started */
     iml1 = 8;                              /* number of wait          */
     while (   (ADSL_CONN1_G->adsc_wtsudp1->boc_started == FALSE)  /* UDP not yet started */
            && (ADSL_CONN1_G->adsc_wtsudp1->boc_udp_closed == FALSE)  /* UDP socket not closed */
            && (iml1 > 0)) {
       iml1--;                              /* decrement counter       */
       Sleep( 500 );                        /* wait some time          */
     }
     if (ADSL_CONN1_G->adsc_wtsudp1->boc_started == FALSE) {  /* UDP not yet started */
       m_hlnew_printf( HLOG_XYZ1, "HLGW_sendto_LB l%05d UUUU", __LINE__ );
       return;
     }
   }
#ifdef D_MAX_LOAD_BAL
   inl_load_bal_no = 0;                     /* clear number of load balanced WTS */
#endif
#ifdef D_LOAD_BAL_R1                        /* random processing       */
   iml_lb_rand = 0;                         /* clear random position   */
   achl_lbal_tab = chrl_lbal_tab;           /* pointer on array        */
#endif
   adsl_wtsg1_w1 = ADSL_CONN1_G->adsc_server_conf_1->adsc_wtsg1;
   if (adsl_wtsg1_w1 == NULL) {             /* do broadcast            */
     memset( (char *) &dsl_soa_lbgw1, 0, sizeof(struct sockaddr) );
     ((struct sockaddr_in *) &dsl_soa_lbgw1)->sin_family = AF_INET;
     ((struct sockaddr_in *) &dsl_soa_lbgw1)->sin_port
       = IP_htons( ADSL_CONN1_G->adsc_server_conf_1->inc_wts_br_port );
     ((struct sockaddr_in *) &dsl_soa_lbgw1)->sin_addr.s_addr
        = 0XFFFFFFFF;                       /* set broadcast           */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "HLGW_sendto_LB send broadcast port=%d",
                     ADSL_CONN1_G->adsc_server_conf_1->inc_wts_br_port );
#endif
     goto pstlb40;                          /* send to LB              */
   }
#ifdef D_MAX_LOAD_BAL
   do {
     if (inl_load_bal_no >= D_MAX_LOAD_BAL) break;
     adsrl_wtsg1[ inl_load_bal_no++ ] = adsl_wtsg1_w1;  /* get address structure */
     adsl_wtsg1_w1 = adsl_wtsg1_w1->next;           /* get next in chain       */
   } while (adsl_wtsg1_w1);
#endif
#ifdef D_LOAD_BAL_R1                        /* random processing       */
   iml_lbal_count = 0;                      /* clear number of load balanced WTS */
   do {                                     /* loop over all WTS       */
     iml_lbal_count++;                      /* count random position   */
     adsl_wtsg1_w1 = adsl_wtsg1_w1->adsc_next;  /* get next in chain   */
   } while (adsl_wtsg1_w1);
   if (iml_lbal_count > sizeof(chrl_lbal_tab)) {
     achl_lbal_tab = (char *) malloc( iml_lbal_count );
   }
   memset( achl_lbal_tab, 0, iml_lbal_count );
   iml_lb_rand = iml_lbal_count;            /* start with count        */
#endif

   pstlb20:                                 /* send to next LB         */
#ifdef D_LOAD_BAL_R1                        /* random processing       */
   iml1 = m_get_random_number( iml_lb_rand );
   adsl_wtsg1_w1 = ADSL_CONN1_G->adsc_server_conf_1->adsc_wtsg1;
   achl1 = achl_lbal_tab;                   /* start of table          */
   while (TRUE) {                           /* loop over array         */
     if (*achl1 == 0) {                     /* entry not yet used      */
       if (iml1 == 0) break;                /* target position reached */
       iml1--;                              /* count random position   */
     }
     achl1++;                               /* next entry in array     */
     adsl_wtsg1_w1 = adsl_wtsg1_w1->adsc_next;  /* get next in chain   */
   }
   *achl1 = 1;                              /* mark element used       */
   iml_lb_rand--;                           /* one entry less          */
#endif
#ifdef OLD_1112
   memset( (char *) &dsl_soa_lbgw1, 0, sizeof(struct sockaddr) );
   ((struct sockaddr_in *) &dsl_soa_lbgw1)->sin_family = AF_INET;
   ((struct sockaddr_in *) &dsl_soa_lbgw1)->sin_port
     = IP_htons( adsl_wtsg1_w1->imc_port );
   ((struct sockaddr_in *) &dsl_soa_lbgw1)->sin_addr.s_addr
     = adsl_wtsg1_w1->umc_ineta;
#endif
#ifndef D_LOAD_BAL_R1                       /* random processing       */
   adsl_wtsg1_w1 = adsl_wtsg1_w1->adsc_next;  /* get next in chain     */
#endif

   pstlb40:                                 /* send to LB              */
   iml1 = IP_sendto( ADSL_CONN1_G->adsc_wtsudp1->imc_udp_socket,
                     achp_buf, imp_sendlen,
                     0, &dsl_soa_lbgw1, sizeof(struct sockaddr) );
#ifdef TRACEHL1
   {
     int imh1 = 0;
     if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
       imh1 = cl_tcp_r::afunc_wsaglerr();   /* get error code          */
     }
     m_hlnew_printf( HLOG_XYZ1, "HLGW_sendto_LB IP_sendto completed iml1=%d Error=%d socket=%d",
                     iml1, imh1, ADSL_CONN1_G->adsc_wtsudp1->imc_udp_socket );
   }
#endif
#ifdef D_MAX_LOAD_BAL
   if (inl_load_bal_no) goto pstlb20;       /* send to next LB         */
#else
#ifdef D_LOAD_BAL_R1                        /* random processing       */
   if (iml_lb_rand) goto pstlb20;           /* send to next LB         */
   if (achl_lbal_tab != chrl_lbal_tab) {    /* check pointer on array  */
     free( achl_lbal_tab );                 /* free array              */
   }
#else
   if (adsl_wtsg1_w1) goto pstlb20;         /* send to next LB         */
#endif
#endif
#undef ADSL_CONN1_G
} /* end HLGW_sendto_LB()                                              */

static int HLGW_start_conn( void *apparam,
                            UNSIG_MED ump_ineta, int imp_port ) {
   int        iml1;                         /* working variable        */
   struct dsd_recudp1 *adsl_recudp1_w1;     /* chain of data received  */

#define ADSL_CONN1_G ((class clconn1 *) apparam)
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "HLGW_start_conn( apparam=%p, ump_ineta=%d.%d.%d.%d imp_port=%d )",
                   apparam,
                   ump_ineta & 0XFF, ((ump_ineta >> 8) & 0XFF),
                   ((ump_ineta >> 16) & 0XFF), ((ump_ineta >> 24) & 0XFF),
                   imp_port );
#endif
#ifdef TRYCONNE
   int iu1 = 1;
   if (iu1) {
     ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_error_conn;  /* status server */
     m_hlnew_printf( HLOG_XYZ1, "HLGW_start_conn TRYCONE" );
     return iu1;
   }
#endif
   /* connect was successfull                                          */
#ifdef B060616
   if (ADSL_CONN1_G->adsc_wtsudp1->imc_udp_socket >= 0) {  /* socket open     */
     ADSL_CONN1_G->adsc_wtsudp1->boc_udp_close_active = TRUE;
     IP_closesocket( ADSL_CONN1_G->adsc_wtsudp1->imc_udp_socket );
     ADSL_CONN1_G->adsc_wtsudp1->imc_udp_socket = -1;
   }
#endif
   if (ADSL_CONN1_G->adsc_wtsudp1->boc_udp_closed == FALSE) {  /* UDP socket not closed */
     ADSL_CONN1_G->adsc_wtsudp1->boc_udp_close_active = TRUE;
     IP_closesocket( ADSL_CONN1_G->adsc_wtsudp1->imc_udp_socket );
     ADSL_CONN1_G->adsc_wtsudp1->boc_udp_closed = TRUE;  /* UDP socket closed  */
   }
   while (ADSL_CONN1_G->adsc_wtsudp1->adsc_recudp1) {
     adsl_recudp1_w1 = ADSL_CONN1_G->adsc_wtsudp1->adsc_recudp1;
     ADSL_CONN1_G->adsc_wtsudp1->adsc_recudp1 = ADSL_CONN1_G->adsc_wtsudp1->adsc_recudp1->adsc_next;
     free( adsl_recudp1_w1 );
   }
#ifdef OLD01
   if (ADSL_CONN1_G->adsc_wtsudp1->bo_timer_set) {
     sub_time_rel( ADSL_CONN1_G );            /* no more in chain        */
     ADSL_CONN1_G->adsc_wtsudp1->bo_timer_set = FALSE;
     if (ADSL_CONN1_G->adsc_gate1->itimeout > 0) {  /* set timeout          */
       ADSL_CONN1_G->dtime1_e.iwaitsec = audclconn1->adsc_gate1->itimeout;
       sub_time_set( ADSL_CONN1_G );          /* set timeout now         */
     }
   }
#else
#ifdef B060325
   if (ADSL_CONN1_G->dtime1_e.bo_timer_set) {  /* if timer already set   */
     sub_time_rel( ADSL_CONN1_G );            /* no more in chain        */
   }
#endif
   if (ADSL_CONN1_G->adsc_wtsudp1->boc_timer_set) {
     m_aux_timer_del( ADSL_CONN1_G, ied_src_fu_lbal, NULL );
     ADSL_CONN1_G->adsc_wtsudp1->boc_timer_set = FALSE;
   }
#ifdef B060325
   ADSL_CONN1_G->bo_no_timeout = FALSE;       /* nothing happened        */
#endif
   iml1 = ADSL_CONN1_G->adsc_gate1->itimeout;  /* from GATE              */
   if (ADSL_CONN1_G->adsc_server_conf_1) {    /* server connected        */
     if (ADSL_CONN1_G->adsc_server_conf_1->inc_timeout) {
       if (   (iml1 == 0)
           || (ADSL_CONN1_G->adsc_server_conf_1->inc_timeout < iml1)) {
         iml1 = ADSL_CONN1_G->adsc_server_conf_1->inc_timeout;
       }
     }
   }
   if (iml1 > 0) {                          /* set timeout             */
     ADSL_CONN1_G->ilc_timeout = m_get_epoch_ms() + iml1 * 1000;  /* set new end-time */
   }
#ifdef B060325
   if (iml1 > 0) {                          /* set timeout             */
     ADSL_CONN1_G->dtime1_e.iwaitsec = iml1;
     sub_time_set( ADSL_CONN1_G );            /* set timeout now         */
   }
#endif
#endif
#ifdef B060415
   return ((class clconn1 *) apparam)->conn_server( ADSL_CONN1_G->adsc_hco_wothr, ump_ineta, imp_port );
#endif
   return ((class clconn1 *) apparam)->conn_server( ADSL_CONN1_G->adsc_aux_cf1_cur, ump_ineta, imp_port );
#undef ADSL_CONN1_G
} /* end HLGW_start_conn()                                             */

static int HLGW_check_name( void *apparam,
                            char *apname, int iplenname,
                            char *apdomain, int iplendomain ) {
   int iu1;
#ifndef NO_NAME_UNICODE
   int        inl1, inl2, inl3;             /* working variables       */
#endif
   char *au1, *au2;
   char *al1;                               /* working variable        */
   char byarruwork1[512];                   /* working variable        */
   char byarruwork2[512];                   /* working variable        */
   HL_WCHAR   wcharruwork1[256];            /* working variable        */
   struct dsd_auxf_1 *adsl_auxf_1_1;        /* auxiliary extension fi  */
   /* 04.08.04 KB + Joachim Frank */
   char       byrl_cout[512];
#ifdef TRACEHL1
   char *ah1, *ah2;
   ah1 = ah2 = "--- not defined ---";
   if (iplenname) ah1 = apname;
   if (iplendomain) ah2 = apdomain;
   m_hlnew_printf( HLOG_XYZ1, "HLGW_check_name name=%s domain=%s", ah1, ah2 );
#endif
#define auclconn11 ((class clconn1 *) apparam)
//#define NO_NAME_UNICODE
#ifdef NO_NAME_UNICODE
   if (iplenname) {
     iu1 = sprintf( byarruwork1, "user-name: " );
     memcpy( byarruwork2, byarruwork1, iu1 );
     au1 = &byarruwork1[iu1];
     au2 = &byarruwork2[iu1];
     for ( iu1 = 0; iu1 < iplenname; iu1++ ) {
       *au1++ = ucrg_tab_819_to_850[ *(apname + iu1) ];
       *au2++ = *(apname + iu1);
       wcharruwork1[iu1] = *(apname + iu1);
     }
     if (iplendomain) {
       sprintf( au1, " domain-name: " );
       iu1 = strlen( byarruwork1 );
       au1 = &byarruwork1[iu1];
       for ( iu1 = 0; iu1 < iplendomain; iu1++ ) {
         *au1++ = ucrg_tab_819_to_850[ *(apdomain + iu1) ];
         *au2++ = *(apdomain + iu1);
       }
     }
     *au1 = 0;                              /* make zero-terminated    */
     *au2 = 0;                              /* make zero-terminated    */
   } else {
     iu1 = sprintf( byarruwork1, "no user-name" );
     memcpy( byarruwork2, byarruwork1, iu1 + 1 );
   }
#else
   if (iplenname) {
     inl3 = m_u16l_from_u8l( wcharruwork1, sizeof(wcharruwork1) / sizeof(wcharruwork1[0]) - 1,
                             apname, iplenname );
     wcharruwork1[inl3] = 0;                /* make zero-terminated    */
     inl1 = inl2 = sprintf( byarruwork1, "user-name: " );
     memcpy( byarruwork2, byarruwork1, inl1 );
     inl1 += m_a850l_from_u8l( &byarruwork1[inl1], sizeof(byarruwork1) - inl1 - 32, apname, iplenname );
     inl2 += m_a819l_from_u8l( &byarruwork2[inl2], sizeof(byarruwork2) - inl2 - 32, apname, iplenname );
     if (iplendomain) {
       inl1 += sprintf( &byarruwork1[inl1], " domain-name: " );
       inl2 += sprintf( &byarruwork2[inl2], " domain-name: " );
       inl1 += m_a850l_from_u8l( &byarruwork1[inl1], sizeof(byarruwork1) - inl1 - 1, apdomain, iplendomain );
       inl2 += m_a819l_from_u8l( &byarruwork2[inl2], sizeof(byarruwork2) - inl2 - 1, apdomain, iplendomain );
     }
     byarruwork1[inl1] = 0;                 /* make zero-terminated    */
     byarruwork2[inl2] = 0;                 /* make zero-terminated    */
   } else {
     inl1 = inl2 = sprintf( byarruwork1, "no user-name" );
     memcpy( byarruwork2, byarruwork1, inl1 + 1 );
   }
#endif
   al1 = "WTS";
#ifdef OLD_1112
   if (auclconn11->adsc_server_conf_1->boc_is_blade_server) {  /* check BLADE */
     al1 = "BLADE";
   }
#endif
#ifndef OLD_1112
   if (auclconn11->adsc_server_conf_1->boc_is_blade_server) {  /* check BLADE */
     al1 = "VDI";
   }
#endif
#ifdef OLD01
   /* 04.08.04 KB + Joachim Frank */
// printf( "%S INETA=%s %s query %s\n",
//         (WCHAR *) (auclconn11->adsc_gate1 + 1), auclconn11->chrc_ineta, al1, byarruwork1 );
   _snprintf( byrl_cout, sizeof(byrl_cout), "HWSPS040I GATE=%S SNO=%08d INETA=%s %s query %s\n",
              (WCHAR *) (auclconn11->adsc_gate1 + 1), auclconn11->dsc_co_sort.imc_sno,
      4        auclconn11->chrc_ineta, al1, byarruwork1 );
#ifndef TRACE_PRINTF
   cout << byrl_cout << endl;
#else
   EnterCriticalSection( &dss_critsect_printf );
   printf( "%s\n", (char *) byrl_cout );
   fflush( stdout );
   LeaveCriticalSection( &dss_critsect_printf );
#endif
#endif
   m_hlnew_printf( HLOG_XYZ1, "HWSPS040I GATE=%(ux)s SNO=%08d INETA=%s %s query %s",
                   (WCHAR *) (auclconn11->adsc_gate1 + 1), auclconn11->dsc_co_sort.imc_sno,
                   auclconn11->chrc_ineta, al1, byarruwork2 );
   iu1 = 0;                                 /* set return value success */
#ifdef OLD01
   if (auclconn11->adsc_gate1->adsc_server_conf_1->boc_wts_check_name) {  /* check name WTS */
   }
#endif
   if (auclconn11->adsc_server_conf_1->boc_wts_check_name) {  /* check name WTS */
     adsl_auxf_1_1 = auclconn11->adsc_auxf_1;  /* anchor of extensions */
     while (adsl_auxf_1_1) {                /* loop over chain         */
       if (adsl_auxf_1_1->iec_auxf_def == ied_auxf_certname) break;
       adsl_auxf_1_1 = adsl_auxf_1_1->adsc_next;
     }
     if (   (adsl_auxf_1_1 == NULL)
         || (*((int *) (adsl_auxf_1_1 + 1)) != iplenname)
         || (memcmp( wcharruwork1,
                     (((int *) (adsl_auxf_1_1 + 1)) + 1),
                     iplenname * sizeof(WCHAR) ))) {
       iu1 = 2;
       m_hlnew_printf( HLOG_XYZ1, "HWSPS033W GATE=%(ux)s SNO=%08d INETA=%s names not equal - connection refused",
                       auclconn11->adsc_gate1 + 1, auclconn11->dsc_co_sort.imc_sno,
                       auclconn11->chrc_ineta );
     }
   }
   return iu1;
#undef auclconn11
} /* end HLGW_check_name()                                             */

static void HLGW_set_abend( void *apparam ) {
#define ADSL_CONN1_G ((class clconn1 *) apparam)
#ifndef B150117
   if (ADSL_CONN1_G->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
     ADSL_CONN1_G->adsc_int_webso_conn_1->imc_connect_error = HL_ERROR_LB_NO_SERVER;  /* connect error */
     return;
   }
#endif
   ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_abend;
   if (ADSL_CONN1_G->achc_reason_end == NULL) {  /* reason end session */
     ADSL_CONN1_G->achc_reason_end = "Abend Load-Balancing";
   }
#undef ADSL_CONN1_G
} /* end HLGW_set_abend()                                              */
#endif

static int m_hlgw_printf( void *apparam, char *aptext, ... ) {
   va_list    dsl_argptr;
   int        iml1, iml2;                   /* working-variables       */
   char       chrl_out1[ 512 ];             /* buffer                  */

   va_start( dsl_argptr, aptext );
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, aptext, dsl_argptr );
   va_end( dsl_argptr );
#define ADSL_CONN1_G ((class clconn1 *) apparam)
   iml2 = m_hlnew_printf( HLOG_XYZ1, "HWSPS019W GATE=%(ux)s SNO=%08d INETA=%s WTS/VDI load-balancing %.*(u8)s",
                          ADSL_CONN1_G->adsc_gate1 + 1, ADSL_CONN1_G->dsc_co_sort.imc_sno,
                          ADSL_CONN1_G->chrc_ineta,
                          iml1, chrl_out1 );
   return iml2;
#undef ADSL_CONN1_G
} /* end m_hlgw_printf()                                               */

extern "C" dsd_time_1 m_get_time( void ) {
#ifdef B111010
   dsd_time_1 iltime;

#ifndef TRACEHLB
   return time( &iltime );
#else
   int iph1 = time( &iltime );
   m_hlnew_printf( HLOG_TRACE1, "m_get_time() returns %d", iph1 );
   return iph1;
#endif
#else
   return time( NULL );
#endif
} /* end m_get_time()                                                  */

/* return the Epoch value in milliseconds                              */
static HL_LONGLONG m_get_epoch_ms( void ) {
   struct __timeb64 timebuffer;

   _ftime64( &timebuffer );

   ucs_random_01 = timebuffer.millitm >> 4;
#ifdef B090211
   return ( timebuffer.time * 1000 - timebuffer.timezone * 60 * 1000 + timebuffer.millitm );
#else
   return ( timebuffer.time * 1000 + timebuffer.millitm );
#endif
} /* end m_get_epoch_ms()                                              */

/* return the Epoch value in microseconds                              */
extern "C" HL_LONGLONG m_get_epoch_microsec( void ) {
   BOOL       bol_rc;                       /* return code             */
   HL_LONGLONG ill_perform_cur;             /* current performance counter */
   struct __timeb64 timebuffer;

   if (ils_freq == 0) {                     /* do not use QueryPerformanceFrequency() */
     goto p_windows_api;                    /* use the Windows API     */
   }
   bol_rc = QueryPerformanceCounter( (LARGE_INTEGER *) &ill_perform_cur );  /* performance counter at start of WSP */
   if (bol_rc == FALSE) {                 /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPMnnnW l%05d error QueryPerformanceCounter() %d.",
                     __LINE__, GetLastError() );
     goto p_windows_api;                    /* use the Windows API     */
   }
   ucs_random_01 = (unsigned char) ill_perform_cur;
   return ils_epoch_start + ((ill_perform_cur - ils_perform_start) * 1000000) / ils_freq;

   p_windows_api:                           /* use the Windows API     */

   _ftime64( &timebuffer );

   ucs_random_01 = timebuffer.millitm >> 4;
   return timebuffer.time * 1000 * 1000 + timebuffer.millitm * 1000 + 500;
} /* end m_get_epoch_microsec()                                        */

#ifdef B140914
static void m_display( char *apparam ) {
   m_hlnew_printf( HLOG_XYZ1, apparam );
} /* end m_display()                                                   */
#endif

/* this routine returns a number between zero and impmax minus one     */
/* 0 <= ret-val < impmax                                               */
extern "C" int m_get_random_number( int impmax ) {
   HL_LONGLONG ill1;

   ill1 = (HL_LONGLONG) rand() * impmax;
   /* correction 30.09.08 KB - proposal Mr. Tischh�fer */
// ill1 /= RAND_MAX - 1;
   ill1 /= RAND_MAX + 1;
   return (int) ill1;
} /* end m_get_random_number()                                         */

static void m_lock_blade_control( void ) {  /* lock resource           */
#ifdef B080324
   EnterCriticalSection( &ds_blade_control.dc_critsect );
#endif
   EnterCriticalSection( &d_clutil_critsect );
} /* end m_lock_blade_control()                                        */

static void m_unlock_blade_control( void ) {  /* unlock resource       */
#ifdef B080324
   LeaveCriticalSection( &ds_blade_control.dc_critsect );
#endif
   LeaveCriticalSection( &d_clutil_critsect );
} /* m_unlock_blade_control()                                          */

#ifdef B080324
/* send UDP packet with blade INETA to twins                           */
static void m_blade_control_send( UNSIG_MED umpineta ) {
   struct sockaddr dlsockaddr1;             /* client address informat */
   char byrlsend1[128];                     /* area to send            */
   int imlsend, imlret;                     /* for sendto              */
   struct d_blade_twin *adl_blatw_1;        /* blade trimming twin     */

   memcpy( byrlsend1, "HOB Blade Control 1", 20 );
   *((UNSIG_MED *) (byrlsend1 + 20)) = umpineta;
   imlsend = 20 + sizeof(UNSIG_MED);
   adl_blatw_1 = ds_blade_control.adc_blatw_anchor;  /* get anchor     */

   pblcos20:                                /* send to twin            */
#ifdef TRACEHLB
   int imhport = adl_blatw_1->imc_port;
#endif
   memset( (char *) &dlsockaddr1, 0, sizeof(struct sockaddr) );
   ((struct sockaddr_in *) &dlsockaddr1)->sin_family = AF_INET;
   ((struct sockaddr_in *) &dlsockaddr1)->sin_port
     = IP_htons( adl_blatw_1->imc_port );
   ((struct sockaddr_in *) &dlsockaddr1)->sin_addr.s_addr
     = adl_blatw_1->umc_ineta;
   adl_blatw_1 = adl_blatw_1->next;         /* get next in chain       */

   imlret = IP_sendto( ds_blade_control.imc_socket,
                       byrlsend1, imlsend,
                       0, &dlsockaddr1, sizeof(struct sockaddr) );
#ifdef TRACEHLB
   {
     int inh1 = 0;
     if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
       inh1 = cl_tcp_r::afunc_wsaglerr();   /* get error code          */
     }
     m_hlnew_printf( HLOG_XYZ1, "m_blade_control_send() IP_sendto completed imlret=%d Error=%d socket=%d port=%d",
                     imlret, inh1, ds_blade_control.imc_socket, imhport );
   }
#endif
   if (adl_blatw_1) goto pblcos20;          /* send to next twin       */
} /* end m_blade_control_send()                                        */

static htfunc1_t m_blade_twin_rec_thread( LPVOID ulThreadArg ) {
   struct sockaddr_in dlsoa_client1;        /* client address informat */
   char     byrlrecv1[ DEF_UDP_RECLEN ];    /* area for receive        */
   int      iml_lenrece;
   int      iml_lenfrom;
   int      iml_rc_sock;
   UNSIG_MED uml_ineta;

#ifdef TRACEHLB
   m_hlnew_printf( HLOG_XYZ1, "m_blade_twin_rec_thread() start" );
#endif
   pblcor20:                                /* receive from twin       */
   memset( &dlsoa_client1, 0, sizeof(dlsoa_client1) );
   iml_lenfrom = sizeof(dlsoa_client1);
   iml_lenrece = IP_recvfrom( ds_blade_control.imc_socket, byrlrecv1, sizeof(byrlrecv1), 0,
                              (struct sockaddr *) &dlsoa_client1, &iml_lenfrom );
#ifdef TRACEHLB
   m_hlnew_printf( HLOG_XYZ1, "m_blade_twin_rec_thread() socket %d received length %d INETA %d.%d.%d.%d",
                   ds_blade_control.imc_socket, iml_lenrece,
                   ((struct sockaddr_in *) &dlsoa_client1)->sin_addr.s_addr & 0XFF,
                   (((struct sockaddr_in *) &dlsoa_client1)->sin_addr.s_addr >> 8) & 0XFF,
                   (((struct sockaddr_in *) &dlsoa_client1)->sin_addr.s_addr >> 16) & 0XFF,
                   (((struct sockaddr_in *) &dlsoa_client1)->sin_addr.s_addr >> 24) & 0XFF );
#endif
   if (iml_lenrece <= 0) {
     iml_rc_sock = iml_lenrece;
     if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
       iml_rc_sock = cl_tcp_r::afunc_wsaglerr();  /* get error code    */
     }
     m_hlnew_printf( HLOG_XYZ1, "blade twin trimming received UDP error %d/%d",
                     iml_lenrece, iml_rc_sock );
     if (iml_rc_sock != WSAECONNRESET) {
       Sleep( 1000 );
     }
     goto pblcor20;
   }
   if (iml_lenrece != (20 + sizeof(UNSIG_MED))) {
     goto pblcor20;
   }
   if (memcmp( byrlrecv1, "HOB Blade Control 1", 20 )) {
     goto pblcor20;
   }
   uml_ineta = *((UNSIG_MED *) (byrlrecv1 + 20));
   dcl_blasetr_1::m_set_twin_ineta( uml_ineta );
   goto pblcor20;
} /* end m_blade_twin_rec_thread()                                     */
#endif

/* process VDI-WSP received from other cluster member                  */
extern "C" void m_recv_cluster_vdi( char *achp_ineta, int imp_len_ineta ) {
   char       chrl_ineta_port[ 2 + 16 + 2 ];

   if (   (imp_len_ineta != (4 + 2))        /* not IPV4                */
       && (imp_len_ineta != (16 + 2))) {    /* not IPV6                */
     return;
   }
   chrl_ineta_port[ 0 ] = (unsigned char) (2 + imp_len_ineta);
   chrl_ineta_port[ 1 ] = 0X12;
   memcpy( &chrl_ineta_port[ 2 ], achp_ineta, imp_len_ineta );
   dcl_blasetr_1::m_set_twin_ineta( chrl_ineta_port );
} /* end m_recv_cluster_vdi()                                          */

#ifdef OLD_1112
#include "xiipgw08-radius.cpp"
#endif
#include "xiipgw08-aux.cpp"
#include "xiipgw08-tcp.cpp"
#include "xiipgw08-pttd.cpp"
#ifdef D_INCL_HOB_TUN
#include "xiipgw08-tun.cpp"
#endif
#include "xiipgw08-trace.cpp"
#include "xiipgw08-admin.cpp"
#ifdef DEBUG_HOB_TUN_1407
#include "xiipgw08-debug-hob-tun-1407.cpp"
#endif

static inline void * m_clconn1_dcl_tcp_r_c( void  * apdconn1 ) {
   return &((class clconn1 *) apdconn1)->dcl_tcp_r_c;
} /* end m_clconn1_dcl_tcp_r_c()                                       */

static inline WCHAR * m_clconn1_gatename( void * apdconn1 ) {
   return (WCHAR *) (((class clconn1 *) apdconn1)->adsc_gate1 + 1);
} /* end m_clconn1_gatename()                                          */

static inline int m_clconn1_sno( void * adsp_clconn1 ) {
   return ((class clconn1 *) adsp_clconn1)->dsc_co_sort.imc_sno;
} /* end m_clconn1_sno()                                               */

static inline char * m_clconn1_chrc_ineta( void * apdconn1 ) {
   return ((class clconn1 *) apdconn1)->chrc_ineta;
} /* end m_clconn1_chrc_ineta()                                        */

static inline void m_clconn1_critsect_enter( void * apdconn1 ) {
   EnterCriticalSection( &((class clconn1 *) apdconn1)->d_act_critsect );
} /* end m_clconn1_critsect_enter()                                    */

static inline void m_clconn1_critsect_leave( void * apdconn1 ) {
   LeaveCriticalSection( &((class clconn1 *) apdconn1)->d_act_critsect );
} /* end m_clconn1_critsect_leave()                                    */

#ifndef B120121
static inline void m_clconn1_naeg1( void * adsp_clconn1 ) {
   BOOL       bol_naeg1_disa;               /* disable naegle algorithm */
#define ADSL_CONN1_G ((class clconn1 *) adsp_clconn1)  /* pointer on connection */

   /* first direction to client                                        */
   bol_naeg1_disa = TRUE;                   /* disable naegle algorithm */
   if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) {  /* no configuration server */
     goto p_client_20;                      /* check gate for client   */
   }
   if (ADSL_CONN1_G->adsc_server_conf_1->iec_naeg1_cl == ied_naeg1_yes) {  /* do disable naegle algorithm */
     goto p_client_80;                      /* direction to client set */
   }
   if (ADSL_CONN1_G->adsc_server_conf_1->iec_naeg1_cl == ied_naeg1_no) {  /* do not disable naegle algorithm */
     bol_naeg1_disa = FALSE;                /* disable naegle algorithm */
     goto p_client_80;                      /* direction to client set */
   }

   p_client_20:                             /* check gate for client   */
   if (ADSL_CONN1_G->adsc_gate1->iec_naeg1_cl == ied_naeg1_yes) {  /* do disable naegle algorithm */
     goto p_client_80;                      /* direction to client set */
   }
   if (ADSL_CONN1_G->adsc_gate1->iec_naeg1_cl == ied_naeg1_no) {  /* do not disable naegle algorithm */
     bol_naeg1_disa = FALSE;                /* disable naegle algorithm */
     goto p_client_80;                      /* direction to client set */
   }
   /* both automatic, so take setting of protocol                      */
   if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) {  /* no configuration server */
     goto p_client_80;                      /* direction to client set */
   }
   switch (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def) {
     case ied_scp_http:                     /* protocol HTTP           */
     case ied_scp_ldap:                     /* protocol LDAP           */
     case ied_scp_hoby:                     /* protocol HOB-Y          */
     case ied_scp_3270:                     /* protocol IBM 3270       */
     case ied_scp_5250:                     /* protocol IBM 5250       */
     case ied_scp_smb:                      /* protocol SMB server message block */
     case ied_scp_soap:                     /* protocol SOAP           */
       bol_naeg1_disa = FALSE;              /* disable naegle algorithm */
       break;
   }

   p_client_80:                             /* direction to client set */
   ADSL_CONN1_G->dcl_tcp_r_c.mc_naeg1_disa( bol_naeg1_disa );  /* disable naegle algorithm */

   /* second direction to server                                       */
   if (ADSL_CONN1_G->iec_servcotype != ied_servcotype_normal_tcp) return;  /* not normal TCP */
   bol_naeg1_disa = TRUE;                   /* disable naegle algorithm */
   if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) {  /* no configuration server */
     goto p_server_20;                      /* check gate for server   */
   }
   if (ADSL_CONN1_G->adsc_server_conf_1->iec_naeg1_cl == ied_naeg1_yes) {  /* do disable naegle algorithm */
     goto p_server_80;                      /* direction to server set */
   }
   if (ADSL_CONN1_G->adsc_server_conf_1->iec_naeg1_cl == ied_naeg1_no) {  /* do not disable naegle algorithm */
     bol_naeg1_disa = FALSE;                /* disable naegle algorithm */
     goto p_server_80;                      /* direction to server set */
   }

   p_server_20:                             /* check gate for server   */
   if (ADSL_CONN1_G->adsc_gate1->iec_naeg1_cl == ied_naeg1_yes) {  /* do disable naegle algorithm */
     goto p_server_80;                      /* direction to server set */
   }
   if (ADSL_CONN1_G->adsc_gate1->iec_naeg1_cl == ied_naeg1_no) {  /* do not disable naegle algorithm */
     bol_naeg1_disa = FALSE;                /* disable naegle algorithm */
     goto p_server_80;                      /* direction to server set */
   }
   /* both automatic, so take setting of protocol                      */
   if (ADSL_CONN1_G->adsc_server_conf_1 == NULL) {  /* no configuration server */
     goto p_server_80;                      /* direction to server set */
   }
   switch (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def) {
     case ied_scp_http:                     /* protocol HTTP           */
     case ied_scp_ldap:                     /* protocol LDAP           */
     case ied_scp_hoby:                     /* protocol HOB-Y          */
     case ied_scp_3270:                     /* protocol IBM 3270       */
     case ied_scp_5250:                     /* protocol IBM 5250       */
     case ied_scp_smb:                      /* protocol SMB server message block */
     case ied_scp_soap:                     /* protocol SOAP           */
       bol_naeg1_disa = FALSE;              /* disable naegle algorithm */
       break;
   }

   p_server_80:                             /* direction to server set */
   ADSL_CONN1_G->dcl_tcp_r_s.mc_naeg1_disa( bol_naeg1_disa );  /* disable naegle algorithm */
   return;                                  /* all done                */

#undef ADSL_CONN1_G                         /* pointer on connection   */
} /* end m_clconn1_naeg1()                                             */
#endif

#ifdef OLD_1112
static inline BOOL m_clconn1_act_thread_x( void * apdconn1 ) {
   if (((class clconn1 *) apdconn1)->boc_st_act) return FALSE;  /* util-thread active */
#ifdef B060404
   if (((class clconn1 *) apdconn1)->dcl_tcp_r_c.adsentcp1 != NULL) return FALSE;
   if (((class clconn1 *) apdconn1)->dcl_tcp_r_s.adsentcp1 != NULL) return FALSE;
#endif
   if (((class clconn1 *) apdconn1)->dcl_tcp_r_c.m_check_send_act()) return FALSE;
   if (((class clconn1 *) apdconn1)->dcl_tcp_r_s.m_check_send_act()) return FALSE;
   if (   (((class clconn1 *) apdconn1)->adsc_sdhc1_c1)  /* data received from client */
       || (((class clconn1 *) apdconn1)->adsc_sdhc1_s1)  /* data received from server */
       || (   (((class clconn1 *) apdconn1)->adsc_wtsudp1)
           && (((class clconn1 *) apdconn1)->adsc_wtsudp1->adsc_recudp1))) {
     ((class clconn1 *) apdconn1)->boc_st_act = TRUE;  /* util-thread active */
     return TRUE;
   }
   return FALSE;
}
#endif
#ifndef OLD_1112
static inline BOOL m_clconn1_act_thread_x( void * apdconn1 ) {
   if (((class clconn1 *) apdconn1)->boc_st_act) return FALSE;  /* util-thread active */
#ifdef B060404
   if (((class clconn1 *) apdconn1)->dcl_tcp_r_c.adsentcp1 != NULL) return FALSE;
   if (((class clconn1 *) apdconn1)->dcl_tcp_r_s.adsentcp1 != NULL) return FALSE;
#endif
   if (((class clconn1 *) apdconn1)->dcl_tcp_r_c.m_check_send_act()) return FALSE;
   if (((class clconn1 *) apdconn1)->dcl_tcp_r_s.m_check_send_act()) return FALSE;
   if (   (((class clconn1 *) apdconn1)->adsc_sdhc1_c1)  /* data received from client */
       || (((class clconn1 *) apdconn1)->adsc_sdhc1_s1)  /* data received from server */
       || (   (((class clconn1 *) apdconn1)->adsc_wtsudp1)
           && (((class clconn1 *) apdconn1)->adsc_wtsudp1->adsc_sdhc1_rec))) {
     ((class clconn1 *) apdconn1)->boc_st_act = TRUE;  /* util-thread active */
     return TRUE;
   }
   return FALSE;
}
#endif

static inline void m_clconn1_act_thread_1( void * apdconn1 ) {
   m_act_thread_1( (class clconn1 *) apdconn1 );
} /* end m_clconn1_act_thread_1()                                      */

static inline BOOL m_clconn1_rec_complete( void * apdconn1,
                                           class cl_tcp_r *adpcltcpr,
                                           struct dsd_sdh_control_1 *adsp_sdhc1,
                                           int iplen ) {
   return ((class clconn1 *) apdconn1)->rec_complete( adpcltcpr, adsp_sdhc1, iplen );
}

static inline BOOL m_clconn1_check_client( void * apdconn1,
                                           class cl_tcp_r *adspcltcpr ) {
   if (adspcltcpr == &((class clconn1 *) apdconn1)->dcl_tcp_r_c) return TRUE;  /* is from client */
   return FALSE;                            /* is from server          */
}

static inline char ** m_clconn1_get_addr_reason_end( void * apdconn1 ) {
   return &((class clconn1 *) apdconn1)->achc_reason_end;
}

/* put work area in chain inuse                                        */
static inline void m_clconn1_mark_work_area( void * apdconn1, struct dsd_sdh_control_1 *adsp_sdhc1 ) {
   m_clconn1_critsect_enter( apdconn1 );
   adsp_sdhc1->adsc_next = ((class clconn1 *) apdconn1)->adsc_sdhc1_inuse;  /* chain of buffers in use */
   ((class clconn1 *) apdconn1)->adsc_sdhc1_inuse = adsp_sdhc1;  /* append to chain */
   m_clconn1_critsect_leave( apdconn1 );
} /* end m_clconn1_mark_work_area()                                    */

#ifdef B130223
/* check end L2TP                                                      */
static inline void m_clconn1_check_end_l2tp( void * apdconn1 ) {
#define ADSL_CONNECT_G ((class clconn1 *) apdconn1)
   if (ADSL_CONNECT_G->iec_servcotype != ied_servcotype_l2tp) return;  /* not L2TP */
   m_l2tp_client_end( &ADSL_CONNECT_G->dsc_l2tp_session );  /* call function of L2TP */
#undef ADSL_CONNECT_G
} /* end m_clconn1_check_end_l2tp()                                    */
#endif

/* check end server                                                    */
static inline void m_clconn1_check_end_server( void * adsp_conn1, class cl_tcp_r *adsp_tcp_r ) {
   class clconn1 *adsl_conn1;

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_clconn1_check_end_server( %p , %p ) called",
                   __LINE__, adsp_conn1, adsp_tcp_r );
#endif
   adsl_conn1 = (class clconn1 *) adsp_conn1;
   if (adsp_tcp_r == &adsl_conn1->dcl_tcp_r_c) return;  /* class to receive client */
   adsl_conn1->m_end_server();              /* the server has ended    */
} /* end m_clconn1_check_end_server()                                  */

#ifdef TRACEHL_STOR_USAGE
static inline class clconn1 * m_clconn1_get_conn( void * adsp_conn1 ) {
   return (class clconn1 *) adsp_conn1;
} /* end m_clconn1_get_conn()                                          */

static inline struct dsd_sdh_control_1 * m_clconn1_get_sdhc1_chain( void * adsp_conn1 ) {
   return ((class clconn1 *) adsp_conn1)->adsc_sdhc1_chain;
} /* m_clconn1_get_sdhc1_chain()                                       */
#endif

static inline int m_clconn1_get_trace_level( void * adsp_conn1 ) {
   return ((class clconn1 *) adsp_conn1)->imc_trace_level;
} /* m_clconn1_get_sdhc1_chain()                                       */

static inline void m_clconn1_clear_recv_packets( void * adsp_conn1 ) {
   switch (((class clconn1 *) adsp_conn1)->iec_servcotype) {  /* type of server connection */
#ifdef D_INCL_HOB_TUN
     case ied_servcotype_htun:              /* HOB-TUN                 */
#ifdef B130808
       ((class clconn1 *) adsp_conn1)->dsc_tun_contr1.imc_on_the_fly_packets_client = 0;  /* number of packets on the fly to the client */
#else
       ((class clconn1 *) adsp_conn1)->dsc_tun_contr_conn.imc_on_the_fly_packets_client = 0;  /* number of packets on the fly to the client */
#endif
       return;                              /* all done                */
#endif
     case ied_servcotype_l2tp:              /* L2TP                    */
       ((class clconn1 *) adsp_conn1)->dsc_l2tp_session.imc_on_the_fly_packets_client = 0;  /* number of packets on the fly to the client */
       return;                              /* all done                */
   }
} /* end m_clconn1_clear_recv_packets()                                */

#ifdef TRACE_HL_SESS_01
static void m_clconn1_last_action( void *apdconn1, int imp1 ) {  /* last action      */
   int iml1;

   m_clconn1_critsect_enter( apdconn1 );
   for ( iml1 = 0; iml1 < (DEF_LEN_LAST_ACTION - 1); iml1++ ) {
     ((class clconn1 *) apdconn1)->ir_last_action[ iml1 ]
       = ((class clconn1 *) apdconn1)->ir_last_action[ iml1 + 1 ];
   }
   ((class clconn1 *) apdconn1)->ir_last_action[ iml1 ]
     = ((class clconn1 *) apdconn1)->i_last_action;
   ((class clconn1 *) apdconn1)->i_last_action = imp1;
   m_clconn1_critsect_leave( apdconn1 );
} /* end m_clconn1_last_action()                                       */
#endif  /* TRACE_HL_SESS_01 */

#ifdef TRACEHLC
static void m_check_aclconn1( void *apparam, int ipno ) {
   int iml1, iml2, iml3, iml4;
   struct DTIME1_C *audtime1_c_1;
   class clconn1 *auclconn11;               /* connection              */
   class clconn1 *auclconn12;               /* connection              */

   iml4 = 0;
   EnterCriticalSection( &dss_timer_critsect );
   audtime1_c_1 = adtime1_c_anchor;
   while (audtime1_c_1) {
     auclconn11 = audtime1_c_1->adconn1_first;
     auclconn12 = NULL;
     while (auclconn11) {
       if (auclconn12 != auclconn11->dtime1_e.adconn1_prev) {
         m_hlnew_printf( HLOG_XYZ1, "m_check_aclconn1 no=%d adconn1_prev invalid", ipno );
         goto psubab00;
       }
       if (auclconn11->dtime1_e.bo_timer_set == FALSE) {
         m_hlnew_printf( HLOG_XYZ1, "m_check_aclconn1 no=%d bo_timer_set invalid", ipno );
         goto psubab00;
       }
       if (auclconn11->dtime1_e.iwaitsec != audtime1_c_1->iwaitsec) {
         m_hlnew_printf( HLOG_XYZ1, "m_check_aclconn1 no=%d iwaitsec invalid val=%d inv=%d",
                     ipno, audtime1_c_1->iwaitsec, auclconn11->dtime1_e.iwaitsec );
         goto psubab00;
       }
       iml4 = auclconn11->dtime1_e.iendtime;
       auclconn12 = auclconn11;
       auclconn11 = auclconn11->dtime1_e.adconn1_next;
     }
     if (auclconn12 != audtime1_c_1->adconn1_last) {
       m_hlnew_printf( HLOG_XYZ1, "m_check_aclconn1 no=%d adconn1_last invalid", ipno );
       goto psubab00;
     }
     audtime1_c_1 = audtime1_c_1->next;
   }
   LeaveCriticalSection( &dss_timer_critsect );
   if (apparam == NULL) {
     if (ipno >= 200) return;
     m_hlnew_printf( HLOG_XYZ1, "m_check_aclconn1 no=%d apparam zero", ipno );
     goto psubab00;
   }
   if (((class clconn1 *) apparam)->im_check_no == DEF_CHECK_ACLCONN1_NO) return;
   m_hlnew_printf( HLOG_XYZ1, "m_check_aclconn1 no=%d im_check_no invalid", ipno );

   psubab00:
   iml1 = 0;
   iml2 = iml1;
   iml3 = 5 / iml2;
   printf( "%d/%d\n", iml3, iml4 );
}
#endif

#ifdef B140810
// 07.02.14 KB - move to xiipgw08-tcp.cpp
/** Connect Callback Server-Side SSL                                   */
static void m_ssl_conn_cl_compl_se( struct dsd_hl_ssl_ccb_1 *adsp_ccb_1 ) {
   int        inl1, inl2;                   /* working variables       */
   char       *achl1, *achl2;               /* working variables       */
   BOOL       bol1;                         /* working variable        */
   int        inl_len_cert;                 /* length of certificate n */
   int        iml_ns_prot, iml_ns_ci_sui, iml_ns_keyexch, iml_ns_ci_alg,
              iml_ns_ci_type, iml_ns_mac, iml_ns_auth, iml_ns_compr;
#ifdef OLD_1112
   en_at_claddrtype iel_claddrtype;         /* type of address         */
   void *     avol_client_netaddr;          /* address net-addr        */
#endif
   struct dsd_auxf_1 *adsl_auxf_1_1;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_2;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_3;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_dn;       /* aux ext fi dn distinguished name */
   struct dsd_auxf_1 *adsl_auxf_1_ce;       /* aux ext fi ce certificate */
   char       *achl_pfs;                    /* pfs = YES / NO          */
   char       *achl_ssl_tls;                /* SSL / TLS version       */
   char       byrlwork1[ 112 + DEF_MAX_LEN_CERT_NAME + 1 ];
   char       byrlwork2[ 112 + DEF_MAX_LEN_CERT_NAME + 1 ];
   char       byrlwork_ssl[ 256 ];          /* for text cipher         */
   char       byrl_ssl_tls[ 32 ];           /* SSL / TLS version       */
   /* 04.08.04 KB + Joachim Frank */
   char       byrl_cout[1024];

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_ssl_conn_cl_compl_se called" );
#endif
#ifdef B121009
#define hssl_QueryInfo ((HSSL_QUERYINFO *) adsp_ccb_1->ac_conndata)
#endif
#ifndef HELP_DEBUG                           /* 04.04.06 KB - help in tracing */
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) adsp_ccb_1->vpc_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#define ADSL_SSL_QUERY_INFO ((struct dsd_ssl_query_info *) adsp_ccb_1->ac_conndata)
#define AUCL_CONNDATA ((unsigned char *) adsp_ccb_1->ac_conndata)
#else
   struct dsd_aux_cf1 *ADSL_AUX_CF1 = (struct dsd_aux_cf1 *) adsp_ccb_1->vpc_userfld;  /* auxiliary control structure */
#ifndef HL_UNIX
   class clconn1 *ADSL_CONN1_G = ADSL_AUX_CF1->adsc_conn;  /* pointer on connection */
#else
   struct dsd_conn1 *ADSL_CONN1_G = ADSL_AUX_CF1->adsc_conn;  /* pointer on connection */
#endif
   struct dsd_ssl_query_info *ADSL_SSL_QUERY_INFO = (struct dsd_ssl_query_info *) adsp_ccb_1->ac_conndata;
   unsigned char *AUCL_CONNDATA = (unsigned char *) adsp_ccb_1->ac_conndata;
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_ssl_conn_cl_compl_se called adsp_ccb_1=%p", adsp_ccb_1 );
   m_hlnew_printf( HLOG_TRACE1, "-- vpc_userfld=%p ac_conndata=%p achc_fingerprint=%p achc_certificate=%p inc_len_certificate=%d",
                   adsp_ccb_1->vpc_userfld, adsp_ccb_1->ac_conndata, adsp_ccb_1->achc_fingerprint, adsp_ccb_1->achc_certificate, adsp_ccb_1->inc_len_certificate );
// partners name is Big-endian unicode. For simplicity we assume Latin
// and convert this unicode to a char string.
   char szString[512];
   int j, i;
         j=0;
         for (i = 0; i < (ADSL_SSL_QUERY_INFO->hssl_byPartnerNameLength*2); i= i+2)
         {
       szString[j++] = ADSL_SSL_QUERY_INFO->hssl_byPartnerName[i+1];
         }
         szString[j++] = 0x0;
   m_hlnew_printf( HLOG_TRACE1, "partner-id %s", szString );
#endif
   if (ADSL_CONN1_G->boc_st_sslc) {         /* ssl handshake complete  */
     m_hlnew_printf( HLOG_WARN1, "HWSPS00nW SSL handshake complete double" );
   }
   adsl_auxf_1_1 = ADSL_CONN1_G->adsc_auxf_1;  /* anchor of extensions   */
   adsl_auxf_1_3 = NULL;                    /* no previous yet         */
   while (adsl_auxf_1_1) {                  /* loop over chain         */
     adsl_auxf_1_2 = adsl_auxf_1_1;         /* save this entry         */
     adsl_auxf_1_1 = adsl_auxf_1_1->adsc_next;  /* get next in chain   */
     bol1 = FALSE;                          /* is not double           */
     if (adsl_auxf_1_2->iec_auxf_def == ied_auxf_certname) {
       m_hlnew_printf( HLOG_WARN1, "HWSPS071W GATE=%(ux)s SNO=%08d INETA=%s Certificate Name (dn) came double",
                       ADSL_CONN1_G->adsc_gate1 + 1,
                       ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta );
       bol1 = TRUE;                         /* remove this entry       */
     } else if (adsl_auxf_1_2->iec_auxf_def == ied_auxf_certificate) {
       m_hlnew_printf( HLOG_WARN1, "HWSPS072W GATE=%(ux)s SNO=%08d INETA=%s Certificate came double",
                       ADSL_CONN1_G->adsc_gate1 + 1,
                       ADSL_CONN1_G->dsc_co_sort.imc_sno,
                       ADSL_CONN1_G->chrc_ineta );
       bol1 = TRUE;                         /* remove this entry       */
     }
     if (bol1) {                            /* remove this entry       */
       if (adsl_auxf_1_3 == NULL) {         /* is first in chain       */
         ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_1;
       } else {                             /* in middle of chain      */
         adsl_auxf_1_3->adsc_next = adsl_auxf_1_1;
       }
       free( adsl_auxf_1_2 );               /* free this entry         */
     } else {
       adsl_auxf_1_3 = adsl_auxf_1_2;       /* save previous           */
     }
   }
#ifdef B121009
   inl_len_cert = hssl_QueryInfo->hssl_byPartnerNameLength;
#endif
   inl_len_cert = ADSL_SSL_QUERY_INFO->ucc_partner_name_length;
   if (   (inl_len_cert < 0)
       || (inl_len_cert > DEF_MAX_LEN_CERT_NAME)) {
     m_hlnew_printf( HLOG_WARN1, "HWSPS073W GATE=%(ux)s SNO=%08d INETA=%s length of certificate name invalid %d",
                     (WCHAR *) (ADSL_CONN1_G->adsc_gate1 + 1),
                     ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta,
                     inl_len_cert );
     inl_len_cert = 0;
   }
   byrlwork_ssl[0] = 0;                     /* no data about handshake */
   if (adsg_loconf_1_inuse->inc_network_stat >= 2) {
     achl_pfs = "NO";                       /* pfs = YES / NO          */
     if (adsp_ccb_1->boc_pfs_used) {        /* Was a key exchange with PFS used? */
       achl_pfs = "YES";                    /* pfs = YES / NO          */
     }
     iml_ns_prot = ADSL_SSL_QUERY_INFO->imc_ssl_tls_prot_vers >> 16;  /* SSL / TLS protocol version */
     if (iml_ns_prot >= (sizeof(achrs_ssl_prot) / sizeof(achrs_ssl_prot[0]))) {
       iml_ns_prot = 0;                     /* make unknown            */
     }
     achl_ssl_tls = (char *) achrs_ssl_prot[ iml_ns_prot ];  /* SSL / TLS version */
     if (   (iml_ns_prot == 1)
         || (iml_ns_prot == 2)) {
       sprintf( byrl_ssl_tls,
                "%s-V%d.%d",
                achrs_ssl_prot[ iml_ns_prot ],
                (ADSL_SSL_QUERY_INFO->imc_ssl_tls_prot_vers >> 8) & 0XFF,
                ADSL_SSL_QUERY_INFO->imc_ssl_tls_prot_vers & 0XFF );
       achl_ssl_tls = byrl_ssl_tls;         /* SSL / TLS version       */
     }
     iml_ns_ci_sui = *(AUCL_CONNDATA + 51);
     if (iml_ns_ci_sui >= (sizeof(achrs_ssl_ci_prot) / sizeof(achrs_ssl_ci_prot[0]))) {
       iml_ns_ci_sui = sizeof(achrs_ssl_ci_prot) / sizeof(achrs_ssl_ci_prot[0]) - 1;
     }
     iml_ns_keyexch = *(AUCL_CONNDATA + 52);
     if (iml_ns_keyexch >= (sizeof(achrs_ssl_keyexch) / sizeof(achrs_ssl_keyexch[0]))) {
       iml_ns_keyexch = 0;                  /* make unknown            */
     }
     iml_ns_ci_alg = *(AUCL_CONNDATA + 53);
     if (iml_ns_ci_alg >= (sizeof(achrs_ssl_ci_alg) / sizeof(achrs_ssl_ci_alg[0]))) {
       iml_ns_ci_alg = 0;                   /* make unknown            */
     }
     iml_ns_ci_type = *(AUCL_CONNDATA + 54);
     if (iml_ns_ci_type >= (sizeof(achrs_ssl_ci_type) / sizeof(achrs_ssl_ci_type[0]))) {
       iml_ns_ci_type = (sizeof(achrs_ssl_ci_type) / sizeof(achrs_ssl_ci_type[0])) - 1;
     }
     iml_ns_mac = *(AUCL_CONNDATA + 55);
     if (iml_ns_mac >= (sizeof(achrs_ssl_ci_alg) / sizeof(achrs_ssl_ci_alg[0]))) {
       iml_ns_mac = 0;                      /* make unknown            */
     }
     iml_ns_auth = *(AUCL_CONNDATA + 57) & 3;
     iml_ns_auth |= 1;                      /* always server authentication */
     iml_ns_compr = *(AUCL_CONNDATA + 49);
     if (iml_ns_compr) {                    /* is not none             */
       if (iml_ns_compr == 0XF4) {          /* is defined              */
         iml_ns_compr = 1;
       } else {
         iml_ns_compr = 2;                  /* make unknown            */
       }
     }
     sprintf( byrlwork_ssl, " - pfs:%s protocol:%s cipher-suite:%s key-exchange-mode:%s"
              " cipher-algorithm:%s cipher-type:%s MAC-algorithm:%s authentication:%s compression:%s",
              achl_pfs,                     /* pfs = YES / NO          */
              achl_ssl_tls,                 /* SSL / TLS version       */
              achrs_ssl_ci_prot[ iml_ns_ci_sui ],
              achrs_ssl_keyexch[ iml_ns_keyexch ],
              achrs_ssl_ci_alg[ iml_ns_ci_alg ],
              achrs_ssl_ci_type[ iml_ns_ci_type ],
              achrs_ssl_mac[ iml_ns_mac ],
              achrs_ssl_auth[ iml_ns_auth ],
              achrs_ssl_compr[ iml_ns_compr ] );
   }
#ifdef B121009
   if (hssl_QueryInfo->hssl_byPartnerNameLength == 0) {
     achl1 = "SSL logon - no client certificate";
     achl2 = achl1;
     goto psussl80;
   }
#endif
   if (ADSL_SSL_QUERY_INFO->ucc_partner_name_length == 0) {
     achl1 = "SSL logon - no client certificate";
     achl2 = achl1;
     goto psussl80;
   }
   adsl_auxf_1_dn = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                                  + sizeof(int)
                                                  + (inl_len_cert + 1) * sizeof(HL_WCHAR) );
   adsl_auxf_1_dn->iec_auxf_def = ied_auxf_certname;  /* name from certificate */
   *((int *) (adsl_auxf_1_dn + 1)) = inl_len_cert;  /* set length name  */
   inl1 = sprintf( byrlwork1, "SSL logon - " );
   if (adsp_ccb_1->achc_fingerprint) {
     inl1 += sprintf( &byrlwork1[inl1], "fingerprint: " );
     inl2 = 0;
     do {
       inl1 += sprintf( &byrlwork1[inl1], "%02X",
                        *((unsigned char *) adsp_ccb_1->achc_fingerprint + inl2) );

       if (inl2 % 2) byrlwork1[ inl1++ ] = ' ';
       inl2++;                              /* next character          */
     } while (inl2 < DEF_SSL_LEN_FINGERPRINT);
     inl1 += sprintf( &byrlwork1[inl1], "- " );  /* separate following text */
   }
   inl1 += sprintf( &byrlwork1[inl1], "DN (name from certificate): " );
   achl1 = &byrlwork1[inl1];                /* name comes here         */
   memcpy( byrlwork2, byrlwork1, inl1 );
   achl2 = &byrlwork2[inl1];                /* name comes here         */
   for (inl1 = 0; inl1 < inl_len_cert; inl1++ ) {
#ifdef B121009
     inl2 = GHHW( *((unsigned short int *) &hssl_QueryInfo->hssl_byPartnerName[ inl1 * 2 ]) );
#endif
     inl2 = GHHW( *((unsigned short int *) &ADSL_SSL_QUERY_INFO->ucrc_partner_name[ inl1 * 2 ]) );
     *((HL_WCHAR *) (((int *) (adsl_auxf_1_dn + 1)) + 1) + inl1) = inl2;
     if (inl2 < 0X0100) {
       *achl1++ = ucrg_tab_819_to_850[ inl2 ];
       *achl2++ = (char) inl2;
     } else {
       *achl1++ = '?';
       *achl2++ = '?';
     }
   }
   *((HL_WCHAR *) (((int *) (adsl_auxf_1_dn + 1)) + 1) + inl_len_cert) = 0;
   adsl_auxf_1_dn->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_dn;  /* set new chain       */
   *achl1 = 0;                              /* make zero-terminated    */
   achl1 = byrlwork1;
   *achl2 = 0;                              /* make zero-terminated    */
   achl2 = byrlwork2;
   if (adsp_ccb_1->inc_len_certificate == 0) goto psussl80;  /* write message */
   /* store certificate                                                */
   adsl_auxf_1_ce = (struct dsd_auxf_1 *) malloc( sizeof(struct dsd_auxf_1)
                                                  + sizeof(int)
                                                  + adsp_ccb_1->inc_len_certificate );
   adsl_auxf_1_ce->iec_auxf_def = ied_auxf_certificate;  /* certificate */
   *((int *) (adsl_auxf_1_ce + 1)) = adsp_ccb_1->inc_len_certificate;  /* set length certificate */
   memcpy( (int *) (adsl_auxf_1_ce + 1) + 1,
           adsp_ccb_1->achc_certificate,
           adsp_ccb_1->inc_len_certificate );
   adsl_auxf_1_ce->adsc_next = ADSL_CONN1_G->adsc_auxf_1;  /* get old chain */
   ADSL_CONN1_G->adsc_auxf_1 = adsl_auxf_1_ce;  /* set new chain       */

   psussl80:                                /* write message           */
#ifdef B060506
   /* 04.08.04 KB + Joachim Frank */
// printf( "%S INETA=%s %s\n",
//         (WCHAR *) (auclconn11->adsc_gate1 + 1), auclconn11->chrc_ineta, au1 );
   _snprintf( byrl_cout, sizeof(byrl_cout), "HWSPS080I GATE=%S SNO=%08d INETA=%s %s%s\n",
              (WCHAR *) (ADSL_CONN1_G->adsc_gate1 + 1),
              ADSL_CONN1_G->dsc_co_sort.imc_sno,
              ADSL_CONN1_G->chrc_ineta, achl1, byrlwork_ssl );
#ifndef TRACE_PRINTF
   cout << byrl_cout;
#else
   EnterCriticalSection( &dss_critsect_printf );
   printf( "%s", (char *) byrl_cout );
   LeaveCriticalSection( &dss_critsect_printf );
#endif
#endif
   m_hlnew_printf( HLOG_INFO1, "HWSPS080I GATE=%(ux)s SNO=%08d INETA=%s %s%s",
                   ADSL_CONN1_G->adsc_gate1 + 1,
                   ADSL_CONN1_G->dsc_co_sort.imc_sno,
                   ADSL_CONN1_G->chrc_ineta, achl2, byrlwork_ssl );
#ifdef WORK051119
   /* start authentication                                             */
   if (ADSL_CONN1_G->adsc_gate1->ad_auth_startup) {  /* must do authentication */
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "call ADSL_CONN1_G->dcl_wsat1_1 before" );
#endif
#ifdef NOTYET050819
     ADSL_CONN1_G->dcl_wsat1_1 = (*ADSL_CONN1_G->adsc_gate1->ad_authlib1->am_constr)
       ( ADSL_CONN1_G->adsc_gate1->ad_auth_startup,
         (HL_WCHAR *) (((int *) (adsl_auxf_1_1 + 1)) + 1),
         inl_len_cert,
         ADSL_CONN1_G->adsc_gate1->ienatfa,
#ifndef HL_IPV6
         en_atca_IPV4,
         (void *) &ADSL_CONN1_G->dcl_tcp_r_c.dclient1
#else
         en_atca_IPV6,
         (void *) &ADSL_CONN1_G->dcl_tcp_r_c.uncl1
#endif
       );
#endif
#ifdef TRACEHL1
     m_hlnew_printf( HLOG_XYZ1, "call ADSL_CONN1_G->dcl_wsat1_1 after" );
#endif
   }
   if (   (ADSL_CONN1_G->adsc_server_conf_1)
       && (ADSL_CONN1_G->adsc_server_conf_1->iec_scp_def != ied_scp_http)
       && (   (ADSL_CONN1_G->adsc_gate1->inc_no_radius)  /* authenticate Radius */
           || (ADSL_CONN1_G->adsc_gate1->inc_no_usgro))) {  /* authenticate usgr */
#ifndef HL_IPV6
     iel_claddrtype = en_atca_IPV4;
     avol_client_netaddr = (void *) &ADSL_CONN1_G->dcl_tcp_r_c.dclient1;
#else
     iel_claddrtype = en_atca_IPV6;
     avol_client_netaddr = (void *) &ADSL_CONN1_G->dcl_tcp_r_c.uncl1;
     if (bog_ipv6 == FALSE) {
       iel_claddrtype = en_atca_IPV4;
     }
#endif
     ADSL_CONN1_G->adsc_radqu = new dsd_radius_query( ADSL_CONN1_G,
                                                      ADSL_CONN1_G->adsc_gate1->inc_no_radius,
                                                      ADSL_CONN1_G->adsc_gate1->inc_no_usgro,
                                                      (HL_WCHAR *) (((int *) (adsl_auxf_1_1 + 1)) + 1),
                                                      inl_len_cert,
                                                      &(ADSL_CONN1_G->adsc_gate1->dsc_radius_conf),
                                                      iel_claddrtype,
                                                      avol_client_netaddr );
   }
#endif
   ADSL_CONN1_G->boc_st_sslc = TRUE;        /* ssl handshake complete  */
#ifndef HELP_DEBUG
#undef AUCL_CONNDATA
//#undef hssl_QueryInfo
#undef ADSL_SSL_QUERY_INFO
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
#endif
} /* end m_ssl_conn_cl_compl_se()                                      */

#ifdef CSSSL_060620
/* Connect Callback Client-Side SSL                                    */
static void m_ssl_conn_cl_compl_cl( struct dsd_hl_ssl_ccb_1 *adsp_ccb_1 ) {
   int        iml1, iml2;                   /* working variables       */
   char       *achl1, *achl2;               /* working variables       */
#ifdef XYZ1
   BOOL       bol1;                         /* working variable        */
#endif
   BOOL       bol_not_valid_dn;             /* check DN                */
   int        iml_len_msg_ssl;              /* length of SSL message   */
   int        iml_len_cert;                 /* length of certificate n */
   int        iml_ns_prot, iml_ns_ci_sui, iml_ns_keyexch, iml_ns_ci_alg,
              iml_ns_ci_type, iml_ns_mac, iml_ns_auth, iml_ns_compr;
#ifdef XYZ1
   en_at_claddrtype iel_claddrtype;         /* type of address         */
   void *     avol_client_netaddr;          /* address net-addr        */
   struct dsd_auxf_1 *adsl_auxf_1_1;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_2;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_3;        /* auxiliary extension fi  */
   struct dsd_auxf_1 *adsl_auxf_1_dn;       /* aux ext fi dn distinguished name */
   struct dsd_auxf_1 *adsl_auxf_1_ce;       /* aux ext fi ce certificate */
#endif
#ifndef B140728
   char       *achl_pfs;                    /* pfs = YES / NO          */
   char       *achl_ssl_tls;                /* SSL / TLS version       */
   struct sockaddr *adsl_soa_w1;            /* sockaddr temporary value */
#endif
   char       byrlwork1[ 112 + DEF_MAX_LEN_CERT_NAME + 1 ];
   char       byrlwork_ssl[ 512 ];          /* for text cipher         */
#ifndef B140728
   char       byrl_ssl_tls[ 32 ];           /* SSL / TLS version       */
   char       byrl_ineta_server[ LEN_DISP_INETA ];  /* for INETA server */
#endif
#ifdef XYZ1
   /* 04.08.04 KB + Joachim Frank */
   char       byrl_cout[1024];
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_ssl_conn_cl_compl_cl called" );
#endif
#define ADSL_AUX_CF1 ((struct dsd_aux_cf1 *) adsp_ccb_1->vpc_userfld)  /* auxiliary control structure */
#define ADSL_CONN1_G (ADSL_AUX_CF1->adsc_conn)  /* pointer on connection */
#ifdef B121009
#define hssl_QueryInfo ((HSSL_QUERYINFO *) adsp_ccb_1->ac_conndata)
#endif
#define ADSL_SSL_QUERY_INFO ((struct dsd_ssl_query_info *) adsp_ccb_1->ac_conndata)
#define AUCL_CONNDATA ((unsigned char *) adsp_ccb_1->ac_conndata)
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_ssl_conn_cl_compl_cl l%05d called adsp_ccb_1=%p.", __LINE__, adsp_ccb_1 );
   m_hlnew_printf( HLOG_TRACE1, "-- vpc_userfld=%p ac_conndata=%p achc_fingerprint=%p achc_certificate=%p inc_len_certificate=%d.",
                   adsp_ccb_1->vpc_userfld, adsp_ccb_1->ac_conndata, adsp_ccb_1->achc_fingerprint, adsp_ccb_1->achc_certificate, adsp_ccb_1->inc_len_certificate );
// partners name is Big-endian unicode. For simplicity we assume Latin
// and convert this unicode to a char string.
   char szString[512];
   int j, i;
         j=0;
         for (i = 0; i < (hssl_QueryInfo->hssl_byPartnerNameLength*2); i= i+2)
         {
       szString[j++] = hssl_QueryInfo->hssl_byPartnerName[i+1];
         }
         szString[j++] = 0x0;
   m_hlnew_printf( HLOG_XYZ1, "partner-id %s", szString );
#endif
#ifdef DEBUG_100809
   m_hlnew_printf( HLOG_XYZ1, "m_ssl_conn_cl_compl_cl l%05d called adsp_ccb_1=%p", __LINE__, adsp_ccb_1 );
   m_hlnew_printf( HLOG_XYZ1, "-- vpc_userfld=%p ac_conndata=%p achc_fingerprint=%p achc_certificate=%p inc_len_certificate=%d",
                   adsp_ccb_1->vpc_userfld, adsp_ccb_1->ac_conndata, adsp_ccb_1->achc_fingerprint, adsp_ccb_1->achc_certificate, adsp_ccb_1->inc_len_certificate );
// partners name is Big-endian unicode. For simplicity we assume Latin
// and convert this unicode to a char string.
   char szString[512];
   int j, i;
         j=0;
         for (i = 0; i < (hssl_QueryInfo->hssl_byPartnerNameLength*2); i= i+2)
         {
       szString[j++] = hssl_QueryInfo->hssl_byPartnerName[i+1];
         }
         szString[j++] = 0x0;
   m_hlnew_printf( HLOG_XYZ1, "partner-id %s", szString );
#endif
   if (ADSL_CONN1_G->adsc_csssl_oper_1 == NULL) {
     m_hlnew_printf( HLOG_WARN1, "HWSPS085W Client-Side SSL handshake, but SSL not active" );
     return;
   }
   bol_not_valid_dn = adsg_loconf_1_inuse->boc_csssl_usage_dn;  /* check DN - TRUE if check necessary */
   if (ADSL_CONN1_G->adsc_csssl_oper_1->boc_sslc) {  /* ssl handshake complete */
     m_hlnew_printf( HLOG_WARN1, "HWSPS086W Client-Side SSL handshake complete double" );
   }
#ifdef B121009
   iml_len_cert = hssl_QueryInfo->hssl_byPartnerNameLength;
#endif
   iml_len_cert = ADSL_SSL_QUERY_INFO->ucc_partner_name_length;
   if (   (iml_len_cert < 0)
       || (iml_len_cert > DEF_MAX_LEN_CERT_NAME)) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxW GATE=%(ux)s SNO=%08d INETA=%s length of certificate name invalid %d",
                     ADSL_CONN1_G->adsc_gate1 + 1,
                     ADSL_CONN1_G->dsc_co_sort.imc_sno,
                     ADSL_CONN1_G->chrc_ineta,
                     iml_len_cert );
     iml_len_cert = 0;
   }
   byrlwork_ssl[0] = 0;                     /* no data about handshake */
   iml_len_msg_ssl = 0;                     /* length of SSL message   */
   if (adsg_loconf_1_inuse->inc_network_stat >= 2) {
#ifndef B140728
     achl_pfs = "NO";                       /* pfs = YES / NO          */
     if (adsp_ccb_1->boc_pfs_used) {        /* Was a key exchange with PFS used? */
       achl_pfs = "YES";                    /* pfs = YES / NO          */
     }
     iml_ns_prot = ADSL_SSL_QUERY_INFO->imc_ssl_tls_prot_vers >> 16;  /* SSL / TLS protocol version */
     if (iml_ns_prot >= (sizeof(achrs_ssl_prot) / sizeof(achrs_ssl_prot[0]))) {
       iml_ns_prot = 0;                     /* make unknown            */
     }
     achl_ssl_tls = (char *) achrs_ssl_prot[ iml_ns_prot ];  /* SSL / TLS version */
     if (   (iml_ns_prot == 1)
         || (iml_ns_prot == 2)) {
       sprintf( byrl_ssl_tls,
                "%s-V%d.%d",
                achrs_ssl_prot[ iml_ns_prot ],
                (ADSL_SSL_QUERY_INFO->imc_ssl_tls_prot_vers >> 8) & 0XFF,
                ADSL_SSL_QUERY_INFO->imc_ssl_tls_prot_vers & 0XFF );
       achl_ssl_tls = byrl_ssl_tls;         /* SSL / TLS version       */
     }
#endif
#ifdef B140728
     iml_ns_prot = *(AUCL_CONNDATA + 48);
     if (iml_ns_prot >= (sizeof(achrs_ssl_prot) / sizeof(achrs_ssl_prot[0]))) {
       iml_ns_prot = 0;                     /* make unknown            */
     }
#endif
     iml_ns_ci_sui = *(AUCL_CONNDATA + 51);
     if (iml_ns_ci_sui >= (sizeof(achrs_ssl_ci_prot) / sizeof(achrs_ssl_ci_prot[0]))) {
       iml_ns_ci_sui = sizeof(achrs_ssl_ci_prot) / sizeof(achrs_ssl_ci_prot[0]) - 1;
     }
     iml_ns_keyexch = *(AUCL_CONNDATA + 52);
     if (iml_ns_keyexch >= (sizeof(achrs_ssl_keyexch) / sizeof(achrs_ssl_keyexch[0]))) {
       iml_ns_keyexch = 0;                  /* make unknown            */
     }
     iml_ns_ci_alg = *(AUCL_CONNDATA + 53);
     if (iml_ns_ci_alg >= (sizeof(achrs_ssl_ci_alg) / sizeof(achrs_ssl_ci_alg[0]))) {
       iml_ns_ci_alg = 0;                   /* make unknown            */
     }
     iml_ns_ci_type = *(AUCL_CONNDATA + 54);
     if (iml_ns_ci_type >= (sizeof(achrs_ssl_ci_type) / sizeof(achrs_ssl_ci_type[0]))) {
       iml_ns_ci_type = (sizeof(achrs_ssl_ci_type) / sizeof(achrs_ssl_ci_type[0])) - 1;
     }
     iml_ns_mac = *(AUCL_CONNDATA + 55);
     if (iml_ns_mac >= (sizeof(achrs_ssl_ci_alg) / sizeof(achrs_ssl_ci_alg[0]))) {
       iml_ns_mac = 0;                      /* make unknown            */
     }
     iml_ns_auth = *(AUCL_CONNDATA + 57) & 3;
     iml_ns_auth |= 1;                      /* always server authentication */
     iml_ns_compr = *(AUCL_CONNDATA + 49);
     if (iml_ns_compr) {                    /* is not none             */
       if (iml_ns_compr == 0XF4) {          /* is defined              */
         iml_ns_compr = 1;
       } else {
         iml_ns_compr = 2;                  /* make unknown            */
       }
     }
#ifdef B140728
     iml_len_msg_ssl = sprintf( byrlwork_ssl, " - protocol:%s cipher-suite:%s key-exchange-mode:%s"
                                " cipher-algorithm:%s cipher-type:%s MAC-algorithm:%s authentication:%s compression:%s",
                                achrs_ssl_prot[ iml_ns_prot ],
                                achrs_ssl_ci_prot[ iml_ns_ci_sui ],
                                achrs_ssl_keyexch[ iml_ns_keyexch ],
                                achrs_ssl_ci_alg[ iml_ns_ci_alg ],
                                achrs_ssl_ci_type[ iml_ns_ci_type ],
                                achrs_ssl_mac[ iml_ns_mac ],
                                achrs_ssl_auth[ iml_ns_auth ],
                                achrs_ssl_compr[ iml_ns_compr ] );
#endif
#ifndef B140728
     iml_len_msg_ssl = sprintf( byrlwork_ssl, " - pfs:%s protocol:%s cipher-suite:%s key-exchange-mode:%s"
                                " cipher-algorithm:%s cipher-type:%s MAC-algorithm:%s authentication:%s compression:%s",
                                achl_pfs,   /* pfs = YES / NO          */
                                achl_ssl_tls,  /* SSL / TLS version    */
                                achrs_ssl_ci_prot[ iml_ns_ci_sui ],
                                achrs_ssl_keyexch[ iml_ns_keyexch ],
                                achrs_ssl_ci_alg[ iml_ns_ci_alg ],
                                achrs_ssl_ci_type[ iml_ns_ci_type ],
                                achrs_ssl_mac[ iml_ns_mac ],
                                achrs_ssl_auth[ iml_ns_auth ],
                                achrs_ssl_compr[ iml_ns_compr ] );
#endif
   }
#ifdef B121009
   if (hssl_QueryInfo->hssl_byPartnerNameLength == 0) {
     achl1 = "no server certificate";
     goto psussl80;
   }                                        /* no text yet             */
#endif
   if (ADSL_SSL_QUERY_INFO->ucc_partner_name_length == 0) {
     achl1 = "no server certificate";
     goto psussl80;
   }                                        /* no text yet             */
   iml1 = 0;
   if (adsp_ccb_1->achc_fingerprint) {
     iml1 += sprintf( &byrlwork1[iml1], "fingerprint: " );
     iml2 = 0;
     do {
       iml1 += sprintf( &byrlwork1[iml1], "%02X",
                        *((unsigned char *) adsp_ccb_1->achc_fingerprint + iml2) );

       if (iml2 % 2) byrlwork1[ iml1++ ] = ' ';
       iml2++;                              /* next character          */
     } while (iml2 < DEF_SSL_LEN_FINGERPRINT);
     iml1 += sprintf( &byrlwork1[iml1], "- " );  /* separate following text */
   }
   iml1 += sprintf( &byrlwork1[iml1], "DN (name from certificate): " );
   achl1 = achl2 = &byrlwork1[iml1];        /* name comes here         */
   for (iml1 = 0; iml1 < iml_len_cert; iml1++ ) {
#ifdef B121009
     iml2 = GHHW( *((unsigned short int *) &hssl_QueryInfo->hssl_byPartnerName[ iml1 * 2 ]) );
#endif
     iml2 = GHHW( *((unsigned short int *) &ADSL_SSL_QUERY_INFO->ucrc_partner_name[ iml1 * 2 ]) );
     if (iml2 < 0X0100) {
       *achl1++ = (char) iml2;
     } else {
       *achl1++ = '?';
     }
   }
   *achl1 = 0;                              /* make zero-terminated    */
   iml1 = _stricmp( achl2, (char *) (ADSL_CONN1_G->adsc_csssl_oper_1 + 1) );
   if (iml1) {                              /* strings not equal       */
     strcpy( &byrlwork_ssl[ iml_len_msg_ssl ], " Certificate does not contain valid DNS-name" );
   } else {                                 /* all valid               */
     bol_not_valid_dn = FALSE;              /* check DN successful     */
   }
   achl1 = byrlwork1;

   psussl80:                                /* write message           */
#ifdef B140728
// to-do 30.04.09 KB IPV6 and HTCP
   m_hlnew_printf( HLOG_XYZ1, "HWSPSxxxI GATE=%(ux)s SNO=%08d INETA=%s Client-Side SSL logon - \
host=%s INETA-host=%d.%d.%d.%d - %s%s",
                   ADSL_CONN1_G->adsc_gate1 + 1,
                   ADSL_CONN1_G->dsc_co_sort.imc_sno,
                   ADSL_CONN1_G->chrc_ineta,
                   ADSL_CONN1_G->adsc_csssl_oper_1 + 1,
                   *((unsigned char *) &(((struct sockaddr_in *) ADSL_CONN1_G->dcl_tcp_r_s.m_get_ineta())->sin_addr)),
                   *((unsigned char *) &(((struct sockaddr_in *) ADSL_CONN1_G->dcl_tcp_r_s.m_get_ineta())->sin_addr) + 1),
                   *((unsigned char *) &(((struct sockaddr_in *) ADSL_CONN1_G->dcl_tcp_r_s.m_get_ineta())->sin_addr) + 2),
                   *((unsigned char *) &(((struct sockaddr_in *) ADSL_CONN1_G->dcl_tcp_r_s.m_get_ineta())->sin_addr) + 3),
                   achl1, byrlwork_ssl );
#endif
#ifndef B140728
   byrl_ineta_server[ 0 ] = 0;              /* for INETA server        */
   adsl_soa_w1 = NULL;                      /* sockaddr temporary value */
   switch (ADSL_CONN1_G->iec_servcotype) {  /* type of server connection */
     case ied_servcotype_normal_tcp:        /* normal TCP              */
       adsl_soa_w1 = (struct sockaddr *) &ADSL_CONN1_G->dcl_tcp_r_s.dsc_soa;  /* sockaddr from class to receive server */
       break;
#ifdef D_INCL_HOB_TUN
      case ied_servcotype_htun:             /* HOB-TUN                 */
        if (ADSL_CONN1_G->adsc_ineta_raws_1->boc_with_user) {  /* structure with user */
          adsl_soa_w1 = (struct sockaddr *) &ADSL_CONN1_G->dsc_soa_htcp_server;  /* address information for connected */
        }
        break;
#endif
   }
   if (adsl_soa_w1) {                       /* sockaddr temporary value */
     getnameinfo( adsl_soa_w1, sizeof(struct sockaddr_storage),
                  byrl_ineta_server, sizeof(byrl_ineta_server),
                  0, 0, NI_NUMERICHOST );
   }
   if (byrl_ineta_server[ 0 ] == 0) {       /* for INETA server        */
     strcpy( byrl_ineta_server, "???" );
   }
   m_hlnew_printf( HLOG_INFO1, "HWSPS084I GATE=%(ux)s SNO=%08d INETA=%s Client-Side SSL logon - \
host=%s INETA-host=%s - %s%s",
                   ADSL_CONN1_G->adsc_gate1 + 1,
                   ADSL_CONN1_G->dsc_co_sort.imc_sno,
                   ADSL_CONN1_G->chrc_ineta,
                   ADSL_CONN1_G->adsc_csssl_oper_1 + 1,
                   byrl_ineta_server,
                   achl1, byrlwork_ssl );
#endif
   ADSL_CONN1_G->adsc_csssl_oper_1->boc_sslc = TRUE;  /* ssl handshake complete */
   ADSL_CONN1_G->adsc_csssl_oper_1->boc_error = bol_not_valid_dn;  /* if DNS name wrong, error occured */
#ifndef B100731
   if (ADSL_CONN1_G->iec_st_ses == clconn1::ied_ses_wait_csssl) {  /* wait for client-side SSL */
     ADSL_CONN1_G->iec_st_ses = clconn1::ied_ses_start_server_2;  /* start connection to server part two */
   }
#endif
#undef AUCL_CONNDATA
#undef hssl_QueryInfo
#undef ADSL_CONN1_G
#undef ADSL_AUX_CF1
} /* end m_ssl_conn_cl_compl_cl()                                      */
#endif
#endif

#ifdef B100518
DOMCountErrorHandler::DOMCountErrorHandler() :

    fSawErrors(false)
{
}

DOMCountErrorHandler::~DOMCountErrorHandler()
{
}


// ---------------------------------------------------------------------------
//  DOMCountHandlers: Overrides of the DOM ErrorHandler interface
// ---------------------------------------------------------------------------
bool DOMCountErrorHandler::handleError(const DOMError& domError)
{
#ifndef B050307
   class DOMLocator *adsc_doml1;
#endif
    fSawErrors = true;
#ifdef OLD01
    if (domError.getSeverity() == DOMError::DOM_SEVERITY_WARNING)
        cerr << "\nWarning at file ";
    else if (domError.getSeverity() == DOMError::DOM_SEVERITY_ERROR)
        cerr << "\nError at file ";
    else
        cerr << "\nFatal Error at file ";
#else
#ifdef B050307
   if (domError.getSeverity() == DOMError::DOM_SEVERITY_WARNING)
      m_hlnew_printf( HLOG_XYZ1, "HWSPXMLnnnW Xerxes reported Warning at Input-File" );
   else if (domError.getSeverity() == DOMError::DOM_SEVERITY_ERROR)
      m_hlnew_printf( HLOG_XYZ1, "HWSPXMLnnnW Xerxes reported Error at Input-File" );
   else
      m_hlnew_printf( HLOG_XYZ1, "HWSPXMLnnnW Xerxes reported Fatal Error at Input-File" );
#else
   adsc_doml1 = domError.getLocation();
   if (domError.getSeverity() == DOMError::DOM_SEVERITY_WARNING)
      m_hlnew_printf( HLOG_XYZ1, "HWSPXMLL010W Xerxes reported Warning at Input-File Line=%d Column=%d / Offset=%d",
                  adsc_doml1->getLineNumber(), adsc_doml1->getColumnNumber(), adsc_doml1->getOffset() );
   else if (domError.getSeverity() == DOMError::DOM_SEVERITY_ERROR)
      m_hlnew_printf( HLOG_XYZ1, "HWSPXMLL011W Xerxes reported Error at Input-File Line=%d Column=%d / Offset=%d",
                  adsc_doml1->getLineNumber(), adsc_doml1->getColumnNumber(), adsc_doml1->getOffset() );
   else
      m_hlnew_printf( HLOG_XYZ1, "HWSPXMLL012W Xerxes reported Fatal Error at Input-File Line=%d Column=%d / Offset=%d",
                  adsc_doml1->getLineNumber(), adsc_doml1->getColumnNumber(), adsc_doml1->getOffset() );
#endif
#endif

    return true;
}

void DOMCountErrorHandler::resetErrors()
{
    fSawErrors = false;
}
#endif

/** process the configuration                                          */
static BOOL m_proc_conf( BOOL bop_start ) {
   int        iml1;                         /* working variable        */
   BOOL       bol_rc;                       /* working variable        */
#ifndef NEW_VISUAL_C
   DWORD      dwl1;                         /* working variable        */
#endif
   LONGLONG   ill_file_size;                /* size of this file       */
// LONGLONG   ill_pos_file;                 /* position in file        */
   char       *achl1;                       /* working variable        */
#ifdef B160827
   char       *achl_buffer;                 /* buffer for read         */
#endif
   struct dsd_see_cd_plain_xml *adsl_see_cd_plain_xml;  /* see in core dump plain XML configuration */
// int        iml_read;                     /* so much to read         */
// BOOL       bolerror;                     /* save error              */
// BOOL       bol_read_file;                /* read the file           */
// BOOL       bol_wait;                     /* wait for access to file */
   unsigned long int uml_returned_read;     /* how much read from disk */
   HANDLE     dsl_hfi1;                     /* handle for file         */
   int        imrl_sha1[ SHA_ARRAY_SIZE ];  /* for hash                */
   HL_LONGLONG ilrl_sha384_temp[ SHA384_ARRAY_SIZE ];  /* for hash security-token */
   amd_startprog aml_startprog;             /* pass entry startprog    */
#ifdef XYZ1
   dsd_xml_mis_1 *adsl_xml_mis;             /* for xml parsing         */
#endif
   AbstractDOMParser::ValSchemes valScheme = AbstractDOMParser::Val_Auto;
   bool                       doNamespaces       = false;
   bool                       doSchema           = false;
   bool                       schemaFullChecking = false;
   bool                       doList = false;
   bool                       errorOccurred = false;

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_proc_conf called" );
#endif
   dsl_hfi1 = CreateFileA( adss_path_param, GENERIC_READ, FILE_SHARE_READ, 0,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
   if (dsl_hfi1 == INVALID_HANDLE_VALUE) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPPC001W open input file %s returned Error %d",
                 adss_path_param, GetLastError() );
     return FALSE;                          /* return with error       */
   }
#ifdef NEW_VISUAL_C
   bol_rc = GetFileSizeEx( dsl_hfi1, (PLARGE_INTEGER) &ill_file_size );
   if (bol_rc == FALSE) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPPC002W GetFileSizeEx( %s ) returned Error %d",
                 adss_path_param, GetLastError() );
     CloseHandle( dsl_hfi1 );               /* close configuration file */
     return FALSE;                          /* return with error       */
   }
#else
   *((DWORD *) &ill_file_size + 0) = GetFileSize( dsl_hfi1, ((DWORD *) &ill_file_size + 1) );
   while (*((DWORD *) &ill_file_size + 0) == INVALID_FILE_SIZE) {
     dwl1 = GetLastError();
     if (dwl1 == NO_ERROR) break;
     m_hlnew_printf( HLOG_XYZ1, "HWSPPC002W GetFileSize( %s ) returned Error %d",
                 adss_path_param, dwl1 );
     CloseHandle( dsl_hfi1 );               /* close configuration file */
     return FALSE;                          /* return with error       */
   }
#endif
   if (ill_file_size > DEF_MAX_LEN_CONF_FILE) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPPC003W configuration file %s too big (size=%lld)",
                 adss_path_param, ill_file_size );
     CloseHandle( dsl_hfi1 );
     return FALSE;                          /* return with error       */
   }
#ifdef B160827
   achl_buffer = (char *) malloc( (int) ill_file_size );
   if (achl_buffer == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPPC004W error malloc() content configuration-file %s",
                 adss_path_param );
     CloseHandle( dsl_hfi1 );               /* close configuration file */
     return FALSE;                          /* return with error       */
   }
   bol_rc = ReadFile( dsl_hfi1, achl_buffer, (int) ill_file_size, &uml_returned_read, 0 );
   if (bol_rc == FALSE) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPPC005W ReadFile() file %s returned Error %d",
                 adss_path_param, GetLastError() );
     free( achl_buffer );                   /* free memory again       */
     CloseHandle( dsl_hfi1 );               /* close configuration file */
     return FALSE;                          /* return with error       */
   }
#endif
#define imp_hlog HLOG_EMER1  /* temporary */
   adsl_see_cd_plain_xml                    /* see in core dump plain XML configuration */
     = (struct dsd_see_cd_plain_xml *) malloc( sizeof(struct dsd_see_cd_plain_xml) + ill_file_size );
   if (adsl_see_cd_plain_xml == NULL) {     /* out of memory           */
     m_hlnew_printf( imp_hlog, "HWSPPC004W error malloc() content configuration-file %s",
                     adss_path_param );
     CloseHandle( dsl_hfi1 );               /* close configuration file */
     return 1;                              /* return with error       */
   }
   memset( adsl_see_cd_plain_xml, 0, sizeof(struct dsd_see_cd_plain_xml) );
   adsl_see_cd_plain_xml->dsc_time_loaded = m_get_time();  /* epoch when loaded */
   memcpy( adsl_see_cd_plain_xml->byrc_eye_catcher,
           DEF_LOAD_XML_CONF_EC,
           sizeof(DEF_LOAD_XML_CONF_EC) - 1 );
   strftime( adsl_see_cd_plain_xml->byrc_eye_catcher + sizeof(DEF_LOAD_XML_CONF_EC) - 1,
             sizeof(adsl_see_cd_plain_xml->byrc_eye_catcher) - sizeof(DEF_LOAD_XML_CONF_EC) + 1,
             "%d.%m.%y %H:%M:%S",
             localtime( &adsl_see_cd_plain_xml->dsc_time_loaded ) );
   adsl_see_cd_plain_xml->adsc_next = adss_see_cd_plain_xml_anchor;
   adss_see_cd_plain_xml_anchor = adsl_see_cd_plain_xml;
   bol_rc = ReadFile( dsl_hfi1, (char *) (adsl_see_cd_plain_xml + 1), (int) ill_file_size, &uml_returned_read, 0 );
   if (bol_rc == FALSE) {
     m_hlnew_printf( imp_hlog, "HWSPPC005W ReadFile() file %s returned Error %d",
                     adss_path_param, GetLastError() );
#ifdef B160827
     free( achl_buffer );                   /* free memory again       */
#endif
     CloseHandle( dsl_hfi1 );               /* close configuration file */
     return 1;                              /* return with error       */
   }
#undef imp_hlog  /* temporary */
   bol_rc = CloseHandle( dsl_hfi1 );
   if (bol_rc == FALSE) {
     m_hlnew_printf( HLOG_WARN1, "HWSPPC006W CloseHandle configuration file %s returned Error %d",
                     adss_path_param, GetLastError() );
   }
   /* compute fingerprint / hash                                       */
   SHA1_Init( imrl_sha1 );
#ifdef B160827
   SHA1_Update( imrl_sha1, achl_buffer, 0, (int) ill_file_size );
#endif
   SHA1_Update( imrl_sha1, (char *) (adsl_see_cd_plain_xml + 1), 0, (int) ill_file_size );
   SHA1_Final( imrl_sha1, adss_loconf_1_fill->chrc_fingerprint, 0 );
   m_disp_conf_file( FALSE );

#ifdef XYZ1
   adsl_xml_mis = new dsd_xml_mis_1( (XMLByte *) achl_buffer, (int) ill_file_size );
#endif

    // Instantiate the DOM parser.
#ifdef B100518
    static const XMLCh gLS[] = { chLatin_L, chLatin_S, chNull };
    DOMImplementation *impl = DOMImplementationRegistry::getDOMImplementation(gLS);
    DOMBuilder        *parser = ((DOMImplementationLS*)impl)->createDOMBuilder(DOMImplementationLS::MODE_SYNCHRONOUS, 0);

    parser->setFeature(XMLUni::fgDOMNamespaces, doNamespaces);
    parser->setFeature(XMLUni::fgXercesSchema, doSchema);
    parser->setFeature(XMLUni::fgXercesSchemaFullChecking, schemaFullChecking);

    if (valScheme == AbstractDOMParser::Val_Auto)
    {
        parser->setFeature(XMLUni::fgDOMValidateIfSchema, true);
    }
    else if (valScheme == AbstractDOMParser::Val_Never)
    {
        parser->setFeature(XMLUni::fgDOMValidation, false);
    }
    else if (valScheme == AbstractDOMParser::Val_Always)
    {
        parser->setFeature(XMLUni::fgDOMValidation, true);
    }

    // enable datatype normalization - default is off
    parser->setFeature(XMLUni::fgDOMDatatypeNormalization, true);

    // And create our error handler and install it
    DOMCountErrorHandler errorHandler;
    parser->setErrorHandler(&errorHandler);

        //reset error count first
        errorHandler.resetErrors();

        XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *doc = 0;

        try
        {
            // reset document pool
            parser->resetDocumentPool();

            doc = parser->parse( *adsl_xml_mis );
        }

        catch (const XMLException& toCatch)
        {
            errorOccurred = true;
        }
        catch (const DOMException& toCatch)
        {
            const unsigned int maxChars = 2047;
            XMLCh errText[maxChars + 1];



            errorOccurred = true;
        }
        catch (...)
        {
            cerr << "\nUnexpected exception during parsing: '" << asargv[1] << "'\n";
            errorOccurred = true;
        }

        //
        //  Extract the DOM tree, get the list of all the elements and report the
        //  length as the count of elements.
        //
        if (errorHandler.getSawErrors())
        {
#ifndef TRACE_PRINTF
             cout << "\nErrors occurred, no output available\n" << endl;
#else
             EnterCriticalSection( &dss_critsect_printf );
             printf( "\nErrors occurred, no output available\n" );
             LeaveCriticalSection( &dss_critsect_printf );
#endif
            errorOccurred = true;
        }
         else
        {
#ifdef NOTYET050817
          bol_rc = m_build_conf_01( doc );
#endif
          aml_startprog = NULL;             /* do not start program    */
          if (bop_start) {                  /* start the program now   */
            aml_startprog = &m_startprog;   /* pass entry startprog    */
          }
//        bol_rc = m_build_conf_01( doc, &dss_loconf_1_first, aml_startprog );
          bol_rc = m_build_conf_01( doc, adss_loconf_1_fill, aml_startprog );
          if (bol_rc == FALSE)
            errorOccurred = true;
        }

    //
    //  Delete the parser itself.  Must be done prior to calling Terminate, below.
    //
    parser->release();
#else
    // create Xerces Parser:
    dsd_xml_parser_1 *adsl_parser = new dsd_xml_parser_1();
#ifdef B160827
    dsd_xml_mis_1     dsl_xml_mis( (XMLByte *) achl_buffer, (int) ill_file_size );
#endif
    dsd_xml_mis_1     dsl_xml_mis( (XMLByte *) (char *) (adsl_see_cd_plain_xml + 1), (int) ill_file_size );

    // set options:
    adsl_parser->setDoNamespaces                ( doNamespaces );
    adsl_parser->setDoSchema                    ( doSchema );
    adsl_parser->setValidationSchemaFullChecking( schemaFullChecking );
    adsl_parser->setValidationScheme            ( valScheme );

    // what is this ???
    // enable datatype normalization - default is off
    //parser->setFeature(XMLUni::fgDOMDatatypeNormalization, true);

    // create our error handler and install it
    dsd_xml_error_1 dsl_error_handler;
    adsl_parser->setErrorHandler( &dsl_error_handler );

    XERCES_CPP_NAMESPACE_QUALIFIER DOMDocument *doc = 0;

    try
    {
        // reset document pool
        adsl_parser->resetDocumentPool();
        adsl_parser->parse( dsl_xml_mis );
        doc = adsl_parser->getDocument();
    }
    catch (const XMLException& toCatch)
    {
        errorOccurred = true;
    }
    catch (const DOMException& toCatch)
    {
        const unsigned int maxChars = 2047;
        XMLCh errText[maxChars + 1];
        errorOccurred = true;
    }
    catch (...)
    {
        cerr << "\nUnexpected exception during parsing: '" << asargv[1] << "'\n";
        errorOccurred = true;
    }

    //
    //  Extract the DOM tree, get the list of all the elements and report the
    //  length as the count of elements.
    //
    if ( dsl_error_handler.m_error_happened() )
    {
#ifndef TRACE_PRINTF
         cout << "\nErrors occurred, no output available\n" << endl;
#else
         EnterCriticalSection( &dss_critsect_printf );
         printf( "\nErrors occurred, no output available\n" );
         LeaveCriticalSection( &dss_critsect_printf );
#endif
        errorOccurred = true;
    }
     else
    {
#ifdef NOTYET050817
      bol_rc = m_build_conf_01( doc );
#endif
      aml_startprog = NULL;                 /* do not start program    */
      if (bop_start) {                      /* start the program now   */
        aml_startprog = &m_startprog;       /* pass entry startprog    */
      }
//        bol_rc = m_build_conf_01( doc, &dss_loconf_1_first, aml_startprog );
      bol_rc = m_build_conf_01( doc, adss_loconf_1_fill, aml_startprog );
      if (bol_rc == FALSE) {
        errorOccurred = true;
      }
    }
    delete ( adsl_parser );
#endif
#ifdef B160827
   free( achl_buffer );                     /* free memory again       */
#endif
#ifdef XYZ1
   delete( adsl_xml_mis );                  /* delete xml class        */
#endif

   if (errorOccurred) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPXMLL001W Configuration could not be loaded because error in configuration file" );
     return FALSE;
   }
   /* use security-token                                               */
   achl1 = "HOB";
   iml1 = 3;
   if (adss_loconf_1_fill->imc_len_security_token > 0) {  /* length of security-token */
     achl1 = adss_loconf_1_fill->achc_security_token;  /* security-token UTF-8 */
     iml1 = adss_loconf_1_fill->imc_len_security_token;  /* length of security-token */
   }
#ifdef XYZ1
   SHA1_Init( imrl_sha1 );
   SHA1_Update( imrl_sha1, achl1, 0, iml1 );
   memcpy( imrs_sha1_security_token, imrl_sha1, sizeof(imrs_sha1_security_token) );  /* for hash security-token */
#endif
   SHA384_Init( ilrl_sha384_temp );
   SHA384_512_Update( ilrl_sha384_temp, achl1, 0, iml1 );
   memcpy( ilrs_sha384_security_token, ilrl_sha384_temp, sizeof(ilrs_sha384_security_token) );  /* for hash security-token */
#ifdef TCP_SET_SNDBUF                       /* 10.08.11 KB + MJ TCP SNDBUF */
   adss_loconf_1_fill->imc_tcp_sndbuf = TCP_SET_SNDBUF;  /* set TCP SNDBUF   */
   m_hlnew_printf( HLOG_XYZ1, "HWSPXnnnnnnI Configuration processed - set TCP SNDBUF - set to %d.", TCP_SET_SNDBUF );
#endif
   return TRUE;
} /* end m_proc_conf()                                                 */

/** start parts of the program                                         */
static BOOL m_startprog( struct dsd_wsp_startprog *adsp_wsp_startprog ) {
   BOOL       bol1;                         /* working variable        */
   int        inl1, inl2;                   /* working variables       */
   int        iml_rc1;                      /* Return Code 1           */
#ifdef XYZ1
   int        iml_rc2;                      /* Return Code 2           */
#endif
#ifdef B100802
#ifdef D_HPPPT1_1
   DWORD      dwl_ret;                      /* return code             */
   unsigned long int uml_ai_buf_len;        /* length of buffer for adapter info */
   DWORD      dwl_index_if;                 /* holds index of compatible IF */
   PIP_ADAPTER_INFO adsl_adap_info_w1;      /* points to first adapter info */
   PIP_ADAPTER_INFO adsl_adap_info_w2;      /* points to first adapter info */
   IP_ADDR_STRING *adsl_ineta_cur;
#endif
#endif
   char       chrl_work_1[512];             /* working area            */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_startprog() called" );
#endif

#ifndef D_NO_DUMP
   m_hl_setdump();                          /* start dump              */
#endif
   bos_mem_log = m_create_log( adsg_loconf_1_inuse->ilc_mem_ls );
#ifdef B140819
   /* initialize random generator                                      */
   srand( (unsigned int) (m_get_epoch_ms() >> 7) );
#endif
   m_hco_set_thr_sta_func( &m_wothr_start_inj );

   dsrs_heve_main[0] = CreateEvent( NULL, FALSE, FALSE, NULL );
   if (dsrs_heve_main[0] == NULL) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM070W CreateEvent MAIN Error %d", GetLastError() );
     if (boisservice) {
       dclasrvstat.dwCurrentState = SERVICE_STOPPED;  /* service close */
       SetServiceStatus( dclhsrvstat, &dclasrvstat );  /* set state    */
     }
     return FALSE;
   }

   InitializeCriticalSection( &d_clconn_critsect );

   InitializeCriticalSection( &d_clutil_critsect );

   InitializeCriticalSection( &d_clwork_critsect );

   InitializeCriticalSection( &dsalloc_dcritsect );

   iml_rc1 = dss_critsect_aux.m_create();
   if (iml_rc1 < 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_critsect_aux m_create Return Code %d",
                     __LINE__, iml_rc1 );
     return FALSE;                          /* count not start resource */
   }

   iml_rc1 = dss_critsect_slow.m_create();
   if (iml_rc1 < 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_critsect_slow m_create Return Code %d",
                     __LINE__, iml_rc1 );
     return FALSE;                          /* count not start resource */
   }

   iml_rc1 = dsg_global_lock.m_create();
   if (iml_rc1 < 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dsg_global_lock m_create Return Code %d",
                     __LINE__, iml_rc1 );
     return FALSE;                          /* count not start resource */
   }

   iml_rc1 = dss_trace_lock.m_create();     /* lock for WSP-trace      */
   if (iml_rc1 < 0) {                       /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dss_trace_lock m_create return code %d.",
                     __LINE__, iml_rc1 );
     return FALSE;                          /* count not start resource */
   }

   InitializeCriticalSection( &dsg_radius_control.dsc_critsect );

   /* initialize common memory area                                    */
   m_cma1_init();

   /* start SWAP-STOR                                                  */
   m_swap_stor_open();

   m_start_ip();                            /* start TCP/IP            */
   dsd_nblock_acc::mc_startup();
   dss_acccb.am_acceptcallback = &m_acceptcallback; // accept callback routine
   dss_acccb.am_errorcallback = &m_errorcallback;   // error callback routine
   iml_rc1 = dsd_tcpcomp::m_startup( NULL );
   if (iml_rc1) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_startprog() dsd_tcpcomp::m_startup() Return Code %d",
                     __LINE__, iml_rc1 );
   }
   m_gw_udp_start();                        /* start UDP and SIP       */
   /* init AVL Tree functions session                                  */
   bol1 = m_htree1_avl_init( NULL, &dss_htree1_avl_cntl_conn,
                             &m_cmp_session_id );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_htree1_avl_init() Session-Id failed",
                     __LINE__ );
     return FALSE;                          /* could not start resource */
   }
   m_admin_start();                         /* start ADMIN             */
   /* init AVL Tree aux-pipe-listen                                    */
   bol1 = m_htree1_avl_init( NULL, &dss_htree1_avl_cntl_aux_pipe_listen,
                             &m_cmp_aux_pipe_listen );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_htree1_avl_init() aux-pipe-listen failed",
                     __LINE__ );
     return FALSE;                          /* could not start resource */
   }
   /* init AVL Tree SDH-reload                                         */
   bol1 = m_htree1_avl_init( NULL, &dss_htree1_avl_cntl_aux_sdh_reload,
                             &m_cmp_aux_sdh_reload );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_htree1_avl_init() SDH-reload failed",
                     __LINE__ );
     return FALSE;                          /* could not start resource */
   }
   /* give message of SSL Library                                      */
   inl1 = m_hssl_getversioninfo( &inl2, NULL, NULL );
   if (inl1 != HSSL_OP_OK) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM040W Error m_hssl_getversioninfo failed rc=%d.", inl1 );
   } else {
     m_hlnew_printf( HLOG_INFO1, "HWSPM041I m_hssl_getversioninfo SSL-Version: %d, Revision=%d, Release=%d.%d.",
                     (inl2 >> 24) & 0XFF, (inl2 >> 16) & 0XFF,
                     (inl2 >> 8) & 0XFF, inl2 & 0XFF );
   }
   inl2 = sizeof(chrl_work_1);
   inl1 = m_hssl_getversioninfo( NULL, chrl_work_1, &inl2 );
   if (inl1 != HSSL_OP_OK) {
     m_hlnew_printf( HLOG_WARN1, "HWSPM042W Error m_hssl_getversioninfo failed rc=%d.", inl1 );
   } else {
     m_hlnew_printf( HLOG_INFO1, "HWSPM043I m_hssl_getversioninfo %s.", chrl_work_1 );
   }
   m_hco_init( adss_loconf_1_fill->inc_max_poss_workthr, adss_loconf_1_fill->inc_max_act_workthr );
#ifdef D_FILL_LOG                           /* 24.04.08 KB             */
   m_test_fill_log();
#endif
#ifdef WSP_TRACE_FILE_01
   {
     int      imh1;
     struct dsd_wspadm1_q_wsp_trace_1 *adsh_wspadm1_qwt1;
     char     chrh_work1[ 512 ];
#ifdef B111018
     adsg_loconf_1_inuse->boc_allow_wsp_trace = TRUE;  /* <allow-wsp-trace> */
#endif
     adsh_wspadm1_qwt1 = (struct dsd_wspadm1_q_wsp_trace_1 *) chrh_work1;
#ifndef WSP_TRACE_CONSOLE
     memset( adsh_wspadm1_qwt1, 0, sizeof(struct dsd_wspadm1_q_wsp_trace_1) );
#ifndef WSP_TRACE_FILE_PID
     imh1 = sprintf( (char *) (adsh_wspadm1_qwt1 + 1), "%s", WSP_TRACE_FILE_01 );
#else
     imh1 = sprintf( (char *) (adsh_wspadm1_qwt1 + 1), WSP_TRACE_FILE_PID, dsg_this_server.imc_pid );
#endif
     adsh_wspadm1_qwt1->iec_wawt = ied_wawt_target;  /* define new target */
#ifndef WSP_TRACE_FILE_BIN
     adsh_wspadm1_qwt1->iec_wtt = ied_wtt_file_ascii;  /* trace records to file ASCII */
#else
     adsh_wspadm1_qwt1->iec_wtt = ied_wtt_file_bin;  /* trace records to file binary */
#endif
     m_ctrl_wspadm1_wsp_trace( adsh_wspadm1_qwt1, imh1 );
#endif
     memset( adsh_wspadm1_qwt1, 0, sizeof(struct dsd_wspadm1_q_wsp_trace_1) );
     adsh_wspadm1_qwt1->iec_wawt = ied_wawt_trace_new_ineta_all;  /* trace all INETAs */
#ifndef WSP_TRACE_SPECIAL_121001
     adsh_wspadm1_qwt1->imc_trace_level = -1;  /* trace level          */
#else
     adsh_wspadm1_qwt1->imc_trace_level = HL_WT_SESS_SDH_EXT | HL_WT_SESS_SDH_INT | HL_WT_SESS_AUX | HL_WT_SESS_DATA1;
#endif
     m_ctrl_wspadm1_wsp_trace( adsh_wspadm1_qwt1, 0 );
#ifndef WSP_TRACE_SPECIAL_121001
     memset( adsh_wspadm1_qwt1, 0, sizeof(struct dsd_wspadm1_q_wsp_trace_1) );
     adsh_wspadm1_qwt1->iec_wawt = ied_wawt_trace_new_core;  /* new parameters trace WSP core */
     adsh_wspadm1_qwt1->imc_trace_level = -1;  /* trace level          */
     m_ctrl_wspadm1_wsp_trace( adsh_wspadm1_qwt1, 0 );
#endif
   }
#endif
//#ifdef D_HPPPT1_1 13.07.14 KB
#ifdef D_INCL_HOB_TUN
#ifdef B100802
   inl1 = (int) m_htun_start();
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_htun_start() returned %d.",
                   __LINE__, inl1 );
#endif
// to-do 13.05.10 KB - init before start cluster
   /* init AVL Tree functions INETA                                    */
   bol1 = m_htree1_avl_init( NULL, &dss_htree1_avl_cntl_ineta_ipv4,
                             &m_cmp_ineta_n_ipv4 );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_htree1_avl_init() INETA normal IPV4 failed",
                     __LINE__ );
     return FALSE;                          /* count not start resource */
   }
   bol1 = m_htree1_avl_init( NULL, &dss_htree1_avl_cntl_ineta_ipv6,
                             &m_cmp_ineta_n_ipv6 );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_htree1_avl_init() INETA normal IPV6 failed",
                     __LINE__ );
     return FALSE;                          /* count not start resource */
   }
   bol1 = m_htree1_avl_init( NULL, &dss_htree1_avl_cntl_user_i_ipv4,
                             &m_cmp_ineta_user_ipv4 );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_htree1_avl_init() INETA user IPV4 failed",
                     __LINE__ );
     return FALSE;                          /* count not start resource */
   }
   bol1 = m_htree1_avl_init( NULL, &dss_htree1_avl_cntl_user_i_ipv6,
                             &m_cmp_ineta_user_ipv6 );
   if (bol1 == FALSE) {                     /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPM0xxW l%05d m_htree1_avl_init() INETA user IPV6 failed",
                     __LINE__ );
     return FALSE;                          /* count not start resource */
   }
#ifdef B100802
   if (adss_loconf_1_fill->adsc_raw_packet_if_conf == NULL) return TRUE;
   uml_ai_buf_len = 0;                      /* length of buffer for adapter info */
   adsl_adap_info_w1 = NULL;                /* points to first adapter info */
   dwl_ret = GetAdaptersInfo( adsl_adap_info_w1, &uml_ai_buf_len );
   if (dwl_ret != ERROR_BUFFER_OVERFLOW) {
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W GetAdaptersInfo() returned %d/0X%08X.",
                     __LINE__, dwl_ret, dwl_ret );
   }
   adsl_adap_info_w1 = (PIP_ADAPTER_INFO) malloc( uml_ai_buf_len );
   dwl_ret = GetAdaptersInfo( adsl_adap_info_w1, &uml_ai_buf_len );
   if (dwl_ret != ERROR_SUCCESS) {
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W GetAdaptersInfo() returned %d/0X%08X.",
                     __LINE__, dwl_ret, dwl_ret );
   }
   adsl_adap_info_w2 = adsl_adap_info_w1;
   while (adsl_adap_info_w2) {
     adsl_ineta_cur = &(adsl_adap_info_w2->IpAddressList);
     /* check all addresses                                            */
     while (adsl_ineta_cur) {
#ifndef TRACEHL1_XXX
       m_hl1_printf( "IBIPGW08-l%05d-T m_getindex_if() found INETA \"%s\" Index=%d 0X%08X.",
                     __LINE__,
                     adsl_ineta_cur->IpAddress.String,
                     adsl_adap_info_w1->Index,
                     inet_addr( adsl_ineta_cur->IpAddress.String ) );
#endif
       if (inet_addr( adsl_ineta_cur->IpAddress.String)
             == *((DWORD *) &adss_loconf_1_fill->adsc_raw_packet_if_conf->umc_taif_ineta)) {  /* <TUN-adapter-use-interface-ineta> */
         dss_ser_thr_ctrl.umc_index_if = adsl_adap_info_w2->Index;  /* holds index of compatible IF */
         break;
       }
       adsl_ineta_cur = adsl_ineta_cur->Next;
     }
     if (adsl_ineta_cur) break;
     /* move to next interface                                         */
     adsl_adap_info_w2 = adsl_adap_info_w2->Next;
   }
   free( adsl_adap_info_w1 );
   if (adsl_adap_info_w2 == NULL) {         /* adapter not found       */
// 31.07.10 KB error message
   }
#endif
#endif
#ifdef DEBUG_HOB_TUN_1407
// m_debug_hob_tun_1407_start();
   return TRUE;                             /* all started             */
#endif
   return TRUE;                             /* all started             */
} /* end m_startprog()                                                 */

#ifdef D_INCL_HOB_TUN
static void m_gw_start_htun( struct dsd_raw_packet_if_conf *adsp_rpi_conf ) {
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol_if_arp;                   /* interface for ARP found */
   BOOL       bol_if_route;                 /* interface for routes found */
   DWORD      dwl_ret;                      /* return code             */
   DWORD      dwl_ineta;                    /* temporary INETA         */
   unsigned long int uml_ai_buf_len;        /* length of buffer for adapter info */
   DWORD      dwl_index_if;                 /* holds index of compatible IF */
   PIP_ADAPTER_INFO adsl_adap_info_w1;      /* points to first adapter info */
   PIP_ADAPTER_INFO adsl_adap_info_w2;      /* points to first adapter info */
   IP_ADDR_STRING *adsl_ineta_cur;

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "l%05d IBIPGW08.cpp m_gw_start_htun( 0X%p ) called",
                   __LINE__, adsp_rpi_conf );
#endif
   if (adsp_rpi_conf == NULL) return;
   bol_rc = m_htun_start( adsp_rpi_conf, &dss_tun_ctrl );
//#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T m_htun_start() returned %d.",
                   __LINE__, bol_rc );
//#endif
   if (bol_rc == FALSE) {
     m_hlnew_printf( HLOG_WARN1, "IBIPGW08-l%05d-W m_gw_start_htun() returned %d.",
                     __LINE__, bol_rc );
     return;
   }
   Sleep( 5000 );                           /* wait till Windows has created the TUN adapter */
   bol_if_arp = FALSE;                      /* interface for ARP found */
   bol_if_route = FALSE;                    /* interface for routes found */
   uml_ai_buf_len = 0;                      /* length of buffer for adapter info */
   adsl_adap_info_w1 = NULL;                /* points to first adapter info */
   dwl_ret = GetAdaptersInfo( adsl_adap_info_w1, &uml_ai_buf_len );
   if (dwl_ret != ERROR_BUFFER_OVERFLOW) {
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W GetAdaptersInfo() returned %d/0X%08X.",
                     __LINE__, dwl_ret, dwl_ret );
   }
   adsl_adap_info_w1 = (PIP_ADAPTER_INFO) malloc( uml_ai_buf_len );
   dwl_ret = GetAdaptersInfo( adsl_adap_info_w1, &uml_ai_buf_len );
   if (dwl_ret != ERROR_SUCCESS) {
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W GetAdaptersInfo() returned %d/0X%08X.",
                     __LINE__, dwl_ret, dwl_ret );
   }
   adsl_adap_info_w2 = adsl_adap_info_w1;
   while (adsl_adap_info_w2) {
     adsl_ineta_cur = &(adsl_adap_info_w2->IpAddressList);
     /* check all addresses                                            */
     while (adsl_ineta_cur) {
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_getindex_if() found INETA \"%s\" Index=%d 0X%08X.",
                       __LINE__,
                       adsl_ineta_cur->IpAddress.String,
                       adsl_adap_info_w2->Index,
                       inet_addr( adsl_ineta_cur->IpAddress.String ) );
#endif
       dwl_ineta = inet_addr( adsl_ineta_cur->IpAddress.String);  /* temporary INETA */
#ifdef B130108
       if (dwl_ineta == *((DWORD *) &adss_loconf_1_fill->adsc_raw_packet_if_conf->umc_taif_ineta)) {  /* <TUN-adapter-use-interface-ineta> */
         dss_ser_thr_ctrl.umc_index_if_arp = adsl_adap_info_w2->Index;  /* holds index of compatible IF for ARP */
         bol_if_arp = TRUE;                 /* interface for ARP found */
         if (bol_if_route) break;           /* interface for routes found */
       }
       if (dwl_ineta == *((DWORD *) &adss_loconf_1_fill->adsc_raw_packet_if_conf->umc_ta_ineta_local)) {  /* <TUN-adapter-ineta> */
         dss_ser_thr_ctrl.umc_index_if_route = adsl_adap_info_w2->Index;  /* holds index of compatible IF for routes */
         bol_if_route = TRUE;               /* interface for routes found */
         if (bol_if_arp) break;             /* interface for ARP found */
       }
#else
       if (dwl_ineta == *((DWORD *) &adss_loconf_1_fill->adsc_raw_packet_if_conf->umc_taif_ineta_ipv4)) {  /* <TUN-adapter-use-interface-ineta> */
         dss_ser_thr_ctrl.umc_index_if_arp = adsl_adap_info_w2->Index;  /* holds index of compatible IF for ARP */
         bol_if_arp = TRUE;                 /* interface for ARP found */
         if (bol_if_route) break;           /* interface for routes found */
       }
       if (dwl_ineta == *((DWORD *) adss_loconf_1_fill->adsc_raw_packet_if_conf->achc_ar_ta_ineta_ipv4)) {  /* <TUN-adapter-ineta> */
         dss_ser_thr_ctrl.umc_index_if_route = adsl_adap_info_w2->Index;  /* holds index of compatible IF for routes */
         bol_if_route = TRUE;               /* interface for routes found */
         if (bol_if_arp) break;             /* interface for ARP found */
       }
#endif
       adsl_ineta_cur = adsl_ineta_cur->Next;
     }
     if (adsl_ineta_cur) break;
     /* move to next interface                                         */
     adsl_adap_info_w2 = adsl_adap_info_w2->Next;
   }
   free( adsl_adap_info_w1 );
#ifdef B100806
   if (adsl_adap_info_w2 == NULL) {         /* adapter not found       */
// 31.07.10 KB error message
   }
#endif
   if (bol_if_arp == FALSE) {               /* interface for ARP found */
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W m_gw_start_htun() no interface for ARP found",
                     __LINE__ );
   }
   if (bol_if_route == FALSE) {             /* interface for routes found */
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W m_gw_start_htun() no interface for routes found",
                     __LINE__ );
   }
} /* end m_gw_start_htun()                                             */
#endif

#ifdef D_FILL_LOG                           /* 24.04.08 KB             */
/* fill the log with test data                                         */
static void m_test_fill_log( void ) {
   BOOL       bol_rc;                       /* working variable        */
   int        iml_time;                     /* current time            */
#ifndef NEW_VISUAL_C
   DWORD      dwl1;                         /* working variable        */
#endif
   LONGLONG   ill_file_size;                /* size of this file       */
   char       *achl_buffer;                 /* buffer for read         */
   char       *achl_file_end;               /* end of file content     */
   char       *achl_file_cur;               /* current input in file   */
   char       *achl_inp_cur;                /* current input           */
   unsigned long int uml_returned_read;     /* how much read from disk */
   HANDLE     dsl_hfi1;                     /* handle for file         */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_test_fill_log called", __LINE__ );
#endif
   dsl_hfi1 = CreateFileA( D_FILL_LOG, GENERIC_READ, FILE_SHARE_READ, 0,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
   if (dsl_hfi1 == INVALID_HANDLE_VALUE) {
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W open input file %s returned Error %d",
                     __LINE__, D_FILL_LOG, GetLastError() );
     return;                                /* return with error       */
   }
#ifdef NEW_VISUAL_C
   bol_rc = GetFileSizeEx( dsl_hfi1, (PLARGE_INTEGER) &ill_file_size );
   if (bol_rc == FALSE) {
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W GetFileSizeEx( %s ) returned Error %d",
                     __LINE__, D_FILL_LOG, GetLastError() );
     CloseHandle( dsl_hfi1 );               /* close configuration file */
     return;                                /* return with error       */
   }
#else
   *((DWORD *) &ill_file_size + 0) = GetFileSize( dsl_hfi1, ((DWORD *) &ill_file_size + 1) );
   while (*((DWORD *) &ill_file_size + 0) == INVALID_FILE_SIZE) {
     dwl1 = GetLastError();
     if (dwl1 == NO_ERROR) break;
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W GetFileSize( %s ) returned Error %d",
                     __LINE__, D_FILL_LOG, dwl1 );
     CloseHandle( dsl_hfi1 );               /* close configuration file */
     return;                                /* return with error       */
   }
#endif
   if (ill_file_size > DEF_MAX_LEN_CONF_FILE) {
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W log test file %s too big (size=%lld)",
                     __LINE__, D_FILL_LOG, ill_file_size );
     CloseHandle( dsl_hfi1 );
     return;                                /* return with error       */
   }
   achl_buffer = (char *) malloc( (int) ill_file_size );
   if (achl_buffer == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W error malloc() content log test file %s.",
                     __LINE__, D_FILL_LOG );
     CloseHandle( dsl_hfi1 );               /* close configuration file */
     return;                                /* return with error       */
   }
   bol_rc = ReadFile( dsl_hfi1, achl_buffer, (int) ill_file_size, &uml_returned_read, 0 );
   if (bol_rc == FALSE) {
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W ReadFile() file %s returned Error %d.",
                     __LINE__, D_FILL_LOG, GetLastError() );
     free( achl_buffer );                   /* free memory again       */
     CloseHandle( dsl_hfi1 );               /* close configuration file */
     return;                                /* return with error       */
   }
   bol_rc = CloseHandle( dsl_hfi1 );
   if (bol_rc == FALSE) {
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W CloseHandle log test file %s returned Error %d.",
                     __LINE__, D_FILL_LOG, GetLastError() );
   }
   achl_file_end = achl_buffer + ill_file_size;  /* end of file content */
   achl_file_cur = achl_buffer;             /* current input in file   */

   pli_file_20:                             /* read next line from the file */
   /* this routine overreads empty lines                               */
   while (   (achl_file_cur < achl_file_end)
          && ((*achl_file_cur == CHAR_CR) || (*achl_file_cur == CHAR_LF))) {
     achl_file_cur++;
   }
   if (achl_file_cur >= achl_file_end) {
     free( achl_buffer );                   /* free memory again       */
     iml_time = (int) time( NULL );         /* current time            */
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T current time %02X %02X %02X %02X.",
                     __LINE__,
                     *((unsigned char *) &iml_time + 0),
                     *((unsigned char *) &iml_time + 1),
                     *((unsigned char *) &iml_time + 2),
                     *((unsigned char *) &iml_time + 3) );
     return;                                /* all done                */
   }
   achl_inp_cur = achl_file_cur;
   while (   (achl_file_cur < achl_file_end)
          && (*achl_file_cur != CHAR_CR)
          && (*achl_file_cur != CHAR_LF)) {
     achl_file_cur++;
   }
   m_hlnew_printf( HLOG_XYZ1, "%.*s", achl_file_cur - achl_inp_cur, achl_inp_cur );
   goto pli_file_20;                        /* read next line from the file */
} /* end m_test_fill_log()                                             */
#endif

/** open the log                                                       */
extern "C" void m_open_log( void ) {        /* open log now            */
   m_hlnew_printf( HLOG_XYZ1, MSG_CONS_P1 MSG_CPU_TYPE __DATE__ MSG_CONS_P2 );
} /* end m_open_log()                                                  */

/** Routine injected in Start of Work-Threads                          */
static void m_wothr_start_inj( struct dsd_hco_wothr *adsp_hco_wothr, int imp_threadid ) {
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_wothr_start_inj( %p, %d ) called",
                   adsp_hco_wothr, imp_threadid );
#endif
   srand( (unsigned int) (m_get_epoch_ms() >> 7)
            ^ (unsigned int) imp_threadid ^ ((HL_LONGLONG) adsp_hco_wothr >> 3) );
} /* end m_wothr_start_inj()                                           */

/** compare entries in AVL tree of sessions                            */
static int m_cmp_session_id( void *,
                             struct dsd_htree1_avl_entry *adsp_entry_1,
                             struct dsd_htree1_avl_entry *adsp_entry_2 ) {
#define ADSL_CO_SORT_P1 ((struct dsd_co_sort *) ((char *) adsp_entry_1 - offsetof( struct dsd_co_sort, dsc_sort_1 )))
#define ADSL_CO_SORT_P2 ((struct dsd_co_sort *) ((char *) adsp_entry_2 - offsetof( struct dsd_co_sort, dsc_sort_1 )))
   return ADSL_CO_SORT_P1->imc_sno - ADSL_CO_SORT_P2->imc_sno;
#undef ADSL_CO_SORT_P1
#undef ADSL_CO_SORT_P2
} /* end m_cmp_session_id()                                            */

/** call DOM for subroutines                                           */
extern "C" void * m_call_dom( DOMNode *adsp_domnode, ied_hlcldom_def iep_hlcldom_def ) {
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_call_dom() called adsp_domnode=%p iep_hlcldom_def=%d",
                   adsp_domnode, iep_hlcldom_def );
#endif
   switch (iep_hlcldom_def) {               /* which function called   */
     case ied_hlcldom_get_first_child:      /* getFirstChild()         */
       return adsp_domnode->getFirstChild();
     case ied_hlcldom_get_next_sibling:     /* getNextSibling()        */
       if (adsp_domnode == dsg_cdaux_control.adsc_node_conf) {
         m_hlnew_printf( HLOG_WARN1, "HWSPD001W m_call_dom() call getNextSibling( conf ) forbidden" );
         return NULL;
       }
       return adsp_domnode->getNextSibling();
     case ied_hlcldom_get_node_type:        /* getNodeType()           */
       return (void *) adsp_domnode->getNodeType();
     case ied_hlcldom_get_node_value:       /* getNodeValue()          */
       return (void *) adsp_domnode->getNodeValue();
     case ied_hlcldom_get_node_name:        /* getNodeName()           */
       return (void *) adsp_domnode->getNodeName();
     case ied_hlcldom_get_file_line:        /* get line in file        */
       return (void *) ((int) GET_LINE( adsp_domnode ));
     case ied_hlcldom_get_file_column:      /* get column in file      */
       return (void *) ((int) GET_COLUMN( adsp_domnode ));
   }
   return NULL;
} /* end m_call_dom()                                                  */

static void m_loconf_reset( struct dsd_loconf_1 *adsp_loconf_1 ) {
   int        iml_rc;                       /* return code             */
#ifndef B080407
   struct dsd_gate_1 *adsl_gate_1_w1;       /* gateway listening       */
   struct dsd_gate_listen_1 *adsl_gate_listen_1_w1;  /* listen part of gateway */
#endif
#ifdef B080407
   struct dsd_gate_1 *adsl_gate_1;              /* gateway listening       */
   int        iml_rc_sock;                  /* return code socket      */
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_loconf_reset called" );
#endif
#ifdef B080407
   adsl_gate_1 = adsp_loconf_1->adsc_gate_anchor;  /* get chain gates  */
   while (adsl_gate_1) {                    /* loop over all gates     */
     if (adsl_gate_1->boc_gate_close == FALSE) {  /* gate is not closed */
       adsl_gate_1->boc_gate_close = TRUE;  /* gate is closed now      */
       iml_rc_sock = IP_closesocket( adsl_gate_1->inc_listen_socket );
       if (iml_rc_sock) {
         if (cl_tcp_r::hws2mod != NULL) {   /* functions loaded        */
           iml_rc_sock = cl_tcp_r::afunc_wsaglerr();  /* get error code */
         }
         m_hlnew_printf( HLOG_XYZ1, "HWSPMnnnW gateway %S closesocket Error %d",
                     (WCHAR *) (adsl_gate_1 + 1), iml_rc_sock );
       }
     }
     adsl_gate_1 = adsl_gate_1->adsc_next;  /* get next in chain       */
   }
#endif
#ifndef B080407
   adsl_gate_1_w1 = adsp_loconf_1->adsc_gate_anchor;  /* get chain gates */
   while (adsl_gate_1_w1) {                 /* loop over all gates     */
     if (adsl_gate_1_w1->boc_gate_closed == FALSE) {  /* gate is not closed */
       adsl_gate_listen_1_w1 = adsl_gate_1_w1->adsc_gate_listen_1_ch;
       while (adsl_gate_listen_1_w1) {      /* loop over all active listen */
         if (adsl_gate_listen_1_w1->boc_active) {  /* listen is active */
#ifdef B110925
           adsl_gate_listen_1_w1->adsc_acc_lis->mc_stoplistener( TRUE );
#else
           iml_rc = adsl_gate_listen_1_w1->dsc_acc_listen.mc_stoplistener_fix();
// to-do 25.09.11 KB check return code
#endif
           adsl_gate_listen_1_w1->boc_active = FALSE;  /* listen no more active */
         }
         adsl_gate_listen_1_w1 = adsl_gate_listen_1_w1->adsc_next;  /* get next in chain */
       }
       adsl_gate_1_w1->boc_gate_closed = TRUE;  /* gate is closed now  */
     }
     adsl_gate_1_w1 = adsl_gate_1_w1->adsc_next;  /* get next in chain */
   }
#endif
} /* end m_loconf_reset()                                              */

#ifdef B080322
static void m_radius_send( class dsd_radius_query *adsp_raque, char *achpbuf, int inplen,
                           BOOL bop_timeout ) {
   struct sockaddr dslsockaddr1;            /* client address informat */
   int        imlret;                       /* for sendto              */

#define ADSL_CONN1_G ((class clconn1 *) adsp_raque->vpc_user_fld_conn)
#ifdef TRACEHLB
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08 l%05d m_radius_send() ADSL_CONN1_G=%p",
                   __LINE__, ADSL_CONN1_G );
#endif
   EnterCriticalSection( &dsg_radius_control.dsc_critsect );
   adsp_raque->adsc_raque_chain = adsp_raque->adsc_raent_act->adsc_raque_chain;
   adsp_raque->adsc_raent_act->adsc_raque_chain = adsp_raque;
   LeaveCriticalSection( &dsg_radius_control.dsc_critsect );
#ifdef B060325
   adsp_raque->dsc_timer_are.imcwaitsec
     = adsp_raque->adsc_raent_act->inc_radius_s_timeout;
   m_time_set( &adsp_raque->dsc_timer_are );  /* set timer             */
#endif
   if (bop_timeout) {
     m_aux_timer_new( ADSL_CONN1_G, ied_src_fu_radius, NULL,
                      adsp_raque->adsc_raent_act->inc_radius_s_timeout * 1000 );
   }
   if (adsp_raque->adsc_raent_act->iec_red == ied_red_invalid) return;
   memset( (char *) &dslsockaddr1, 0, sizeof(struct sockaddr) );
   ((struct sockaddr_in *) &dslsockaddr1)->sin_family = AF_INET;
   ((struct sockaddr_in *) &dslsockaddr1)->sin_port
     = IP_htons( adsp_raque->adsc_raent_act->inc_port );
   ((struct sockaddr_in *) &dslsockaddr1)->sin_addr.s_addr
     = adsp_raque->adsc_raent_act->umc_radius_ineta;
   imlret = IP_sendto( adsp_raque->adsc_raent_act->adsc_rathr->imc_socket,
                       achpbuf, inplen,
                       0, &dslsockaddr1, sizeof(struct sockaddr) );
#ifdef TRACEHLB
   {
     int inh1 = 0;
     if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
       inh1 = cl_tcp_r::afunc_wsaglerr();   /* get error code          */
     }
     m_hlnew_printf( HLOG_XYZ1, "m_radius_send() IP_sendto completed imlret=%d Error=%d socket=%d port=%d INETA=%08X/%08X",
                 imlret, inh1,
                 adsp_raque->adsc_raent_act->adsc_rathr->imc_socket,
                 adsp_raque->adsc_raent_act->inc_port,
                 adsp_raque->adsc_raent_act->umc_radius_ineta,
                 ((struct sockaddr_in *) &dslsockaddr1)->sin_addr.s_addr );
   }
#endif
#undef ADSL_CONN1_G
} /* end m_radius_send()                                               */

static void m_radius_remove( class dsd_radius_query *adsp_raque ) {
   class dsd_radius_query *adsl_raque_1;    /* working variable        */
   class dsd_radius_query *adsl_raque_2;    /* working variable        */

#ifdef TRACEHLB
   m_hlnew_printf( HLOG_XYZ1, "m_radius_remove()" );
#endif
   EnterCriticalSection( &dsg_radius_control.dsc_critsect );
   if (adsp_raque->adsc_raent_act) {        /* active radius entry     */
     adsl_raque_1 = (class dsd_radius_query *)
                      ((char *) &adsp_raque->adsc_raent_act->adsc_raque_chain
                                  - offsetof( class dsd_radius_query, adsc_raque_chain ));
     while (true) {
       adsl_raque_2 = adsl_raque_1;         /* save entry              */
       adsl_raque_1 = adsl_raque_1->adsc_raque_chain;
       if (adsl_raque_1 == NULL) {
         m_hlnew_printf( HLOG_XYZ1, "HWSPM110W chain dsd_radius_query corrupted" );
         break;
       }
       if (adsl_raque_1 == adsp_raque) {
         adsl_raque_2->adsc_raque_chain = adsl_raque_1->adsc_raque_chain;
         break;
       }
     }
     adsp_raque->adsc_raent_act = NULL;     /* active radius entry     */
   }
   LeaveCriticalSection( &dsg_radius_control.dsc_critsect );
#ifdef B060325
   m_time_rel( &adsp_raque->dsc_timer_are );  /* remove timer          */
#endif
} /* end m_radius_remove()                                             */

static void m_radius_aux_delete( struct dsd_auxf_1 *adsp_auxf_1 ) {
   ((class dsd_radius_query *)
      ((char *) adsp_auxf_1 - offsetof( dsd_radius_query, dsc_auxf_1 )))
        ->m_delete();                       /* call routine            */
} /* end m_radius_aux_delete()                                         */

/* return the structure of the radius server                           */
static struct dsd_radius_entry * m_radius_get_str_raent( void * vpp_clconn1, int inp_no ) {
#define ADSL_CLCONN1 ((class clconn1 *) vpp_clconn1)
   return (struct dsd_radius_entry *)
            *((void **) ((char *) (ADSL_CLCONN1->adsc_gate1 + 1)
                                    + ((ADSL_CLCONN1->adsc_gate1->inc_len_name
                                         + sizeof(void *) - 1) & (0 - sizeof(void *))))
                          + inp_no );
#undef ADSL_CLCONN1
} /* end m_radius_get_str_raent()                                      */
#endif

#ifdef B100731
#ifdef TRY_HSM_1007
static const unsigned char ucrs_route_next_hop[] = { 10, 50, 60, 5 };
static const unsigned char ucrs_adapter_ineta[] = { 10, 50, 60, 6 };
#ifdef B100715
static const unsigned char ucrs_route_mask[] = { 255, 255, 255, 255 };
#endif
#endif
#endif

#ifdef NEW_HOB_TUN_1103
extern dsd_vnic dsg_vnic;
#endif

#ifdef B130813
/* thread for serializiation                                           */
static htfunc1_t m_serial_thread( void * ) {
   int        iml1;                         /* working-variable        */
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   DWORD      dwl_ret_arp;                  /* return code ARP         */
   DWORD      dwl_ret_route;                /* return code route       */
   char       *achl_w1;                     /* working variable        */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace control record */
   struct dsd_ser_thr_task *adsl_sth_w1;    /* working variable        */
   struct dsd_ser_thr_task dsl_sth_work;    /* work as task for serial thread */
   MIB_IPFORWARDROW dsl_ipforw_01;          /* to set routes           */
#ifdef B100731
#ifdef TRY_HSM_1007
   unsigned long int uml_ai_buf_len;        /* length of buffer for adapter info */
   DWORD      dwl_index_if;                 /* holds index of compatible IF */
   PIP_ADAPTER_INFO adsl_adap_info_w1;      /* points to first adapter info */
   PIP_ADAPTER_INFO adsl_adap_info_w2;      /* points to first adapter info */
   IP_ADDR_STRING *adsl_ineta_cur;
#endif
#endif

#ifdef B100731
#ifdef TRY_HSM_1007
   dwl_index_if = 0;                        /* holds index of compatible IF */
   uml_ai_buf_len = 0;                      /* length of buffer for adapter info */
   adsl_adap_info_w1 = NULL;                /* points to first adapter info */
   dwl_ret = GetAdaptersInfo( adsl_adap_info_w1, &uml_ai_buf_len );
   if (dwl_ret != ERROR_BUFFER_OVERFLOW) {
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W GetAdaptersInfo() returned %d/0X%08X.",
                     __LINE__, dwl_ret, dwl_ret );
   }
   adsl_adap_info_w1 = (PIP_ADAPTER_INFO) malloc( uml_ai_buf_len );
   dwl_ret = GetAdaptersInfo( adsl_adap_info_w1, &uml_ai_buf_len );
   if (dwl_ret != ERROR_SUCCESS) {
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W GetAdaptersInfo() returned %d/0X%08X.",
                     __LINE__, dwl_ret, dwl_ret );
   }
   adsl_adap_info_w2 = adsl_adap_info_w1;
   while (adsl_adap_info_w2) {
     adsl_ineta_cur = &(adsl_adap_info_w2->IpAddressList);
     /* check all addresses                                            */
     while (adsl_ineta_cur) {
#ifndef TRACEHL1_XXX
       m_hl1_printf( "IBIPGW08-l%05d-T m_getindex_if() found INETA \"%s\" Index=%d 0X%08X.",
                     __LINE__,
                     adsl_ineta_cur->IpAddress.String,
                     adsl_adap_info_w1->Index,
                     inet_addr( adsl_ineta_cur->IpAddress.String ) );
#endif
       if (inet_addr( adsl_ineta_cur->IpAddress.String) == *((DWORD *) ucrs_adapter_ineta)) {
         dwl_index_if = adsl_adap_info_w2->Index;
         break;
       }
       adsl_ineta_cur = adsl_ineta_cur->Next;
     }
     if (adsl_ineta_cur) break;
     /* move to next interface                                         */
     adsl_adap_info_w2 = adsl_adap_info_w2->Next;
   }
   free( adsl_adap_info_w1 );
#endif
#endif
   p_serial_00:                             /* serialisation start     */
   if (dss_ser_thr_ctrl.adsc_sth_work) {    /* work as task for serial thread */
     goto p_serial_20;                      /* found work to do        */
   }
   iml_rc = dss_ser_thr_ctrl.dsc_event_thr.m_wait( &iml_error );
   if (iml_rc == 0) goto p_serial_00;       /* serialisation start     */
// to-do 02.07.10 KB error message
   m_hlnew_printf( HLOG_WARN1, "xxxxxxxx-%05d-W m_serial_thread thread m_wait Return Code %d Error %d.",
                   __LINE__, iml_rc, iml_error );
   Sleep( 2000 );                           /* wait some time          */
   goto p_serial_00;                        /* serialisation start     */

   p_serial_20:                             /* found work to do        */
   dsg_global_lock.m_enter();               /* enter critical section  */
   adsl_sth_w1 = dss_ser_thr_ctrl.adsc_sth_work;  /* get work as task for serial thread */
   memcpy( &dsl_sth_work, adsl_sth_w1, sizeof(struct dsd_ser_thr_task) );
   dss_ser_thr_ctrl.adsc_sth_work = adsl_sth_w1->adsc_next;  /* remove from chain */
   adsl_sth_w1->adsc_next = dss_ser_thr_ctrl.adsc_sth_free;  /* get old chain free */
   dss_ser_thr_ctrl.adsc_sth_free = adsl_sth_w1;  /* set new chain free */
   dsg_global_lock.m_leave();               /* leave critical section  */
   switch (dsl_sth_work.iec_sth) {          /* serial thread task type */
     case ied_sth_route_ipv4_add:           /* add a route IPV4        */
#ifdef B100731
       dwl_ret = CreateProxyArpEntry( *((DWORD *) dsl_sth_work.chrc_ineta),
                                      0XFFFFFFFF,  /* 255.255.255.255  */
                                      dwl_index_if );
#endif
       dwl_ret_arp = CreateProxyArpEntry( *((DWORD *) dsl_sth_work.chrc_ineta),
                                          0XFFFFFFFF,  /* 255.255.255.255  */
                                          *((DWORD *) &dsl_sth_work.umc_index_if_arp) );
//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T CreateProxyArpEntry() returned %d/0X%08X.",
                       __LINE__, dwl_ret_arp, dwl_ret_arp );
//#endif
#ifdef NEW_HOB_TUN_1103
       dsg_vnic.m_add_arp_entry((char*)&dsl_sth_work.chrc_ineta, "255.255.255.255");
#endif
//#endif
       memset( &dsl_ipforw_01, 0, sizeof(MIB_IPFORWARDROW) );
       dsl_ipforw_01.dwForwardProto = MIB_IPPROTO_NETMGMT;
       dsl_ipforw_01.dwForwardIfIndex = *((DWORD *) &dsl_sth_work.umc_index_if_route);
#ifndef B120705
       dsl_ipforw_01.dwForwardType = MIB_IPROUTE_TYPE_DIRECT;
#endif
       dsl_ipforw_01.dwForwardMetric1 = 100;
       dsl_ipforw_01.dwForwardMetric2 = -1;
       dsl_ipforw_01.dwForwardMetric3 = -1;
       dsl_ipforw_01.dwForwardMetric4 = -1;
       dsl_ipforw_01.dwForwardMetric5 = -1;
       dsl_ipforw_01.dwForwardDest = *((DWORD *) dsl_sth_work.chrc_ineta);
//     dsl_ipforw_01.dwForwardMask = *((DWORD *) ucrs_route_mask);
       dsl_ipforw_01.dwForwardMask = 0XFFFFFFFF;  /* 255.255.255.255   */
#ifdef B100731
       dsl_ipforw_01.dwForwardNextHop = *((DWORD *) ucrs_route_next_hop);
#endif
#ifdef B120203
#ifdef B100802
       dsl_ipforw_01.dwForwardNextHop = *((DWORD *) &dsl_sth_work.umc_taif_ineta);  /* <TUN-adapter-use-interface-ineta> = next hop */
#endif
       dsl_ipforw_01.dwForwardNextHop = *((DWORD *) &dsl_sth_work.umc_taif_ineta);  /* <TUN-adapter-use-interface-ineta> = next hop */
#endif
       dsl_ipforw_01.dwForwardNextHop = *((DWORD *) &dsl_sth_work.umc_taif_ineta);  /* <TUN-adapter-use-interface-ineta> = next hop */
#ifdef TRACEHL1
       m_console_out( (char *) &dsl_ipforw_01, sizeof(MIB_IPFORWARDROW) );
#endif
       dwl_ret_route = CreateIpForwardEntry( &dsl_ipforw_01 );
//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T CreateIpForwardEntry() returned %d/0X%08X.",
                       __LINE__, dwl_ret_route, dwl_ret_route );
//#endif
       if (dsl_sth_work.boc_trace) {        /* generate record for WSP trace */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNRAD1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_sno = dsl_sth_work.imc_wtrt_sno;  /* WSP session number for trace */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                         "l%05d ied_sth_route_ipv4_add INETA %d.%d.%d.%d CreateProxyArpEntry() returned %d CreateIpForwardEntry() returned %d.",
                         __LINE__,
                         *((unsigned char *) &dsl_sth_work.chrc_ineta[ 0 ]),
                         *((unsigned char *) &dsl_sth_work.chrc_ineta[ 1 ]),
                         *((unsigned char *) &dsl_sth_work.chrc_ineta[ 2 ]),
                         *((unsigned char *) &dsl_sth_work.chrc_ineta[ 3 ]),
                         dwl_ret_arp, dwl_ret_route );
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
         ADSL_WTR_G1->achc_content              /* content of text / data  */
           = (char *) (ADSL_WTR_G1 + 1);
         ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
         achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
         memcpy( ADSL_WTR_G2 + 1, &dsl_ipforw_01, sizeof(MIB_IPFORWARDROW) );
         memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
         ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
         ADSL_WTR_G2->imc_length = sizeof(MIB_IPFORWARDROW);  /* length of text / data */
         ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;  /* append to chain     */
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
       if (dwl_ret_route == NO_ERROR) break;
// to-do 05.07.10 KB error message
       break;
     case ied_sth_route_ipv4_del:           /* delete a route IPV4     */
       dwl_ret_arp = DeleteProxyArpEntry( *((DWORD *) dsl_sth_work.chrc_ineta),
                                          0XFFFFFFFF,  /* 255.255.255.255  */
                                          *((DWORD *) &dsl_sth_work.umc_index_if_arp) );
#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T DeleteProxyArpEntry() returned %d/0X%08X.",
                       __LINE__, dwl_ret_arp, dwl_ret_arp );
#endif
#ifdef NEW_HOB_TUN_1103
       dsg_vnic.m_remove_arp_entry((char*)&dsl_sth_work.chrc_ineta, "255.255.255.255");
#endif
       memset( &dsl_ipforw_01, 0, sizeof(MIB_IPFORWARDROW) );
       dsl_ipforw_01.dwForwardProto = MIB_IPPROTO_NETMGMT;
#ifdef B120705
       dsl_ipforw_01.dwForwardType = MIB_IPROUTE_TYPE_INDIRECT;
#endif
#ifndef B120705
       dsl_ipforw_01.dwForwardType = MIB_IPROUTE_TYPE_DIRECT;
#endif
       dsl_ipforw_01.dwForwardAge = INFINITE;
       dsl_ipforw_01.dwForwardIfIndex = *((DWORD *) &dsl_sth_work.umc_index_if_route);
       dsl_ipforw_01.dwForwardMetric1 = 100;
       dsl_ipforw_01.dwForwardMetric2 = -1;
       dsl_ipforw_01.dwForwardMetric3 = -1;
       dsl_ipforw_01.dwForwardMetric4 = -1;
       dsl_ipforw_01.dwForwardMetric5 = -1;
       dsl_ipforw_01.dwForwardDest = *((DWORD *) dsl_sth_work.chrc_ineta);
//     dsl_ipforw_01.dwForwardMask = *((DWORD *) ucrs_route_mask);
       dsl_ipforw_01.dwForwardMask = 0XFFFFFFFF;  /* 255.255.255.255   */
#ifdef B120619
#ifdef B100731
       dsl_ipforw_01.dwForwardNextHop = *((DWORD *) ucrs_route_next_hop);
#endif
#ifdef B100802
       dsl_ipforw_01.dwForwardNextHop = *((DWORD *) &dsl_sth_work.umc_taif_ineta);  /* <TUN-adapter-use-interface-ineta> = next hop */
#endif
       dsl_ipforw_01.dwForwardNextHop = *((DWORD *) &dsl_sth_work.umc_taif_ineta);  /* <TUN-adapter-use-interface-ineta> = next hop */
#endif
       dsl_ipforw_01.dwForwardNextHop = *((DWORD *) &dsl_sth_work.umc_taif_ineta);  /* <TUN-adapter-use-interface-ineta> = next hop */
#ifdef TRACEHL1
       m_console_out( (char *) &dsl_ipforw_01, sizeof(MIB_IPFORWARDROW) );
#endif
       dwl_ret_route = DeleteIpForwardEntry( &dsl_ipforw_01 );
//#ifdef TRACEHL1
       m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T DeleteIpForwardEntry() returned %d/0X%08X.",
                       __LINE__, dwl_ret_route, dwl_ret_route );
//#endif
       if (dsl_sth_work.boc_trace) {        /* generate record for WSP trace */
         adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
         memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
         adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data   */
         adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
         memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNRDE1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
         adsl_wt1_w1->imc_wtrt_sno = dsl_sth_work.imc_wtrt_sno;  /* WSP session number for trace */
         adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id           */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
         iml1 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                         "l%05d ied_sth_route_ipv4_del INETA %d.%d.%d.%d DeleteProxyArpEntry() returned %d DeleteIpForwardEntry() returned %d.",
                         __LINE__,
                         *((unsigned char *) &dsl_sth_work.chrc_ineta[ 0 ]),
                         *((unsigned char *) &dsl_sth_work.chrc_ineta[ 1 ]),
                         *((unsigned char *) &dsl_sth_work.chrc_ineta[ 2 ]),
                         *((unsigned char *) &dsl_sth_work.chrc_ineta[ 3 ]),
                         dwl_ret_arp, dwl_ret_route );
         ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
         ADSL_WTR_G1->achc_content              /* content of text / data  */
           = (char *) (ADSL_WTR_G1 + 1);
         ADSL_WTR_G1->imc_length = iml1;        /* length of text / data   */
         adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
         achl_w1 = (char *) (((long long int) ((char *) (ADSL_WTR_G1 + 1) + iml1 + sizeof(void *) - 1)) & (0 - sizeof(void *)));
#define ADSL_WTR_G2 ((struct dsd_wsp_trace_record *) achl_w1)
         memcpy( ADSL_WTR_G2 + 1, &dsl_ipforw_01, sizeof(MIB_IPFORWARDROW) );
         memset( ADSL_WTR_G2, 0, sizeof(struct dsd_wsp_trace_record) );
         ADSL_WTR_G2->iec_wtrt = ied_wtrt_data;  /* binary data passed */
         ADSL_WTR_G2->achc_content = (char *) (ADSL_WTR_G2 + 1);  /* content of text / data */
         ADSL_WTR_G2->imc_length = sizeof(MIB_IPFORWARDROW);  /* length of text / data */
         ADSL_WTR_G1->adsc_next = ADSL_WTR_G2;  /* append to chain     */
#undef ADSL_WTR_G1
#undef ADSL_WTR_G2
         m_wsp_trace_out( adsl_wt1_w1 );    /* output of WSP trace record */
       }
       if (dwl_ret_route == NO_ERROR) break;
// to-do 08.08.10 KB error message
       break;
   }
   if (dsl_sth_work.aboc_posted) {          /* with mark posted        */
     *dsl_sth_work.aboc_posted = TRUE;      /* mark posted             */
   }
   if (dsl_sth_work.adsc_event_posted) {    /* event for posted        */
     iml_rc = dsl_sth_work.adsc_event_posted->m_post( &iml_error );  /* event for posted */
// to-do 02.07.10 KB error message
     if (iml_rc < 0) {                     /* error occured           */
       m_hl1_printf( "xxxxxxxr-%05d-W m_hco_shutdown thread m_post Return Code %d Error %d",
                     __LINE__, iml_rc, iml_error );
     }
   }
   goto p_serial_00;                        /* serialisation start     */
} /* end m_serial_thread()                                             */
#endif

static void m_end_proc( void ) {
#ifdef B080324
   if (ds_blade_control.boc_blade_active) {  /* blade funct active     */
     DeleteCriticalSection( &ds_blade_control.dc_critsect );  /* critical section */
   }
#endif
   if (boisservice) {
     dclasrvstat.dwCurrentState = SERVICE_STOPPED;  /* service closed  */
     SetServiceStatus( dclhsrvstat, &dclasrvstat );  /* set state      */
   }
// ExitProcess( 0 );
} /* end m_end_proc()                                                  */

static void m_wait_conn( void *vpp_userfld, int imp_sec ) {  /* wait till activated */
#ifdef OLD01
   DWORD      dwl1;                         /* working variable        */
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "m_wait_conn( vpp_userfld=%p )", vpp_userfld );
#endif
#define ADSL_CONN1_G ((class clconn1 *) vpp_userfld)  /* pointer on connection */
#define ADSL_AUX_CF1 (ADSL_CONN1_G->adsc_aux_cf1_cur)  /* auxiliary control structure */
   m_hco_wothr_wait_sec( ADSL_AUX_CF1->adsc_hco_wothr, imp_sec );
#ifdef B060628
   dwl1 = WaitForSingleObject( (((class clconn1 *) vpp_userfld)->adsc_workth)->hevework,
                               INFINITE );
   if (dwl1 != WAIT_OBJECT_0) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPS00nW GATE=%(ux)s SNO=%08d INETA=%s m_wait_conn() WaitForSingleObject() Returned %d Error %d",
                     m_clconn1_gatename( vpp_userfld ),
                     m_clconn1_sno( vpp_userfld ),
                     m_clconn1_chrc_ineta( vpp_userfld ),
                     dwl1, GetLastError() );
   }
#endif
#undef ADSL_AUX_CF1
#undef ADSL_CONN1_G
} /* end m_wait_conn()                                                 */

static void m_post_conn( void *vpp_userfld ) {  /* post waiting thread */
#ifdef OLD01
   BOOL       bol1;                         /* working variable        */
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_post_conn( vpp_userfld=%p )", vpp_userfld );
#endif
#define ADSL_CONN1_G ((class clconn1 *) vpp_userfld)  /* pointer on connection */
#define ADSL_AUX_CF1 (ADSL_CONN1_G->adsc_aux_cf1_cur)  /* auxiliary control structure */
   m_hco_wothr_post( NULL, ADSL_AUX_CF1->adsc_hco_wothr );
#ifdef CHECK_THR_1
   if ((((class clconn1 *) vpp_userfld)->adsc_workth)->ad_clconn1 == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "--- m_post_conn call m_proc_data( NULL ) - workthr=%p vpp_userfld=%p",
                 (((class clconn1 *) vpp_userfld)->adsc_workth), vpp_userfld );
   }
#endif
#ifdef B060628
   bol1 = SetEvent( (((class clconn1 *) vpp_userfld)->adsc_workth)->hevework );
   if (bol1 == FALSE) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPS00nW GATE=%(ux)s SNO=%08d INETA=%s m_post_conn() SetEvent() Error %d",
                     m_clconn1_gatename( vpp_userfld ),
                     m_clconn1_sno( vpp_userfld ),
                     m_clconn1_chrc_ineta( vpp_userfld ),
                     GetLastError() );
   }
#endif
#undef ADSL_AUX_CF1
#undef ADSL_CONN1_G
} /* end m_post_conn()                                                 */

static void m_act_conn( void *vpp_userfld ) {  /* activate thread      */
   BOOL       bol1;                         /* working variable        */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "m_act_conn( vpp_userfld=%p )", vpp_userfld );
#endif
#define ADSL_CONN1_G ((class clconn1 *) vpp_userfld)  /* pointer on connection */
//#define ADSL_AUX_CF1 (ADSL_CONN1_G->adsc_aux_cf1_cur)  /* auxiliary control structure */
   bol1 = FALSE;
   EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
   if (ADSL_CONN1_G->boc_st_act == FALSE) {  /* util-thread not active */
     ADSL_CONN1_G->boc_st_act = TRUE;       /* util-thread active now  */
     bol1 = TRUE;                           /* activate thread         */
   }
   LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
   if (bol1)
#ifdef B060628
     clworkth::act_thread( ADSL_CONN1_G );
#else
     m_act_thread_2( ADSL_CONN1_G );        /* activate m_proc_data()  */
#endif
//#undef ADSL_AUX_CF1
#undef ADSL_CONN1_G
} /* end m_act_conn()                                                  */

#ifdef TRY_120306_01                        /* flow-control send       */
#ifndef B120313
static inline BOOL m_clconn1_check_act_conn( void * adsp_conn1 ) {
#define ADSL_CONN1_G ((class clconn1 *) adsp_conn1)  /* pointer on connection */
   return ADSL_CONN1_G->boc_st_act;         /* check util-thread active */
#undef ADSL_CONN1_G
} /* end m_clconn1_check_act_conn()                                    */

static inline void m_clconn1_set_act_conn( void * adsp_conn1 ) {
#define ADSL_CONN1_G ((class clconn1 *) adsp_conn1)  /* pointer on connection */
   ADSL_CONN1_G->boc_st_act = TRUE;         /* util-thread active now  */
#undef ADSL_CONN1_G
} /* end m_clconn1_set_act_conn()                                      */

static inline void m_clconn1_do_act_conn( void * adsp_conn1 ) {
#define ADSL_CONN1_G ((class clconn1 *) adsp_conn1)  /* pointer on connection */
   m_act_thread_2( ADSL_CONN1_G );          /* activate m_proc_data()  */
#undef ADSL_CONN1_G
} /* end m_clconn1_do_act_conn()                                       */
#endif
#endif

/* display for connection                                              */
static void m_display_conn( void *vpp_userfld, char *achp_message ) {
#define ADSL_CLCONN1 ((class clconn1 *) vpp_userfld)
   m_hlnew_printf( HLOG_INFO1, "HWSPS081I GATE=%(ux)s SNO=%08d INETA=%s %s",
                   m_clconn1_gatename( vpp_userfld ),
                   m_clconn1_sno( vpp_userfld ),
                   m_clconn1_chrc_ineta( vpp_userfld ),
                   achp_message );
#undef ADSL_CLCONN1
} /* end m_display_conn()                                              */

#ifdef D_INCL_HOB_TUN
#ifdef ERROR_1308
//simulation function which returns a newly allocated buffer amd its length
extern "C" int m_htun_getrecvbuf( void **aap_handle, char **aachp_buffer ) {
#ifdef OLD01
   *aap_handle = new char[16384];
   *aachp_buffer = (char*)*aap_handle;
   return 16384;
#endif
   *aap_handle = m_proc_alloc();
   *aachp_buffer = (char *) *aap_handle + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1);
   return LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1) - sizeof(struct dsd_gather_i_1);
} /* end m_htun_getrecvbuf()                                           */

//simulation function which releases a previously allocated buffer
extern "C" void m_htun_relrecvbuf( void *ap_handle ) {
#ifdef OLD01
   delete ap_handle;
#endif
   m_proc_free( ap_handle );
} /* end m_htun_relrecvbuf()                                           */

extern "C" BOOL m_se_htun_recvbuf( struct dsd_tun_contr1 *adsp_tctl,
                                   struct dsd_buf_vector_ele *adsp_vector,
                                   int imp_ele_vector )
{
   int        iml_index;                    /* index input buffers     */
   BOOL       bol_act;                      /* activate connection     */
   BOOL       bol_ret;                      /* return value            */
   class clconn1 *adsl_conn1;               /* class connection        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_first;  /* first in chain      */
   struct dsd_sdh_control_1 *adsl_sdhc1_last;  /* last in chain        */
#ifdef B120601
   struct dsd_gather_i_1 **aadsl_gai1_w1;   /* for chaining            */
#endif

#ifdef B100702
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tctl
                      - offsetof( class clconn1, dsc_tun_contr1 )));
#endif
#ifndef NEW_HOB_TUN_1103
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tctl - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr1 )))
   adsl_conn1 = (class clconn1 *) ADSL_INETA_RAWS_1_G->ac_conn1;
#undef ADSL_INETA_RAWS_1_G
#endif
#ifdef NEW_HOB_TUN_1103
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tctl
                      - offsetof( class clconn1, dsc_tun_contr1 )));
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_se_htun_recvbuf() adsp_tctl=%p adsl_conn1=%p.",
                   __LINE__, adsp_tctl, adsl_conn1 );
#endif
   if (adsl_conn1->adsc_sdhc1_s2) {         /* all buffer full         */
     m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-W m_se_htun_recvbuf() adsl_conn1=%p adsc_sdhc1_s2 already set",
                     __LINE__, adsl_conn1 );
     return FALSE;
   }
#ifndef B120601
/**
   the blocks sdhc1 are chained together,
   but the gather structures are not yet chained together
*/
#endif
   adsl_sdhc1_last = NULL;                  /* clear last in chain     */
   iml_index = 0;                           /* clear index input buffers */
   do {                                     /* loop over all input buffers */
     adsl_sdhc1_w1 = (struct dsd_sdh_control_1 *) (adsp_vector + iml_index)->ac_handle;
     memset( adsl_sdhc1_w1, 0, sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1) );
#define ADSL_GAI1_W1 ((struct dsd_gather_i_1 *) (adsl_sdhc1_w1 + 1))
     adsl_sdhc1_w1->adsc_gather_i_1_i = ADSL_GAI1_W1;
     ADSL_GAI1_W1->achc_ginp_cur = (adsp_vector + iml_index)->achc_data;
     ADSL_GAI1_W1->achc_ginp_end = (adsp_vector + iml_index)->achc_data + (adsp_vector + iml_index)->imc_len_data;
     if (adsl_sdhc1_last == NULL) {         /* is first in chain       */
       adsl_sdhc1_first = adsl_sdhc1_w1;
     } else {                               /* middle in chain         */
       adsl_sdhc1_last->adsc_next = adsl_sdhc1_w1;
#ifdef B120601
       *aadsl_gai1_w1 = ADSL_GAI1_W1;
#endif
     }
#undef ADSL_GAI1_W1
     adsl_sdhc1_last = adsl_sdhc1_w1;
#ifdef B120601
     aadsl_gai1_w1 = ((struct dsd_gather_i_1 **) (adsl_sdhc1_w1 + 1));
#endif
     iml_index++;                           /* increment index input buffers */
   } while (iml_index < imp_ele_vector);    /* till all buffers read   */
   bol_act = FALSE;                         /* do not activate connection */
#ifndef HL_UNIX
   EnterCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
#else
   adsl_conn1->dsc_critsect.m_enter();      /* critical section        */
#endif
   if (adsl_conn1->adsc_sdhc1_s1 == NULL) {  /* take first buffer      */
     adsl_conn1->adsc_sdhc1_s1 = adsl_sdhc1_first;  /* set first buffer */
     if (adsl_conn1->boc_st_act == FALSE) {  /* util-thread not active */
       adsl_conn1->boc_st_act = TRUE;       /* util-thread active now  */
       bol_act = TRUE;                      /* activate thread         */
     }
     bol_ret = TRUE;                        /* return value            */
#ifndef B120604
   } else if (   (adsp_tctl->iec_tunc == ied_tunc_ppp)
              || (adsp_tctl->iec_tunc == ied_tunc_sstp)) {
     adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_s1;  /* get old chain      */
     while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
     adsl_sdhc1_w1->adsc_next = adsl_sdhc1_first;  /* append new buffers */
#ifdef XYZ1
     if (adsl_conn1->boc_st_act == FALSE) {  /* util-thread not active */
       adsl_conn1->boc_st_act = TRUE;       /* util-thread active now  */
       bol_act = TRUE;                      /* activate thread         */
     }
#endif
     bol_ret = TRUE;                        /* return value            */
#endif
   } else {                                 /* take second buffer      */
// to-do 25.11.08 KB - adsc_sdhc1_s2 already occupied ???
     adsl_conn1->adsc_sdhc1_s2 = adsl_sdhc1_first;  /* set first buffer */
     bol_ret = FALSE;                       /* return value            */
   }
#ifndef HL_UNIX
   LeaveCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
#else
   adsl_conn1->dsc_critsect.m_leave();      /* critical section        */
#endif
   if (bol_act == FALSE) return bol_ret;    /* all done                */
   m_act_thread_2( adsl_conn1 );            /* activate m_proc_data()  */
   return bol_ret;                          /* all done                */
} /* end m_se_htun_recvbuf()                                           */

/* error message when HTCP connect failed                              */
extern "C" void m_htun_htcp_connect_failed( struct dsd_tun_contr1 *adsp_tun_contr1,
   struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_current_index, int imp_total_index, int imp_errno ) {
   int        iml_rc;                       /* return code             */
   char       *achl1;                       /* working variable        */
   class clconn1 *adsl_conn1;               /* class connection        */
   char       chrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_htun_htcp_connect_failed( %p , ... ) called",
                   __LINE__, adsp_tun_contr1 );
#endif
#ifdef B100702
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr1
                      - offsetof( class clconn1, dsc_tun_contr1 )));
#endif
#ifndef NEW_HOB_TUN_1103
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tun_contr1 - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr1 )))
   adsl_conn1 = (class clconn1 *) ADSL_INETA_RAWS_1_G->ac_conn1;
#undef ADSL_INETA_RAWS_1_G
#endif
#ifdef NEW_HOB_TUN_1103
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr1
                      - offsetof( class clconn1, dsc_tun_contr1 )));
#endif
   iml_rc = IP_getnameinfo( adsp_soa, imp_len_soa,
                            chrl_ineta, sizeof(chrl_ineta),
                            0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
#ifdef DEBUG_100923_01
     if (adsl_conn1 == NULL) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnW DEBUG_100923_01 GATE=??? SNO=??? INETA=??? l%05d HTUN connect to %s getnameinfo() returned %d %d.",
                       __LINE__, chrl_ineta, iml_rc, D_TCP_ERROR );
       return;
     }
#endif
     m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d getnameinfo() returned %d %d.",
                     adsl_conn1->adsc_gate1 + 1,
                     adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta,
                     __LINE__, iml_rc, D_TCP_ERROR );
     strcpy( chrl_ineta, "???" );
   }
   achl1 = "";
   if ((imp_current_index + 1) < imp_total_index) {
     achl1 = " - try next INETA from DNS";  /* set additional text     */
   } else if (imp_total_index > 1) {
     achl1 = " - was last INETA from DNS";  /* set additional text     */
   }
#ifdef DEBUG_100923_01
   if (adsl_conn1 == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnW DEBUG_100923_01 GATE=??? SNO=??? INETA=??? l%05d HTUN connect to %s failed %d%s",
                     __LINE__, chrl_ineta, imp_errno, achl1 );
     return;
   }
#endif
   m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnW GATE=%(ux)s SNO=%08d INETA=%s l%05d HTUN connect to %s failed %d%s",
                   adsl_conn1->adsc_gate1 + 1,
                   adsl_conn1->dsc_co_sort.imc_sno,
                   adsl_conn1->chrc_ineta,
                   __LINE__, chrl_ineta, imp_errno, achl1 );
   return;
} /* end m_htun_htcp_connect_failed()                                  */

/* connect has been done - either successfully or the connect failed   */
extern "C" void m_htun_htcp_connect_end( struct dsd_tun_contr1 *adsp_tun_contr1,
                                         int imp_errno ) {
   int        iml_select;                   /* select the events       */
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   struct dsd_netw_post_1 *adsl_netw_post_1;  /* structure to post from network callback */
   class clconn1 *adsl_conn1;               /* class connection        */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_htun_htcp_connect_end( %p , ... ) called",
                   __LINE__, adsp_tun_contr1 );
#endif
#ifdef B100702
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr1
                      - offsetof( class clconn1, dsc_tun_contr1 )));
#endif
#ifndef NEW_HOB_TUN_1103
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tun_contr1 - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr1 )))
   adsl_conn1 = (class clconn1 *) ADSL_INETA_RAWS_1_G->ac_conn1;
#endif
#ifdef NEW_HOB_TUN_1103
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr1
                      - offsetof( class clconn1, dsc_tun_contr1 )));
#define ADSL_INETA_RAWS_1_G adsl_conn1->adsc_ineta_raws_1
#endif
   if (imp_errno == 0) goto p_conn_ok;      /* connect succeeded       */
   iml_select = DEF_NETW_POST_1_HTUN_CONN_ERR;  /* posted for HTUN connect error */
   do {                                     /* pseudo-loop             */
#ifdef OLD_1112
     if (adsl_conn1->adsc_radqu) {          /* radius still active     */
       adsl_conn1->adsc_radqu->imc_connect_error = imp_errno;
       break;
     }
#endif
#ifdef B101214
     adsl_conn1->iec_st_ses = clconn1::ied_ses_error_conn;  /* status server error */
     if (adsl_conn1->adsc_server_conf_1->boc_dynamic == FALSE) break;  /* not dynamicly allocated */
     adsl_conn1->iec_st_ses = clconn1::ied_ses_error_co_dyn;  /* status server error */
#else
     if (adsl_conn1->iec_st_ses != clconn1::ied_ses_wait_conn_s_dynamic) {  /* wait for dynamic connect to server */
       adsl_conn1->iec_st_ses = clconn1::ied_ses_error_conn;  /* status server error */
     } else {
       adsl_conn1->iec_st_ses = clconn1::ied_ses_error_co_dyn;  /* status server error */
     }
#endif
   } while (FALSE);
   goto p_ret_00;                           /* return to HOB-TUN       */

   p_conn_ok:                               /* connect succeeded       */
   iml_select = DEF_NETW_POST_1_HTUN_CONN_OK;  /* posted for HTUN connect ok */
   ADSL_INETA_RAWS_1_G->imc_state |= DEF_STATE_HTUN_CONN_OK;  /* done HTUN connect ok */
   m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnI GATE=%(ux)s SNO=%08d INETA=%s connect (HTCP) to %(ux)s successful",
                   adsl_conn1->adsc_gate1 + 1,
                   adsl_conn1->dsc_co_sort.imc_sno,
                   adsl_conn1->chrc_ineta,
                   (char *) (adsl_conn1->adsc_server_conf_1 + 1)
                     + adsl_conn1->adsc_server_conf_1->inc_no_sdh
                       * sizeof(struct dsd_sdh_work_1) );
#ifndef X101214_XX
   adsl_conn1->iec_st_ses = clconn1::ied_ses_start_server_1;  /* status server continue */
#else
   if (adsl_conn1->iec_st_ses != clconn1::ied_ses_wait_conn_s_dynamic) {  /* wait for dynamic connect to server */
     adsl_conn1->iec_st_ses = clconn1::ied_ses_start_server_1;  /* status server continue */
   } else {
     adsl_conn1->iec_st_ses = clconn1::ied_ses_start_dyn_serv_1;  /* start connection to server part one dynamic */
   }
#endif
#ifdef OLD_1112
   if (adsl_conn1->adsc_radqu) {            /* radius still active     */
     adsl_conn1->adsc_radqu->imc_connect_error = 0;
     adsl_conn1->adsc_radqu->boc_did_connect = TRUE;  /* did connect   */
   }
#endif

   p_ret_00:                                /* return to HOB-TUN       */
#ifndef OLD_1112
   if (adsl_conn1->adsc_wsp_auth_1) {       /* authentication active   */
     adsl_conn1->adsc_wsp_auth_1->imc_connect_error = imp_errno;  /* set connect error */
     adsl_conn1->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
     adsl_conn1->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
   }
#endif
   if (adsl_conn1->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
     adsl_conn1->adsc_int_webso_conn_1->imc_connect_error = imp_errno;  /* set connect error */
     adsl_conn1->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
     adsl_conn1->adsc_int_webso_conn_1->boc_notify = TRUE;  /* notify SDH */
   }
   adsl_netw_post_1 = ADSL_INETA_RAWS_1_G->adsc_netw_post_1;  /* get structure to post from network callback */
   if (   (adsl_netw_post_1)                /* has to do post          */
       && (iml_select & adsl_netw_post_1->imc_select)) {  /* is selected */
     ADSL_INETA_RAWS_1_G->adsc_netw_post_1 = NULL;  /* remove structure to post from network callback */
     adsl_netw_post_1->boc_posted = TRUE;  /* event has been posted  */
     iml_rc = adsl_netw_post_1->adsc_event->m_post( &iml_error );  /* event for posted */
     if (iml_rc < 0) {                     /* error occured           */
       m_hl1_printf( "xxxxxxxr-%05d-W m_htun_htcp_connect_end() m_post Return Code %d Error %d.",
                     __LINE__, iml_rc, iml_error );
     }
   }
   m_act_thread_1( adsl_conn1 );            /* activate thread for session */
   return;                                  /* all done                */
#undef ADSL_INETA_RAWS_1_G
} /* end m_htun_htcp_connect_end()                                     */

/* WSP can free the target INETA                                       */
extern "C" void m_htun_htcp_free_target_ineta( struct dsd_tun_contr1 *adsp_tun_contr1,
                                               struct dsd_target_ineta_1 *adsp_target_ineta_1 ) {
   class clconn1 *adsl_conn_w1;             /* class connection        */

#ifndef NEW_HOB_TUN_1103
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tun_contr1 - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr1 )))
   adsl_conn_w1 = (class clconn1 *) ADSL_INETA_RAWS_1_G->ac_conn1;
#endif
#ifdef NEW_HOB_TUN_1103
   adsl_conn_w1 = ((class clconn1 *)
                     ((char *) adsp_tun_contr1
                        - offsetof( class clconn1, dsc_tun_contr1 )));
#endif
   if (adsl_conn_w1->adsc_server_conf_1 == NULL) return;
   if (adsl_conn_w1->adsc_server_conf_1->inc_function != DEF_FUNC_DIR) return;
   if (adsl_conn_w1->adsc_server_conf_1->boc_dynamic) return;  /* dynamically allocated */
   if (adsl_conn_w1->adsc_server_conf_1->boc_dns_lookup_before_connect == FALSE) return;  /* needs to solve INETA before connect */
   if (adsp_target_ineta_1 == adsl_conn_w1->adsc_server_conf_1->adsc_server_ineta) return;
   free( adsp_target_ineta_1 );             /* free the memory         */
   return;
#ifndef NEW_HOB_TUN_1103
#undef ADSL_INETA_RAWS_1_G
#endif
} /* end m_htun_htcp_free_target_ineta()                               */

/* TCP session of HTCP / HTUN has sent something to the server         */
extern "C" void m_htun_htcp_send_complete( struct dsd_tun_contr1 *adsp_tun_contr1 ) {
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   struct dsd_netw_post_1 *adsl_netw_post_1;  /* structure to post from network callback */
   class clconn1 *adsl_conn1;               /* class connection        */

#ifdef B100824
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_htun_htcp_send_complete( %p ) called",
                   __LINE__, adsp_tun_contr1 );
#endif
#ifndef NEW_HOB_TUN_1103
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tun_contr1 - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr1 )))
   adsl_conn1 = (class clconn1 *) ADSL_INETA_RAWS_1_G->ac_conn1;
#endif
#ifdef NEW_HOB_TUN_1103
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr1
                      - offsetof( class clconn1, dsc_tun_contr1 )));
#define ADSL_INETA_RAWS_1_G adsl_conn1->adsc_ineta_raws_1
#endif
   ADSL_INETA_RAWS_1_G->imc_state |= DEF_STATE_HTUN_SEND_COMPL;  /* done HTUN send complete - m_htun_htcp_send_complete() */
   adsl_netw_post_1 = ADSL_INETA_RAWS_1_G->adsc_netw_post_1;  /* get structure to post from network callback */
   if (   (adsl_netw_post_1)                /* has to do post          */
       && (adsl_netw_post_1->imc_select & DEF_NETW_POST_1_HTUN_SEND_COMPL)) {  /* posted for HTUN HTCP send complete */
     ADSL_INETA_RAWS_1_G->adsc_netw_post_1 = NULL;  /* remove structure to post from network callback */
     adsl_netw_post_1->boc_posted = TRUE;   /* event has been posted  */
     iml_rc = adsl_netw_post_1->adsc_event->m_post( &iml_error );  /* event for posted */
     if (iml_rc < 0) {                      /* error occured           */
       m_hl1_printf( "xxxxxxxr-%05d-W m_htun_session_end() m_post Return Code %d Error %d.",
                     __LINE__, iml_rc, iml_error );
     }
   }
   if (adsl_conn1 == NULL) return;
   m_act_thread_1( adsl_conn1 );            /* activate thread for session */
   return;                                  /* all done                */
#undef ADSL_INETA_RAWS_1_G
} /* end m_htun_htcp_send_complete()                                   */

/* TCP session of HOB-TUN, HTCP HOB-PPP-T1 or SSTP has ended           */
extern "C" void m_htun_session_end( struct dsd_tun_contr1 *adsp_tun_contr1,
                                    int imp_reason ) {
   BOOL       bol1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   int        iml1, iml2;                   /* working variables       */
   int        iml_error;                    /* error code              */
   int        iml_state;                    /* state of HTUN / HTCP session */
   struct dsd_netw_post_1 *adsl_netw_post_1;  /* structure to post from network callback */
   class clconn1 *adsl_conn1;               /* class connection        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */
   void *     al_ineta_raws_1_l;            /* raw packet INETA in use */

#ifdef B100824
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_htun_session_end( %p , %d ) called",
                   __LINE__, adsp_tun_contr1, imp_reason );
#endif
#ifndef NEW_HOB_TUN_1103
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tun_contr1 - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr1 )))
   adsl_conn1 = (class clconn1 *) ADSL_INETA_RAWS_1_G->ac_conn1;
#endif
#ifdef NEW_HOB_TUN_1103
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr1
                      - offsetof( class clconn1, dsc_tun_contr1 )));
#define ADSL_INETA_RAWS_1_G adsl_conn1->adsc_ineta_raws_1
#endif
   bol1 = FALSE;                            /* no WSP trace            */
   iml1 = 0;                                /* session number          */
   al_ineta_raws_1_l = NULL;                /* no raw packet INETA in use */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) {  /* HOB-TUN   */
     bol1 = TRUE;                           /* with WSP trace          */
   }
   if (adsl_conn1) {                        /* with connection         */
     iml1 = adsl_conn1->dsc_co_sort.imc_sno;  /* WSP session number    */
     al_ineta_raws_1_l = ADSL_INETA_RAWS_1_G;  /* raw packet INETA in use */
     if (adsl_conn1->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
       bol1 = TRUE;                         /* with WSP trace          */
     }
   }
   if (bol1) {                              /* generate record WSP-trace */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNMSE1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = iml1;      /* WSP session number      */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "l%05d called m_htun_session_end() adsl_conn1=%p al_ineta_raws_1=%p.",
                     __LINE__, adsl_conn1, al_ineta_raws_1_l );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
#ifdef B100811
   if (adsl_conn1 == NULL) goto p_sess_end_20;  /* no connection associated */
   adsl_conn1->iec_servcotype = ied_servcotype_none;  /* no server connection */
   while (adsl_conn1->adsc_sdhc1_htun_sch) {  /* loop over all buffers  */
     adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_htun_sch;  /* save this buffer */
     adsl_conn1->adsc_sdhc1_htun_sch = adsl_conn1->adsc_sdhc1_htun_sch->adsc_next;  /* get next in chain */
     m_proc_free( adsl_sdhc1_w1 );          /* free this buffer        */
   }
   if (adsl_conn1->achc_reason_end == NULL) {  /* reason end session   */
     /* do not set when dynamic server                                 */
     if (   (adsl_conn1->adsc_server_conf_1 == NULL)
         || (adsl_conn1->adsc_server_conf_1->boc_dynamic == FALSE)) {
       if (imp_reason == 0) {               /* normal end              */
         adsl_conn1->achc_reason_end = "server normal end";
       } else {                             /* abnormal end            */
         adsl_conn1->achc_reason_end = "server ended with error";
       }
     }
   }
// to-do 29.11.08 KB - notify session, start work-thread, set session-status
   p_sess_end_20:                           /* connection part has been processed */
#endif
   if (ADSL_INETA_RAWS_1_G == NULL) return;
   iml_state = DEF_STATE_HTUN_SESS_END;     /* done HTUN HTCP session end */
   if (imp_reason) {                        /* abnormal end            */
     iml_state |= DEF_STATE_HTUN_ERR_SESS_END;  /* done HTUN HTCP session end was with error */
   }
   ADSL_INETA_RAWS_1_G->imc_state |= iml_state;  /* state of HTUN / HTCP session */
   adsl_netw_post_1 = ADSL_INETA_RAWS_1_G->adsc_netw_post_1;  /* get structure to post from network callback */
   if (   (adsl_netw_post_1)                /* has to do post          */
       && (adsl_netw_post_1->imc_select & DEF_NETW_POST_1_HTUN_SESS_END)) {  /* posted for HTUN HTCP session end */
     ADSL_INETA_RAWS_1_G->adsc_netw_post_1 = NULL;  /* remove structure to post from network callback */
     adsl_netw_post_1->boc_posted = TRUE;   /* event has been posted  */
     iml_rc = adsl_netw_post_1->adsc_event->m_post( &iml_error );  /* event for posted */
     if (iml_rc < 0) {                      /* error occured           */
       m_hl1_printf( "xxxxxxxr-%05d-W m_htun_session_end() m_post Return Code %d Error %d.",
                     __LINE__, iml_rc, iml_error );
     }
   }
#ifdef B120206
   if (   (ADSL_INETA_RAWS_1_G->iec_irs != ied_ineta_raws_n_ipv4)  /* INETA IPV4 */
       && (ADSL_INETA_RAWS_1_G->iec_irs != ied_ineta_raws_n_ipv6)) {  /* INETA IPV6 */
     goto p_sess_end_40;                    /* connection part has been processed */
   }
   ADSL_INETA_RAWS_1_G->ac_conn1 = NULL;    /* not associated with session */
   adsl_conn1->adsc_ineta_raws_1 = NULL;    /* no more INETA associated */
   adsl_conn1->iec_servcotype = ied_servcotype_none;  /* no server connection */
   while (adsl_conn1->adsc_sdhc1_htun_sch) {  /* loop over all buffers  */
     adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_htun_sch;  /* save this buffer */
     adsl_conn1->adsc_sdhc1_htun_sch = adsl_conn1->adsc_sdhc1_htun_sch->adsc_next;  /* get next in chain */
     m_proc_free( adsl_sdhc1_w1 );          /* free this buffer        */
   }
   if (adsl_conn1->achc_reason_end == NULL) {  /* reason end session   */
     /* do not set when dynamic server                                 */
     if (   (adsl_conn1->adsc_server_conf_1 == NULL)
         || (adsl_conn1->adsc_server_conf_1->boc_dynamic == FALSE)) {
       if (imp_reason == 0) {               /* normal end              */
         adsl_conn1->achc_reason_end = "server normal end";
       } else {                             /* abnormal end            */
         adsl_conn1->achc_reason_end = "server ended with error";
       }
     }
   }

   p_sess_end_40:                           /* connection part has been processed */
#endif
   m_act_thread_1( adsl_conn1 );            /* activate thread for session */
   return;                                  /* all done                */
#undef ADSL_INETA_RAWS_1_G
} /* end m_htun_session_end()                                          */

/* session of HOB-TUN has ended, free all resources                    */
extern "C" void m_htun_free_resources( struct dsd_tun_contr1 *adsp_tun_contr1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   BOOL       bol_free;                     /* this routine does free  */
   int        iml_state;                    /* state of HTUN / HTCP session */
   int        iml_rc;                       /* return code             */
   int        iml_error;                    /* error code              */
   struct dsd_netw_post_1 *adsl_netw_post_1;  /* structure to post from network callback */
   class clconn1 *adsl_conn1;               /* class connection        */
   struct dsd_wsp_trace_1 *adsl_wt1_w1;     /* WSP trace record        */
   void *     al_ineta_raws_1_l;            /* raw packet INETA in use */

#ifdef B100824
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_htun_free_resources( %p ) called",
                   __LINE__, adsp_tun_contr1 );
#endif
   bol_free = FALSE;                        /* this routine does free  */
#ifndef NEW_HOB_TUN_1103
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tun_contr1 - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr1 )))
   adsl_conn1 = (class clconn1 *) ADSL_INETA_RAWS_1_G->ac_conn1;
#endif
#ifdef NEW_HOB_TUN_1103
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr1
                      - offsetof( class clconn1, dsc_tun_contr1 )));
#define ADSL_INETA_RAWS_1_G adsl_conn1->adsc_ineta_raws_1
#endif
   bol1 = FALSE;                            /* no WSP trace            */
   iml1 = 0;                                /* session number          */
   al_ineta_raws_1_l = NULL;                /* no raw packet INETA in use */
   if (img_wsp_trace_core_flags1 & HL_WT_CORE_HOB_TUN) {  /* HOB-TUN   */
     bol1 = TRUE;                           /* with WSP trace          */
   }
   if (adsl_conn1) {                        /* with connection         */
     iml1 = adsl_conn1->dsc_co_sort.imc_sno;  /* WSP session number    */
     al_ineta_raws_1_l = ADSL_INETA_RAWS_1_G;  /* raw packet INETA in use */
     if (adsl_conn1->imc_trace_level & HL_WT_SESS_NETW) {  /* generate WSP trace record */
       bol1 = TRUE;                         /* with WSP trace          */
     }
   }
   if (bol1) {                              /* generate record WSP-trace */
     adsl_wt1_w1 = (struct dsd_wsp_trace_1 *) m_proc_alloc();  /* WSP trace record */
     memset( adsl_wt1_w1, 0, sizeof(struct dsd_wsp_trace_1) + sizeof(struct dsd_wsp_trace_record) );  /* clear WSP trace record */
     adsl_wt1_w1->iec_wtrt = ied_wtrt_trace_data;  /* trace data       */
     adsl_wt1_w1->ilc_epoch = m_get_epoch_microsec();  /* time trace record recorded */
     memcpy( adsl_wt1_w1->chrc_wtrt_id, "CTUNMFR1", sizeof(adsl_wt1_w1->chrc_wtrt_id) );  /* Id of trace record */
     adsl_wt1_w1->imc_wtrt_sno = iml1;      /* WSP session number      */
     adsl_wt1_w1->imc_wtrt_tid = HL_THRID;  /* thread-id               */
#define ADSL_WTR_G1 ((struct dsd_wsp_trace_record *) (adsl_wt1_w1 + 1))
     iml2 = sprintf( (char *) (ADSL_WTR_G1 + 1),
                     "l%05d called m_htun_free_resources() adsl_conn1=%p al_ineta_raws_1=%p.",
                     __LINE__, adsl_conn1, al_ineta_raws_1_l );
     ADSL_WTR_G1->iec_wtrt = ied_wtrt_text;  /* text passed            */
     ADSL_WTR_G1->achc_content              /* content of text / data  */
       = (char *) (ADSL_WTR_G1 + 1);
     ADSL_WTR_G1->imc_length = iml2;        /* length of text / data   */
     adsl_wt1_w1->adsc_wsp_trace_record = ADSL_WTR_G1;  /* WSP trace records */
#undef ADSL_WTR_G1
     m_wsp_trace_out( adsl_wt1_w1 );        /* output of WSP trace record */
   }
   iml_state = DEF_STATE_HTUN_FREE_R_1;     /* done HOB-TUN free resources */
   if (adsl_conn1) {                        /* connection still alive  */
     adsl_conn1->iec_servcotype = ied_servcotype_none;  /* no server connection */
#ifdef NEW_HOB_TUN_1103
     adsl_conn1->dsc_htun_h = NULL;         /* handle for HOB-TUN      */
#endif
   } else {                                 /* connection not still alive  */
     iml_state |= DEF_STATE_HTUN_FREE_R_2;  /* done HTUN free resources */
   }
#ifdef NEW_HOB_TUN_1103
   if (ADSL_INETA_RAWS_1_G == NULL) return;
#endif
   ADSL_INETA_RAWS_1_G->imc_state |= iml_state;  /* done HTUN free resources */
#ifndef NEW_HOB_TUN_1103
   ADSL_INETA_RAWS_1_G->dsc_htun_h = NULL;  /* handle for HTUN         */
#endif
   adsl_netw_post_1 = ADSL_INETA_RAWS_1_G->adsc_netw_post_1;  /* get structure to post from network callback */
   if (   (adsl_netw_post_1)                /* has to do post          */
       && (adsl_netw_post_1->imc_select & DEF_NETW_POST_1_HTUN_FREE_R)) {  /* posted for HTUN free resources */
     ADSL_INETA_RAWS_1_G->adsc_netw_post_1 = NULL;  /* remove structure to post from network callback */
     adsl_netw_post_1->boc_posted = TRUE;   /* event has been posted   */
     iml_rc = adsl_netw_post_1->adsc_event->m_post( &iml_error );  /* event for posted */
     if (iml_rc < 0) {                      /* error occured           */
       m_hl1_printf( "xxxxxxxr-%05d-W m_htun_htcp_connect_end() m_post Return Code %d Error %d.",
                     __LINE__, iml_rc, iml_error );
     }
   }
   if ((iml_state & DEF_STATE_HTUN_FREE_R_2) == 0) {  /* done HTUN free resources part two */
     return;                                /* clconn1::close1() will free the memory */
   }
   m_cleanup_htun_ineta( ADSL_INETA_RAWS_1_G );
#ifndef TRY_120126_01
   if (ADSL_INETA_RAWS_1_G->adsc_auxf_1_ident) {  /* store ident to free */
     free( ADSL_INETA_RAWS_1_G->adsc_auxf_1_ident );  /* free ident    */
   }
#endif
#define ADSL_TIMER_G ((struct dsd_timer_ele *) ADSL_INETA_RAWS_1_G)  /* timer to free memory later */
   memset( ADSL_TIMER_G, 0, sizeof(struct dsd_timer_ele) );
   ADSL_TIMER_G->amc_compl = &m_timeout_free_memory;  /* set routine for timeout */
   ADSL_TIMER_G->ilcwaitmsec = TIMER_FREE_MEMORY;  /* timer to wait some time before freeing memory */
   m_time_set( ADSL_TIMER_G, FALSE );  /* set timeout now */
#undef ADSL_TIMER_G
#undef ADSL_INETA_RAWS_1_G
} /* end m_htun_free_resources()                                       */

/* put a warning related to the session to the console                 */
extern "C" void m_htun_warning( struct dsd_tun_contr1 *adsp_tun_contr1,
                                int imp_error_number,
                                const char *achp_format, ... ) {
   int        iml_rc;                       /* return code             */
   int        iml_len;                      /* length of message       */
   int        iml_cpy_pos;                  /* position of copy        */
   int        iml_cpy_len;                  /* length of copy          */
   class clconn1 *adsl_conn1;               /* class connection        */
   va_list    dsl_list;                     /* list of arguments       */
   struct sockaddr_storage dsl_soa;         /* filled with INETA       */
   char       chrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */
   char       chrl_port[ 32 ];              /* for message port        */
   char       chrl_msg[ 512 ];              /* area for message        */

#ifndef NEW_HOB_TUN_1103
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tun_contr1 - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr1 )))
#ifdef B110314
#define ADSL_AUXF_1_G ((struct dsd_auxf_1 *) ((char *) ADSL_INETA_RAWS_1_G - sizeof(struct dsd_auxf_1)))
#endif
   adsl_conn1 = (class clconn1 *) ADSL_INETA_RAWS_1_G->ac_conn1;
#endif
#ifdef NEW_HOB_TUN_1103
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr1
                      - offsetof( class clconn1, dsc_tun_contr1 )));
#define ADSL_INETA_RAWS_1_G adsl_conn1->adsc_ineta_raws_1
#endif
   va_start( dsl_list, achp_format );       /* build dsl_list of variable arguments */
   iml_len = m_hlvsnprintf( chrl_msg, sizeof(chrl_msg), ied_chs_utf_8,
                            achp_format, dsl_list );
   va_end( dsl_list );                      /* destroy list            */
   if (adsl_conn1) {                        /* connection valid        */
     m_hlnew_printf( HLOG_XYZ1, "HWSPS121W GATE=%(ux)s SNO=%08d INETA=%s HTUN %.*(u8)s",
                     adsl_conn1->adsc_gate1 + 1,
                     adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta,
                     iml_len, chrl_msg );
     return;                                /* all done                */
   }
   memset( &dsl_soa, 0, sizeof(struct sockaddr_storage) );  /* filled with INETA */
   iml_cpy_len = 0;                         /* clear length copy       */
#ifdef B110314
   switch (ADSL_AUXF_1_G->iec_auxf_def) {
#ifdef FORKEDIT
   }
#endif
#else
   switch (ADSL_INETA_RAWS_1_G->iec_irs) {  /* type of INETA raw socket */
#endif
     case ied_ineta_raws_n_ipv4:            /* INETA IPV4              */
     case ied_ineta_raws_user_ipv4:         /* INETA user IPV4         */
     case ied_ineta_raws_l2tp_ipv4:         /* INETA L2TP IPV4         */
       dsl_soa.ss_family = AF_INET;         /* IPV4                    */
       iml_cpy_pos = offsetof( struct sockaddr_in, sin_addr );  /* position to copy */
       iml_cpy_len = 4;                     /* length to copy          */
       break;
     case ied_ineta_raws_n_ipv6:            /* INETA IPV6              */
     case ied_ineta_raws_user_ipv6:         /* INETA user IPV6         */
     case ied_ineta_raws_l2tp_ipv6:         /* INETA L2TP IPV6         */
       dsl_soa.ss_family = AF_INET6;        /* IPV6                    */
       iml_cpy_pos = offsetof( struct sockaddr_in6, sin6_addr );  /* position to compare */
       iml_cpy_len = 16;                    /* length to copy          */
       break;
   }
   strcpy( chrl_ineta, "???" );
   if (iml_cpy_len > 0) {                   /* length copy set         */
     memcpy( (char *) &dsl_soa + iml_cpy_pos,
             ADSL_INETA_RAWS_1_G + 1,
             iml_cpy_len );
     iml_rc = IP_getnameinfo( (struct sockaddr *) &dsl_soa, sizeof(struct sockaddr_storage),
                              chrl_ineta, sizeof(chrl_ineta),
                              0, 0, NI_NUMERICHOST );
     if (iml_rc) {           /* error occured           */
       m_hlnew_printf( HLOG_XYZ1, "HWSPnnnnW HTUN IBIPGW08 m_htun_warning() l%05d getnameinfo() returned %d %d.",
                       __LINE__, iml_rc, D_TCP_ERROR );
       strcpy( chrl_ineta, "???" );
     }
   }
   chrl_port[0] = 0;                        /* for message port        */
#ifdef B110314
   if (   (ADSL_AUXF_1_G->iec_auxf_def == ied_ineta_raws_user_ipv4)  /* INETA user IPV4 */
       || (ADSL_AUXF_1_G->iec_auxf_def == ied_ineta_raws_user_ipv6)) {  /* INETA user IPV6 */
#ifdef FORKEDIT
   }
#endif
#else
   if (   (ADSL_INETA_RAWS_1_G->iec_irs == ied_ineta_raws_user_ipv4)  /* INETA user IPV4 */
       || (ADSL_INETA_RAWS_1_G->iec_irs == ied_ineta_raws_user_ipv6)) {  /* INETA user IPV6 */
#endif
     sprintf( chrl_port, "TCP source port %d ", ADSL_INETA_RAWS_1_G->usc_appl_port );  /* port in use */
   }
   m_hlnew_printf( HLOG_WARN1, "HWSPTUN0%03dW HOB-TUN message use ineta-appl %s %s%.*(u8)s",
                   imp_error_number,
                   chrl_ineta, chrl_port,
                   iml_len, chrl_msg );
#undef ADSL_INETA_RAWS_1_G
#ifdef B110314
#undef ADSL_AUXF_1_G
#endif
} /* end m_htun_warning()                                              */

/* enter critical section of WSP session from HTUN                     */
extern "C" void m_htun_critsect_enter( struct dsd_tun_contr1 *adsp_tun_contr1 ) {
#ifdef B100702
   EnterCriticalSection( &((class clconn1 *) ((char *) adsp_tun_contr1
                           - offsetof( class clconn1, dsc_tun_contr1 )))
                               ->d_act_critsect );  /* critical section act */
#endif
#ifndef NEW_HOB_TUN_1103
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tun_contr1 - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr1 )))
#define ADSL_CONN1_G ((class clconn1 *) ADSL_INETA_RAWS_1_G->ac_conn1)
   EnterCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#undef ADSL_CONN1_G
#undef ADSL_INETA_RAWS_1_G
#endif
#ifdef NEW_HOB_TUN_1103
   EnterCriticalSection( &((class clconn1 *) ((char *) adsp_tun_contr1
                           - offsetof( class clconn1, dsc_tun_contr1 )))
                               ->d_act_critsect );  /* critical section act */
#endif
} /* end m_htun_critsect_enter()                                       */

/* leave critical section of WSP session from HTUN                     */
extern "C" void m_htun_critsect_leave( struct dsd_tun_contr1 *adsp_tun_contr1 ) {
#ifdef B100702
   LeaveCriticalSection( &((class clconn1 *) ((char *) adsp_tun_contr1
                           - offsetof( class clconn1, dsc_tun_contr1 )))
                               ->d_act_critsect );  /* critical section act */
#endif
#ifndef NEW_HOB_TUN_1103
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tun_contr1 - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr1 )))
#define ADSL_CONN1_G ((class clconn1 *) ADSL_INETA_RAWS_1_G->ac_conn1)
   LeaveCriticalSection( &ADSL_CONN1_G->d_act_critsect );  /* critical section act */
#undef ADSL_CONN1_G
#undef ADSL_INETA_RAWS_1_G
#endif
#ifdef NEW_HOB_TUN_1103
   LeaveCriticalSection( &((class clconn1 *) ((char *) adsp_tun_contr1
                           - offsetof( class clconn1, dsc_tun_contr1 )))
                               ->d_act_critsect );  /* critical section act */
#endif
} /* end m_htun_critsect_leave()                                       */
#endif

#ifdef FOR_ALAN_DUCA
/* enter critical section of WSP session from HTCP                     */
extern "C" void m_htun_htcp_critsect_enter( class dsc_htcp_session *adsp_htcp_session ) {
   m_htun_critsect_enter( &((struct dsd_tun_contr1 *) ((char *) adsp_htcp_session
                              - offsetof( struct dsd_tun_contr1, chrc_htcp_session ))) );
} /* end m_htun_htcp_critsect_enter()                                  */

/* leave critical section of WSP session from HTCP                     */
extern "C" void m_htun_htcp_critsect_leave( class dsc_htcp_session *adsp_htcp_session ) {
   m_htun_critsect_leave( &((struct dsd_tun_contr1 *) ((char *) adsp_htcp_session
                              - offsetof( struct dsd_tun_contr1, chrc_htcp_session ))) );
} /* end m_htun_htcp_critsect_leave()                                  */
#endif

#ifdef ERROR_1308
extern "C" struct dsd_targfi_1 * m_htun_ppp_get_targfi( struct dsd_tun_contr1 *adsp_tun_contr1 ) {
   class clconn1 *adsl_conn1;               /* class connection        */
   char       *achl_stf;                    /* source target-filter    */
   struct dsd_targfi_1 *adsl_targfi_w1;     /* working variable        */

#ifndef NEW_HOB_TUN_1103
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) ((char *) adsp_tun_contr1 - offsetof( struct dsd_ineta_raws_1, dsc_tun_contr1 )))
   adsl_conn1 = (class clconn1 *) ADSL_INETA_RAWS_1_G->ac_conn1;
#undef ADSL_INETA_RAWS_1_G
#endif
#ifdef NEW_HOB_TUN_1103
   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr1
                      - offsetof( class clconn1, dsc_tun_contr1 )));
#endif
   adsl_targfi_w1 = m_get_session_targfi( &achl_stf, adsl_conn1 );
   if (adsl_targfi_w1 == NULL) return NULL;
   if (adsg_loconf_1_inuse->inc_network_stat >= 4) {
     m_hlnew_printf( HLOG_INFO1, "HWSPS083I GATE=%(ux)s SNO=%08d INETA=%s HOB-TUN apply target-filter %(u8)s from %s.",
                     adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta, (char *) adsl_targfi_w1 + adsl_targfi_w1->imc_off_name, achl_stf );
   }
   return adsl_targfi_w1;
} /* end m_htun_ppp_get_targfi()                                       */
#endif
#endif
#ifdef ERROR_1308
extern "C" char * m_htun_ppp_acquire_local_ineta_ipv4( struct dsd_hco_wothr *adsp_hco_wothr,
                                                       struct dsd_tun_contr1 *adsp_tun_contr1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   socklen_t  iml_local_namelen;            /* length of name local    */
   class clconn1 *adsl_conn1;               /* class connection        */
   struct sockaddr_storage dsl_soa_local;   /* address information INETA to be used locally */
   char       chrl_ineta_local[ LEN_DISP_INETA ];  /* for INETA local  */

   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tun_contr1
                      - offsetof( class clconn1, dsc_tun_contr1 )));
#ifdef B120206
   adsl_conn1->adsc_ineta_raws_1            /* auxiliary field for HOB-TUN */
     = (struct dsd_ineta_raws_1 *) malloc( sizeof(struct dsd_ineta_raws_1) +  + sizeof(UNSIG_MED) );
   bol1 = m_prepare_htun_ineta( adsl_conn1->adsc_ineta_raws_1,
                                &dsl_soa_local,
                                &iml_local_namelen,
                                adsl_conn1,
                                adsp_hco_wothr,
                                ied_ineta_raws_n_ipv4 );  /* INETA IPV4 */
   if (bol1 == FALSE) {                     /* could not get INETA     */
     m_hlnew_printf( HLOG_XYZ1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s tries to start raw-interface PPP but no ineta-ppp available",
                     adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta );
     free( adsl_conn1->adsc_ineta_raws_1 );  /* free memory auxiliary field for HOB-TUN */
     adsl_conn1->adsc_ineta_raws_1 = NULL;  /* no more auxiliary field for HOB-TUN */
     return NULL;
   }
#endif
   adsl_conn1->adsc_ineta_raws_1            /* auxiliary field for HOB-TUN */
     = m_prepare_htun_ineta( &dsl_soa_local,
                             &iml_local_namelen,
                             adsl_conn1,
                             adsp_hco_wothr,
                             ied_ineta_raws_n_ipv4 );  /* INETA IPV4   */
   if (adsl_conn1->adsc_ineta_raws_1 == NULL) {  /* no INETA found     */
     m_hlnew_printf( HLOG_WARN1, "HWSPS190W GATE=%(ux)s SNO=%08d INETA=%s tries to start raw-interface PPP but no ineta-ppp available",
                     adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta );
     return NULL;
   }
   iml_rc = IP_getnameinfo( (struct sockaddr *) &dsl_soa_local, iml_local_namelen,
                            chrl_ineta_local, sizeof(chrl_ineta_local),
                            0, 0, NI_NUMERICHOST );
   if (iml_rc < 0) {                  /* error occured           */
     if (cl_tcp_r::hws2mod != NULL) {  /* functions loaded       */
       iml_rc = cl_tcp_r::afunc_wsaglerr();  /* get error code   */
     }
     m_hlnew_printf( HLOG_WARN1, "HWSPS191W GATE=%(ux)s SNO=%08d INETA=%s getnameinfo local failed with code %d.",
                     adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta, iml_rc );
     strcpy( chrl_ineta_local, "???" );
   }
   m_hlnew_printf( HLOG_INFO1, "HWSPS192I GATE=%(ux)s SNO=%08d INETA=%s use ineta-ppp %s.",
                   adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta, chrl_ineta_local );
   adsl_conn1->adsc_ineta_raws_1->ac_conn1 = adsl_conn1;  /* set connection  */
   return (char *) (adsl_conn1->adsc_ineta_raws_1 + 1);  /* return address of field with INETA */
} /* end m_htun_ppp_acquire_local_ineta_ipv4()                         */

extern "C" void m_htun_ppp_use_local_ineta( struct dsd_tun_contr1 *adsp_tun_contr1,
                                            char *achrp_local_ineta ) {
#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) (achrp_local_ineta - sizeof(struct dsd_ineta_raws_1)))
   if (ADSL_INETA_RAWS_1_G->ac_conn1) {     /* set in old connection   */
     ((class clconn1 *) ADSL_INETA_RAWS_1_G->ac_conn1)->adsc_ineta_raws_1 = NULL;
   }
   ADSL_INETA_RAWS_1_G->ac_conn1
     = ((class clconn1 *)
          ((char *) adsp_tun_contr1
             - offsetof( class clconn1, dsc_tun_contr1 )));
#undef ADSL_INETA_RAWS_1_G
} /* end m_htun_ppp_use_local_ineta()                                  */

extern "C" void m_htun_ppp_release_local_ineta( struct dsd_tun_contr1 *adsp_tun_contr1,
                                                char *achrp_local_ineta ) {
   class clconn1 *adsl_conn1;               /* class connection        */

#define ADSL_INETA_RAWS_1_G ((struct dsd_ineta_raws_1 *) (achrp_local_ineta - sizeof(struct dsd_ineta_raws_1)))
   adsl_conn1 = (class clconn1 *) ADSL_INETA_RAWS_1_G->ac_conn1;
   m_cleanup_htun_ineta( ADSL_INETA_RAWS_1_G );  /* cleanup INETA      */
   free( ADSL_INETA_RAWS_1_G );             /* free memory area with INETA */
#undef ADSL_INETA_RAWS_1_G
   if (adsl_conn1 == NULL) return;          /* not used with connection */
   adsl_conn1->adsc_ineta_raws_1 = NULL;    /* no more auxiliary field for HOB-TUN */
} /* end m_htun_ppp_release_local_ineta()                              */
#endif

/* send something to the client                                        */
extern "C" void m_l2tp_to_client( struct dsd_l2tp_session *adsp_l2tp_session,
                                  struct dsd_sdh_control_1 *adsp_sdhc1,
                                  BOOL bop_locked ) {
   BOOL       bol_act;                      /* activate thread         */
   class clconn1 *adsl_conn1;               /* class connection        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* chain of buffers       */

   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_l2tp_session
                      - offsetof( class clconn1, dsc_l2tp_session )));
   bol_act = FALSE;                         /* not yet set             */
/**
   the blocks sdhc1 are chained together,
   but the gather structures are not yet chained together
*/
   if (bop_locked == FALSE) {               /* connection not locked   */
     EnterCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
   }
   if (adsl_conn1->adsc_sdhc1_s1 == NULL) {  /* receive buffer server 1 */
     adsl_conn1->adsc_sdhc1_s1 = adsp_sdhc1;  /* get data received first buffer */
     if (adsl_conn1->boc_st_act == FALSE) {  /* thread does not run    */
       adsl_conn1->boc_st_act = TRUE;       /* thread will run soon    */
       bol_act = TRUE;                      /* activate thread         */
     }
   } else {                                 /* already receive data    */
     adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_s1;  /* get first buffer   */
     while (adsl_sdhc1_w1->adsc_next) adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;
     adsl_sdhc1_w1->adsc_next = adsp_sdhc1;  /* append data received to first buffer */
   }
   if (bop_locked == FALSE) {               /* connection not locked   */
     LeaveCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
   }
   if (bol_act) {                           /* activate thread         */
     m_act_thread_2( adsl_conn1 );
   }
   return;
} /* end m_l2tp_to_client()                                            */

/* put a warning related to the session to the console                 */
extern "C" void m_l2tp_warning( struct dsd_l2tp_session *adsp_l2tp_session,
                                const char *achp_format, ... ) {
   int        iml_len;                      /* length of message       */
   class clconn1 *adsl_conn1;               /* class connection        */
   va_list    dsl_list;                     /* list of arguments       */
   char       chrl_msg[ 512 ];              /* area for message        */

   if (adsp_l2tp_session) {
     adsl_conn1 = ((class clconn1 *)
                     ((char *) adsp_l2tp_session
                        - offsetof( class clconn1, dsc_l2tp_session )));
   }
   va_start( dsl_list, achp_format );       /* build dsl_list of variable arguments */
   iml_len = m_hlvsnprintf( chrl_msg, sizeof(chrl_msg), ied_chs_utf_8,
                            achp_format, dsl_list );
   va_end( dsl_list );                      /* destroy list            */
   if (adsp_l2tp_session) {
     m_hlnew_printf( HLOG_WARN1, "HWSPS122W GATE=%(ux)s SNO=%08d INETA=%s L2TP %.*(u8)s",
                     adsl_conn1->adsc_gate1 + 1,
                     adsl_conn1->dsc_co_sort.imc_sno,
                     adsl_conn1->chrc_ineta,
                     iml_len, chrl_msg );
     return;
   }
   m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW no connection - L2TP %.*(u8)s",
                   iml_len, chrl_msg );
} /* end m_l2tp_warning()                                              */

/* put information related to the session to the console               */
extern "C" void m_l2tp_information( struct dsd_l2tp_session *adsp_l2tp_session,
                                    const char *achp_format, ... ) {
   int        iml_len;                      /* length of message       */
   class clconn1 *adsl_conn1;               /* class connection        */
   va_list    dsl_list;                     /* list of arguments       */
   char       chrl_msg[ 512 ];              /* area for message        */

   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_l2tp_session
                      - offsetof( class clconn1, dsc_l2tp_session )));
   va_start( dsl_list, achp_format );       /* build dsl_list of variable arguments */
   iml_len = m_hlvsnprintf( chrl_msg, sizeof(chrl_msg), ied_chs_utf_8,
                            achp_format, dsl_list );
   va_end( dsl_list );                      /* destroy list            */
   m_hlnew_printf( HLOG_INFO1, "HWSPS123I GATE=%(ux)s SNO=%08d INETA=%s L2TP %.*(u8)s",
                   adsl_conn1->adsc_gate1 + 1,
                   adsl_conn1->dsc_co_sort.imc_sno,
                   adsl_conn1->chrc_ineta,
                   iml_len, chrl_msg );
} /* end m_l2tp_information()                                          */

extern "C" void m_l2tp_set_ppp_auth( struct dsd_l2tp_session *adsp_l2tp_session, char *achp_ppp_auth ) {
   class clconn1 *adsl_conn1;               /* class connection        */

   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_l2tp_session
                      - offsetof( class clconn1, dsc_l2tp_session )));
   if (adsl_conn1->adsc_server_conf_1 == NULL) return;  /* no configuration server */
   memcpy( achp_ppp_auth, adsl_conn1->adsc_server_conf_1->chrc_ppp_auth, DEF_NO_PPP_AUTH );
} /* end m_l2tp_set_ppp_auth()                                         */

/* repeat sending data of this session                                 */
extern "C" void m_l2tp_repeat_send( struct dsd_hco_wothr *adsp_hco_wothr, struct dsd_l2tp_session *adsp_l2tp_session ) {
   class clconn1 *adsl_conn1;               /* class connection        */

   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_l2tp_session
                      - offsetof( class clconn1, dsc_l2tp_session )));
   m_ext_send_server( adsp_hco_wothr, adsl_conn1, NULL );
} /* end m_l2tp_repeat_send()                                          */

/* get address of INETA configured                                     */
extern "C" char * m_l2tp_get_client_ineta( struct dsd_l2tp_session *adsp_l2tp_session ) {
#ifdef B100702
   class clconn1 *adsl_conn1;               /* class connection        */

   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_l2tp_session
                      - offsetof( class clconn1, dsc_l2tp_session )));
   return (char *) &adsl_conn1->umc_ineta_ppp_ipv4;  /* INETA PPP IPV4 */
#endif
// to-do 03.07.10 KB - needs to use m_prepare_htun_ineta() without setting the route
   return NULL;
} /* end m_l2tp_get_client_ineta()                                     */

/* L2TP connection has ended                                           */
extern "C" void m_l2tp_server_end( struct dsd_l2tp_session *adsp_l2tp_session,
                                   BOOL bop_locked,
                                   char *achp_reason_end ) {
   BOOL       bol_act;                      /* activate thread         */
   class clconn1 *adsl_conn1;               /* class connection        */
   struct dsd_sdh_control_1 *adsl_sdhc1_w1;  /* working variable       */
   struct dsd_sdh_control_1 *adsl_sdhc1_w2;  /* working variable       */

   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_l2tp_session
                      - offsetof( class clconn1, dsc_l2tp_session )));
   adsl_conn1->iec_servcotype = ied_servcotype_ended;  /* server connection ended */
   bol_act = FALSE;                         /* not yet set             */
   if (bop_locked == FALSE) {               /* critical section not yet set */
     EnterCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
   }
   adsl_sdhc1_w1 = adsl_conn1->adsc_sdhc1_l2tp_sch; /* get buffers in chain */
   adsl_conn1->adsc_sdhc1_l2tp_sch = NULL;  /* chain is empty now      */
   if (adsl_conn1->achc_reason_end == NULL) {  /* reason end session   */
     adsl_conn1->achc_reason_end = "L2TP ended";
     if (achp_reason_end) {
       adsl_conn1->achc_reason_end = achp_reason_end;
     }
   }
   if (adsl_conn1->boc_st_act == FALSE) {   /* thread does not run     */
     adsl_conn1->boc_st_act = TRUE;         /* thread will run soon    */
     bol_act = TRUE;                        /* activate thread         */
   }
   if (bop_locked == FALSE) {               /* critical section not yet set */
     LeaveCriticalSection( &adsl_conn1->d_act_critsect );  /* critical section act */
   }
   if (bol_act) {                           /* activate thread         */
     m_act_thread_2( adsl_conn1 );
   }
   while (adsl_sdhc1_w1) {                  /* loop over buffers to free */
     adsl_sdhc1_w2 = adsl_sdhc1_w1;         /* get buffer              */
     adsl_sdhc1_w1 = adsl_sdhc1_w1->adsc_next;  /* get next in chain   */
     m_proc_free( adsl_sdhc1_w2 );          /* free buffer             */
   }
} /* end m_l2tp_server_end()                                           */

#ifdef B120915
static void m_session_new_params( class clconn1 *adsp_conn1 ) {
#ifdef B100702
#ifdef D_HPPPT1_1
   if (adsp_conn1->iec_servcotype == ied_servcotype_htun) {  /* HOB_TUN */
     *((UNSIG_MED *) &((struct sockaddr_in *) &adsp_conn1->dsc_tun_contr1.dsc_soa_local)->sin_addr)
       = adsp_conn1->umc_ineta_ppp_ipv4;    /* INETA PPP IPV4          */
   }
#endif
#endif
// to-do 03.07.10 KB - remove this subroutine
} /* end m_session_new_params()                                        */
#endif

/* put a warning related to the session to the console                 */
extern "C" void m_radius_warning( void * ap_conn1,
                                  int imp_error_number,
                                  const char *achp_format, ... ) {
   int        iml_len;                      /* length of message       */
   va_list    dsl_list;                     /* list of arguments       */
   char       chrl_msg[ 512 ];              /* area for message        */

#define ADSL_CLCONN1_G ((class clconn1 *) ap_conn1)
   va_start( dsl_list, achp_format );       /* build dsl_list of variable arguments */
   iml_len = m_hlvsnprintf( chrl_msg, sizeof(chrl_msg), ied_chs_utf_8,
                            achp_format, dsl_list );
   va_end( dsl_list );                      /* destroy list            */
   m_hlnew_printf( HLOG_XYZ1, "HWSPRA%03dW GATE=%(ux)s SNO=%08d INETA=%s radius %.*(u8)s",
                   imp_error_number,
                   ADSL_CLCONN1_G->adsc_gate1 + 1,
                   ADSL_CLCONN1_G->dsc_co_sort.imc_sno,
                   ADSL_CLCONN1_G->chrc_ineta,
                   iml_len, chrl_msg );
   return;                                  /* all done                */
#undef ADSL_CLCONN1_G
} /* end m_radius_warning()                                            */

/* put a warning related to the session to the console for LDAP        */
extern "C" void m_ldap_warning( void * ap_conn1,
                                int imp_error_number,
                                const char *achp_format, ... ) {
} /* end m_ldap_warning()                                              */

/* put a informational message related to the session to the console for LDAP */
extern "C" void m_ldap_info( void * ap_conn1,
                             int imp_error_number,
                             const char *achp_format, ... ) {
} /* end m_ldap_info()                                                 */

/* query the OS, number of CPUs                                        */
extern "C" int m_get_no_cpu( void ) {
   SYSTEM_INFO dsl_systeminfo;              /* query OS                */

   GetSystemInfo( &dsl_systeminfo );
   return dsl_systeminfo.dwNumberOfProcessors;
} /* end m_get_no_cpu()                                                */

extern PTYPE UNSIG_MED m_get_ineta_single( char *achp1 ) {
   UNSIG_MED  uml_ineta;                    /* INETA to be returned    */
   struct hostent *adsl_hostentry;          /* for gethostbyname()     */

   uml_ineta = IP_inet_addr( achp1 );
   if (uml_ineta == 0XFFFFFFFF) {           /* invalid IP-address      */
     adsl_hostentry = IP_gethostbyname( achp1 );
     if (adsl_hostentry) {                  /* API call successful     */
       uml_ineta = *((UNSIG_MED *) *(adsl_hostentry->h_addr_list) );
     }
   }
   return uml_ineta;
} /* end m_get_ineta_single()                                          */

#ifdef OLD01
extern PTYPE UNSIG_MED m_get_ineta_dotted( char *achp1 ) {
   return IP_inet_addr( achp1 );
} /* end m_get_ineta_dotted()                                          */
#endif

/* start the IP interface of the program                               */
static void m_start_ip( void ) {
   WORD     wVersionRequested;
   WSADATA  wsaData;
   int      rcu;
   int      iu1;
   int      iu2;
   BOOL     bou1;

   /* Initialize with sockets.                                         */
   cl_tcp_r::loaddll();                     /* load dll                */
   LoadWinSockFunctions();
   bou1 = FALSE;                            /* do not try again        */
#ifdef HL_IPV6
   bog_ipv6 = FALSE;
#endif
   iu1 = iu2 = 1;
#ifdef HL_IPV6
   if (cl_tcp_r::hws2mod != NULL) {         /* Handle to ws2_32.dll    */
     iu1 = 2;
     iu2 = 2;
     bou1 = TRUE;                           /* try again if failed     */
     bog_ipv6 = TRUE;
   }

   ptrystart:
#endif
   wVersionRequested = MAKEWORD( iu1, iu2 );
   rcu = IP_WSAStartup( wVersionRequested, &wsaData );
   if (rcu != 0) {
     IP_WSACleanup();
#ifdef HL_IPV6
     if (bou1) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPIP001I WSAStartup for IPV6 failed with code %d / retry", rcu );
       iu2 = 0;
       bou1 = FALSE;                        /* do not try again        */
       bog_ipv6 = FALSE;
       goto ptrystart;
     }
#endif
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP002WI WSAStartup failed with code %d", rcu );
     m_end_proc();
     fflush( stdout );
     ExitProcess( 1 );
   }
#ifdef HL_IPV6
   if (wsaData.wHighVersion < wVersionRequested) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP003I WSAStartup returned Version %04X", wsaData.wHighVersion );
     if (bou1) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPIP004I IPV6 not supported" );
       bog_ipv6 = FALSE;
     }
   }
   if (bog_ipv6) {
     bou1 = loadws_IPV6_functions();
     if (bou1 == FALSE) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPIP005I cannot load IPV6 functions - IPV6 not supported" );
       bog_ipv6 = FALSE;
     }
   }
#endif
#ifdef TRACEHL9
   bog_ipv6 = FALSE;                         /* for test bind           */
#endif
} /* end m_start_ip()                                                  */

 //-------------------------------------------
 // LoadWinSockFunctions()
 // - Die WinSock-Funktionen werden dynamisch auf function-pointers geladen.
 // - Es wird zun�chst versucht die Funktionen aus
 //   Winsock2 = WS2_32.DLL zu laden.
 // - Wird die Winsock2-DLL jedoch nicht gefunden, dann werden die Funktionen
 //   aus WSOCK32.DLL geladen.
 //-------------------------------------------
static void LoadWinSockFunctions(void) {
   DWORD   nResult;

   if (cl_tcp_r::hws2mod != NULL) {         /* Handle to ws2_32.dll    */
     hInstWinsockDll = (HINSTANCE) cl_tcp_r::hws2mod;
   } else {
     //-----------------------------------------------------------
     // Winsock2 NOT found
     // so lets take us WinSock = WSOCK_32.DLL
     //-----------------------------------------------------------

     hInstWinsockDll = LoadLibraryA( "WSOCK32.DLL" );
     if (hInstWinsockDll <= (HINSTANCE) HINSTANCE_ERROR) {
       m_hlnew_printf( HLOG_XYZ1, "HWSPIP010W Library WSOCK32 not available. RC: %d", hInstWinsockDll );
       ExitProcess( 1 );
     }
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP011I Library WSOCK32 loaded" );
   }
   lpfnWSAStartup = (fnIP_WSAStartup) GetProcAddress((HINSTANCE)hInstWinsockDll, "WSAStartup");
   if (lpfnWSAStartup == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP020W WSAStartup - function not found %d", nResult );
     return ;
   }
   lpfnWSACleanup = (fnIP_WSACleanup) GetProcAddress((HINSTANCE)hInstWinsockDll, "WSACleanup");
   if (lpfnWSACleanup == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP021W WSACleanup - function not found %d", nResult );
     return ;
   }
   lpfnsocket = (fnIP_socket) GetProcAddress((HINSTANCE)hInstWinsockDll, "socket");
   if (lpfnsocket == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP022W socket - function not found %d", nResult );
     return ;
   }
   lpfnlisten = (fnIP_listen) GetProcAddress((HINSTANCE)hInstWinsockDll, "listen");
   if (lpfnlisten == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP023W listen - function not found %d", nResult );
     return ;
   }
   lpfnaccept = (fnIP_accept) GetProcAddress((HINSTANCE)hInstWinsockDll, "accept");
   if (lpfnaccept == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP024W accept - function not found %d", nResult );
     return ;
   }
   lpfnsend = (fnIP_send) GetProcAddress((HINSTANCE)hInstWinsockDll, "send");
   if (lpfnsend == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP025W send - function not found %d", nResult );
     return ;
   }
   lpfnrecv = (fnIP_recv) GetProcAddress((HINSTANCE)hInstWinsockDll, "recv");
   if (lpfnrecv == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP026W recv - function not found %d", nResult );
     return ;
   }
   lpfnshutdown = (fnIP_shutdown) GetProcAddress((HINSTANCE)hInstWinsockDll, "shutdown");
   if (lpfnshutdown == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP027W shutdown - function not found %d", nResult );
     return ;
   }
   lpfnclosesocket = (fnIP_closesocket) GetProcAddress((HINSTANCE)hInstWinsockDll, "closesocket");
   if (lpfnclosesocket == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP028W closesocket - function not found %d", nResult );
     return ;
   }
   lpfnbind = (fnIP_bind) GetProcAddress((HINSTANCE)hInstWinsockDll, "bind");
   if (lpfnbind == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP029W bind - function not found %d", nResult );
     return ;
   }
   lpfnconnect = (fnIP_connect) GetProcAddress((HINSTANCE)hInstWinsockDll, "connect");
   if (lpfnconnect == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP030W connect - function not found %d", nResult );
     return ;
   }
   lpfnrecvfrom = (fnIP_recvfrom) GetProcAddress((HINSTANCE)hInstWinsockDll, "recvfrom");
   if (lpfnrecvfrom == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP031W recvfrom - function not found %d", nResult );
     return ;
   }
   lpfnsendto = (fnIP_sendto) GetProcAddress((HINSTANCE)hInstWinsockDll, "sendto");
   if (lpfnsendto == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP032W sendto - function not found %d", nResult );
     return ;
   }
   lpfnsetsockopt = (fnIP_setsockopt) GetProcAddress((HINSTANCE)hInstWinsockDll, "setsockopt");
   if (lpfnsetsockopt == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP033W setsockopt - function not found %d", nResult );
     return ;
   }
   lpfninet_addr = (fnIP_inet_addr) GetProcAddress((HINSTANCE)hInstWinsockDll, "inet_addr");
   if (lpfninet_addr == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP034W inet_addr - function not found %d", nResult );
     return ;
   }
   lpfnhtons = (fnIP_htons) GetProcAddress((HINSTANCE)hInstWinsockDll, "htons");
   if (lpfnhtons == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP035W htons - function not found %d", nResult );
     return ;
   }
   lpfnntohs = (fnIP_ntohs) GetProcAddress((HINSTANCE)hInstWinsockDll, "ntohs");
   if (lpfnntohs == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP036W ntohs - function not found %d", nResult );
     return ;
   }
   lpfngethostbyname = (fnIP_gethostbyname) GetProcAddress((HINSTANCE)hInstWinsockDll, "gethostbyname");
   if (lpfngethostbyname == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP037W gethostbyname - function not found %d", nResult );
     return ;
   }
   lpfngethostbyaddr = (fnIP_gethostbyaddr) GetProcAddress((HINSTANCE)hInstWinsockDll, "gethostbyaddr");
   if (lpfngethostbyaddr == NULL) {
     nResult = GetLastError();
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP038W gethostbyaddr - function not found %d", nResult );
     return ;
   }
} /* end LoadWinSockFunctions()                                        */

#ifdef HL_IPV6
static BOOL loadws_IPV6_functions( void ) {
   lpfngetaddrinfo = (fnIP_getaddrinfo) GetProcAddress((HINSTANCE)hInstWinsockDll, "getaddrinfo" );
   if (lpfngetaddrinfo == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP080W getaddrinfo - function not found %d", GetLastError() );
     return FALSE;
   }
   lpfngetnameinfo = (fnIP_getnameinfo) GetProcAddress((HINSTANCE)hInstWinsockDll, "getnameinfo" );
   if (lpfngetnameinfo == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP081W getnameinfo - function not found %d", GetLastError() );
     return FALSE;
   }
   lpfngetsockname = (fnIP_getsockname) GetProcAddress((HINSTANCE)hInstWinsockDll, "getsockname" );
   if (lpfngetsockname == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP082W getsockname - function not found %d", GetLastError() );
     return FALSE;
   }
   lpfnfreeaddrinfo = (fnIP_freeaddrinfo) GetProcAddress((HINSTANCE)hInstWinsockDll, "freeaddrinfo" );
   if (lpfnfreeaddrinfo == NULL) {
     m_hlnew_printf( HLOG_XYZ1, "HWSPIP083W freeaddrinfo - function not found %d", GetLastError() );
     return FALSE;
   }
   return TRUE;
} /* end loadws_IPV6_functions()                                       */

#endif
// error callback routine
static void m_errorcallback( dsd_nblock_acc *, void *, char *, int, int ) // Error callback function.
{
// do-to 27.01.08 KB
   m_hl1_printf( "xbipgw16-%05d-W accept error",
                 __LINE__ );
   return;
} /* end m_errorcallback()                                             */

// accept callback routine
static void m_acceptcallback( dsd_nblock_acc * dsp_, void * vpp_userfld,
                              int imp_socket, struct sockaddr *adsp_soa, int imp_len_soa ) {
   BOOL       bol1;                         /* working-variable        */
   int        iml1;                         /* working-variable        */
   int        iml_session_no;               /* session no              */
   time_t     dsl_time_1;                   /* for time                */
#ifdef D_NAEGLE_ALGOR_OFF
   int ioptval;
#endif
   class clconn1 *adsl_conn1;               /* class created           */
   struct dsd_gate_1 *adsl_gate_1_w1;       /* gate of listen          */
   union {
     struct dsd_wsp_snmp_trap_conn_maxconn dsl_snmpt_conn_maxconn;  /* connection maxconn reached */
     struct dsd_wsp_snmp_trap_conn_thresh dsl_snmpt_conn_thresh;  /* connection threshold reached */
   };

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_acceptcallback() called",
                   __LINE__ );
#endif
   adsl_gate_1_w1 = ((struct dsd_gate_listen_1 *) vpp_userfld)->adsc_gate_1;  /* gate of this listen */
#ifdef D_REFUSE_CONNECT_1                   /* 25.06.07 KB             */
   adsl_gate_1_w1->i_session_max = audg1->i_session_cur = 1;
#endif
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nach Accept" );
#endif
   bol1 = TRUE;                             /* session is valid        */
#ifdef D_NAEGLE_ALGOR_OFF
// 13.03.2007, G.Oed
   ioptval = 1;
   if(IP_setsockopt(imp_socket,IPPROTO_TCP,TCP_NODELAY,
		    (const char *) (void *) &ioptval, sizeof(int)) != 0)
     m_hlnew_printf( HLOG_XYZ1, "TCPAThread: failed to set accepted socket TCP_NODELAY!");
   else
     m_hlnew_printf( HLOG_XYZ1, "TCPAThread: accepted socket set to TCP_NODELAY");
#endif // defined NAGLE_ALGOR_OFF
   EnterCriticalSection( &adsl_gate_1_w1->dcritsect );
   adsl_gate_1_w1->i_session_cos++;         /* count start of session  */
   if (   (adsl_gate_1_w1->i_session_max)
       && (adsl_gate_1_w1->i_session_cur >= adsl_gate_1_w1->i_session_max)) {
     bol1 = FALSE;                          /* session not valid       */
     adsl_gate_1_w1->i_session_exc++;       /* count times exceeded    */
   } else {
     adsl_gate_1_w1->i_session_cur++;       /* count current session   */
     if (adsl_gate_1_w1->i_session_cur > adsl_gate_1_w1->i_session_mre)
       adsl_gate_1_w1->i_session_mre = adsl_gate_1_w1->i_session_cur;
     ins_session_no++;                      /* get new session no      */
     iml_session_no = ins_session_no;
   }
/* 19.12.04 KB - session-ID UUUUU */
   LeaveCriticalSection( &adsl_gate_1_w1->dcritsect );
   if (bol1 == FALSE) {                     /* do not start session    */
     D_TCP_CLOSE( imp_socket );
     m_hlnew_printf( HLOG_XYZ1, "HWSPS001W GATE=%(ux)s maximum number of session exceeded",
                     adsl_gate_1_w1 + 1 );
     time( &dsl_time_1 );                   /* get current time        */
     iml1 = adss_loconf_1_fill->imc_time_rda;  /* <time-repeat-delay-alert> */
     if (iml1 <= 0) iml1 = DEF_TIME_SNMP_TRAP_RDA;  /* set default value */
     if (   (adsl_gate_1_w1->imc_snmpt_epoch_conn_maxconn != 0)
         && ((adsl_gate_1_w1->imc_snmpt_epoch_conn_maxconn + iml1) > dsl_time_1)) {
       return;                              /* trap already sent       */
     }
     adsl_gate_1_w1->imc_snmpt_epoch_conn_maxconn = dsl_time_1;  /* set current time SNMP Trap */
     memset( &dsl_snmpt_conn_maxconn, 0, sizeof(struct dsd_wsp_snmp_trap_conn_maxconn) );  /* connection maxconn reached */
     dsl_snmpt_conn_maxconn.imc_no_conn = adsl_gate_1_w1->i_session_cur;  /* current number of connections */
     dsl_snmpt_conn_maxconn.dsc_conn_name.ac_str = adsl_gate_1_w1 + 1;  /* address of string */
     dsl_snmpt_conn_maxconn.dsc_conn_name.imc_len_str = -1;  /* length string in elements */
     dsl_snmpt_conn_maxconn.dsc_conn_name.iec_chs_str = ied_chs_utf_16;  /* character set string */
     m_snmp_trap_1( ied_wsp_snmp_trap_conn_maxconn, &dsl_snmpt_conn_maxconn );  /* send the Trap */
     return;                                /* all done                */
   }
   adsl_conn1 = new clconn1( adsl_gate_1_w1, (struct dsd_gate_listen_1 *) vpp_userfld,
                             adsp_soa, imp_len_soa,
                             imp_socket, iml_session_no );
   if (adsl_conn1 == NULL) {                /* constructor failed      */
     D_TCP_CLOSE( imp_socket );
     EnterCriticalSection( &adsl_gate_1_w1->dcritsect );
     adsl_gate_1_w1->i_session_cur--;       /* count current session   */
     LeaveCriticalSection( &adsl_gate_1_w1->dcritsect );
     m_hlnew_printf( HLOG_XYZ1, "HWSPS002W GATE=%(ux)s SNO=%08d constructor clconn1 failed - short on memory",
                     adsl_gate_1_w1 + 1, iml_session_no );
     return;                                /* all done                */
   }
   while (   (adsl_gate_1_w1->imc_thresh_session != 0)  /* threshold-session configured */
          && (adsl_gate_1_w1->i_session_cur >= adsl_gate_1_w1->imc_thresh_session)) {  /* threshold-session reached */
     time( &dsl_time_1 );                   /* get current time        */
     iml1 = adss_loconf_1_fill->imc_time_rda;  /* <time-repeat-delay-alert> */
     if (iml1 <= 0) iml1 = DEF_TIME_SNMP_TRAP_RDA;  /* set default value */
     if (   (adsl_gate_1_w1->imc_snmpt_epoch_conn_thresh != 0)
         && ((adsl_gate_1_w1->imc_snmpt_epoch_conn_thresh + iml1) > dsl_time_1)) {
       break;                               /* trap already sent       */
     }
     adsl_gate_1_w1->imc_snmpt_epoch_conn_thresh = dsl_time_1;  /* set current time SNMP Trap */
     memset( &dsl_snmpt_conn_thresh, 0, sizeof(struct dsd_wsp_snmp_trap_conn_thresh) );  /* connection threshold reached */
     dsl_snmpt_conn_thresh.imc_no_conn = adsl_gate_1_w1->i_session_cur;  /* current number of connections */
     dsl_snmpt_conn_thresh.dsc_conn_name.ac_str = adsl_gate_1_w1 + 1;  /* address of string */
     dsl_snmpt_conn_thresh.dsc_conn_name.imc_len_str = -1;  /* length string in elements */
     dsl_snmpt_conn_thresh.dsc_conn_name.iec_chs_str = ied_chs_utf_16;  /* character set string */
     m_snmp_trap_1( ied_wsp_snmp_trap_conn_thresh, &dsl_snmpt_conn_thresh );  /* send the Trap */
     break;
   }
#ifdef NOT_YET_080407
   int        iml_rc;                       /* return code             */
   struct dsd_connect *adsl_connect_w1;     /* for TCP connection      */
   char       chrl_date_time[ 32 ];         /* for date and time       */

   adsl_connect_w1 = (struct dsd_connect *) malloc( sizeof(struct dsd_connect) );
   memset( adsl_connect_w1, 0, sizeof(struct dsd_connect) );
   adsl_connect_w1->dsc_timer.amc_compl = &m_timeout_tcp;  /* set routine for timeout */
   dss_critsect_main.m_enter();             /* enter CriticalSection   */
   ims_session_no++;                        /* get new session no      */
   adsl_connect_w1->imc_session_no = ims_session_no;  /* get new session no */
   adsl_connect_w1->adsc_next = adss_conn_1_anchor;  /* get anchor connection chain */
   adss_conn_1_anchor = adsl_connect_w1;    /* set new anchor connection chain */
   dss_critsect_main.m_leave();             /* leave CriticalSection   */
#ifdef XYZ1
   adsl_connect_w1->imc_usage_count = 1;    /* usage count two half-sessions */
   adsl_connect_w1->imc_dropped_packet_client = -1;  /* number of packets dropped by the client not set */
#endif
   m_get_date_time( chrl_date_time );
   iml_rc = m_ip_getnameinfo( (struct sockaddr *) adsp_soa, imp_len_soa,
                              adsl_connect_w1->chrc_client_ineta, sizeof(adsl_connect_w1->chrc_client_ineta),
                              0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hl1_printf( "xbipgw16-%05d-W getnameinfo Error %d %d",
                   __LINE__, iml_rc, D_TCP_ERROR );
     strcpy( adsl_connect_w1->chrc_client_ineta, "???" );
   }
   m_hl1_printf( "xbipgw16-%05d-I %s connect-in INETA %s SNO=%08d.",
                 __LINE__, chrl_date_time,
                 adsl_connect_w1->chrc_client_ineta, adsl_connect_w1->imc_session_no );
   iml_rc = adsl_connect_w1->dsc_tcpco1.m_startco_fb(
                imp_socket,
                &dss_tcpcomp_cb1,
                adsl_connect_w1 );
   if (iml_rc) {                            /* error occured           */
     m_hl1_printf( "xbipgw16-%05d-W INETA %s SNO=%08d m_startco_fb() failed",
                   __LINE__,
                   adsl_connect_w1->chrc_client_ineta, adsl_connect_w1->imc_session_no );
     m_cleanup_tcp( adsl_connect_w1 );      /* cleanup again           */
     return;                                /* all done                */
   }
   adsl_connect_w1->dsc_tcpco1.m_recv();    /* start receiving         */
   adsl_connect_w1->dsc_timer.ilcwaitmsec = TIMER_TCP_INIT;   /* wait in milliseconds */
   m_time_set( &adsl_connect_w1->dsc_timer, FALSE );  /* set timeout now */
#endif
   return;                                  /* all done                */
} /* end m_acceptcallback()                                            */

/* error message when TCPCOMP connect failed                           */
static void m_cb_tcpc_conn_err( dsd_tcpcomp *adsp_tcpco, void * vpp_userfld,
   struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_current_index, int imp_total_index, int imp_errno ) {
   int        iml_rc;                       /* return code             */
   char       *achl_msg_no;                 /* message number          */
   char       *achl_conn_type;              /* message type of connecttion */
   char       *achl_msg_01;                 /* part one of message     */
   HL_WCHAR   *awcl_server;                 /* name of server          */
   char       *achl_doing;                  /* message what it is doing */
   class clconn1 *adsl_conn1;               /* class created           */
   char       chrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */

#define ADSL_TCP_R ((class cl_tcp_r *) vpp_userfld)
   adsl_conn1 = (class clconn1 *) ADSL_TCP_R->aclconn1;  /* get connection */
   iml_rc = getnameinfo( adsp_soa, imp_len_soa,
                         chrl_ineta, sizeof(chrl_ineta),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s getnameinfo target server failed with code %d.",
                     adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta,
                     iml_rc, D_TCP_ERROR );
     strcpy( chrl_ineta, "???" );
   }
   achl_msg_no = "???";                     /* message number          */
   achl_conn_type = "???";                  /* message type of connection */
   switch (adsl_conn1->iec_st_ses) {        /* status server           */
     case clconn1::ied_ses_wait_conn_s_static:  /* wait for static connect to server */
       achl_msg_no = "HWSPS027W";           /* message number          */
       achl_conn_type = "(static)";         /* message type of connecttion */
       break;
     case clconn1::ied_ses_wait_conn_s_dynamic:  /* wait for dynamic connect to server */
       achl_msg_no = "HWSPS055W";           /* message number          */
       achl_conn_type = "(dynamic)";        /* message type of connecttion */
       break;
   }
   achl_msg_01 = "";                        /* part one of message     */
   awcl_server = (HL_WCHAR *) L"";
   if (adsl_conn1->adsc_server_conf_1->inc_len_name > 0) {  /* length of name bytes */
     achl_msg_01 = " server ";              /* part one of message     */
     awcl_server = adsl_conn1->adsc_server_conf_1->awcc_name;  /* address of name */
   }
   achl_doing = ".";
   if ((imp_current_index + 1) < imp_total_index) {
     achl_doing = " - try next INETA from DNS";  /* set additional text */
   } else if (imp_total_index > 1) {
     achl_doing = " - was last INETA from DNS";  /* set additional text */
   }
   m_hlnew_printf( HLOG_WARN1, "%s GATE=%(ux)s SNO=%08d INETA=%s connect %s to%s%(ux)s INETA %s failed with code %d%s",
                   achl_msg_no,
                   adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta,
                   achl_conn_type, achl_msg_01, awcl_server, chrl_ineta,
                   imp_errno, achl_doing );
#ifdef DEBUG_120121_01                      /* connect callback not called - TCPCOMP error */
   ADSL_TCP_R->m_set_conn_error( imp_errno );
#endif
   return;
#ifdef XYZ1
   ADSL_TCP_R->m_post_netw_post_1( DEF_NETW_POST_1_TCPCOMP_CONN_ERR );  /* posted for TCPCOMP connect error */
#endif
#undef ADSL_TCP_R
} /* end m_cb_tcpc_conn_err()                                               */

/** TCPCOMP connect callback function                                  */
static void m_cb_tcpc_connect( dsd_tcpcomp *adsp_tcpco, void *vpp_userfld,
#ifndef B121120
                               struct dsd_target_ineta_1 *, void * ap_free_ti1,  /* INETA to free */
#endif
                               struct sockaddr *adsp_soa, socklen_t imp_len_soa, int imp_error ) {
   int        iml_rc;                       /* return code             */
   char       *achl_msg_no;                 /* message number          */
   char       *achl_conn_type;              /* type of connect         */
   char       *achl_msg_01;                 /* part one of message     */
#ifdef X101214_XX
   enum ied_state_server iel_st_ses;        /* status server           */
#endif
   HL_WCHAR   *awcl_server;                 /* name of server          */
   class clconn1 *adsl_conn1;               /* class created           */
   struct dsd_netw_post_1 *adsl_netw_post_1;  /* structure to post from network callback */
   char       chrl_ineta[ LEN_DISP_INETA ];  /* internet-address char  */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_cb_tcpc_connect( %p , %p , %p, %d , %d ) called",
                   __LINE__, adsp_tcpco, vpp_userfld, adsp_soa, imp_len_soa, imp_error );
#endif
#define ADSL_TCP_R ((class cl_tcp_r *) vpp_userfld)
#ifndef B121120
   if (ap_free_ti1) free( ap_free_ti1 );    /* INETA to free           */
#endif
   adsl_conn1 = (class clconn1 *) ADSL_TCP_R->aclconn1;  /* get connection */
   if (imp_error) {                         /* called with error       */
     ADSL_TCP_R->m_set_conn_error( imp_error );
// to-do 27.12.11 KB activate work-thread of connection ???
     return;                                /* all done                */
   }
#ifndef B131125
   memcpy( &ADSL_TCP_R->dsc_soa, adsp_soa, imp_len_soa );  /* address information session */
#endif
   iml_rc = getnameinfo( adsp_soa, imp_len_soa,
                         chrl_ineta, sizeof(chrl_ineta),
                         0, 0, NI_NUMERICHOST );
   if (iml_rc) {                            /* error occured           */
     m_hlnew_printf( HLOG_WARN1, "HWSPSnnnW GATE=%(ux)s SNO=%08d INETA=%s getnameinfo target server failed with code %d.",
                     adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta,
                     iml_rc, D_TCP_ERROR );
     strcpy( chrl_ineta, "???" );
   }
   achl_msg_no = "???";                     /* message number          */
   achl_conn_type = "???";
   switch (adsl_conn1->iec_st_ses) {        /* status server           */
     case clconn1::ied_ses_wait_conn_s_static:  /* wait for static connect to server */
       achl_msg_no = "HWSPS028I";           /* message number          */
       achl_conn_type = "static";           /* type of connect         */
#ifdef X101214_XX
       iel_st_ses = clconn1::ied_ses_start_server_1;  /* status server continue */
#endif
       break;
     case clconn1::ied_ses_wait_conn_s_dynamic:  /* wait for dynamic connect to server */
       achl_msg_no = "HWSPS060I";           /* message number          */
       achl_conn_type = "dynamic";          /* type of connect         */
#ifdef X101214_XX
       iel_st_ses = clconn1::ied_ses_start_dyn_serv_1;  /* start connection to server part one dynamic */
#endif
       break;
   }
   achl_msg_01 = "";                        /* part one of message     */
   awcl_server = (HL_WCHAR *) L"";
   if (adsl_conn1->adsc_server_conf_1->inc_len_name > 0) {  /* length of name bytes */
     achl_msg_01 = " server ";              /* part one of message     */
     awcl_server = adsl_conn1->adsc_server_conf_1->awcc_name;  /* address of name */
   }
   m_hlnew_printf( HLOG_XYZ1, "%s GATE=%(ux)s SNO=%08d INETA=%s connect (%s) to%s%(ux)s INETA %s successful",
                   achl_msg_no,
                   adsl_conn1->adsc_gate1 + 1,
                   adsl_conn1->dsc_co_sort.imc_sno,
                   adsl_conn1->chrc_ineta,
                   achl_conn_type, achl_msg_01, awcl_server, chrl_ineta );
   ADSL_TCP_R->m_did_conn_1();              /* connect successful      */
#ifndef X101214_XX
   adsl_conn1->iec_st_ses = clconn1::ied_ses_start_server_1;  /* status server continue */
#else
   adsl_conn1->iec_st_ses = iel_st_ses;     /* status server           */
#endif
#ifdef OLD_1112
   if (adsl_conn1->adsc_radqu) {            /* radius still active     */
     adsl_conn1->adsc_radqu->boc_did_connect = TRUE;  /* did connect   */
   }
#endif
#ifndef OLD_1112
   if (adsl_conn1->adsc_wsp_auth_1) {       /* authentication active   */
     adsl_conn1->adsc_wsp_auth_1->boc_did_connect = TRUE;  /* did connect */
     adsl_conn1->adsc_wsp_auth_1->boc_notify = TRUE;  /* notify authentication routine */
   }
#endif
   if (adsl_conn1->adsc_int_webso_conn_1) {  /* connect for WebSocket applications - internal */
#ifdef DEBUG_150220_01                      /* Dod connect too earl    */
     m_hlnew_printf( HLOG_TRACE1, "DEBUG_150220_01 l%05d m_cb_tcpc_connect()", __LINE__ );
#endif
     adsl_conn1->adsc_int_webso_conn_1->boc_did_connect = TRUE;  /* did connect */
     adsl_conn1->adsc_int_webso_conn_1->boc_notify = TRUE;  /* notify SDH  */
   }
   ADSL_TCP_R->m_post_netw_post_1( DEF_NETW_POST_1_TCPCOMP_CONN_OK );  /* posted for TCPCOMP connect ok */
#ifdef DEBUG_100830_02
#ifdef TRY_DEBUG_100830_02
   m_hlnew_printf( HLOG_XYZ1, "m_cb_tcpc_connect() l%05d before m_act_thread_1()",
                   __LINE__ );
#endif
#endif
   m_act_thread_1( adsl_conn1 );            /* activate thread for session */
   return;                                  /* all done                */
#undef ADSL_TCP_R
} /* end m_cb_tcpc_connect()                                              */

/**
 * Send callback function. Resend buffers.
 * @param ads_con corresponding tcpcomp object for nonblocking IO.
 * @param ads_data corresponding condata object.
 */
static void m_cb_tcpc_send( dsd_tcpcomp* ads_con, void * vpp_userfld ) {
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_cb_tcpc_send() called",
                   __LINE__ );
#endif
// ((class cl_tcp_r *) vpp_userfld)->boc_tcpc_act = FALSE;  /* TCPCOMP no more active */
#define ADSL_TCP_R ((class cl_tcp_r *) vpp_userfld)
   if (ADSL_TCP_R->adsc_sdhc1_send == NULL) return;  /* nothing to send */
#ifdef B080407
   ADSL_TCP_R->bo_may_send = FALSE;
#endif
   ADSL_TCP_R->m_send_gather( (struct dsd_sdh_control_1 *) ADSL_TCP_R->adsc_sdhc1_send, TRUE );
#undef ADSL_TCP_R
#ifdef NOT_YET_080407
   int        iml_rc;                       /* return code             */
#ifdef XYZ1
   BOOL       bol1;
   struct dsd_tcp_session *adsl_tcp_se_w1;  /* TCP session             */
   struct dsd_tcp_session *adsl_tcp_se_w2;  /* TCP session             */
#endif

#ifdef TRACEHL1
   m_hl1_printf( "xbipgw16-%05d-T Resend data", __LINE__ );
#endif
#ifdef XYZ1
   adsl_tcp_se_w1 = (struct dsd_tcp_session *) vpp_userfld;
   adsl_tcp_se_w2 = adsl_tcp_se_w1->adsc_tcp_se_p;  /* get partner     */
   if (adsl_tcp_se_w2 == NULL) return;      /* no more partner         */
   bol1 = m_send_data( adsl_tcp_se_w2 );
   if (bol1 == FALSE) return;               /* do not restart receive  */
   adsl_tcp_se_w2->dsc_tcpco1.m_recv();
#endif
#define ADSL_CONNECT_G ((struct dsd_connect *) vpp_userfld)

   p_send_00:                               /* check if something to send */
   if (ADSL_CONNECT_G->imc_no_send_buf_1 == 0) return;  /* so many send buffers */

   p_send_20:                               /* send one buffer         */
   iml_rc = ADSL_CONNECT_G->dsc_tcpco1.m_send( ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ].achc_data_cur,
              ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ].achc_data_end - ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ].achc_data_cur );
   if (iml_rc < 0) {                        /* error occured           */
     return;                                /* nothing more to do      */
   }
   ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ].achc_data_cur += iml_rc;  /* add data sent */
   if (ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ].achc_data_cur < ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ].achc_data_end) {  /* not all data sent */
     ADSL_CONNECT_G->dsc_tcpco1.m_sendnotify();
     return;                                /* all done                */
   }
   m_proc_free( ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ].achc_handle );  /* free buffer */
   dss_critsect_main.m_enter();             /* enter CriticalSection   */
   ADSL_CONNECT_G->imc_no_send_buf_1++;     /* decrement send buffers  */
   if (ADSL_CONNECT_G->imc_no_send_buf_1) {  /* so many send buffers   */
     memmove( &ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ],
              &ADSL_CONNECT_G->dsrc_send_buf_1[ 1 ],
              ADSL_CONNECT_G->imc_no_send_buf_1 * sizeof(ADSL_CONNECT_G->dsrc_send_buf_1[ 0 ]) );
   }
   dss_critsect_main.m_leave();             /* leave CriticalSection   */
   goto p_send_00;                          /* check if something to send */
#undef ADSL_CONNECT_G
#endif
} // void m_cdsend(dsd_tcpcomp*, void*)

/**
 * Get receive buffer callback function.
 * @param ads_con corresponding tcpcomp object for nonblocking IO.
 * @param ads_data corresponding condata object.
 * @param aavo_handle pointer to the buffer handle field of the tcpcomp object.
 * @param aach_data pointer to the address field of the tcpcomp object.
 * @param aaim_datalen pointer to the data length field of the tcpcomp object.
 * @return number of bytes that may be received. Must be <= size of field, 0 = receive not allowed
 * pointed to by aach_data.
 */
static int m_cb_tcpc_getbuf(dsd_tcpcomp* ads_con,
               void * vpp_userfld,
               void** aavo_handle,
               char** aach_data,
               int** aaim_datalen)
{
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_cb_tcpc_getbuf() called",
                   __LINE__ );
#endif
   *aavo_handle = m_proc_alloc();
#ifdef TRACEHL_STOR_USAGE
   m_proc_mark_1( *aavo_handle, "m_cb_tcpc_getbuf" );
#endif
   *aach_data = (char *) *aavo_handle + sizeof(struct dsd_sdh_control_1) + sizeof(struct dsd_gather_i_1);
   *aaim_datalen = (int *) *aavo_handle;
   return LEN_TCP_RECV - sizeof(struct dsd_sdh_control_1) - sizeof(struct dsd_gather_i_1);
#ifdef NOT_YET_080407
   void *     ac_buffer;                    /* buffer returned         */
#ifdef XYZ1
   struct dsd_tcp_session *adsl_tcp_se_w1;  /* TCP session             */

   adsl_tcp_se_w1 = (struct dsd_tcp_session *) vpp_userfld;
#ifdef TRACEHL1
   m_hl1_printf( "Receive buffer requested" );
#endif
#ifdef XYZ1
   if(bo_verbose)
   {
      printf("Receive buffer requested for socket %d.\n", ((condata*)ads_data)->ds_sock);
   }
   if(!((condata*)ads_data)->bo_receive)
   {
      if(bo_verbose)
      {
         printf("Receive not allowed.\n");
      }
      return 0;
   }
   ((condata*)ads_data)->ach_conbuffer = (char*)malloc(DEFAULT_BUFFERSIZE);
   if(!((condata*)ads_data)->ach_conbuffer)
   {
      if(bo_verbose)
      {
         printf("Unable to allocate storage.\n");
      }
      // Since there is only one buffer, this means, that this connection
      // is dead now. How could it be reactivated? Or should we simply kill it?
      return 0;
   }
   ((condata*)ads_data)->ach_startdata = ((condata*)ads_data)->ach_conbuffer;
   *aavo_handle = ((condata*)ads_data)->ach_conbuffer;
   *aaim_datalen = &(((condata*)ads_data)->im_bufferlen);
   *aach_data = ((condata*)ads_data)->ach_startdata;
   return DEFAULT_BUFFERSIZE;
#endif
// return 0;
   adsl_tcp_se_w1->achc_buffer = (char *) malloc( D_BUFFER_LEN );  /* receive buffer */
   if (adsl_tcp_se_w1->achc_buffer == NULL) return 0;  /* could not allocate memory */
   adsl_tcp_se_w1->achc_send_cur = adsl_tcp_se_w1->achc_buffer;  /* current position to send */
   *aach_data = adsl_tcp_se_w1->achc_buffer;
   *aavo_handle = adsl_tcp_se_w1->achc_buffer;
   *aaim_datalen = &adsl_tcp_se_w1->imc_len_recv;  /* length received  */
#endif
   ac_buffer = m_proc_alloc();              /* allocate buffer         */
   if (ac_buffer == NULL) return 0;         /* no memory available     */
   *aach_data = (char *) ac_buffer + sizeof(struct dsd_rec_buf);
   *aavo_handle = ac_buffer;
   *aaim_datalen = (int *) ac_buffer;       /* length received         */
   return D_BUFFER_LEN - sizeof(struct dsd_rec_buf);
#endif
} // int m_cb_tcpc_getbuf(dsd_tcpcomp*, void*, void**, char**,  int**)

/**
 * Receive callback function.
 * @param ads_con corresponding tcpcomp object for nonblocking IO.
 * @param ads_data corresponding condata object.
 * @param avo_handle handle of buffer.
 * @return TRUE, if more data should be received, otherwise FALSE.
 */
static int m_cb_tcpc_recv( dsd_tcpcomp* ads_con,
             void * vpp_userfld,
             void * avo_handle )
{
   int        iml_len_recv;                 /* length received         */

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_cb_tcpc_recv() called",
                   __LINE__ );
#endif
   iml_len_recv = 0;                        /* length received         */
   if (avo_handle) {                        /* buffer passed           */
     iml_len_recv = *((int *) avo_handle);  /* get length passed       */
   }
#ifdef TRACEHL_101209
   m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T m_cb_tcpc_recv() called iml_len_recv=%d/0X%p.",
                   __LINE__, iml_len_recv, iml_len_recv );
#endif
   return ((class clconn1 *) ((class cl_tcp_r *) vpp_userfld)->aclconn1)
            ->rec_complete( (class cl_tcp_r *) vpp_userfld,
                            (struct dsd_sdh_control_1 *) avo_handle,
                            iml_len_recv );
} /* end m_cb_tcpc_recv()                                              */

/**
 * Error callback function.
 * @param ads_con corresponding tcpcomp object for nonblocking IO.
 * @param ads_data corresponding condata object.
 * @param im_errno error number.
 * @param im_where Error location. (See tcpcomp::ERRORAT_XXXX flags)
 */
static void m_cb_tcpc_error( dsd_tcpcomp* ads_con,
               void * vpp_userfld,
               char * achp_error,
               int imp_error,
               int imp_where )
{
   class clconn1 *adsl_conn_w1;             /* connection              */
   char       *achl_cl_se;                  /* client or server        */

   adsl_conn_w1 = (class clconn1 *) ((class cl_tcp_r *) vpp_userfld)->aclconn1;  /* address of calling */
   achl_cl_se = "client";                   /* client or server        */
   if (((class cl_tcp_r *) vpp_userfld) != &adsl_conn_w1->dcl_tcp_r_c) {  /* class to receive client */
     achl_cl_se = "server";                 /* client or server        */
   }
   m_hlnew_printf( HLOG_WARN1, "HWSPS160W GATE=%(ux)s SNO=%08d INETA=%s %s TCP error %s %d %d.",
                   adsl_conn_w1->adsc_gate1 + 1, adsl_conn_w1->dsc_co_sort.imc_sno, adsl_conn_w1->chrc_ineta,
                   achl_cl_se,
                   achp_error, imp_error, imp_where );
} /* end m_cb_tcpc_error()                                             */

/* TCPCOMP cleanup callback function                                   */
static void m_cb_tcpc_cleanup( dsd_tcpcomp *adsp_tcpco, void *vpp_userfld ) {
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_TRACE1, "IBIPGW08-l%05d-T m_cb_tcpc_cleanup() called",
                   __LINE__ );
#endif
#ifdef TRACE_090506
#define ADSL_CONNECT_G ((class clconn1 *) ((class cl_tcp_r *) vpp_userfld)->aclconn1)
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_cb_tcpc_cleanup() adsp_tcpco=%p vpp_userfld=%p ADSL_CONNECT_G=%p SNO=%08d.",
                   __LINE__, adsp_tcpco, vpp_userfld, ADSL_CONNECT_G, ADSL_CONNECT_G->dsc_co_sort.imc_sno );
#undef ADSL_CONNECT_G
#endif
// ((class cl_tcp_r *) vpp_userfld)->boc_tcpc_act = FALSE;  /* TCPCOMP no more active */
#define ADSL_TCP_R ((class cl_tcp_r *) vpp_userfld)
   ADSL_TCP_R->m_cleanup_1();               /* TCPCOMP no more active */
   ADSL_TCP_R->m_post_netw_post_1( DEF_NETW_POST_1_TCPCOMP_CLEANUP );  /* posted for TCPCOMP cleanup */
#undef ADSL_TCP_R
} /* end m_cb_tcpc_cleanup()                                                   */

#ifdef B121120
static void m_cb_tcpc_free_target_ineta( dsd_tcpcomp *adsp_tcpcomp, void *vpp_userfld,
                                         const struct dsd_target_ineta_1 *adsp_target_ineta_1 ) {
#ifdef XYZ1
15.11.10 KB is const struct dsd_target_ineta_1 *adsp_target_ineta_1 correct ???
#endif
   class clconn1 *adsl_conn_w1;             /* connection              */

   adsl_conn_w1 = (class clconn1 *) ((class cl_tcp_r *) vpp_userfld)->aclconn1;  /* address of calling */
   if (adsl_conn_w1->adsc_server_conf_1 == NULL) return;
   if (adsl_conn_w1->adsc_server_conf_1->inc_function != DEF_FUNC_DIR) return;
   if (adsl_conn_w1->adsc_server_conf_1->boc_dynamic) return;  /* dynamicly allocated */
   if (adsl_conn_w1->adsc_server_conf_1->boc_dns_lookup_before_connect == FALSE) return;  /* needs to solve INETA before connect */
   if (adsp_target_ineta_1 == adsl_conn_w1->adsc_server_conf_1->adsc_server_ineta) return;
#ifdef B101115
   free( adsp_target_ineta_1 );             /* free the memory         */
#else
   free( (void *) adsp_target_ineta_1 );    /* free the memory         */
#endif
   return;
} /* end m_cb_tcpc_free_target_ineta()                                 */
#endif

/**
* open the connection for listen
* parameter 1 and 2 is address of work area to return error-messages
* parameter 3 and 4 is for the routine to display the error messages
* parameter 5 is what to do when listen fails
* parameter 6 is the target structure
* parameter 7 is the source structure
* parameter 8 is the port to be used
*/
extern "C" enum ied_opli_ret m_open_listen( char *achp_work, int inp_len_work,
                                            amd_msgprog amp_msgproc, void * vpp_userfld,
                                            enum ied_lierr iep_lierr,
                                            struct dsd_gate_listen_1 *adsp_gate_listen_1,
                                            struct dsd_ineta_single_1 *adsp_ineta_s,
                                            int imp_port ) {
   int        iml1;                         /* working variable        */
   int        iml_rc;                       /* return code             */
   char       *achl1;                       /* working-variable        */
#ifdef XYZ1
#ifdef XYZ1
   BOOL       bol1;                         /* working variable        */
#endif
   int        iml1;                         /* working variable        */
   int        inl_no_socket;                /* number of sockets       */
   int        iml_listen_socket;            /* socket to be used       */
   int        iml_rc;                       /* return code             */
#ifdef HL_IPV6
   struct addrinfo dsl_addrinfo_w1;
   struct addrinfo *adsl_addrinfo_w2;
   struct addrinfo *adsl_addrinfo_w3;
   char       *achl_port;                   /* address of port         */
   char       chrl_port[12];                /* for temporary string port */
#endif
   struct sockaddr_in dsl_soin_listen;      /* address information */
// UUUU 27.03.06 KB
#ifdef HL_IPV6
   SOCKADDR_STORAGE dsl_soast_w1;
#endif
#endif

#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08 l%05d m_open_listen() called", __LINE__ );
#endif
#ifdef XYZ1
   amp_msgproc( vpp_userfld, "test", 0 );
   return ied_oplir_failure;
#else
   memset( adsp_gate_listen_1, 0, sizeof(struct dsd_gate_listen_1) );
   /* Get a socket for accepting connections.                          */
   adsp_gate_listen_1->imc_socket = IP_socket( adsp_ineta_s->usc_family, SOCK_STREAM, 0 );
   if (adsp_gate_listen_1->imc_socket < 0) {  /* error occured         */
     iml1 = adsp_gate_listen_1->imc_socket;
     if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
       iml1 = cl_tcp_r::afunc_wsaglerr();   /* get error code          */
     }
     _snprintf( achp_work, inp_len_work, "Socket() Error %d/%d - ignored",
                adsp_gate_listen_1->imc_socket, iml1 );
     amp_msgproc( vpp_userfld, achp_work, 7 );
     return ied_oplir_failure;              /* return error            */
   }
   adsp_gate_listen_1->dsc_soa.ss_family = adsp_ineta_s->usc_family;
#ifdef B160804
   ((struct sockaddr_in *) &adsp_gate_listen_1->dsc_soa)->sin_port = IP_htons( imp_port );
   achl1 = (char *) &((struct sockaddr_in *) &adsp_gate_listen_1->dsc_soa)->sin_addr;
   if (adsp_ineta_s->usc_family == AF_INET6) {
     achl1 = (char *) &((struct sockaddr_in6 *) &adsp_gate_listen_1->dsc_soa)->sin6_addr;
   }
#endif
#ifndef B160804
   if (adsp_ineta_s->usc_family == AF_INET) {
     ((struct sockaddr_in *) &adsp_gate_listen_1->dsc_soa)->sin_port = htons( imp_port );
     achl1 = (char *) &((struct sockaddr_in *) &adsp_gate_listen_1->dsc_soa)->sin_addr;
   } else if (adsp_ineta_s->usc_family == AF_INET6) {
     ((struct sockaddr_in6 *) &adsp_gate_listen_1->dsc_soa)->sin6_port = htons( imp_port );
     achl1 = (char *) &((struct sockaddr_in6 *) &adsp_gate_listen_1->dsc_soa)->sin6_addr;
   } else {
     _snprintf( achp_work, inp_len_work, "INETA invalid family %d - ignored",
                adsp_ineta_s->usc_family );
     amp_msgproc( vpp_userfld, achp_work, 9 );
     closesocket( adsp_gate_listen_1->imc_socket );
     adsp_gate_listen_1->imc_socket = -1;   /* mark as invalid         */
     return ied_oplir_failure;              /* return error            */
   }
#endif
   memcpy( achl1, adsp_ineta_s + 1, adsp_ineta_s->usc_length );
   iml_rc = IP_bind( adsp_gate_listen_1->imc_socket,
                     (struct sockaddr *) &adsp_gate_listen_1->dsc_soa,
                     sizeof(struct sockaddr_storage) );
   if (iml_rc != 0) {                       /* error occured           */
     iml1 = iml_rc;
     if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
       iml1 = cl_tcp_r::afunc_wsaglerr();   /* get error code          */
     }
     _snprintf( achp_work, inp_len_work, "Bind() port=%d Error %d/%d - ignored",
                imp_port, iml_rc, iml1 );
     amp_msgproc( vpp_userfld, achp_work, 8 );
     IP_closesocket( adsp_gate_listen_1->imc_socket );
     adsp_gate_listen_1->imc_socket = -1;   /* mark as invalid         */
     return ied_oplir_failure;              /* return error            */
   }
   return ied_oplir_ok;                     /* return success          */
#ifdef NOT_YET_080407
   struct sockaddr_storage dsc_soa;         /* address information listen */
   /* Bind the socket to the server address.                           */
   memset( (char *) &dsl_soin_listen, 0, sizeof(struct sockaddr_in) );
   dsl_soin_listen.sin_family = AF_INET;
   dsl_soin_listen.sin_port   = IP_htons( imp_port );
   dsl_soin_listen.sin_addr.s_addr = ump_multih;

   iml_rc = IP_bind( adsp_listen_ineta_1->imc_socket,
                     (struct sockaddr *) &dsl_soin_listen,
                     sizeof(dsl_soin_listen) );
   if (iml_rc != 0) {
     iml1 = iml_rc;
     if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
       iml1 = cl_tcp_r::afunc_wsaglerr();   /* get error code          */
     }
     _snprintf( achp_work, inp_len_work, "Bind() port=%d Error %d/%d - ignored",
                imp_port, iml_rc, iml1 );
     amp_msgproc( vpp_userfld, achp_work, 8 );
     IP_closesocket( iml_listen_socket );
     return 0;                              /* return error            */
   }
#ifdef TRACEHL1
   m_hlnew_printf( HLOG_XYZ1, "nach Bind" );
#endif

   /* Listen for connections. Specify the backlog.                     */
   iml_rc = IP_listen( iml_listen_socket, inp_backlog );
   if (iml_rc != 0) {
     iml1 = iml_rc;
     if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
       iml1 = cl_tcp_r::afunc_wsaglerr();   /* get error code          */
     }
     _snprintf( achp_work, inp_len_work, "Listen() port=%d Error %d/%d - ignored",
                inp_port, iml_rc, iml1 );
     amp_msgproc( vpp_userfld, achp_work, 9 );
     IP_closesocket( iml_listen_socket );
     return 0;                              /* return error            */
   }
   *((int *) achp_work) = iml_listen_socket;  /* return socket         */
   *((int *) achp_work + 1) = inp_port;     /* return port of listen   */
   return 1;                                /* return one open socket  */
#endif
#endif
} /* end m_open_listen()                                               */
#ifndef B080407
/**
* start listen of one connection
* returns the number of listen started
*/
extern "C" int m_start_listen( struct dsd_gate_1 *adsp_gate_1 ) {
   int        iml_count;                    /* count listen started    */
   int        iml_rc;                       /* return code             */
#ifdef XYZ1
   char       *achl1;                       /* working variable        */
#endif
   struct dsd_gate_listen_1 *adsl_gate_listen_1_w1;  /* listen part of gateway */

   iml_count = 0;                           /* clear count listen started */
   adsl_gate_listen_1_w1 = adsp_gate_1->adsc_gate_listen_1_ch;  /* chain of listen part of gateway */
   while (adsl_gate_listen_1_w1) {
     while (adsl_gate_listen_1_w1->boc_active == FALSE) {  /* listen not active */
       if (adsl_gate_listen_1_w1->imc_socket < 0) {  /* prepare socket first */
         adsl_gate_listen_1_w1->imc_socket = IP_socket( adsl_gate_listen_1_w1->dsc_soa.ss_family, SOCK_STREAM, 0 );
         if (adsl_gate_listen_1_w1->imc_socket < 0) {  /* error occured */
#ifdef XYZ1
           iml1 = adsl_gate_listen_1_w1->imc_socket;
           if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
             iml1 = cl_tcp_r::afunc_wsaglerr();   /* get error code          */
           }
           _snprintf( achp_work, inp_len_work, "Socket() Error %d/%d - ignored",
                      adsl_gate_listen_1_w1->imc_socket, iml1 );
           amp_msgproc( vpp_userfld, achp_work, 7 );
           return FALSE;                          /* return error            */
#endif
           m_hlnew_printf( HLOG_XYZ1, "HWSPxxxxW l%05d Error socket() gate \"%(ux)s\" returned %d %d.",
                           __LINE__, adsp_gate_1 + 1, adsl_gate_listen_1_w1->imc_socket, D_TCP_ERROR );
           break;
         }
         iml_rc = IP_bind( adsl_gate_listen_1_w1->imc_socket,
                           (struct sockaddr *) &adsl_gate_listen_1_w1->dsc_soa,
                           sizeof(struct sockaddr_storage) );
         if (iml_rc != 0) {                       /* error occured           */
#ifdef XYZ1
           iml1 = iml_rc;
           if (cl_tcp_r::hws2mod != NULL) {       /* functions loaded        */
             iml1 = cl_tcp_r::afunc_wsaglerr();   /* get error code          */
           }
           _snprintf( achp_work, inp_len_work, "Bind() port=%d Error %d/%d - ignored",
                      imp_port, iml_rc, iml1 );
           amp_msgproc( vpp_userfld, achp_work, 8 );
           IP_closesocket( adsl_gate_listen_1_w1->imc_socket );
           adsl_gate_listen_1_w1->imc_socket = -1;   /* mark as invalid         */
           return FALSE;                          /* return error            */
#endif
           m_hlnew_printf( HLOG_XYZ1, "HWSPxxxxW l%05d Error bind() gate \"%(ux)s\" returned %d %d.",
                           __LINE__, adsp_gate_1 + 1, iml_rc, D_TCP_ERROR );
           adsl_gate_listen_1_w1->imc_socket = -1;  /* mark as invalid */
           break;
         }
       }
       iml_rc = listen( adsl_gate_listen_1_w1->imc_socket, adsp_gate_1->imc_backlog );
       if (iml_rc) {                        /* error occured           */
         m_hlnew_printf( HLOG_XYZ1, "HWSPxxxxW l%05d Error listen() gate \"%(ux)s\" returned %d %d.",
                         __LINE__, adsp_gate_1 + 1, iml_rc, D_TCP_ERROR );
         break;
       }
#ifdef B110925
       adsl_gate_listen_1_w1->adsc_acc_lis
         = dsd_nblock_acc::mc_startlisten( adsl_gate_listen_1_w1->imc_socket,
                                           &dss_acccb,
                                           adsl_gate_listen_1_w1 );
#else
       iml_rc = adsl_gate_listen_1_w1->dsc_acc_listen.mc_startlisten_fix( adsl_gate_listen_1_w1->imc_socket,
                                                                          &dss_acccb,
                                                                          adsl_gate_listen_1_w1 );
// to-do 25.09.11 KB check return code
#endif
       adsl_gate_listen_1_w1->boc_active = TRUE;  /* listen is active now */
       iml_count++;                         /* increment count listen started */
       break;
     }
     adsl_gate_listen_1_w1 = adsl_gate_listen_1_w1->adsc_next;  /* get next in chain */
   }
   return iml_count;                        /* return count listen started */
} /* end m_start_listen()                                              */

/**
* stop listen of one connection
* returns the number of listen stopped
*/
extern "C" int m_stop_listen( struct dsd_gate_1 *adsl_gate_1 ) {
   int        iml_count;                    /* count listen stopped    */
   int        iml_rc;                       /* return code             */
   struct dsd_gate_listen_1 *adsl_gate_listen_1_w1;  /* listen part of gateway */

   iml_count = 0;                           /* clear count listen stopped */
   adsl_gate_listen_1_w1 = adsl_gate_1->adsc_gate_listen_1_ch;  /* chain of listen part of gateway */
   while (adsl_gate_listen_1_w1) {
     if (adsl_gate_listen_1_w1->boc_active) {  /* listen is active     */
#ifdef B110925
       adsl_gate_listen_1_w1->adsc_acc_lis->mc_stoplistener( TRUE );
#else
       iml_rc = adsl_gate_listen_1_w1->dsc_acc_listen.mc_stoplistener_fix();
// to-do 25.09.11 KB check return code
#endif
       adsl_gate_listen_1_w1->imc_socket = -1;  /* socket is now invalid */
       adsl_gate_listen_1_w1->boc_active = FALSE;  /* listen is not active */
       iml_count++;                         /* increment count listen stopped */
     }
     adsl_gate_listen_1_w1 = adsl_gate_listen_1_w1->adsc_next;  /* get next in chain */
   }
// dsg_sys_state_1.boc_listen_active = FALSE;  /* listen is currently not active */
   return iml_count;                        /* return count listen stopped */
} /* end m_stop_listen()                                               */

/**
* start listen of all connections
* returns the number of listen started
*/
extern "C" int m_start_all_listen( BOOL bop_lbal ) {
   int        iml_count;                    /* count listen started    */
   struct dsd_gate_1 *adsl_gate_1_w1;       /* for start listen        */

   iml_count = 0;                           /* clear count listen started */
   adsl_gate_1_w1 = adsg_loconf_1_inuse->adsc_gate_anchor;  /* get anchor gate */
   while (adsl_gate_1_w1) {                 /* loop over all gates     */
     if (   (adsl_gate_1_w1->boc_not_close_lbal == FALSE)  /* do not close listen by load-balancing */
         || (bop_lbal == FALSE)) {
       iml_count += m_start_listen( adsl_gate_1_w1 );  /* start listen */
     }
     adsl_gate_1_w1 = adsl_gate_1_w1->adsc_next;
   }
   dsg_sys_state_1.boc_listen_active = TRUE;  /* listen is currently active */
   return iml_count;                        /* return count listen started */
} /* end m_start_all_listen()                                          */

/**
* stop listen of all connections
* returns the number of listen stopped
*/
extern "C" int m_stop_all_listen( BOOL bop_lbal ) {
   int        iml_count;                    /* count listen stopped    */
   struct dsd_gate_1 *adsl_gate_1_w1;       /* for stop listen         */

   iml_count = 0;                           /* clear count listen stopped */
   adsl_gate_1_w1 = adsg_loconf_1_inuse->adsc_gate_anchor;  /* get anchor gate */
   while (adsl_gate_1_w1) {                 /* loop over all gates     */
     if (   (adsl_gate_1_w1->boc_not_close_lbal == FALSE)  /* do not close listen by load-balancing */
         || (bop_lbal == FALSE)) {
       iml_count += m_stop_listen( adsl_gate_1_w1 );  /* stop listen   */
     }
     adsl_gate_1_w1 = adsl_gate_1_w1->adsc_next;
   }
   dsg_sys_state_1.boc_listen_active = FALSE;  /* listen is currently not active */
   return iml_count;                        /* return count listen stopped */
} /* end m_stop_all_listen()                                           */
#endif

/** CMA module starts synchronization passive                          */
extern "C" void m_notify_cma_sync_passive_start( void ) {
} /* end m_notify_cma_sync_passive_start()                             */

/** CMA module stopps synchronization passive                          */
extern "C" void m_notify_cma_sync_passive_stop( void ) {
} /* end m_notify_cma_sync_passive_stop()                              */

/** CMA module starts synchronization active                           */
extern "C" void m_notify_cma_sync_active_start( void ) {
} /* end m_notify_cma_sync_active_start()                              */

/** CMA module stopps synchronization active                           */
extern "C" void m_notify_cma_sync_active_stop( void ) {
} /* end m_notify_cma_sync_active_stop()                               */

#ifdef B100702
/**
  this routine will be called from HTUN when the given INETA is already
  in use.
*/
extern "C" BOOL m_htun_sess_ineta_double( struct dsd_tun_contr1 * adsp_tctl ) {
   class clconn1 *adsl_conn1;               /* class connection        */

   adsl_conn1 = ((class clconn1 *)
                   ((char *) adsp_tctl
                      - offsetof( class clconn1, dsc_tun_contr1 )));
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_htun_sess_ineta_double() adsp_tctl=%p adsl_conn1=%p.",
                   __LINE__, adsp_tctl, adsl_conn1 );
   /* no INETA available, cancel the session                           */
   if (adsl_conn1->achc_reason_end == NULL) {  /* reason end session */
     adsl_conn1->achc_reason_end = "session canceled because no INETA for HOB-TUN";  /* set text */
   }
   m_hlnew_printf( HLOG_XYZ1, "HWSPS120W GATE=%(ux)s SNO=%08d INETA=%s no INETA for HOB-TUN available",
                   adsl_conn1->adsc_gate1 + 1, adsl_conn1->dsc_co_sort.imc_sno, adsl_conn1->chrc_ineta );
   adsl_conn1->dcl_tcp_r_c.close1();
   return FALSE;                            /* could not give INETA    */
} /* end m_htun_sess_ineta_double()                                    */
#endif

extern "C" struct dsd_wsptun_conf_1 * m_get_wsptun_conf_1() {
   struct dsd_raw_packet_if_conf *adsl_raw_packet_if_conf;  /* configuration raw-packet-interface */

#ifdef B100702
   return &dss_wsptun_conf_1;
#endif
   adsl_raw_packet_if_conf = adsg_loconf_1_inuse->adsc_raw_packet_if_conf;  /* get configuration raw-packet-interface */
   if (adsl_raw_packet_if_conf == NULL) return NULL;  /* did not find the configuration */
   return &adsl_raw_packet_if_conf->dsc_wsptun_conf_1;  /* TUN PPP INETAs */
} /* end m_get_wsptun_conf_1()                                         */

extern "C" char * m_get_wsptun_ineta_ipv4_adapter() {
   struct dsd_raw_packet_if_conf *adsl_raw_packet_if_conf;  /* configuration raw-packet-interface */

   adsl_raw_packet_if_conf = adsg_loconf_1_inuse->adsc_raw_packet_if_conf;  /* get configuration raw-packet-interface */
   if (adsl_raw_packet_if_conf == NULL) return NULL;  /* did not find the configuration */
#ifdef B130108
   return (char *) &adsl_raw_packet_if_conf->umc_ta_ineta_local;  /* <TUN-adapter-ineta> */
#else
   return adsl_raw_packet_if_conf->achc_ar_ta_ineta_ipv4;  /* <TUN-adapter-ineta> */
#endif
} /* end m_get_wsptun_ineta_ipv4_adapter()                             */

#ifdef XYZ1
/* SNMP Trap - temporary, will move in Albert Bezzina's source         */
extern "C" void m_snmp_trap_1( ied_wsp_snmp_trap_def iep_trap_no, void * ap_trap_struct ) {
   m_hlnew_printf( HLOG_XYZ1, "IBIPGW08-l%05d-T m_snmp_trap_1( %d , 0X%p ).",
                   __LINE__, iep_trap_no, ap_trap_struct );
} /* end m_snmp_trap_1()                                               */
#endif

#ifdef TRACEHL_CO_OUT
extern "C" void m_console_out( char *achp_buff, int implength ) {
   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variable */
   char       byl1;                         /* working-variable        */
   char       chrlwork1[ 76 ];              /* buffer to print         */

   iml1 = 0;
   while (iml1 < implength) {
     iml2 = iml1 + 16;
     if (iml2 > implength) iml2 = implength;
     for ( iml3 = 4; iml3 < 75; iml3++ ) {
       chrlwork1[iml3] = ' ';
     }
     chrlwork1[58] = '*';
     chrlwork1[75] = '*';
     iml3 = 4;
     do {
       iml3--;
       chrlwork1[ iml3 ] = chrstrans[ (iml1 >> ((4 - 1 - iml3) << 2)) & 0X0F ];
     } while (iml3 > 0);
     iml4 = 6;                              /* start hexa digits here  */
     iml5 = 59;                             /* start ASCII here        */
     iml6 = 4;                              /* times normal            */
     do {
       byl1 = achp_buff[ iml1++ ];
       chrlwork1[ iml4++ ] = chrstrans[ (byl1 >> 4) & 0X0F ];
       chrlwork1[ iml4++ ] = chrstrans[ byl1 & 0X0F ];
       iml4++;
       if (byl1 > 0X20) {
         chrlwork1[ iml5 ] = byl1;
       }
       iml5++;
       iml6--;
       if (iml6 == 0) {
         iml4++;
         iml6 = 4;
       }
     } while (iml1 < iml2);
     printf( "%.*s\n", sizeof(chrlwork1), chrlwork1 );
   }
   fflush( stdout );
} /* end m_console_out()                                            */
#endif
