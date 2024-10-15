#define NEW_WSP_1102
#ifdef TO_DO_140316
ied_chs_special_cma_1                       /* special for CMA         */
ied_chs_special_ldap_1                      /* special for LDAP        */
usage: target only when equal to source
       or in sprintf()
DEF_AUX_GET_SERVER_CERT
#endif
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| FILE NAME: hob-xsclib01.h                                         |*/
/*| ----------                                                        |*/
/*|  Header-File for communication between a Server-Data-Hook         |*/
/*|  and the WebSecureProxy                                           |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|  Copyright (C) HOB Germany 2016                                   |*/
/*|  Copyright (C) HOB Germany 2017                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/
#if 0
//-------------------------------------------------------------
// Interface structure definition for Server Interface,
// Revised Version (Configuration Parameters removed)
//-------------------------------------------------------------
#endif

#if 0
// Caller Function codes
#endif

#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif
#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif

#ifndef DEF_IFUNC_START
#define DEF_IFUNC_START            0        // socket has been connected
#endif

#ifndef DEF_IFUNC_CONT
#define DEF_IFUNC_CONT             1        // process data as specified
                                            // by buffer pointers
#endif
#ifndef DEF_IFUNC_CLOSE
#define DEF_IFUNC_CLOSE            2        // release buffers, do house-
                                            // keeping
#endif
/* 3 reserved for DEF_IFUNC_RESET                                      */
/* 4 reserved for DEF_IFUNC_END                                        */
#ifndef DEF_IFUNC_FROMSERVER
#define DEF_IFUNC_FROMSERVER       5        // data from server
#endif

#ifndef DEF_IFUNC_TOSERVER
#define DEF_IFUNC_TOSERVER         6        // data to server
#endif

#ifndef DEF_IFUNC_REFLECT
#define DEF_IFUNC_REFLECT          7        // reflect data
#endif

#ifndef DEF_IFUNC_PREP_CLOSE
#define DEF_IFUNC_PREP_CLOSE       8        /* prepare close           */
#endif

#ifndef DEF_IFUNC_CLIENT_DISCO
#define DEF_IFUNC_CLIENT_DISCO     9        /* client is disconnected  */
#endif

#ifndef DEF_IFUNC_RELOAD
#define DEF_IFUNC_RELOAD           10       /* SDH reload              */
#endif

#ifndef DEF_IRET_NORMAL
#define DEF_IRET_NORMAL            0        // o.k. returned
#endif

#ifndef DEF_IRET_END
#define DEF_IRET_END               1        // connection should be ended
#endif

#ifndef DEF_IRET_ERRAU
#define DEF_IRET_ERRAU             2        // fatal error occured.
#endif

#ifndef DEF_IRET_INVDA
#define DEF_IRET_INVDA             3        /* invalid data passed     */
#endif

#ifndef DEF_IRET_INV_CLIENT_DATA
#define DEF_IRET_INV_CLIENT_DATA   4        /* invalid data from client */
#endif

#ifndef DEF_IRET_INT_ERROR
#define DEF_IRET_INT_ERROR         5        /* internal error occured  */
#endif

#ifndef DEF_IRET_OTHER_TARGET
#define DEF_IRET_OTHER_TARGET      6        /* return because of other target */
#endif

/**
   In HOBLink VPN there is no server and no client.
   The client is always the connection that is encrypted,
   so in HOBLink VPN the client is the HOBLink VPN gateway
   on the other side of the network.
   30.06.10  KB
*/

#if 0
// NOTE: All negative returncodes also indicate a fatal error
// -----
#endif

#ifndef DEF_AUX_MEMGET
#define DEF_AUX_MEMGET             0        // get a block of memory
#endif
#ifndef DEF_AUX_MEMFREE
#define DEF_AUX_MEMFREE            1        // release a block of memory
#endif
#ifndef DEF_AUX_CONSOLE_OUT
#define DEF_AUX_CONSOLE_OUT        2        // output to console
#endif
#ifndef DEF_AUX_CO_UNICODE
#define DEF_AUX_CO_UNICODE         3        // output to console Unicode
#endif
#ifndef DEF_AUX_RADIUS_QUERY
#define DEF_AUX_RADIUS_QUERY       4        // send radius query
#endif
#ifndef DEF_AUX_RADIUS_FREE
#define DEF_AUX_RADIUS_FREE        5        // free data received from radius
#endif
/* superseded thru DEF_AUX_CHECK_IDENT ??? - 26.07.05 KB */
#ifndef DEF_AUX_CHECK_USERID
#define DEF_AUX_CHECK_USERID       6        // check userid against radius
#endif
#ifndef DEF_AUX_DISKFILE_ACCESS
#define DEF_AUX_DISKFILE_ACCESS    7        // access a disk file
#endif
#ifndef DEF_AUX_DISKFILE_RELEASE
#define DEF_AUX_DISKFILE_RELEASE   8        // release a disk file
#endif
#ifndef DEF_AUX_DISKFILE_TIME_LM
#define DEF_AUX_DISKFILE_TIME_LM   9        // time (epoch) disk file last modified
#endif
#ifndef DEF_AUX_GET_TIME
#define DEF_AUX_GET_TIME           10       // get time
#endif
#ifndef DEF_AUX_STRING_FROM_EPOCH
#define DEF_AUX_STRING_FROM_EPOCH  11       // get time as string
#endif
#ifndef DEF_AUX_EPOCH_FROM_STRING
#define DEF_AUX_EPOCH_FROM_STRING  12       /* get epoch from string   */
#endif
#ifndef DEF_AUX_GET_CERTIFICATE
#define DEF_AUX_GET_CERTIFICATE    13       /* get address certificate */
#endif
#ifndef DEF_AUX_GET_DN
#define DEF_AUX_GET_DN             14       /* get address Distinguished Name */
#endif
#ifndef DEF_AUX_TCP_CONN
#define DEF_AUX_TCP_CONN           15       /* TCP Connect to Server   */
#endif
#ifndef DEF_AUX_COM_CMA
#define DEF_AUX_COM_CMA            16       /* command common memory area */
#endif
#ifndef DEF_AUX_TCP_CLOSE
#define DEF_AUX_TCP_CLOSE          17       /* close TCP to Server     */
#endif
#ifndef DEF_AUX_QUERY_CLIENT
#define DEF_AUX_QUERY_CLIENT       18       /* query TCP client connection */
#endif
#ifndef DEF_AUX_QUERY_RECEIVE
#define DEF_AUX_QUERY_RECEIVE      19       /* query TCP data          */
#endif
#ifndef DEF_AUX_QUERY_MAIN_STR
#define DEF_AUX_QUERY_MAIN_STR     20       /* query main program for string */
#endif
#ifndef DEF_AUX_QUERY_MAIN_OPT
#define DEF_AUX_QUERY_MAIN_OPT     21       /* query main program for option */
#endif
#ifndef DEF_AUX_QUERY_MAIN_SEQ
#define DEF_AUX_QUERY_MAIN_SEQ     22       /* query main program with sequence of options */
#endif
#ifdef XYZ1 /* not necessary 21.02.05 KB */
#ifndef DEF_AUX_SET_AUTH
#define DEF_AUX_SET_AUTH           23       /* set authentication      */
#endif
#endif
// DEF_AUX_GET_AUTH deprecated 11.09.13 KB
#ifndef DEF_AUX_GET_AUTH
#define DEF_AUX_GET_AUTH           23       /* get authentication      */
#endif
#ifndef DEF_AUX_RANDOM_RAW
#define DEF_AUX_RANDOM_RAW         24       /* calcalute random        */
#endif
#ifndef DEF_AUX_RANDOM_BASE64
#define DEF_AUX_RANDOM_BASE64      25       /* calcalute random MIME   */
#endif
#ifndef DEF_AUX_CHECK_IDENT
#define DEF_AUX_CHECK_IDENT        26       /* check ident - authenticate */
#endif
#ifndef DEF_AUX_TIMER1_SET
#define DEF_AUX_TIMER1_SET         27       /* set timer in milliseconds */
#endif
#ifndef DEF_AUX_TIMER1_REL
#define DEF_AUX_TIMER1_REL         28       /* release timer set before */
#endif
#ifndef DEF_AUX_TIMER1_QUERY
#define DEF_AUX_TIMER1_QUERY       29       /* return struct dsd_timer1_ret */
#endif
#ifndef DEF_AUX_QUERY_GATHER
#define DEF_AUX_QUERY_GATHER       30       /* query Gather Structure, struct dsd_q_gather_1 */
#endif
#ifndef DEF_AUX_GET_SC_PROT
#define DEF_AUX_GET_SC_PROT        31       /* get Server Entry Protocol */
#endif
#ifndef DEF_AUX_COUNT_SERVENT
#define DEF_AUX_COUNT_SERVENT      32       /* count server entries    */
#endif
#ifndef DEF_AUX_GET_SERVENT
#define DEF_AUX_GET_SERVENT        33       /* get server entry        */
#endif
#ifndef DEF_AUX_RADIUS_FILL_PTTD
#define DEF_AUX_RADIUS_FILL_PTTD   34       /* fill connect Pass-Thru-to-Desktop data from Radius */
#endif
#ifndef DEF_AUX_RADIUS_GET_ATTR
#define DEF_AUX_RADIUS_GET_ATTR    35       /* get attributes from received Radius packet */
#endif
#ifndef DEF_AUX_CONN_PREPARE
#define DEF_AUX_CONN_PREPARE       36       /* prepare for connect HOB-WSP-AT3 */
#endif
#ifndef DEF_AUX_GET_PRIV_PERS
#define DEF_AUX_GET_PRIV_PERS      37       /* return priviliges of user entry */
#endif
#ifndef DEF_AUX_SET_PRIV_SESSION
#define DEF_AUX_SET_PRIV_SESSION   38       /* set priviliges of session */
#endif
#ifndef DEF_AUX_GET_PRIV_SESSION
#define DEF_AUX_GET_PRIV_SESSION   39       /* return priviliges of session */
#endif
#ifndef DEF_AUX_PUT_SESS_STOR
#define DEF_AUX_PUT_SESS_STOR      40       /* put Session Storage     */
#endif
#ifndef DEF_AUX_GET_SESS_STOR
#define DEF_AUX_GET_SESS_STOR      41       /* get Session Storage     */
#endif
#ifndef DEF_AUX_DESCR_SESS_STOR
#define DEF_AUX_DESCR_SESS_STOR    42       /* get Session Storage Descriptor */
#endif
#ifndef DEF_AUX_QUERY_SYSADDR
#define DEF_AUX_QUERY_SYSADDR      43       /* return array with system addresses */
#endif
/* the following values cannot be used in WSP Version 2.2 - 29.12.06 KB - start */
#ifndef DEF_AUX_GET_WORKAREA
#define DEF_AUX_GET_WORKAREA       44       /* get additional work area */
#endif
#ifndef DEF_AUX_GET_T_MSEC
#define DEF_AUX_GET_T_MSEC         45       /* get time / epoch in milliseconds */
#endif
#ifndef DEF_AUX_MARK_WORKAREA_INC
#define DEF_AUX_MARK_WORKAREA_INC  46       /* increment usage count in work area */
#endif
#ifndef DEF_AUX_MARK_WORKAREA_DEC
#define DEF_AUX_MARK_WORKAREA_DEC  47       /* decrement usage count in work area */
#endif
#ifndef DEF_AUX_SERVICE_REQUEST
#define DEF_AUX_SERVICE_REQUEST    48       /* service request         */
#endif
#ifndef DEF_AUX_LDAP_REQUEST
#define DEF_AUX_LDAP_REQUEST       49       /* LDAP service request    */
#endif
#ifndef DEF_AUX_SDH_OBJECT
#define DEF_AUX_SDH_OBJECT         50       /* Server-Data-Hook object */
#endif
#ifndef DEF_AUX_SIP_REQUEST
#define DEF_AUX_SIP_REQUEST        51       /* SIP protocol request    */
#endif
#ifndef DEF_AUX_UDP_REQUEST
#define DEF_AUX_UDP_REQUEST        52       /* UDP request             */
#endif
#ifndef DEF_AUX_GET_IDENT_SETTINGS
#define DEF_AUX_GET_IDENT_SETTINGS 53       /* return settings of this user */
#endif
#ifndef DEF_AUX_SNMP_ALERT
#define DEF_AUX_SNMP_ALERT         54       /* SNMP alert              */
#endif
#ifndef DEF_AUX_SESSION_CONF
#define DEF_AUX_SESSION_CONF       55       /* configure session parameters */
#endif
#ifndef DEF_AUX_ADMIN
#define DEF_AUX_ADMIN              56       /* administration command  */
#endif
#ifndef DEF_AUX_SET_IDENT
#define DEF_AUX_SET_IDENT          57       /* set ident - userid and user-group */
#endif
#ifndef DEF_AUX_GET_CONN_SNO
#define DEF_AUX_GET_CONN_SNO       58       /* get connection SNO session number */
#endif
#ifndef DEF_AUX_CHECK_TARGET_FILTER
#define DEF_AUX_CHECK_TARGET_FILTER 59      /* check against target-filter */
#endif
#ifndef DEF_AUX_KRB5_SIGN_ON
#define DEF_AUX_KRB5_SIGN_ON       60       /* sign-on with Kerberos   */
#endif
#ifndef DEF_AUX_KRB5_SE_TI_GET
#define DEF_AUX_KRB5_SE_TI_GET     61       /* Kerberos get Service Ticket */
#endif
#ifndef DEF_AUX_KRB5_SE_TI_C_R
#define DEF_AUX_KRB5_SE_TI_C_R     62       /* Kerberos check Service Ticket Response */
#endif
#ifndef DEF_AUX_KRB5_ENCRYPT
#define DEF_AUX_KRB5_ENCRYPT       63       /* Kerberos encrypt data   */
#endif
#ifndef DEF_AUX_KRB5_DECRYPT
#define DEF_AUX_KRB5_DECRYPT       64       /* Kerberos decrypt data   */
#endif
#ifndef DEF_AUX_KRB5_SE_TI_REL
#define DEF_AUX_KRB5_SE_TI_REL     65       /* Kerberos release Service Ticket Resources */
#endif
#ifndef DEF_AUX_KRB5_LOGOFF
#define DEF_AUX_KRB5_LOGOFF        66       /* release Kerberos TGT    */
#endif
#ifndef DEF_AUX_GET_KRB5_CONF
#define DEF_AUX_GET_KRB5_CONF      67       /* get Kerberos Configuration Entry */
#endif
#ifndef DEF_AUX_SET_KRB5_CONF
#define DEF_AUX_SET_KRB5_CONF      68       /* set Kerberos Configuration Entry */
#endif
#ifndef DEF_AUX_REL_KRB5_CONF
#define DEF_AUX_REL_KRB5_CONF      69       /* release Kerberos Configuration Entry */
#endif
#ifndef DEF_AUX_SESSION_KRB5_CONF
#define DEF_AUX_SESSION_KRB5_CONF  70       /* assign Kerberos Configuration Entry to session */
#endif
#ifndef DEF_AUX_GET_LDAP_CONF
#define DEF_AUX_GET_LDAP_CONF      71       /* get LDAP Configuration Entry */
#endif
#ifndef DEF_AUX_SET_LDAP_CONF
#define DEF_AUX_SET_LDAP_CONF      72       /* set LDAP Configuration Entry */
#endif
#ifndef DEF_AUX_REL_LDAP_CONF
#define DEF_AUX_REL_LDAP_CONF      73       /* release LDAP Configuration Entry */
#endif
#ifndef DEF_AUX_GET_SESSION_INFO
#define DEF_AUX_GET_SESSION_INFO   74       /* get information about the session */
#endif
#ifndef DEF_AUX_UDP_GATE
#define DEF_AUX_UDP_GATE           75       /* handle UDP-gate         */
#endif
#ifndef DEF_AUX_NTLM_AUTH
#define DEF_AUX_NTLM_AUTH          76       /* NTLM authentication against Kerberos-5 KDC */
#endif
// to-do 01.04.13 KB - remove DEF_AUX_LOAD_N_LIB, use DEF_AUX_DYN_LIB
#ifndef DEF_AUX_LOAD_N_LIB
#define DEF_AUX_LOAD_N_LIB         77       /* load native library     */
#endif
#ifndef DEF_AUX_WSP_TRACE
#define DEF_AUX_WSP_TRACE          78       /* write WSP trace         */
#endif
#ifndef DEF_AUX_BASE64_ENCODE
#define DEF_AUX_BASE64_ENCODE      79       /* encode MIME / BASE64    */
#endif
#ifndef DEF_AUX_BASE64_DECODE
#define DEF_AUX_BASE64_DECODE      80       /* decode MIME / BASE64    */
#endif
#ifndef DEF_AUX_NOT_DROP_TCP_PACKET
#define DEF_AUX_NOT_DROP_TCP_PACKET 81      /* do not drop TCP packets */
#endif
#ifndef DEF_AUX_GET_DUIA
#define DEF_AUX_GET_DUIA           82       /* get domain userid INETA */
#endif
#ifndef DEF_AUX_SECURE_XOR
#define DEF_AUX_SECURE_XOR         83       /* apply secure XOR        */
#endif
#ifndef DEF_AUX_KRB5_SE_TI_CHECK
#define DEF_AUX_KRB5_SE_TI_CHECK   84       /* Kerberos check Service Ticket */
#endif
#ifndef DEF_AUX_GET_RADIUS_CONF
#define DEF_AUX_GET_RADIUS_CONF    85       /* get Radius group Configuration Entry */
#endif
#ifndef DEF_AUX_SET_RADIUS_CONF
#define DEF_AUX_SET_RADIUS_CONF    86       /* set Radius group Configuration Entry */
#endif
#ifndef DEF_AUX_REL_RADIUS_CONF
#define DEF_AUX_REL_RADIUS_CONF    87       /* release Radius group Configuration Entry */
#endif
#ifndef DEF_AUX_SYNC_TIMER
#define DEF_AUX_SYNC_TIMER         88       /* synchronise the timer   */
#endif
#ifndef DEF_AUX_WEBSO_CONN
#define DEF_AUX_WEBSO_CONN         89       /* connect for WebSocket applications */
#endif
#ifndef DEF_AUX_SECURE_RANDOM
#define DEF_AUX_SECURE_RANDOM      90       /* get secure random       */
#endif
#ifndef B160501
#ifndef DEF_AUX_SECURE_RANDOM_SEED
#define DEF_AUX_SECURE_RANDOM_SEED DEF_AUX_SECURE_RANDOM
#endif
#ifndef DEF_AUX_SECURE_SEED
#define DEF_AUX_SECURE_SEED        90       /* get secure seed         */
#endif
#endif
#ifndef DEF_AUX_GET_WSP_FINGERPRINT
#define DEF_AUX_GET_WSP_FINGERPRINT 91      /* get WSP fingerprint     */
#endif
#ifndef DEF_AUX_PIPE
#define DEF_AUX_PIPE               92       /* aux-pipe                */
#endif
#ifndef DEF_AUX_UTILITY_THREAD
#define DEF_AUX_UTILITY_THREAD     93       /* create unitliy thread   */
#endif
#ifndef DEF_AUX_SWAP_STOR
#define DEF_AUX_SWAP_STOR          94       /* manage swap storage     */
#endif
#ifndef DEF_AUX_DYN_LIB
#define DEF_AUX_DYN_LIB            95       /* manage dynamic library  */
#endif
#ifndef DEF_AUX_SIG_GET_CLIENT
#define DEF_AUX_SIG_GET_CLIENT     96       /* signature - get client credentials */
#endif
#ifndef DEF_AUX_SIG_SIGN_NONCE
#define DEF_AUX_SIG_SIGN_NONCE     97       /* signature - sign nonce  */
#endif
#ifndef DEF_AUX_SET_SESSION_TIMEOUT
#define DEF_AUX_SET_SESSION_TIMEOUT 98      /* set session timeout     */
#endif
#ifndef DEF_AUX_GET_SEND_BUFFER
#define DEF_AUX_GET_SEND_BUFFER    99       /* get send buffer, not used in the WSP */
#endif
#ifndef DEF_AUX_GET_DOMAIN_INFO
#define DEF_AUX_GET_DOMAIN_INFO    100      /* retrieve domain-information of connection - gate */
#endif
#ifndef DEF_AUX_GET_RPC_CONF
#define DEF_AUX_GET_RPC_CONF       101      /* get RPC Configuration Entry */
#endif
#ifndef DEF_AUX_SET_RPC_CONF
#define DEF_AUX_SET_RPC_CONF       102      /* set RPC Configuration Entry */
#endif
#ifndef DEF_AUX_REL_RPC_CONF
#define DEF_AUX_REL_RPC_CONF       103      /* release RPC Configuration Entry */
#endif
/* to-do 12.09.14 KB - makes no sense, PAP, MS-CHAP-V2 and EAP do not need to go over aux-cb. */
#ifndef DEF_AUX_AUTH_RPC
#define DEF_AUX_AUTH_RPC           104      /* authenticate over RPC   */
#endif
#ifdef INCL_TEST_RPC
#ifndef DEF_AUX_AUTH_RPC_NTLMV2
#define DEF_AUX_AUTH_RPC_NTLMV2    104      /* authenticate NTLMv2 over RPC */
#endif
#endif
#ifndef DEF_AUX_FILE_IO
#define DEF_AUX_FILE_IO            105      /* file input-output       */
#endif
#ifndef DEF_AUX_SET_LOCAL_USER
#define DEF_AUX_SET_LOCAL_USER     106      /* set local user          */
#endif
#ifndef DEF_AUX_CHECK_LOGOUT
#define DEF_AUX_CHECK_LOGOUT       107      /* check logout at sign on */
#endif
#ifndef DEF_AUX_GET_ADDR_SERVER_ERROR
#define DEF_AUX_GET_ADDR_SERVER_ERROR 108   /* get address zero-terminated message server error */
#endif
#ifndef DEF_AUX_GET_SSL_SERVER_CERT
#define DEF_AUX_GET_SSL_SERVER_CERT 109     /* get address SSL used server certificate */
#endif
#ifndef DEF_AUX_SDH_RELOAD
#define DEF_AUX_SDH_RELOAD         110      /* manage SDH reload       */
#endif
#ifndef DEF_AUX_KRB5_GET_SESS_KEY
#define DEF_AUX_KRB5_GET_SESS_KEY  111      /* Kerberos-5 retrieve session key */
#endif
#ifndef DEF_AUX_DEBUG_CHECK
#define DEF_AUX_DEBUG_CHECK        112      /* debug check             */
#endif
#ifndef B160702
#ifndef DEF_AUX_RANDOM_VISIBLE
#define DEF_AUX_RANDOM_VISIBLE     115      /* get visible secure random - nonce */
#endif
#ifndef DEF_AUX_RANDOM_HIDDEN
#define DEF_AUX_RANDOM_HIDDEN      116      /* get hidden secure random */
#endif
#endif
#ifndef DEF_AUX_GET_CS_SSL_ADDR
#define DEF_AUX_GET_CS_SSL_ADDR    120      /* get addresses of client-side SSL implementation */
#endif
#ifdef XYZ1  /* use DEF_AUX_GET_SESSION_INFO */
#ifndef DEF_AUX_QUERY_SERVER
#define DEF_AUX_QUERY_SERVER       18       /* query server connection, TCP or other */
#endif
#endif
/* the following values cannot be used in WSP Version 2.2 - 29.12.06 KB - end */
#ifndef DEF_CLIB1_CONF_SERVLI
#define DEF_CLIB1_CONF_SERVLI      0X00000001
#endif
#ifndef DEF_CLIB1_CONF_HOBWSAT3
#define DEF_CLIB1_CONF_HOBWSAT3    0X00000002
#endif
#ifndef DEF_CLIB1_CONF_USERLI
#define DEF_CLIB1_CONF_USERLI      0X00000004
#endif
#ifndef DEF_CLIB1_CONF_RADIUS
#define DEF_CLIB1_CONF_RADIUS      0X00000008
#endif
#ifndef DEF_CLIB1_CONF_DYN_RADIUS
#define DEF_CLIB1_CONF_DYN_RADIUS  0X00000010
#endif
#ifndef DEF_CLIB1_CONF_KRB5
#define DEF_CLIB1_CONF_KRB5        0X00000020  /* Kerberos 5 KDC defined */
#endif
#ifndef DEF_CLIB1_CONF_DYN_KRB5
#define DEF_CLIB1_CONF_DYN_KRB5    0X00000040  /* dynamic Kerberos 5 KDC defined */
#endif
#ifndef DEF_CLIB1_CONF_LDAP
#define DEF_CLIB1_CONF_LDAP        0X00000080  /* LDAP group defined   */
#endif
#ifndef DEF_CLIB1_CONF_DYN_LDAP
#define DEF_CLIB1_CONF_DYN_LDAP    0X00000100  /* dynamic LDAP groups defined */
#endif
#ifndef HL_AUX_SIGNALS
#define HL_AUX_SIGNALS
#define HL_AUX_SIGNAL_TIMER        0X00000001
#define HL_AUX_SIGNAL_IO_1         0X00000002
#define HL_AUX_SIGNAL_IO_2         0X00000004
#define HL_AUX_SIGNAL_IO_3         0X00000008
#define HL_AUX_SIGNAL_IO_4         0X00000010
#define HL_AUX_SIGNAL_CANCEL       0X80000000
#endif

#ifndef DEF_BGT_WSP_END
#define DEF_BGT_WSP_END            1
#endif
#ifndef DEF_BGT_INP_STATISTIC
#define DEF_BGT_INP_STATISTIC      2
#endif
#ifndef DEF_BGT_INP_ADMIN
#define DEF_BGT_INP_ADMIN          3
#endif
#define HL_AUX_WT_DATA1            1        /* include data short      */
#define HL_AUX_WT_DATA2            2        /* include data extended   */
#define HL_AUX_WT_ALL              4        /* WSP Trace SDH all       */

#define MAX_KRB5_SE_TI             (2 * 1024)  /* maximum length Kerberos 5 Service Ticket */
#define MAX_KRB5_SE_KEY            64       /* maximum length Kerberos 5 session key */
#define MAX_UTIL_THR_MEM_AREA      16       /* maximum number of memory areas passed to and from an utility thread */

#define DEF_LEN_UDP_GATE_NONCE 22           /* length of UDP-gate nonce */
#ifdef XYZ1
#define DEF_LEN_UDP_GATE_KEYS  128          /* length of UDP-gate keys for HOBPhone */
#define DEF_LEN_UDP_GATE_ENCRY 128          /* length of UDP-gate encrytion for HOBPhone */
#endif
#define DEF_LEN_UDP_GATE_KEYS  1024         /* length of UDP-gate keys for HOBPhone */
#define DEF_LEN_UDP_GATE_ENCRY 1024         /* length of UDP-gate encrytion for HOBPhone */

#ifndef B131225
#define SHIFT_BLOCK_SWAP       16           /* shift bits length block of swap area */
#define LEN_BLOCK_SWAP         (1 << SHIFT_BLOCK_SWAP)  /* length block of swap area */
#endif

#define LEN_SECURE_XOR_PWD     512          /* length of encrypted password field */

#ifndef DEF_HL_CHARSET
/**
   hob-xslunic1.h
   hob-xsclib01.h hob-wspat3.h hob-rdpserver1.h hob-llog01.h
   hob-netw-01.h hob-xsltime1.h hob-ipsec-01.h
*/
#define DEF_HL_CHARSET

enum ied_charset {                          /* define character set    */
   /* in the comments below the enum value lines, square brackets mean a
      "MIBenum" number, by which further reading can be looked up from
      http://www.iana.org/assignments/character-sets                   */
   ied_chs_invalid = 0,                     /* parameter is invalid    */

   ied_chs_ascii_850,                       /* ASCII 850               */
   /* [2009] "DOS-Multilingual"                                        */

   ied_chs_ansi_819,                        /* ANSI 819                */
   /* [4] ISO-8859-1, Latin1, iso-ir-100, other Windows-CP 28591       */

   ied_chs_utf_8,                           /* Unicode UTF-8           */
   /* [106] (specified in RFC 3629) Windows-CP 65001                   */

   ied_chs_utf_16,                          /* Unicode UTF-16 = WCHAR  */
   /* (mix of [1015]/[1000]) assumes native endianness of the machine  */

   ied_chs_be_utf_16,                       /* Unicode UTF-16 big endian */
   /* [1013] (two-byte-word encoding) Windows-CP 1201                  */

   ied_chs_le_utf_16,                       /* Unicode UTF-16 little endian */
   /* [1014] (two-byte-word encoding) Windows-CP 1200                  */

   ied_chs_utf_32,                          /* Unicode UTF-32          */
   /* [1001] assumes native endianness of the machine    */

   ied_chs_be_utf_32,                       /* Unicode UTF-32 big endian */
   /* [1018] (four-byte encoding) Windows-CP 65006                     */

   ied_chs_le_utf_32,                       /* Unicode UTF-32 little endian */
   /* [1019] (four-byte encoding) Windows-CP 65005                     */

   ied_chs_html_1,                          /* HTML character set      */
   /* e.g. "&uuml;", cf. www.w3.org/TR/html4/sgml/entities.html        */

   ied_chs_uri_1,                           /* URI                     */
   /* RFC 3986, e.g. encoding with percent sign like "?" to "%3F"      */

   ied_chs_idna_1,                          /* IDNA RFC 3492 etc. - Punycode */
   /* www.icann.org/en/resources/idn/rfcs,www.unicode.org/faq/idn.html */

   ied_chs_oem_437,                         /* DOS-Codepage 437        */
   /* [2011] "DOS-US"                                                  */

   ied_chs_wcp_874,                         /* Windows-Codepage  874   */
   /* [2109] (Thai)                                                    */

   ied_chs_wcp_1250,                        /* Windows-Codepage 1250   */
   /* [2250] (Central European)                                        */

   ied_chs_wcp_1251,                        /* Windows-Codepage 1251   */
   /* [2251] (Cyrillic)                                                */

   ied_chs_wcp_1252,                        /* Windows-Codepage 1252   */
   /* [2252] (Western European)                                        */

   ied_chs_wcp_1253,                        /* Windows-Codepage 1253   */
   /* [2253] (Greek)                                                   */

   ied_chs_wcp_1254,                        /* Windows-Codepage 1254   */
   /* [2254] (Turkish)                                                 */

   ied_chs_wcp_1255,                        /* Windows-Codepage 1255   */
   /* [2255] (Hebrew)                                                  */

   ied_chs_wcp_1256,                        /* Windows-Codepage 1256   */
   /* [2256] (Arabic)                                                  */

   ied_chs_wcp_1257,                        /* Windows-Codepage 1257   */
   /* [2257] (Baltic)                                                  */

   ied_chs_wcp_1258,                        /* Windows-Codepage 1258   */
   /* [2258] (Vietnamese)                                              */

   ied_chs_wcp_932,                         /* Windows-Codepage 932 (MBCS) */
   /* [2024] Windows-31J, "Microsoft Shift-JIS" (Japanese)             */

   ied_chs_wcp_936,                         /* Windows-Codepage 936 (MBCS) */
   /* [113] GBK (Mainland Chinese)                                     */

   ied_chs_wcp_949,                         /* Windows-Codepage 949 (MBCS) */
   /* "Unified Hangul Code (UHC)", "Extended Wansung" (Korean)         */

   ied_chs_wcp_950,                         /* Windows-Codepage 950 (MBCS) */
   /* (Taiwan/ Hongkong Chinese, resembles Big5 [2026])                */

   ied_chs_iso8859_2,                       /* ISO 8859-2              */
   /* [5] Latin2, iso-ir-101, Windows-CP 28592 (Central European)      */

   ied_chs_iso8859_3,                       /* ISO 8859-3              */
   /* [6] Latin3, iso-ir-109, Windows-CP 28593 (South European)        */

   ied_chs_iso8859_4,                       /* ISO 8859-4              */
   /* [7] Latin4, iso-ir-110, Windows-CP 28594 (North European/ Baltic) */

   ied_chs_iso8859_5,                       /* ISO 8859-5              */
   /* [8] iso-ir-144, Windows-CP 28595 (Cyrillic)                      */

   ied_chs_iso8859_6,                       /* ISO 8859-6              */
   /* [9] iso-ir-127, ECMA-114, ASMO-708, Windows-CP 28596 (Arabic)    */

   ied_chs_iso8859_7,                       /* ISO 8859-7              */
   /* [10] iso-ir-126, ELOT_928, ECMA-118, Greek8, Windows-CP 28597    */

   ied_chs_iso8859_8,                       /* ISO 8859-8              */
   /* [11] iso-ir-138, ISO_8859-8, Windows-CP 28598 (Hebrew)           */

   ied_chs_iso8859_9,                       /* ISO 8859-9              */
   /* [12] Latin5, iso-ir-148, Windows-CP 28599 (Turkish)              */

   ied_chs_iso8859_10,                      /* ISO 8859-10             */
   /* [13] Latin6, iso-ir-157 (Nordic)                                 */

   ied_chs_iso8859_11,                      /* ISO 8859-11             */
   /* (Thai, resembles TIS-620 [2259])                                 */

   ied_chs_iso8859_13,                      /* ISO 8859-13             */
   /* [109] Latin-7, Windows-CP 28603 (Baltic Rim/ Estonian)           */

   ied_chs_iso8859_14,                      /* ISO 8859-14             */
   /* [110] Latin8, iso-ir-199, iso-celtic                             */

   ied_chs_iso8859_15,                      /* ISO 8859-15             */
   /* [111] Latin-9, Windows-CP 28605                                  */

   ied_chs_iso8859_16,                      /* ISO 8859-16             */
   /* [112] Latin10, iso-ir-226 (South-Eastern European)               */

   ied_chs_xml_utf_8,                       /* XML Unicode UTF-8       */

   ied_chs_xml_wcp_1252,                    /* XML Windows-Codepage 1252 */
   /* encoding="Windows-1252"                                          */

   ied_chs_xml_utf_16,                      /* XML Unicode UTF-16      */
   /* ied_chs_utf_16 plus &apos; etc.                                  */

   ied_chs_ldap_escaped_utf_8               /* LDAP UTF-8 escaped      */
};

struct dsd_unicode_string {                 /* unicode string          */
   void *     ac_str;                       /* address of string       */
   int        imc_len_str;                  /* length string in elements */
   enum ied_charset iec_chs_str;            /* character set string    */
};
#endif

#ifndef DEF_FUNC_INCLUDE
#define DEF_FUNC_INCLUDE
#define DEF_FUNC_DIR           0            /* set function direct     */
#define DEF_FUNC_RDP           1            /* set function RDP        */
#define DEF_FUNC_ICA           2            /* set function ICA        */
#define DEF_FUNC_PTTD          3            /* PASS-THRU-TO-DESKTOP    */
#define DEF_FUNC_SS5H          4            /* SELECT-SOCKS5-HTTP      */
#define DEF_FUNC_HRDPE1        5            /* set function HOB RDP Extension 1 */
#define DEF_FUNC_HPPPT1        6            /* set function HOB-PPP-T1 Tunnel */
#define DEF_FUNC_SSTP          7            /* set function SSTP Tunnel */
#define DEF_FUNC_CASC_WSP      8            /* set function CASCADED-WSP */
#define DEF_FUNC_L2TP          9            /* set function L2TP UDP connection */
#ifdef XYZ1
#define DEF_FUNC_RDG_OUT       10           /* set function remote desktop gateway out */
#define DEF_FUNC_RDG_IN        11           /* set function remote desktop gateway in */
#endif
#define DEF_FUNC_WTS           -1           /* set function WTSGATE    */
#define DEF_FUNC_VDI_WSP       -2           /* set function VDI-WSP-GATE */
#endif

#ifndef HL_UNIX
#define HL_DLL_PUBLIC __declspec( dllexport )
#endif
#ifdef HL_UNIX
#ifdef __GNUC__
#if __GNUC__ >= 4
#define HL_DLL_PUBLIC __attribute__ ((visibility ("default")))
#else
#define HL_DLL_PUBLIC
#endif
#ifndef __GNUC__
#define HL_DLL_PUBLIC
#endif
#endif
#endif

#ifndef B130704
/* <connection> <conn-type>                                            */
enum ied_conn_type_def {                    /* connection type         */
   ied_coty_undef = 0,                      /* parameter is undefined  */
   ied_coty_primary,                        /* primary listen          */
   ied_coty_secondary,                      /* secondary listen        */
   ied_coty_admin                           /* for administrator       */
};
#endif

enum ied_tcpconn_ret {                      /* returned from TCP connect */
   ied_tcr_ok,                              /* connect successful      */
   ied_tcr_invalid,                         /* parameter is invalid    */
   ied_tcr_no_ocos,                         /* option-connect-other-server not configured */
   ied_tcr_no_cs_ssl,                       /* no Client-Side SSL configured */
   ied_tcr_denied_tf,                       /* access denied because of target-filter */
   ied_tcr_hostname,                        /* host-name not in DNS    */
   ied_tcr_no_route,                        /* no route to host        */
   ied_tcr_refused,                         /* connection refused      */
   ied_tcr_timeout,                         /* connection timed out    */
   ied_tcr_error                            /* other error             */
};

#ifndef DEF_HL_STR_G_I_1
#define DEF_HL_STR_G_I_1
struct dsd_gather_i_1 {                     /* gather input data       */
   struct dsd_gather_i_1 *adsc_next;        /* next in chain           */
   char *     achc_ginp_cur;                /* current position        */
   char *     achc_ginp_end;                /* end of input data       */
};
#endif

typedef struct {                            /* capabilities TCP connect */
   unsigned int ibc_ssl_client : 1;         /* may use client side SSL */
   unsigned int filler : 31;                /* filler                  */
} dsd_aux_tcp_def;

struct dsd_aux_tcp_conn_1 {                 /* TCP Connect to Server   */
   enum ied_tcpconn_ret iec_tcpconn_ret;    /* returned from TCP connect */
#ifdef B100814
   char *     achc_server_ineta;            /* ineta server            */
   char *     achc_gateout_ineta;           /* ineta gate out          */
   char *     achc_server_service;          /* service for IPV6        */
#endif
   struct dsd_unicode_string dsc_target_ineta;  /* INETA of target / server */
   int        imc_server_port;              /* port of server          */
   dsd_aux_tcp_def dsc_aux_tcp_def;         /* flags                   */
};

struct dsd_aux_query_client {               /* query TCP Connection to Client */
   int        inc_addr_family;              /* address family IPV4 / IPV6 */
   char       chrc_multih_ineta[16];        /* multihomed ineta        */
   char       chrc_client_ineta[16];        /* client ineta            */
   int        inc_port;                     /* port of connection      */
};

struct dsd_aux_query_receive {              /* query TCP data to process */
   BOOL       boc_data_client;              /* data from client available */
   BOOL       boc_data_server;              /* data from server available */
};

#ifndef DEF_GET_WA
#define DEF_GET_WA
/* the following values cannot be used in WSP Version 2.2 - 29.12.06 KB - start */
struct dsd_aux_get_workarea {               /* acquire additional work area */
   char *     achc_work_area;               /* addr work-area returned */
   int        imc_len_work_area;            /* length work-area returned */
};
/* the following values cannot be used in WSP Version 2.2 - 29.12.06 KB - end */
#endif

struct dsd_aux_get_send_buffer {            /* acquire send buffer     */
   char *     achc_send_buffer;             /* addr send buffer returned */
   int        imc_len_send_buffer;          /* length send buffer returned */
};

/**
   aux-call DEF_AUX_GET_DOMAIN_INFO - retrieve domain-information of connection - gate
   supply Host: from HTTP header received from client,
     - achc_hostname and imc_stored_hostname
   and you get NTLMv2 fields, permanently moved etc.
*/

enum ied_dom_inf_auth_type {                /* domain information authentication-type */
   ied_diat_undef = 0,                      /* undefined               */
   ied_diat_xml_db,                         /* XML-DB                  */
   ied_diat_radius,                         /* Radius                  */
   ied_diat_krb5,                           /* Kerberos 5              */
   ied_diat_ldap,                           /* LDAP                    */
   ied_diat_rpc_dc                          /* RPC-DC                  */
};

enum ied_domain_info_ret {                  /* returned from get domain information */
   ied_dir_unused = 0,                      /* value is unused         */
   ied_dir_found,                           /* domain information found */
   ied_dir_default,                         /* returned domain information default values */
   ied_dir_notfound,                        /* domain information not found */
   ied_dir_param_inv                        /* input paramater invalid */
};

struct dsd_aux_get_domain_info_1 {          /* retrieve domain-information of connection - gate */
   enum ied_domain_info_ret iec_dir;        /* returned from get domain information */
   enum ied_conn_type_def iec_coty;         /* connection type         */
   struct dsd_unicode_string dsc_ucs_hostname;  /* HTTP Host: input value */
// to-do 04.07.13 KB - 2 fields for NTLM client
   struct dsd_unicode_string dsc_ucs_netbios_computer_name;  /* server ComputerNameNetBIOS */
   struct dsd_unicode_string dsc_ucs_dns_domain_name;  /* server-DNS-domain-name */
   struct dsd_unicode_string dsc_ucs_dns_computer_name;  /* server-DNS-computer-name */
   struct dsd_unicode_string dsc_ucs_dns_tree_name;  /* server-DNS-tree-name */
   struct dsd_unicode_string dsc_ucs_netbios_domain_name;  /* NetBIOS-domain-name */
   struct dsd_unicode_string dsc_ucs_cookie_domain_name;  /* domain name for Cookie */
   struct dsd_unicode_string dsc_ucs_permmov_url;  /* permanently-moved-URL */
#ifndef B160423
   struct dsd_unicode_string dsc_ucs_group_id;  /* group Id            */
   struct dsd_unicode_string dsc_ucs_auth_token;  /* authentication token */
#endif
   struct dsd_unicode_string dsc_ucs_comment;  /* comment              */
   enum ied_dom_inf_auth_type iec_diat;     /* domain information authentication-type */
   BOOL       boc_use_full_pm_url;          /* use-full-permanently-moved-URL */
};

#ifndef DEF_HL_AUX_CHUSER_1
#define DEF_HL_AUX_CHUSER_1

#ifdef B140328
#ifndef HL_AUX_AUTH_DEF
#define HL_AUX_AUTH_DEF
enum ied_auth_def { ied_ad_ok,              /* userid and password fit */
                    ied_ad_inv_user,        /* userid invalid - not fo */
                    ied_ad_inv_password };  /* password invalid        */
#endif
#endif

#ifdef B140328
struct dsd_hl_aux_chuser_1 {                /* check user              */
   char *     achc_name;                    /* name UTF-8              */
   int        inc_len_name;                 /* length name in bytes    */
   char *     achc_password;                /* password UTF-8          */
   int        inc_len_password;             /* length password in byte */
   enum ied_auth_def iec_auth_def;          /* returned authenticated  */
};
#endif
#endif

#ifndef DEF_HL_AUX_RADIUS_1
#define DEF_HL_AUX_RADIUS_1

#define LEN_RADIUS_MSG_AUTH    16           /* length Radius MD5 message authenticator */

enum ied_radius_resp {                      /* response from radius server */
   ied_rar_invalid,                         /* parameter is invalid    */
   ied_rar_access_accept,                   /* accept sign on          */
   ied_rar_access_reject,                   /* reject access           */
   ied_rar_challenge,                       /* request challenge       */
   ied_rar_need_new_password,               /* needs new password      */
   ied_rar_error                            /* error, no valid response */
};

enum ied_certra_def {                       /* send certificate Radius */
  ied_certra_nothing = 0,                   /* do not send certificate */
  ied_certra_audhob1                        /* Attr User Def HOB       */
};

struct dsd_hl_aux_radius_1 {                /* radius request          */
#ifdef B111228
   char *     achc_name;                    /* name UTF-8              */
   int        inc_len_name;                 /* length name in bytes    */
   char *     achc_password;                /* password UTF-8          */
   int        inc_len_password;             /* length password in byte */
   char *     achc_attr_out;                /* attributes output       */
   int        inc_len_attr_out;             /* length attributes outp  */
   BOOL       boc_send_nas_ineta;           /* send NAS IP Address     */
   enum ied_certra_def iec_certra_def;      /* send certificate Radius */
   enum ied_radius_resp iec_radius_resp;    /* response from radius server */
   char *     achc_attr_in;                 /* attributes input        */
   int        inc_attr_in;                  /* length attributes inp   */
#endif
   struct dsd_unicode_string dsc_ucs_userid;  /* userid                */
   struct dsd_unicode_string dsc_ucs_password;  /* password            */
   struct dsd_unicode_string dsc_ucs_new_password;  /* new password    */
   char *     achc_attr_out;                /* attributes output       */
   int        imc_len_attr_out;             /* length attributes output */
   int        imrc_pos_identifier[ 16 ];    /* insert identifier       */
   BOOL       boc_send_nas_ineta;           /* send NAS IP Address     */
   BOOL       boc_radius_eap;               /* Radius EAP message      */
   BOOL       boc_radius_msg_auth;          /* with Radius message authentication */
   enum ied_certra_def iec_certra_def;      /* send certificate Radius */
   enum ied_radius_resp iec_radius_resp;    /* response from radius server */
   int        imc_ms_chap_v2_error;         /* error from MS-CHAP-V2   */
   char *     achc_attr_in;                 /* attributes input        */
   int        imc_attr_in;                  /* length attributes input */
//#ifdef NOT_YET_140920
   char *     achc_radius_msg_auth;         /* address message authenticator output */
//#endif
#ifndef B171207
   char *     achc_reply_message;           /* save reply message      */
   int        imc_len_reply_message;        /* length reply message    */
#endif
};
#endif

/* to-do 12.09.14 KB - makes no sense, PAP, MS-CHAP-V2 and EAP do not need to go over aux-cb. */
enum ied_auth_rpc_resp {                    /* response from RPC server */
   ied_arr_invalid,                         /* parameter is invalid    */
   ied_arr_ok,                              /* returns O.K.            */
   ied_arr_rpc_dc_not_set,                  /* RPC DC not set / selected */
   ied_arr_not_operational,                 /* RPC connection not operational */
   ied_arr_access_accept,                   /* accept sign on          */
   ied_arr_access_reject,                   /* reject access           */
   ied_arr_challenge,                       /* request challenge       */
   ied_arr_need_new_password,               /* needs new password      */
   ied_arr_error                            /* error, no valid response */
};

struct dsd_aux_auth_rpc_1 {                 /* authenticate over RPC   */
   struct dsd_unicode_string dsc_ucs_userid;  /* userid                */
   struct dsd_unicode_string dsc_ucs_password;  /* password            */
   struct dsd_unicode_string dsc_ucs_new_password;  /* new password    */
   enum ied_auth_rpc_resp iec_arr;          /* response from RPC server */
};

#ifdef INCL_TEST_RPC
#ifndef DEF_HL_NTLM_FUNC
#define DEF_HL_NTLM_FUNC

enum ied_ntlm_function {                    /* NTLM request function to process */
   ied_ntlmf_invalid = 0,                   /* parameter is invalid    */
   ied_ntlmf_neg_gen,                       /* generate NTLMSSP_NEGOTIATE */
   ied_ntlmf_neg_check,                     /* check NTLMSSP_NEGOTIATE */
   ied_ntlmf_chal_gen,                      /* generate NTLMSSP_CHALLENGE */
   ied_ntlmf_auth_gen,                      /* generate NTLMSSP_AUTH   */
   ied_ntlmf_auth_prep,                     /* prepare from NTLMSSP_AUTH */
   ied_ntlmf_auth_check                     /* check NTLMSSP_AUTH      */
};
#endif

struct dsd_aux_auth_rpc_ntlmv2_1 {          /* authenticate NTLMv2 over RPC */
   enum ied_auth_rpc_resp iec_arr;          /* response from RPC server */
   enum ied_ntlm_function iec_ntlmf;        /* NTLM request function to process */
#ifdef XYZ1
   void *     vpc_handle;                   /* handle of active connection to MS-AD */
#endif
   int        imc_ret_error_line;           /* returns line with error */
   BOOL       boc_gssapi;                   /* use GSSAPI              */
   char       *achc_negotiate;              /* address of packet NTLMSSP_NEGOTIATE */
   int        imc_len_negotiate;            /* length of packet NTLMSSP_NEGOTIATE */
// int        imc_offset_negotiate;         /* offset of content NTLMSSP_NEGOTIATE */
   char       *achc_challenge;              /* address of packet NTLMSSP_CHALLENGE */
   int        imc_len_challenge;            /* length of packet NTLMSSP_CHALLENGE */
// int        imc_offset_challenge;         /* offset of content NTLMSSP_CHALLENGE */
   char       *achc_auth;                   /* address of packet NTLMSSP_AUTH */
   int        imc_len_auth;                 /* length of packet NTLMSSP_AUTH */
   struct dsd_unicode_string dsc_ucs_domain;  /* domain name           */
   struct dsd_unicode_string dsc_ucs_userid;  /* userid / user name    */
#ifdef XYZ1
   struct dsd_unicode_string dsc_ucs_password;  /* password            */
#endif
   struct dsd_unicode_string dsc_ucs_workstation;  /* workstation      */
   struct dsd_unicode_string dsc_ucs_prot_target;  /* protocol and target */
   struct dsd_unicode_string dsc_ucs_targetname;  /* TargetName        */
   struct dsd_unicode_string dsc_ucs_netbios_computer_name;
   struct dsd_unicode_string dsc_ucs_netbios_domain_name;
   struct dsd_unicode_string dsc_ucs_dns_computer_name;
   struct dsd_unicode_string dsc_ucs_dns_domain_name;
   struct dsd_unicode_string dsc_ucs_dns_tree_name;
};
#endif

#ifndef DEF_HL_AUX_DISKFILE_1
#define DEF_HL_AUX_DISKFILE_1

enum ied_dfar_def {                         /* disk-file access return code */
   ied_dfar_ok,                             /* access is o.k.          */
#ifdef AUX_NEW_1411
   ied_dfar_parm_error,                     /* command parameter invalid */
#endif
   ied_dfar_mem_entry,                      /* no memory for entry     */
   ied_dfar_mem_file,                       /* no memory for file      */
   ied_dfar_cache_inv,                      /* in cache invalid        */
   ied_dfar_os_error,                       /* error from os           */
   ied_dfar_file_att,                       /* error fileattributes os */
   ied_dfar_get_file_size,                  /* error get file-size os  */
   ied_dfar_get_file_inf,                   /* error get file-inf os   */
   ied_dfar_file_read,                      /* error read from os      */
   ied_dfar_rep_error                       /* repeated error          */
};

struct dsd_hl_int_diskfile_1 {              /* diskfile intern         */
#ifndef HL_UNIX
   HL_WCHAR   *awcc_name;                   /* name Unicode UTF-16     */
   int        inc_len_name;                 /* length name in WCHAR    */
#else
   char       *achc_name;                   /* name Unicode UTF-8      */
   int        inc_len_name;                 /* length name in UTF-8    */
#endif
   char       *achc_filecont_start;         /* address file contents st */
   char       *achc_filecont_end;           /* addr file contents end  */
   int        imc_time_last_mod;            /* time last modified      */
};

struct dsd_hl_aux_diskfile_1 {              /* diskfile request        */
#ifndef AUX_NEW_1411
   void *     ac_name;                      /* name                    */
   enum ied_charset iec_chs_name;           /* character set           */
   int        inc_len_name;                 /* length name in elements */
#endif
#ifdef AUX_NEW_1411
   struct dsd_unicode_string dsc_ucs_file_name;  /* name of file       */
   BOOL       boc_unix_style_fn;            /* filename Unix style     */
#endif
   enum ied_dfar_def iec_dfar_def;          /* return-code             */
   void *     ac_handle;                    /* returned handle         */
   struct dsd_hl_int_diskfile_1 *adsc_int_df1;  /* returned diskfile intern */
   int        imc_time_last_mod;            /* time last modified      */
};
#endif

#ifndef DEF_HL_AUX_EPOCH_1
#define DEF_HL_AUX_EPOCH_1

enum ied_hl_aux_epoch_ret {
    ied_hl_aux_ep_failed = 0,               /* parsing failed          */
    ied_hl_aux_ep_ok,                       /* everything fine         */
    ied_hl_aux_ep_inv_format,               /* parsable but inv format */
    ied_hl_aux_ep_inv_mday,                 /* wrong monthday          */
    ied_hl_aux_ep_inv_wday                  /* wrong weekday           */
};

struct dsd_hl_aux_epoch_1 {                 /* request compute epoch   */
   void *     ac_epoch_str;                 /* epoch                   */
   enum ied_charset iec_chs_epoch;          /* character set           */
   int        inc_len_epoch;                /* length epoch in elements */
   int        imc_epoch_val;                /* epoch value             */
   enum ied_hl_aux_epoch_ret iec_parse_ret;  /* parser return code     */
};
#endif

#ifndef DEF_HL_AUX_C_CMA_1
#define DEF_HL_AUX_C_CMA_1

#define D_CMA_ALL_ACCESS           1        /* calling program wants all types of access */
#define D_CMA_READ_DATA            2        /* calling program wants read access */
#define D_CMA_WRITE_DATA           4        /* calling program wants write access */
#define D_CMA_SHARE_READ           256      /* calling program allows read access from others */
#define D_CMA_SHARE_WRITE          512      /* calling program allows write access from others */

//#define NOT_YET_080604
#ifdef NOT_YET_080604
enum ied_ccma_def {                         /* disk-file access return code */
   ied_ccma_query,                          /* query size of cma area  */
   ied_ccma_set_size,                       /* set new size of cma area */
   ied_ccma_lock_global,                    /* set global lock         */
   ied_ccma_lock_region,                    /* set lock on region      */
   ied_ccma_lock_release,                   /* release lock            */
   ied_ccma_lock_rel_upd,                   /* release lock and update */
   ied_ccma_retention_set,                  /* set retention time      */
   ied_ccma_retention_get,                  /* get retention time      */
//#ifdef NEW_080311
   ied_ccma_check_lock                      /* check if lock exists    */
//#endif
};
#else
enum ied_ccma_def {                         /* common memory area command */
   ied_ccma_query,                          /* query size of cma area  */
   ied_ccma_set_size,                       /* set new size of cma area */
   ied_ccma_lock_global,                    /* set global lock         */
   ied_ccma_lock_region,                    /* set lock on region      */
   ied_ccma_lock_release,                   /* release lock            */
   ied_ccma_lock_rel_upd,                   /* release lock and update */
   ied_ccma_retention_set,                  /* set retention time      */
   ied_ccma_retention_get,                  /* get retention time      */
   ied_ccma_browse_entry_gr_eq,             /* browse entry greater equal */
   ied_ccma_browse_entry_greater,           /* browse entry greater    */
   ied_ccma_check_lock                      /* check if lock exists    */
};
#endif

struct dsd_hl_aux_c_cma_1 {                 /* command common memory area */
   void *     ac_cma_name;                  /* cma name                */
   enum ied_charset iec_chs_name;           /* character set           */
   int        inc_len_cma_name;             /* length cma name in elements */
#ifndef NOT_YET_080604
   void *     ac_cma_browse_name;           /* result cma browse name  */
   enum ied_charset iec_chs_browse_name;    /* character set           */
   int        imc_len_cma_browse_name;      /* length cma brwose name in elements */
   int        imc_mem_cma_browse_name;      /* length cma browse name area in bytes */
#endif
   void *     ac_cma_handle;                /* cma handle              */
   enum ied_ccma_def iec_ccma_def;          /* command to process      */
   char       *achc_cma_area;               /* address cma area        */
   int        inc_len_cma_area;             /* length of cma area      */
   BOOL       boc_ret_lock_fails;           /* return immediately if lock fails */
   void *     vpc_cma_lock;                 /* lock handle             */
   int        inc_lock_disp;                /* displacement locked area */
   int        inc_lock_len;                 /* length of locked area   */
   int        imc_lock_type;                /* flags of lock           */
   int        imc_retention_time;           /* retention time in seconds */
//#ifdef NEW_080311
   int        imc_ret_no_locks;             /* return number of lock that exist */
//#endif
};
#endif

enum ied_chid_ret {                         /* check ident return code */
   ied_chid_ok,                             /* userid and password valid */
   ied_chid_inv_userid,                     /* userid invalid - not known in system */
   ied_chid_inv_password,                   /* password invalid - does not match */
   ied_chid_cont                            /* not yet complete, continue processing */
};

struct dsd_hl_aux_ch_ident {                /* check ident             */
   enum ied_charset iec_chs_userid;         /* character set userid    */
   void *     ac_userid;                    /* userid                  */
   int        inc_len_userid;               /* length userid in elements */
   enum ied_charset iec_chs_password;       /* character set password  */
   void *     ac_password;                  /* password                */
   int        inc_len_password;             /* length password in elements */
   enum ied_chid_ret iec_chid_ret;          /* check ident return code */
   void **    avpc_usent;                   /* user entry              */
   void **    avpc_usgro;                   /* user-group entry        */
};

struct dsd_hl_descr_sess_stor {             /* describe session storage */
   char       *achc_sess_stor;              /* pointer to session storage */
   int        inc_len_sess_stor;            /* length of session storage */
};

#ifdef OLD01
/* what for 06.08.04 KB */
struct dsd_call_co_1 {                      /* call control            */
   BOOL       boc_call_gatse;               /* call next data gatew se */
   BOOL       boc_call_setga;               /* call next data se gatew */
};
#endif

struct dsd_timer1_ret {                     /* timer return values     */
   HL_LONGLONG ilc_epoch;                   /* Epoch in milliseconds   */
   BOOL       boc_timer_set;                /* a timer is set and active */
   HL_LONGLONG ilc_timer;                   /* Epoch when timer elapses */
};

#ifndef DEF_Q_GATHER
#define DEF_Q_GATHER
/**
  structure to query if a Gather Structure (struct dsd_gather_i_1)
  is still being sent, that means active and waiting to get processed.
  when imc_set_signal is not zero, there will be a Signal when this
  Gather Structure has been processed and is no more active.
*/
struct dsd_q_gather_1 {                     /* query gather active     */
   void *     ac_gather;                    /* address of gather structure */
   BOOL       boc_still_active;             /* return TRUE if still active */
   int        imc_set_signal;               /* set Signal when no more active */
};
#endif

#ifndef DEF_SCP
#define DEF_SCP
/* hob-xsclib01.h, hob-wspat3.h and hob-xbipgw08-2.h */
enum ied_scp_def {                          /* server-conf protocol    */
   ied_scp_undef,                           /* protocol undefined      */
   ied_scp_http,                            /* protocol HTTP           */
   ied_scp_rdp,                             /* protocol MS RDP         */
   ied_scp_hrdpe1,                          /* protocol HOB MS RDP Extension 1 */
   ied_scp_ica,                             /* protocol ICA            */
   ied_scp_ldap,                            /* protocol LDAP           */
   ied_scp_hoby,                            /* protocol HOB-Y          */
   ied_scp_3270,                            /* protocol IBM 3270       */
   ied_scp_5250,                            /* protocol IBM 5250       */
   ied_scp_vt,                              /* protocol VT (100 - 525) */
   ied_scp_socks5,                          /* protocol Socks-5        */
   ied_scp_ssh,                             /* protocol SSH Secure Shell */
   ied_scp_smb,                             /* protocol SMB server message block */
   ied_scp_hpppt1,                          /* protocol HOB-PPP-T1     */
   ied_scp_hvoip1,                          /* protocol HOB-VOIP-1     */
   ied_scp_krb5ts1,                         /* protocol KRB5TS1 Kerberos Ticket Service */
   ied_scp_sstp,                            /* protocol SSTP           */
   ied_scp_soap,                            /* protocol SOAP           */
   ied_scp_ms_rpc,                          /* protocol MS-RPC         */
   ied_scp_websocket,                       /* protocol WebSocket      */
   ied_scp_hl_dash,                         /* protocol HOBLink data share */
   ied_scp_rdg_out_d,                       /* protocol MS RDG_OUT_DATA */
   ied_scp_rdg_in_d,                        /* protocol MS RDG_IN_DATA */
   ied_scp_openvpn_1,                       /* protocol OpenVPN        */
   ied_scp_spec                             /* special protocol        */
};

#define DEF_MAX_LEN_PROT       64           /* maximum length protocol */

struct dsd_get_sc_prot_1 {                  /* get Server Entry Protocol */
   enum ied_charset iec_chs_scp;            /* character set protocol  */
   void *     ac_scp;                       /* store protocol          */
   int        inc_len_scp;                  /* length of protocol in elements */
   enum ied_scp_def *aiec_scp_def;          /* server-conf protocol    */
};
#endif

#ifndef DEF_HOB_LDAP_1

/* hob-xsclib01.h and hob-hlwspat2.h ??? 14.01.07 KB */
#define DEF_HOB_LDAP_1

enum ied_ret_ldap_def                       /**< LDAP return codes (m_ldap_auth)  */
{
   ied_ret_ldap_ok,                         /**< successful, user authenticated   */
   ied_ret_ldap_failure,                    /**< wrong parameter or configuration */
   ied_ret_ldap_not_avail,                  /**< ldap service not available       */
   ied_ret_ldap_inv_userid,                 /**< userid not found                 */
   ied_ret_ldap_inv_password                /**< userid found, but wrong password */
};

enum ied_co_ldap_def                        /**< LDAP command */
{
   ied_co_ldap_invalid = 0,                 /**< value undefined                           */
   ied_co_ldap_bind,                        /**< LDAP open, bind    - Application[0]       */
   ied_co_ldap_search,                      /**< LDAP search entry  - Application[3]       */
   ied_co_ldap_modify,                      /**< LDAP modify entry  - Application[6]       */
   ied_co_ldap_add,                         /**< LDAP Add entry     - Application[8]       */
   ied_co_ldap_delete,                      /**< LDAP Delete entry  - Application[10]      */
   ied_co_ldap_modify_dn,                   /**< LDAP modify dn     - Application[12]      */
   ied_co_ldap_compare,                     /**< LDAP compare       - Application[14]      */
   ied_co_ldap_abandon,                     /**< LDAP abandon       - Application[16]      */
   ied_co_ldap_get_attrlist,                /**< LDAP get attribute list of user           */
   ied_co_ldap_get_membership,              /**< LDAP get 'memberOf'-attribute of an entry */
   ied_co_ldap_get_membership_nested,       /**< LDAP get nested 'member'-attributes       */
   ied_co_ldap_get_members,                 /**< LDAP get 'member'-attribute of an entry   */
   ied_co_ldap_get_members_nested,          /**< LDAP get nested 'member'-attributes       */
   ied_co_ldap_get_sysinfo,                 /**< LDAP get system informations              */
   ied_co_ldap_check_pwd_age,               /**< LDAP check the user's password age        */
   ied_co_ldap_explode_dn,                  /**< LDAP explode the DN                       */
   ied_co_ldap_clone_dn,                    /**< LDAP clone the given DN                   */
   ied_co_ldap_get_bind,                    /**< LDAP get the current bind-context         */
   ied_co_ldap_lookup,                      /**< LDAP test validity of a DN                */
   ied_co_ldap_close,                       /**< LDAP close server connection              */
   ied_co_ldap_get_last_err                 /**< LDAP get last error message               */
};

enum ied_resp_ldap_def                      /**< response/error from ldap */
{
   ied_ldap_invalid = 0,                    /**< LDAP, error code undefined         */
   ied_ldap_op_err,                         /**< LDAP: operationsError              */
   ied_ldap_prot_err,                       /**< LDAP: protocolError                */
   ied_ldap_tlimit_exceeded,                /**< LDAP: timeLimitExceeded            */
   ied_ldap_slimit_exceeded,                /**< LDAP: sizeLimitExceeded            */
   ied_ldap_cmp_false,                      /**< LDAP: compareFalse                 */
   ied_ldap_cmp_true,                       /**< LDAP: compareTrue                  */
   ied_ldap_auth_notsupp,                   /**< LDAP: authMethodNotSupported       */
   ied_ldap_strong_auth_req,                /**< LDAP: strongAuthRequired           */
   ied_ldap_referral = 10,                  /**< LDAP: referral                     */
   ied_ldap_admin_lim_exceeded,             /**< LDAP: adminLimitExceeded           */
   ied_ldap_unavail_critext,                /**< LDAP: unavailableCriticalExtension */
   ied_ldap_confid_req,                     /**< LDAP: confidentialityRequired      */
   ied_ldap_sasl_bind,                      /**< LDAP: saslBindInProgress           */
   // LDAP attribute errors...
   ied_ldap_no_such_attr = 16,              /**< LDAP: noSuchAttribute              */
   ied_ldap_undef_attr_type,                /**< LDAP: undefinedAttributeType       */
   ied_ldap_inappr_matching,                /**< LDAP: inappropriateMatching        */
   ied_ldap_constraint_violation,           /**< LDAP: constraintViolation          */
   ied_ldap_attr_or_val_exist,              /**< LDAP: attributeOrValueExists       */
   ied_ldap_inv_attr_syntax,                /**< LDAP: invalidAttributeSyntax       */
   // LDAP name errors...
   ied_ldap_no_such_obj = 32,               /**< LDAP: noSuchObject                 */
   ied_ldap_alias_problem,                  /**< LDAP: aliasProblem                 */
   ied_ldap_inv_dn_syntax,                  /**< LDAP: invalidDNSyntax              */
   ied_ldap_alias_deref_problem = 36,       /**< LDAP: aliasDereferencingProblem    */
   // LDAP security errors...
   ied_ldap_password_change,                /**< LDAP: password must change         */
   ied_ldap_no_logon_this_time,             /**< LDAP: no logon at this time        */
   ied_ldap_account_disabled,               /**< LDAP: account disabled             */
   ied_ldap_account_expired,                /**< LDAP: account expired              */
   ied_ldap_account_locked,                 /**< LDAP: account locked               */
   ied_ldap_need_ssl,                       /**< LDAP: SSL connection needed        */
   ied_ldap_password_expired,               /**< LDAP: password has expired         */
   ied_ldap_password_do_not_expire,         /**< LDAP: password don't expire        */
   ied_ldap_password_not_a_user_account,    /**< LDAP: not a normal user account    */
   ied_ldap_password_not_required,          /**< LDAP: no password is required      */
   ied_ldap_inappr_auth = 48,               /**< LDAP: inappropriateAuthentication  */
   ied_ldap_inv_cred,                       /**< LDAP: invalidCredentials           */
   ied_ldap_insuff_access_rights,           /**< LDAP: insufficientAccessRights     */
   // LDAP service errors...
   ied_ldap_busy,                           /**< LDAP: busy                         */
   ied_ldap_unavail,                        /**< LDAP: unavailable                  */
   ied_ldap_unwill_to_perform,              /**< LDAP: unwillingToPerform           */
   ied_ldap_loop_detect,                    /**< LDAP: loopDetect                   */
   ied_ldap_would_block,                    /**< LDAP: request would block          */
   // LDAP update errors...
   ied_ldap_name_violation = 64,            /**< LDAP: namingViolation              */
   ied_ldap_objcls_violation,               /**< LDAP: objectClassViolation         */
   ied_ldap_not_allowed_on_nleaf,           /**< LDAP: notAllowedOnNonLeaf          */
   ied_ldap_not_allowed_on_rdn,             /**< LDAP: notAllowedOnRDN              */
   ied_ldap_entr_already_exists,            /**< LDAP: entryAlreadyExists           */
   ied_ldap_objcls_mode_prohib,             /**< LDAP: objectClassModsProhibited    */
   ied_ldap_other = 80,                     /**< LDAP: other                        */
   // API error codes...
   ied_ldap_param_inv = 100,                /**< API: parameter is invalid          */
   ied_ldap_server_down,                    /**< API: LDAP server is down           */
   ied_ldap_connect_err,                    /**< API: LDAP server connect error     */
   ied_ldap_send_err,                       /**< API: LDAP tcp send error           */
   ied_ldap_send_blocked,                   /**< API: LDAP tcp send blocked         */
   ied_ldap_connection_closed,              /**< API: LDAP connection closed        */
   ied_ldap_connection_active,              /**< API: LDAP new connect without close*/
   ied_ldap_session_limit,                  /**< API: LDAP session limit reached    */
   ied_ldap_auth_unknown,                   /**< API: authentication unknown        */
   ied_ldap_filter_err,                     /**< API: wrong LDAP filter             */
   ied_ldap_no_memory,                      /**< API: no more memory available      */
   ied_ldap_tcpcomp_err,                    /**< API: TCPCOMP error occurred        */
   ied_ldap_wsa_err,                        /**< API: WSA error occurred            */
   ied_ldap_socket_err,                     /**< API: Socket error occurred         */
   ied_ldap_no_bind,                        /**< API: no bind was initiated         */
   ied_ldap_not_supp,                       /**< API: LDAP is not supported         */
   ied_ldap_no_config,                      /**< API: LDAP configuration not found  */
   ied_ldap_timeout,                        /**< API: LDAP time out                 */
   ied_ldap_no_results,                     /**< API: no (more) data results found  */
   ied_ldap_more_results,                   /**< API: more data results returned    */
   // ASN.1 error codes...
   ied_ldap_encoding_err = 200,             /**< ASN.1: invalid len/fmt sended      */
   ied_ldap_decoding_err,                   /**< ASN.1: invalid len/fmt received    */
   ied_ldap_inv_result_type,                /**< ASN.1: invalid result type         */
   // LDAP failure codes...
   ied_ldap_bind_err,                       /**< LDAP: Bind error                   */
   ied_ldap_search_err,                     /**< LDAP: Search error                 */
   ied_ldap_lookup_err,                     /**< LDAP: Lookup error                 */
   ied_ldap_unbind_err,                     /**< LDAP: Unbind error                 */
   ied_ldap_abandon_err,                    /**< LDAP: Abandon error                */
   ied_ldap_compare_err,                    /**< LDAP: Compare error                */
   ied_ldap_modify_err,                     /**< LDAP: Modify error                 */
   ied_ldap_modify_dn_err,                  /**< LDAP: Modify(DN) error             */
   ied_ldap_add_err,                        /**< LDAP: Add error                    */
   ied_ldap_delete_err,                     /**< LDAP: Delete error                 */
   ied_ldap_check_pwd_err,                  /**< LDAP: Check password expire error  */
   ied_ldap_explode_dn_err,                 /**< LDAP: Explode DN error             */
   ied_ldap_clone_dn_err,                   /**< LDAP: Clone DN error               */
   ied_ldap_change_pwd_err,                 /**< LDAP: Password change error        */
   // LDAP common return codes...
   ied_ldap_success = 1000,                 /**< API: successful, no errors         */
   ied_ldap_failure = -1                    /**< LDAP function's error value        */
};


enum ied_objectclass                        /**< LDAP entry type definitions */
{
   ied_objectclass_person,                  /**< objectclass 'person'        */
   ied_objectclass_group                    /**< objectclass 'group'         */
};


#define DEF_LDAP_IBM       "IBM Directory Server"
#define DEF_LDAP_MSAD      "Microsoft Active Directory"
#define DEF_LDAP_IPLANET   "iPlanet Directory Server"
#define DEF_LDAP_NOVELL    "Novell Directory Server"
#define DEF_LDAP_SIEMENS   "Siemens DirX LDAP"
#define DEF_LDAP_OPENLDAP  "OpenLDAP"
#define DEF_LDAP_OPENDS    "OpenDS"
#define DEF_LDAP_OPENDJ    "OpenDJ"

enum ied_type_ldap_def                      /**< LDAP type definitions      */
{
   ied_sys_ldap_ibm = 1,                    /**< IBM directory server       */
   ied_sys_ldap_msad,                       /**< Microsoft active directory */
   ied_sys_ldap_iplanet,                    /**< iPlanet directory server   */
   ied_sys_ldap_novell,                     /**< Novell directory server    */
   ied_sys_ldap_siemens,                    /**< Siemens DirX LDAP          */
   ied_sys_ldap_openldap,                   /**< OpenLDAP                   */
   ied_sys_ldap_generic,                    /**< generic type               */
   ied_sys_ldap_opends,                     /**< OpenDS                     */
   ied_sys_ldap_opendj                      /**< OpenDJ                     */
};

enum ied_auth_ldap_def       /**< kind of ldap authentication (bind) */
{
   ied_auth_user,            /**< search dn of this user and use dn for authentication */
   ied_auth_user_pwd_change, /**< change the (expired) password of the user            */
   ied_auth_dn,              /**< use the user name dn for authentication              */
   ied_auth_admin,           /**< use configured administrator dn for authentication   */
   ied_auth_ntlm,            /**< SASL: NTLM-mechanism                                 */
   ied_auth_krb5,            /**< SASL: KRB5-mechanism                                 */
   ied_auth_sid              /**< MSAD only: the user name dn contains a 'objectSID'   */
};

enum ied_scope_ldap_def      /**< kind of ldap search range, search at... */
{
   ied_sear_baseobject,      /**< the baseObject only                                        */
   ied_sear_onelevel,        /**< the baseObject and the next level                          */
   ied_sear_sublevel,        /**< the baseObject and all sub-levels                          */
   ied_sear_children,        /**< the baseObject and its children nodes                      */
   ied_sear_superlevel,      /**< the baseObject and all super-level (backwards to the root) */
   ied_sear_root,            /**< the root and all sub-levels (root == namingcontexts)       */
   ied_sear_basedn,          /**< the <base-dn> defined address                              */
   ied_sear_attronly         /**< only a attribute list without values is returned           */
};

enum ied_confirm_def         /**< types of confirmation        */
{
   ied_confirm_no,           /**< no, do nothing (default)     */
   ied_confirm_yes,          /**< yes, force operation         */
   ied_confirm_skip          /**< skip the action and continue */
};


struct dsd_ldap_template;
struct dsd_target_ineta_1;

struct dsd_ldap_val         /**< LDAP value attribute description */
{
   struct dsd_ldap_val *adsc_next_val;   /**< [in,out] next in value chain (only by multivalued)         */
   enum ied_charset     iec_chs_val;     /**< [in,out] value(s) character set                            */
   int                  imc_len_val;     /**< [in,out] value length                                      */
   char                *ac_val;          /**< [in,out] value                                             */
   enum ied_charset     iec_chs_val_old; /**< [in]     old value(s) character set                        */
   int                  imc_len_val_old; /**< [in]     old value length                                  */
   char                *ac_val_old;      /**< [in]     old value to be changed (ied_co_ldap_modify only) */
};

struct dsd_ldap_attr        /**< LDAP attribute description */
{
   struct dsd_ldap_attr *adsc_next_attr; /**< [in,out] next in chain                                        */
   enum  ied_charset     iec_chs_attr;   /**< [in,out] character set of the requested or returned attribute */
   int                   imc_len_attr;   /**< [in,out] length of the attribute name in bytes                */
   char                 *ac_attr;        /**< [in,out] attribute name                                       */
   struct dsd_ldap_val   dsc_val;        /**< [in,out] attribute value description(s)                       */
};

struct dsd_ldap_attr_desc   /**< LDAP attribute dn description */
{
   struct dsd_ldap_attr_desc *adsc_next_attr_desc; /**< [in,out] next in chain          */
   enum ied_charset           iec_chs_dn;          /**< [in,out] (R)DN character set    */
   int                        imc_len_dn;          /**< [in,out] (R)DN-name length      */
   char                      *ac_dn;               /**< [in,out] (R)DN-name             */
   struct dsd_ldap_attr      *adsc_attr;           /**< [in,out] attribute description  */
};

struct dsd_ldap_sysinfo     /**< LDAP system information description */
{
   enum ied_type_ldap_def     iec_type;           /**< [out] ldap server type, e.g. OpenLDAP          */
   int                        imc_port;           /**< [out] ldap server port                         */
   struct dsd_target_ineta_1 *adsc_target_ineta;  /**< [out] ldap server address                      */
   struct dsd_ldap_template  *adsc_ldap_template; /**< [out] ldap used template information           */
   struct dsd_ldap_val       *adsc_base_dn;       /**< [out] list of LDAP returned base-dn(s)         */
   struct dsd_ldap_val       *adsc_base_dn_def;   /**< [out] LDAP returned default base-dn (optional) */
   struct dsd_ldap_val       *adsc_base_dn_conf;  /**< [out] configured '<base-dn>'-entry             */
   int                        imc_len_admin;      /**< [out] administrator name length                */
   char                      *ac_admin;           /**< [out] administrator name (utf-8)               */
};

struct dsd_ldap_pwd         /**< LDAP password properties */
{
   enum ied_resp_ldap_def  iec_account_control; /**< [out] ldap user account control */
   HL_LONGLONG             ilc_exp_minutes;     /**< [out] expire time in minutes    */
   HL_LONGLONG             ilc_exp_hours;       /**< [out] expire time in hours      */
   HL_LONGLONG             ilc_exp_days;        /**< [out] expire time in days       */
};

#define SM_USE_LDAP_AUX_CALL 1

struct dsd_co_ldap_1     /**< LDAP request parameter */
{
   // common LDAP command definitions...
   enum ied_co_ldap_def       iec_co_ldap;        /**< [in]  ldap command                                     */
   enum ied_confirm_def       iec_ldap_confirm;   /**< [in]  ldap confirmation (set by user or program)       */
   enum ied_resp_ldap_def     iec_ldap_resp;      /**< [out] ldap response ('ied_ldap_success' or error code) */
   // optional: client storage handle
#if SM_USE_LDAP_AUX_CALL
   BOOL                       (* amc_aux) ( void *, int, void *, int );  /* auxiliary callback routine */
   void*                      vpc_userfld;                               /* User Field Subroutine      */
#else
   void**                     avoc_stor_handle;   /**< [in]  client storage handler (xslstor01.cpp)           */
#endif
   // Error message (if 'iec_ldap_resp != ied_ldap_success')
   enum ied_charset           iec_chs_errmsg;     /**< [out] errmsg charset                                   */
   int                        imc_len_errmsg;     /**< [out] errmsg length                                    */
   char                      *ac_errmsg;          /**< [out] errmsg                                           */
   // LDAP authentication (simple/sasl)
   enum ied_auth_ldap_def     iec_ldap_auth;      /**< [in,out] bind with dn, user name, admin or sasl        */
   enum ied_charset           iec_chs_userid;     /**< [in,out] user name character set                       */
   int                        imc_len_userid;     /**< [in,out] user name length                              */
   char                      *ac_userid;          /**< [in,out] user name                                     */
   enum ied_charset           iec_chs_passwd;     /**< [in]     password character set (ignored for sasl)     */
   int                        imc_len_passwd;     /**< [in,out] password or credentials length                */
   char                      *ac_passwd;          /**< [in,out] password or credentials                       */
   enum ied_charset           iec_chs_passwd_new; /**< [in]     new password character set                    */
   int                        imc_len_passwd_new; /**< [in]     new password length                           */
   char                      *ac_passwd_new;      /**< [in]     new password                                  */
   struct dsd_ldap_pwd       *adsc_pwd_info;      /**< [out]    ldap password properties (expire-date, ...)   */
   // LDAP distinguished name (baseObject)
   enum ied_charset           iec_chs_dn;         /**< [in,out] (R)DN character set                           */
   int                        imc_len_dn;         /**< [in,out] (R)DN-name length                             */
   char                      *ac_dn;              /**< [in,out] (R)DN-name                                    */
   struct dsd_unicode_string  dsc_add_dn;         /**< [in]  additional (user)-dn                             */
   enum ied_scope_ldap_def    iec_sear_scope;     /**< [in]  search scope (dn, tree, ...)                     */
   // LDAP search filter description
   enum ied_charset           iec_chs_filter;     /**< [in]  filter expression character set                  */
   int                        imc_len_filter;     /**< [in]  filter expression length                         */
   char                      *ac_filter;          /**< [in]  filter expression (e.g. '(&(ou=hob)(o=malta)))') */
   // LDAP modify dn description
   enum ied_charset           iec_chs_newrdn;     /**< [in]  new modifyRDN-name character set                 */
   int                        imc_len_newrdn;     /**< [in]  new modifyRDN-name length                        */
   char                      *ac_newrdn;          /**< [in]  new modifyRDN-name                               */
   // LDAP search attribute-list description
   enum ied_charset           iec_chs_attrlist;   /**< [in]  attribute(s)-list character set                  */
   int                        imc_len_attrlist;   /**< [in]  attribute(s)-list length                         */
   char                      *ac_attrlist;        /**< [in]  attribute(s)-list, comma separated (CSV)         */
   // LDAP 'attribute=value' description
   struct dsd_ldap_attr_desc *adsc_attr_desc;     /**< [in,out] attribute(s),value(s) (single- / multi-valued)*/
   // LDAP 'membership'-description
   struct dsd_ldap_val       *adsc_memship_desc;  /**< [out] member and membership entries                    */
   // LDAP system description
   enum ied_objectclass       iec_objectclass;    /**< [in]  objectclass type of a new entry (e.g. clone...)  */
   struct dsd_ldap_sysinfo   *adsc_sysinfo;       /**< [out] ldap system description                          */
};

#endif // DEF_HOB_LDAP_1

enum ied_ret_krb5_def {                     /* return from Kerberos    */
   ied_ret_krb5_ok = 0,                     /* success                 */
   ied_ret_krb5_kdc_not_conf,               /* KDC not configured      */
   ied_ret_krb5_kdc_not_sel,                /* KDC not selected        */
   ied_ret_krb5_no_sign_on,                 /* session not signed on   */
   ied_ret_krb5_kdc_inv,                    /* KDC invalid             */
   ied_ret_krb5_userid_unknown,             /* Userid unknown          */
   ied_ret_krb5_password,                   /* password invalid        */
   ied_ret_krb5_pwd_expired,                /* password has expired    */
   ied_ret_krb5_no_tgt,                     /* TGT not found           */
   ied_ret_krb5_buf_too_sm,                 /* buffer size is too small */
   ied_ret_krb5_decrypt_err,                /* decryption error        */
   ied_ret_krb5_kdc_not_found,              /* previously used KDC not found */
   ied_ret_krb5_conf_already_set,           /* KDC already set         */
   ied_ret_krb5_not_mult_conf,              /* not multiple KDC configured */
   ied_ret_krb5_key_not_found,              /* check service ticket, key not in keytab */
   ied_ret_krb5_clock_skew_expired,         /* clock skew does not match */
   ied_ret_krb5_misc                        /* miscellaneous error     */
};

struct dsd_aux_krb5_sign_on_1 {             /* Kerberos 5 Sign On      */
   enum ied_ret_krb5_def iec_ret_krb5;      /* return from Kerberos    */
// return value 25.08.09 KB
   struct dsd_unicode_string dsc_user_name;  /* Username Sign On       */
   struct dsd_unicode_string dsc_user_group;  /* Usergroup Sign On     */
   struct dsd_unicode_string dsc_password;  /* Password Sign On        */
#ifdef NEW110210
   struct dsd_unicode_string dsc_new_password;  /* for password changed */
#endif
};

#define HL_KRB5_OPT_MUTUAL 1
#define HL_KRB5_OPT_GSSAPI 2                /* including SPNEGO        */

struct dsd_aux_krb5_se_ti_get_1 {           /* Kerberos get Service Ticket */
   enum ied_ret_krb5_def iec_ret_krb5;      /* return from Kerberos    */
// return value 25.08.09 KB
   int        imc_options;                  /* options to process      */
#ifdef NOT_YET_130806
   BOOL       boc_gssapi;                   /* use GSSAPI              */
- or -
#define HL_KRB5_OPT_GSSAPI 2
#endif
   void *     vpc_handle;                   /* handle returned         */
#ifdef XYZ1
/* use values stored in aux of session */
   struct dsd_unicode_string dsc_user_name;  /* Username               */
   struct dsd_unicode_string dsc_user_group;  /* Usergroup             */
#endif
   struct dsd_unicode_string dsc_server_name;  /* Server-Name          */
   struct dsd_unicode_string dsc_server_group;  /* Server-Group        */
   char       *achc_ticket_buffer;          /* address buffer for service ticket */
   int        imc_ticket_buffer_len;        /* length buffer for service ticket */
   int        imc_ticket_length;            /* length of returned service ticket */
};

struct dsd_aux_krb5_se_ti_c_r_1 {           /* Kerberos check Service Ticket Response */
   enum ied_ret_krb5_def iec_ret_krb5;      /* return from Kerberos    */
// return value 25.08.09 KB
   void *     vpc_handle;                   /* handle returned by DEF_AUX_KRB5_SE_TI_GET */
   char       *achc_response_buffer;        /* address buffer of response */
   int        imc_response_length;          /* length of response      */
};

struct dsd_aux_krb5_opt_1 {                 /* Kerberos options        */
   unsigned int ibc_no_ret_handle : 1;      /* do not return handle    */
   unsigned int filler : 31;                /* filler                  */
};

struct dsd_aux_krb5_se_ti_check_1 {         /* Kerberos check Service Ticket */
   enum ied_ret_krb5_def iec_ret_krb5;      /* return from Kerberos    */
   struct dsd_aux_krb5_opt_1 dsc_aux_krb5_opt_1;  /* Kerberos options  */
   void *     vpc_handle;                   /* handle returned         */
   struct dsd_unicode_string dsc_ucs_realm_service;  /* realm service returned */
   struct dsd_unicode_string dsc_ucs_princ_service;  /* principal service returned */
   struct dsd_unicode_string dsc_ucs_realm_client;  /* realm client returned */
   struct dsd_unicode_string dsc_ucs_princ_client;  /* principal client returned */
   char       *achc_keytab;                 /* address of keytab       */
   int        imc_len_keytab;               /* length of keytab        */
   int        imc_clock_skew;               /* maximum allowed clock skew of ticket */
   char       *achc_ticket_in;              /* address buffer for service ticket input */
   int        imc_ticket_length;            /* length of input service ticket */
   char       *achc_mutual_resp_buffer;     /* address buffer for mutual response */
   int        imc_mutual_resp_buffer_len;   /* length buffer for mutual response */
   int        imc_mutual_resp_length;       /* length of returned mutual response */
};

struct dsd_aux_krb5_get_session_key {       /* retrieve Kerberos-5 session key */
   enum ied_ret_krb5_def iec_ret_krb5;      /* return from Kerberos    */
   void *     vpc_handle;                   /* returned by DEF_AUX_KRB5_SE_TI_GET */
   char *     achc_key_buffer;              /* output buffer for key data */
   int        imc_key_buffer_len;           /* length output buffer for key data */
   int        imc_key_len_ret;              /* length of actual key data */
};

struct dsd_aux_krb5_encrypt {               /* Kerberos encrypt data   */
   enum ied_ret_krb5_def iec_ret_krb5;      /* return from Kerberos    */
// return value 10.10.09 KB
   void *     vpc_handle;                   /* handle returned by DEF_AUX_KRB5_SE_TI_GET */
   char       *achc_inp_data;               /* input data              */
   int        imc_len_inp_data;             /* length input data       */
   char       *achc_out_enc_buffer;         /* output buffer for encrypted data */
   int        imc_enc_buffer_len;           /* length output buffer for encrypted data */
   int        imc_enc_len_ret;              /* returned length of encrypted data */
};

struct dsd_aux_krb5_decrypt {               /* Kerberos decrypt data   */
   enum ied_ret_krb5_def iec_ret_krb5;      /* return from Kerberos    */
// return value 10.10.09 KB
   void *     vpc_handle;                   /* handle returned by DEF_AUX_KRB5_SE_TI_GET */
   char       *achc_inp_enc_data;           /* input encrypted data    */
   int        imc_len_inp_enc_data;         /* length input encrypted data */
   char       *achc_out_dec_buffer;         /* output buffer for decrypted data */
   int        imc_dec_buffer_len;           /* length output buffer for decrypted data */
   int        imc_dec_len_ret;              /* returned length of decrypted data */
};

struct dsd_aux_krb5_se_ti_rel_1 {           /* Kerberos release Service Ticket Resources */
   enum ied_ret_krb5_def iec_ret_krb5;      /* return from Kerberos    */
// return value 10.10.09 KB
   void *     vpc_handle;                   /* handle returned by DEF_AUX_KRB5_SE_TI_GET */
};

struct dsd_aux_krb5_logoff {                /* Kerberos logoff         */
   enum ied_ret_krb5_def iec_ret_krb5;      /* return from Kerberos    */
};

struct dsd_aux_krb5_session_assign_conf {   /* assign Kerberos to Session */
   enum ied_ret_krb5_def iec_ret_krb5;      /* return from Kerberos    */
};

enum ied_co_service_def {                   /* service command         */
   ied_co_service_invalid,                  /* value undefined         */
   ied_co_service_open,                     /* service open connection */
   ied_co_service_requ,                     /* service request         */
   ied_co_service_close                     /* service close connection */
};

enum ied_ret_service_def {                  /* service return code     */
   ied_ret_service_ok,                      /* service command o.k.    */
   ied_ret_service_open_failed,             /* service open failed     */
   ied_ret_service_not_open,                /* service not open        */
   ied_ret_service_inv_name,                /* invalid service name - not found */
   ied_ret_service_req_failed               /* request failed          */
};

struct dsd_aux_service_query_1 {            /* service query           */
   enum ied_co_service_def iec_co_service;  /* service command         */
   enum ied_ret_service_def iec_ret_service;  /* service return code   */
   void *     vpc_sequ_handle;              /* handle of service query */
   void *     ac_service_name;              /* service name            */
   int        imc_len_service_name;         /* length service name in elements */
   enum ied_charset iec_chs_service_name;   /* character set service name */
   int        imc_signal;                   /* signal to set           */
   void *     ac_control_area;              /* control area request    */
};

/**
   Structure for DEF_AUX_COUNT_SERVENT and DEF_AUX_GET_SERVENT
*/
struct dsd_get_servent_1 {                  /* get Server Entry        */
   void *     vpc_usent;                    /* user entry              */
   void *     vpc_usgro;                    /* user-group entry        */
   void *     vpc_handle;                   /* handle of entry         */
   enum ied_scp_def iec_scp_def;            /* server-conf protocol    */
#ifdef OLD_1112
   enum ied_charset iec_chs_scp;            /* character set protocol  */
   void *     ac_scp;                       /* store protocol          */
   int        inc_len_scp;                  /* length of protocol in elements */
#else
   struct dsd_unicode_string dsc_ucs_protocol;  /* protocol            */
#endif
   enum ied_charset iec_chs_target;         /* character set target    */
   void *     ac_servent_target;            /* store Server Entry Name */
   int *      ainc_len_target_bytes;        /* length of target area in bytes */
   int *      aimc_function;                /* store function of this server entry */
   int *      ainc_no_servent;              /* only for DEF_AUX_COUNT_SERVENT */
};

enum ied_ret_get_sdho_def {                 /* get sdh object return code */
   ied_ret_g_sdho_ok,                       /* get sdh object command o.k. */
   ied_ret_g_sdho_not_found                 /* Server-Data-Hook not found */
};

struct dsd_get_sdh_object_1 {               /* get Server-Data-Hook object */
   enum ied_ret_get_sdho_def iec_ret_get_sdho;  /* get sdh object return code */
   void *     ac_sdho_name;                 /* Server-Data-Hook object name */
   int        imc_len_sdho_name;            /* length Server-Data-Hook object name in elements */
   enum ied_charset iec_chs_sdho_name;      /* character set Server-Data-Hook object name */
   struct dsd_sdh_stack_1 *adsc_sdh_stack_1;  /* Server-Data-Hook stack */
};

struct dsd_sdh_udp_recbuf_1 {               /* UDP receive buffer      */
   struct dsd_sdh_udp_recbuf_1 *adsc_next;  /* next in chain           */
   char       *achc_data;                   /* pointer to data         */
   char       *achc_sockaddr;               /* pointer to sockaddr structure */
   int        imc_len_data;                 /* length of data          */
   int        imc_len_sockaddr;             /* length of sockaddr structure */
   int        imc_error_os;                 /* error from the operating system */
   int        imc_error_hob;                /* HOB specific error number */
};

enum ied_sdh_sip_requ_1_def {               /* SIP request command     */
   ied_sdh_sipr1_register,                  /* SIP register entry      */
   ied_sdh_sipr1_send,                      /* SIP send packet         */
   ied_sdh_sipr1_send_gather,               /* SIP send gather         */
   ied_sdh_sipr1_update_recv,               /* SIP update received packets */
   ied_sdh_sipr1_free_buffer,               /* SIP free buffer(s)      */
   ied_sdh_sipr1_close                      /* SIP close               */
};

enum ied_ret_sip_requ_1_def {               /* return value SIP request */
   ied_ret_sipr1_ok,                        /* SIP request command o.k. */
   ied_ret_sipr1_net_err,                   /* SIP request network error */
   ied_ret_sipr1_ident_invalid,             /* SIP ident invalid parameter */
   ied_ret_sipr1_entry_double,              /* SIP entry defined double */
   ied_ret_sipr1_send_error                 /* SIP send failed         */
};

struct dsd_sdh_sip_requ_1 {                 /* SIP protocol request    */
   enum ied_sdh_sip_requ_1_def iec_sdh_sipr1;  /* SIP request command  */
   enum ied_ret_sip_requ_1_def iec_ret_sipr1;  /* return value SIP request */
   void *     vpc_sipr_handle;              /* handle of SIP request   */
   void *     ac_sip_ident;                 /* SIP ident               */
   int        imc_len_sip_ident;            /* length SIP ident in elements */
   enum ied_charset iec_chs_sip_ident;      /* character set SIP ident */
   char *     achc_ineta_sip_gw;            /* INETA SIP gateway       */
   char       *achc_local_sip_sockaddr;     /* pointer to sockaddr structure */
   int        imc_len_ineta_sip_gw;         /* length INETA SIP gateway */
   int        imc_len_local_sip_sockaddr;   /* length of sockaddr structure */
   char       *achc_data_send;              /* data to send            */
   char       *achc_sockaddr;               /* pointer to sockaddr structure */
   int        imc_len_data_send;            /* length data to send     */
   int        imc_len_sockaddr;             /* length of sockaddr structure */
   struct dsd_gather_i_1 *adsc_gai1_send;   /* gather to send          */
   struct dsd_sdh_udp_recbuf_1 *adsc_recb_1;  /* chain of receive buffers */
   int        imc_signal;                   /* signal to set           */
};

enum ied_sdh_udp_requ_1_def {               /* UDP request command     */
   ied_sdh_udpr1_register,                  /* UDP register entry      */
   ied_sdh_udpr1_send,                      /* UDP send packet         */
   ied_sdh_udpr1_send_gather,               /* UDP send gather         */
   ied_sdh_udpr1_update_recv,               /* UDP update received packets */
   ied_sdh_udpr1_free_buffer,               /* UDP free buffer(s)      */
   ied_sdh_udpr1_close                      /* UDP close               */
};

struct dsd_sdh_udp_requ_1 {                 /* UDP request             */
   enum ied_sdh_udp_requ_1_def iec_sdh_udpr1;  /* UDP request command  */
   void *     vpc_udpr_handle;              /* handle of UDP request   */
   void *     ac_bind;                      /* name configured bind    */
   int        imc_len_bind;                 /* length bind name in elements */
   enum ied_charset iec_chs_bind;           /* character set bind name */
   char       *achc_soa_bind;               /* pointer to sockaddr structure bind */
   int        imc_len_soa_bind;             /* in/out length of sockaddr structure bind */
   int        imc_port_bind;                /* port of bind            */
   char       *achc_data_send;              /* data to send            */
   char       *achc_sockaddr;               /* pointer to sockaddr structure */
   int        imc_len_data_send;            /* length data to send     */
   int        imc_len_sockaddr;             /* length of sockaddr structure */
   struct dsd_gather_i_1 *adsc_gai1_send;   /* gather to send          */
   struct dsd_sdh_udp_recbuf_1 *adsc_recb_1;  /* chain of receive buffers */
   int        imc_signal;                   /* signal to set           */
};

enum ied_ret_get_idset1_def {               /* get sdh ident settings return code */
   ied_ret_g_idset1_ok,                     /* ident known, parameters returned, o.k. */
   ied_ret_g_idset1_not_found               /* ident not found         */
};

#ifdef B100403
struct dsd_sdh_ident_set_1 {                /* settings for given ident */
   enum ied_ret_get_idset1_def iec_ret_g_idset1;  /* return code       */
#ifdef B090802
   void *     ac_userid;                    /* userid                  */
   int        imc_len_userid;               /* length userid in elements */
   ied_charset iec_chs_userid;              /* character set userid    */
#else
   struct dsd_unicode_string dsc_userid;    /* unicode string userid   */
   struct dsd_unicode_string dsc_user_group;  /* unicode string user-group */
#endif
// to-do 5.3.10 KB change to struct dsd_config_ineta_1 *
   char *     achc_ineta_ppp;               /* INETA PPP Tunnel        */
   int        imc_len_ineta_ppp;            /* length INETA PPP Tunnel */
   char *     achc_ineta_appl;              /* INETA HTCP personal     */
   int        imc_len_ineta_appl;           /* length INETA HTCP       */
   void *     ac_sip_ident;                 /* SIP ident               */
   int        imc_len_sip_ident;            /* length SIP ident in elements */
   enum ied_charset iec_chs_sip_ident;      /* character set SIP ident */
   void *     ac_sip_shase;                 /* SIP shared secret       */
   int        imc_len_sip_shase;            /* length SIP shared secret in elements */
   enum ied_charset iec_chs_sip_shase;      /* character set SIP shared secret */
   char *     achc_ineta_sip_gw;            /* INETA SIP gateway       */
   int        imc_len_ineta_sip_gw;         /* length INETA SIP gateway */
};
#endif
struct dsd_sdh_ident_set_1 {                /* settings for given ident */
   enum ied_ret_get_idset1_def iec_ret_g_idset1;  /* return code       */
   struct dsd_unicode_string dsc_userid;    /* unicode string userid   */
   struct dsd_unicode_string dsc_user_group;  /* unicode string user-group */
   struct dsd_unicode_string dsc_sip_fullname;  /* unicode string SIP fullname */
   struct dsd_unicode_string dsc_sip_ident;  /* unicode string SIP ident */
   struct dsd_unicode_string dsc_sip_display_number;  /* unicode string SIP display-number */
   struct dsd_unicode_string dsc_sip_shase;  /* unicode string SIP shared secret */
//#ifdef NEW_1406
   struct dsd_unicode_string dsc_e_mail;    /* unicode string e-mail address */
   struct dsd_unicode_string dsc_aux_1;     /* unicode string auxiliary field 1 */
   struct dsd_unicode_string dsc_aux_2;     /* unicode string auxiliary field 2 */
   struct dsd_unicode_string dsc_aux_3;     /* unicode string auxiliary field 3 */
   struct dsd_unicode_string dsc_aux_4;     /* unicode string auxiliary field 4 */
//#endif
   char *     achc_ineta_sip_gw;            /* INETA SIP gateway       */
   int        imc_len_ineta_sip_gw;         /* length INETA SIP gateway */
   char       *achc_userfld;                /* user field for session  */
   int        imc_len_userfld;              /* length user field for session */
};

struct dsd_aux_session_conf_1 {             /* configure session parameters */
   BOOL       boc_use_default_servli;       /* use default server list */
   struct dsd_aux_conf_servli_1 *adsc_servli_1;  /* chain of configure server list */
   struct dsd_unicode_string dsc_targfi_1_name;  /* unicode string target-filter name */
   struct dsd_config_ineta_1 *adsc_co_ineta_ppp;  /* configured INETAs PPP */
   struct dsd_config_ineta_1 *adsc_co_ineta_appl;  /* configured INETAs application / HTCP */
};

struct dsd_aux_conf_servli_1 {              /* configure server list   */
   struct dsd_aux_conf_servli_1 *adsc_next;  /* next in chain          */
   struct dsd_unicode_string dsc_servli_name;  /* unicode string server-list name */
};

struct dsd_ldap_session_conf_1 {            /* configure session parameters */
   struct dsd_unicode_string dsc_user_group;  /* unicode string user-group */
   BOOL       boc_use_default_servli;       /* use default server list */
   struct dsd_aux_conf_servli_1 *adsc_servli_1;  /* chain of configure server list */
   struct dsd_unicode_string dsc_targfi_1_name;  /* unicode string target-filter name */
   char       chrl_ineta_ipv4_ppp[4];       /* ineta-ppp or zero       */
   char       chrl_ineta_ipv4_appl[4];      /* ineta-appl or zero      */
};

/**
   The structures struct dsd_config_ineta_1
   is followed by structures struct dsd_ineta_single_1
   and each followed by the corresponding INETA.
   These structures contain no pointers,
   so they can by copied to another area.
*/

struct dsd_config_ineta_1 {                 /* definition configured INETA */
   int        imc_no_ineta;                 /* number of INETA         */
   int        imc_len_mem;                  /* length of memory including this structure */
};

#ifndef DEF_HOB_INETA_S_1

/* hob-xsclib01.h and hob-netw-01.h */
#define DEF_HOB_INETA_S_1

struct dsd_ineta_single_1 {                 /* single INETA target / listen / configured */
   unsigned short int usc_family;           /* family IPV4 / IPV6      */
   unsigned short int usc_length;           /* length of following address */
};

#endif

struct dsd_aux_admin_1 {                    /* process admin request   */
   HL_LONGLONG ilc_handle_cluster;          /* select cluster          */
   char       *achc_command;                /* address of command      */
   int        imc_len_command;              /* length of command       */
   BOOL       boc_free_buffers;             /* free old buffers        */
   int        imc_signal;                   /* signal to set           */
   struct dsd_gather_i_1 *adsc_gai1_ret;    /* data returned from call */
};

struct dsd_aux_set_ident_1 {                /* set ident - userid and user-group */
   struct dsd_unicode_string dsc_userid;    /* unicode string userid   */
   struct dsd_unicode_string dsc_user_group;  /* unicode string user-group */
   char       *achc_userfld;                /* user field for session  */
   int        imc_len_userfld;              /* length user field for session */
};

struct dsd_aux_check_target_filter_1 {      /* check against target-filter */
   BOOL       boc_ret_ok;                   /* return TRUE if o.k.     */
   struct dsd_unicode_string dsc_name_target_filter;  /* name of target filter */
   struct dsd_unicode_string dsc_ineta;     /* INETA to check          */
   int        imc_port;                     /* port to check           */
};

struct dsd_aux_get_radius_entry {           /* retrieve configured radius group */
   int        imc_no_entry;                 /* input index of entry    */
   BOOL       boc_ret_ok;                   /* return TRUE if o.k.     */
   int        imc_ret_conf_entry;           /* return number of configured entries */
   BOOL       boc_option_ms_chap_v2;        /* entry supports MS-CHAP-V2 */
   struct dsd_unicode_string dsc_ret_name;  /* return name of configured entry */
   struct dsd_unicode_string dsc_ret_comment;  /* return comment of configured entry */
};

struct dsd_aux_set_radius_entry {           /* set configured radius group */
   int        imc_no_entry;                 /* input index of entry    */
   BOOL       boc_ret_ok;                   /* return TRUE if o.k.     */
};

enum ied_ret_rel_radius_def {               /* return code release configured Radius group */
   ied_ret_rel_radius_ok,                   /* release o.k.            */
   ied_ret_rel_radius_not_set,              /* Radius group not set    */
   ied_ret_rel_radius_not_mult_conf         /* not multiple Radius group */
};

struct dsd_aux_rel_radius_entry {           /* release configured Radius group */
   enum ied_ret_rel_radius_def iec_ret_rel_radius;
};

struct dsd_aux_get_krb5_entry {             /* retrieve configured Kerberos 5 KDC */
   int        imc_no_entry;                 /* input index of entry    */
   BOOL       boc_ret_ok;                   /* return TRUE if o.k.     */
   BOOL       imc_ret_conf_entry;           /* return number of configured entries */
   struct dsd_unicode_string dsc_ret_name;  /* return name of configured entry */
   struct dsd_unicode_string dsc_ret_comment;  /* return comment of configured entry */
};

struct dsd_aux_set_krb5_entry {             /* set configured Kerberos 5 KDC */
   int        imc_no_entry;                 /* input index of entry    */
   BOOL       boc_ret_ok;                   /* return TRUE if o.k.     */
};

enum ied_ret_rel_krb5_def {                 /* return code release configured Kerberos 5 KDC */
   ied_ret_rel_krb5_ok,                     /* release o.k.            */
   ied_ret_rel_krb5_not_set,                /* KDC not set             */
   ied_ret_rel_krb5_not_mult_conf           /* not multiple KDC configured */
};

struct dsd_aux_rel_krb5_entry {             /* release configured Kerberos 5 KDC */
   enum ied_ret_rel_krb5_def iec_ret_rel_krb5;
};

struct dsd_aux_get_ldap_entry {             /* retrieve configured LDAP service */
   int        imc_no_entry;                 /* input index of entry    */
   BOOL       boc_ret_ok;                   /* return TRUE if o.k.     */
   BOOL       imc_ret_conf_entry;           /* return number of configured entries */
   struct dsd_unicode_string dsc_ret_name;  /* return name of configured entry */
   struct dsd_unicode_string dsc_ret_comment;  /* return comment of configured entry */
};

struct dsd_aux_set_ldap_entry {             /* set configured LDAP service */
   int        imc_no_entry;                 /* input index of entry    */
   BOOL       boc_ret_ok;                   /* return TRUE if o.k.     */
};

enum ied_ret_rel_ldap_def {                 /* return code release configured LDAP service */
   ied_ret_rel_ldap_ok,                     /* release o.k.            */
   ied_ret_rel_ldap_not_set,                /* LDAP not set            */
   ied_ret_rel_ldap_not_mult_conf           /* not multiple LDAP configured */
};

struct dsd_aux_rel_ldap_entry {             /* release configured LDAP service */
   enum ied_ret_rel_ldap_def iec_ret_rel_ldap;
};

enum ied_ret_webso_conn {                   /* return code WebSocket connect */
   ied_rwc_invalid = 0,                     /* invalid                 */
   ied_rwc_no_webso_prot,                   /* connection not WebSocket protocol */
   ied_rwc_inv_param,                       /* invalid parameters in call */
#ifdef XYZ1
   ied_rwc_lb_vdi_timeout,                  /* load-balancing - VDI timeout */
#endif
   ied_rwc_ok,                              /* processing o.k.         */
   ied_rwc_xyz
};

enum ied_co_webso_conn {                    /* command WebSocket connect */
   ied_cwc_invalid = 0,                     /* invalid                 */
   ied_cwc_open,                            /* open - connect to internal routine */
   ied_cwc_conn,                            /* connect to target       */
   ied_cwc_lbvdi_send,                      /* send data WTS load-balancing or VDI */
   ied_cwc_status,                          /* check status            */
   ied_cwc_close                            /* close connection to internal routine */
};

enum ied_type_webso_conn {                  /* type of WebSocket connect */
   ied_twc_invalid = 0,                     /* invalid                 */
   ied_twc_static,                          /* static, server configured */
   ied_twc_dynamic,                         /* dynamic, nothing configured */
   ied_twc_lbal,                            /* WTS load-balancing      */
   ied_twc_vdi,                             /* VDI                     */
   ied_twc_pttd                             /* pass thru to desktop - DOD desktop-on-demand */
};

struct dsd_aux_webso_conn_1 {               /* connect for WebSocket applications */
   enum ied_co_webso_conn iec_cwc;          /* command WebSocket connect */
   enum ied_ret_webso_conn iec_rwc;         /* return code WebSocket connect */
   enum ied_type_webso_conn iec_twc;        /* type of WebSocket connect */
   BOOL       boc_internal_act;             /* internal WebSocket component active */
   int        imc_signal;                   /* signal to set           */
   BOOL       boc_connected;                /* connected to target / server */
   int        imc_connect_error;            /* connect error           */
   char       *achc_lbvdi_send;             /* address data send WTS load-balancing or VDI */
   int        imc_len_lbvdi_send;           /* length data send WTS load-balancing or VDI */
   char       *achc_data_recv;              /* address data received   */
   int        imc_len_data_recv;            /* length data received    */
   /* fields for Pass-Thru-to-Desktop only                             */
   struct dsd_unicode_string dsc_ucs_target;  /* INETA DNS / IPV4 / IPV6 */
// to-do 30.01.12 KB maybe struct sockaddr_storage should be included and used - with port ???
   int        imc_port;                     /* port to connect to      */
   BOOL       boc_with_macaddr;             /* macaddr is included     */
   char       chrc_macaddr[6];              /* macaddr switch on       */
   int        imc_waitconn;                 /* wait for connect compl  */
};

#ifdef DEF_HL_INCL_INET
/**
   for Windows
   #include <winsock2.h>
   is needed before
   #include <windows.h>
*/
enum ied_aux_server_type_co {               /* type of connection to the server */
   ied_ast_none = 0,                        /* no connection to server */
   ied_ast_tcp_os,                          /* TCP of OS               */
   ied_ast_tcp_htun,                        /* TCP of HOB-TUN, HOB-TCP */
   ied_ast_l2tp,                            /* L2TP over UDP           */
   ied_ast_htun                             /* HOB-TUN for HOB-PPP-T1 or SSTP */
};

enum ied_aux_server_status {                /* status about the server connection */
   ied_ass_invalid = 0,                     /* invalid                 */
   ied_ass_not_conf,                        /* server not configured   */
   ied_ass_disco,                           /* disconnected from server */
   ied_ass_connected                        /* connected to server     */
};

struct dsd_aux_get_session_info {           /* get information about the session */
   int        imc_session_no;               /* session number          */
   enum ied_conn_type_def iec_coty;         /* connection type         */
   enum ied_scp_def iec_scp_def;            /* server-conf protocol    */
   struct dsd_unicode_string dsc_scp_name;  /* server-conf protocol, only if ied_scp_spec */
   struct sockaddr_storage dsc_soa_client;  /* address information client */
   struct sockaddr_storage dsc_soa_server_this;  /* address information server on this side */
   struct sockaddr_storage dsc_soa_server_other;  /* address information server on other side */
   enum ied_aux_server_status iec_ass;      /* status about the server connection */
   enum ied_aux_server_type_co iec_ast;     /* type of connection to the server */
   BOOL       boc_csssl;                    /* with client-side SSL    */
// 30.07.10 KB missing L2TP / HTCP ...
   int        imc_server_port;              /* port of the server      */
   struct dsd_bind_ineta_1 *adsc_bind_out;  /* IP address multihomed   */
   struct dsd_target_ineta_1 *adsc_server_ineta;  /* INETAs of the server */
#ifndef B170213
// 26.01.17 KB - add dsc_ucs_server_dns_name
   struct dsd_unicode_string dsc_server_dns_name;  /* DNS name of server */
#endif
};
#endif

enum ied_cmd_udp_gate_def {                 /* command for UDP-gate    */
   ied_cmd_udp_gate_create,                 /* create an entry         */
   ied_cmd_udp_gate_delete,                 /* delete the entry        */
   ied_cmd_uga_subch_register,              /* register sub-channel    */
   ied_cmd_uga_subch_close,                 /* close sub-channel       */
/**
RTP sub-channel-create
RTP sub-channel-delete
*/
   ied_cmd_udp_gate_not_mult_conf           /* not multiple KDC configured */
};

enum ied_ret_udp_gate_def {                 /* return from command for UDP-gate */
   ied_ret_udp_gate_ok,                     /* return success          */
   ied_ret_udp_gate_nonce_double,           /* nonce is double         */
   ied_ret_udp_gate_not_conf,               /* UDP-gate not configured */
   ied_ret_udp_gate_cmd_not_def,            /* command not defined     */
   ied_ret_udp_gate_handle_invalid,         /* the handle is invalid   */
   ied_ret_udp_gate_not_in_tree,            /* the entry is not in the AVL-tree */
   ied_ret_uga_subch_already_def,           /* sub-channel to register already defined */
   ied_ret_udp_gate_misc                    /* miscellaneous error     */
};

struct dsd_aux_cmd_udp_gate {               /* command for UDP-gate    */
   enum ied_cmd_udp_gate_def iec_cmd_ug;    /* command for UDP-gate    */
   enum ied_ret_udp_gate_def iec_ret_ug;    /* return from command for UDP-gate */
   void *     vpc_ug_handle;                /* handle of entry for UDP-gate */
   char       chrc_nonce[ DEF_LEN_UDP_GATE_NONCE ];  /* the nonce      */
   int        imc_udp_gate_ipv4_port;       /* UDP port IPV4           */
   int        imc_udp_gate_ipv6_port;       /* UDP port IPV6           */
   struct dsd_bind_ineta_1 *adsc_udp_gate_ineta;  /* <UDP-gate>        */
   void *     vpc_ug_subch_handle;          /* handle of UDP-gate subchannel */
   unsigned char ucc_subchannel_id;         /* subchannel Id           */
   void *     vpc_udpr_handle;              /* handle of UDP associated request */
   char       *achc_subch_keys;             /* address of subchannel keys */
   char       *achc_subch_sockaddr;         /* pointer to sockaddr structure subchannel */
   int        imc_len_subch_sockaddr;       /* length of sockaddr structure subchannel */
   BOOL       boc_subch_srtp;               /* SRTP is used            */
// RTP sub-channel-create / register
// RTP sub-channel-delete
// struct dsd_sdh_udp_requ_1                 /* UDP request             */
//   enum ied_sdh_udp_requ_1_def iec_sdh_udpr1;  /* UDP request command  */
//   void *     vpc_udpr_handle;              /* handle of UDP request   */
//   MIME sub-channel-no
// char       *achc_sockaddr;               /* pointer to sockaddr structure */
// int        imc_len_sockaddr;             /* length of sockaddr structure */
// encryption ???
// flag RTP / SRTP
};

enum ied_cmd_ntlm_auth_def {                /* command for NTLM authentication */
   ied_cmd_ntlm_auth_nonce                  /* create an entry ???     */
};

struct dsd_aux_ntlm_auth_1 {                /* NTLM authentication against Kerberos-5 KDC */
   enum ied_cmd_ntlm_auth_def iec_cna;      /* command for NTLM authentication */
};

enum ied_wsp_trace_record_type {            /* record type of WSP trace */
   ied_wtrt_text,                           /* text passed             */
   ied_wtrt_data                            /* binary data passed      */
};

struct dsd_wsp_trace_header {               /* WSP trace header        */
   char       chrc_wtrt_id[ 8 ];            /* Id of trace record      */
   int        imc_wtrh_sno;                 /* WSP session number      */
   struct dsd_wsp_trace_record *adsc_wtrh_chain;  /* chain of WSP trace records */
};

struct dsd_wsp_trace_record {               /* WSP trace record        */
   struct dsd_wsp_trace_record *adsc_next;  /* for chaining            */
   enum ied_wsp_trace_record_type iec_wtrt;  /* record type of WSP trace */
   char       *achc_content;                /* content of text / data  */
   int        imc_length;                   /* length of text / data   */
   BOOL       boc_more;                     /* more data to follow     */
};

struct dsd_aux_base64_ctrl_1 {              /* base64 encode / decode control area */
   int        imc_ret;
   struct dsd_gather_i_1 *adsc_gather_i_1_in;  /* input data           */
   char *     achc_out_cur;                 /* current address output data */
   char *     achc_out_end;                 /* end of area output data */
   BOOL       boc_cont;                     /* not first call          */
   char       chrc_sr_work[ 32 ];           /* workarea for subroutine */
};

struct dsd_aux_get_duia_1 {                 /* get domain userid INETA */
   int        imc_len_field;                /* length of field, input  */
   int        imc_len_string;               /* length of string, output */
   char       *achc_string;                 /* address of string       */
};

struct dsd_aux_cma_duia_1 {                 /* CMA entry for DUIA      */
   unsigned char ucc_version;               /* version of entry / programs */
   unsigned char ucrc_rdp_acc[ 16 ];        /* values for RDP-ACC      */
   unsigned char ucc_len_password;          /* length of password      */
};

enum ied_cma_duia_00_sign_on {              /* sign on over RDP        */
   ied_cd00_so_none = 0,                    /* nothing special         */
   ied_cd00_so_automtic                     /* automatic sign-on       */
};

enum ied_cma_duia_01_ldm {                  /* local-drive-mapping     */
   ied_cd01_ldm_all = 0,                    /* nothing special, all allowed */
   ied_cd01_ldm_vc,                         /* use Virus-Checking      */
   ied_cd01_ldm_block                       /* block all local-drive-mapping */
};

struct dsd_aux_secure_xor_1 {               /* apply secure XOR        */
   int        imc_len_post_key;             /* length of post key string */
   int        imc_len_xor;                  /* length of string        */
   char       *achc_post_key;               /* address of post key string */
   char       *achc_source;                 /* address of source       */
   char       *achc_destination;            /* address of destination  */
};

enum ied_aux_pipe_scope {                   /* scope of an aux-pipe    */
   ied_aps_invalid = 0,                     /* invalid parameter       */
   ied_aps_session,                         /* for current session     */
   ied_aps_process,                         /* for current process     */
   ied_aps_global                           /* global, for cluster     */
};

enum ied_aux_pipe_command {                 /* aux-pipe command        */
   ied_apc_invalid = 0,                     /* invalid value           */
   ied_apc_create,                          /* create, server side open */
   ied_apc_open,                            /* open, client side open  */
   ied_apc_close_listen,                    /* close listen, created by create */
   ied_apc_close_conn,                      /* close single connection */
   ied_apc_close_all,                       /* close all               */
   ied_apc_state,                           /* check state session     */
   ied_apc_free_read_buffer,                /* free passed read buffers */
   ied_apc_write,                           /* write to session        */
   ied_apc_signal_nowait,                   /* send signal to pipe, server side open, do not wait */
   ied_apc_signal_wait                      /* send signal to pipe, server side open, do check if sent */
};

enum ied_aux_pipe_return_code {             /* aux-pipe command return code */
   ied_aprc_invalid = 0,                    /* invalid value           */
   ied_aprc_ok,                             /* command returns o.k.    */
   ied_aprc_idle,                           /* command returns nothing */
   ied_aprc_new_conn,                       /* command returns new incomming connection */
   ied_aprc_signal,                         /* command returns signal received */
   ied_aprc_read_buf,                       /* command returns read buffers */
   ied_aprc_session_closed,                 /* command returns session has been closed by partner */
   ied_aprc_listen_double,                  /* aux-pipe-name already defined */
   ied_aprc_listen_undef,                   /* aux-pipe-name not defined */
   ied_aprc_conn_ended,                     /* connection has ended    */
   ied_aprc_signal_no_server,               /* signal did not find server-side pipe */
   ied_aprc_parm_error,                     /* aux-pipe command parameter invalid */
   ied_aprc_not_implemented,                /* aux-pipe command not implemented */
   ied_aprc_misc                            /* miscellaneous error     */
};

struct dsd_aux_pipe_req_1 {                 /* aux-pipe request        */
   enum ied_aux_pipe_command iec_apc;       /* aux-pipe command        */
   enum ied_aux_pipe_return_code iec_aprc;  /* aux-pipe command return code */
   void *     vpc_aux_pipe_handle;          /* handle of aux-pipe      */
   char       *achc_aux_pipe_name;          /* address name of aux-pipe */
   int        imc_len_aux_pipe_name;        /* length of name of aux-pipe */
   enum ied_aux_pipe_scope iec_aps;         /* scope of an aux-pipe    */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input and output data   */
   int        boc_session_active;           /* session is active       */
   int        boc_same_process;             /* partner is in same OS process */
   int        imc_signal;                   /* signal to set           */
   int        imc_sno;                      /* session number          */
};

enum ied_aux_util_thread_command {          /* util-thread command     */
   ied_autc_invalid = 0,                    /* invalid value           */
   ied_autc_start,                          /* start utility thread    */
   ied_autc_signal,                         /* send signal to utility thread */
   ied_autc_check                           /* check if running and get return values */
};

enum ied_aux_util_thread_rc {               /* util-thread command return code */
   ied_autrc_invalid = 0,                   /* invalid value           */
   ied_autrc_ok,                            /* command processed o.k.  */
   ied_autrc_inv_param,                     /* invalid parameters passed */
   ied_autrc_too_many_util_thr,             /* there are already too many utility threads running */
   ied_autrc_start_util_thr_failed,         /* failed to start utility thread */
   ied_autrc_ended                          /* util-thread has ended   */
};

struct dsd_aux_util_thread_param_1 {        /* utility thread parameter */
   BOOL (* amc_aux) ( void *, int, void *, int );  /* auxiliary callback routine */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   volatile int imc_signal;                 /* signals occured         */
   int        imc_sno;                      /* session number          */
   int        imc_trace_level;              /* WSP trace level         */
   int        imc_no_xchg_mem_area;         /* number of entries arc_xchg_mem_area */
   void *     arc_xchg_mem_area[ MAX_UTIL_THR_MEM_AREA ];
   struct dsd_gather_i_1 *adsc_gai1_xchg;   /* input and output data   */
};

typedef void ( * amd_util_thread )( struct dsd_aux_util_thread_param_1 * );

struct dsd_aux_util_thread_call_1 {         /* create utility thread   */
   enum ied_aux_util_thread_command iec_autc;  /* util-thread command  */
   enum ied_aux_util_thread_rc iec_autrc;   /* util-thread command return code */
   amd_util_thread amc_util_thread;         /* entry of utility thread */
   struct dsd_aux_util_thread_param_1 *adsc_aux_util_thread_param_1;  /* paramter call utility thread */
   int        imc_thread_priority;          /* priority of utility thread to be created */
   BOOL       boc_thread_priority_relative;  /* priority of utility thread to be created is relative */
   int        imc_signal_parent;            /* signal for parent       */
   int        imc_signal_send;              /* signal to send to utility thread */
   int        imc_no_xchg_mem_area;
   void *     arc_xchg_mem_area[ MAX_UTIL_THR_MEM_AREA ];
   struct dsd_gather_i_1 *adsc_gai1_xchg;   /* input and output data   */
};

enum ied_aux_dyn_lib_command {              /* dynamic library command */
   ied_adlc_invalid = 0,                    /* invalid value           */
   ied_adlc_load,                           /* load dynamic library    */
   ied_adlc_unload,                         /* unload dynamic library  */
   ied_adlc_entry                           /* return entry of dynamic library */
};

enum ied_ret_dyn_lib_def {                  /* return code dynamic library */
   ied_ret_dl_ok,                           /* command returned o.k.   */
   ied_ret_dl_fn_inv,                       /* file name invalid       */
   ied_ret_dl_fn_too_long,                  /* file name too long      */
   ied_ret_dl_fn_not_found,                 /* file name not found     */
   ied_ret_dl_entry_not_found,              /* entry not found in dynamic library */
   ied_ret_dl_inv_handle,                   /* invalid handle of dynamic library passed */
   ied_ret_dl_inv_param                     /* invalid parameters passed */
};

struct dsd_aux_dyn_lib_req_1 {              /* dynamic library request */
   enum ied_aux_dyn_lib_command iec_adlc;   /* dynamic library command */
   enum ied_ret_dyn_lib_def iec_ret_dl;     /* return code dynamic library */
   int        imc_error;                    /* error code              */
   void *     vpc_aux_dyn_lib_handle;       /* handle of dynamic library */
   void *     vpc_aux_dyn_lib_entry;        /* entry in dynamic library */
   union {
     struct dsd_unicode_string dsc_dyn_lib_name;  /* name and path dynamic library */
     struct dsd_unicode_string dsc_dyn_lib_entry;  /* name of entry of dynamic library */
   };
};

enum ied_aux_swap_stor_command {            /* swap storage command    */
   ied_swsc_invalid = 0,                    /* invalid value           */
   ied_swsc_open,                           /* open swap storage       */
   ied_swsc_close,                          /* close swap storage      */
   ied_swsc_clear_and_close,                /* clear content and close swap storage */
   ied_swsc_get_buf,                        /* acquire swap storage buffer */
   ied_swsc_read,                           /* read swap storage buffer */
   ied_swsc_write,                          /* write swap storage buffer */
   ied_swsc_unused,                         /* swap storage buffer not used */
   ied_swsc_release                         /* release swap storage chunk */
};

enum ied_aux_swap_stor_ret {                /* return code swap storage command */
   ied_swsr_ok = 0,                         /* o.k.                    */
   ied_swsr_not_conf,                       /* swap storage not configured */
   ied_swsr_full,                           /* swap storage is full    */
   ied_swsr_param_error,                    /* parameter error         */
   ied_swsr_chunk_not_found,                /* chunk not found         */
   ied_swsr_nomem,                          /* out of memory           */
   ied_swsr_inv_access,                     /* invalid access          */
   ied_swsr_int_error,                      /* internal error          */
   ied_swsr_access_out_of_order,            /* access out of order     */
   ied_swsr_xyz                             /* o.k.                    */
};

struct dsd_aux_swap_stor_req_1 {            /* swap storage request    */
   enum ied_aux_swap_stor_command iec_swsc;  /* swap storage command   */
   enum ied_aux_swap_stor_ret iec_swsr;     /* return code swap storage command */
   void *     vpc_aux_swap_stor_handle;     /* handle of swap storage  */
   char       *achc_stor_addr;              /* storage address         */
   int        imc_index;                    /* index of dataset / chunk */
};

#ifndef DEF_HL_DASH
/**
   hob-dash-01.h
   hob-xsclib01.h
*/
#define DEF_HL_DASH
enum ied_dash_open_flags {                  /* open flags              */
   ied_dof_invalid = 0,                     /* value is invalid        */
   ied_dof_read_share_all,                  /* open read and share all */
   ied_dof_read_share_read,                 /* open read and share read */
   ied_dof_param_inv                        /* input paramater invalid */
};

enum ied_dash_access {                      /* access                  */
   ied_dac_deny = 0,                        /* access denied           */
   ied_dac_read_only,                       /* access read-only        */
   ied_dac_read_write,                      /* access read-write       */
   ied_dac_write_only,                      /* access write-only       */
   ied_dac_dummy                            /* dummy entry             */
};
#endif

enum ied_aux_file_io_command {              /* command for file IO     */
   ied_fioc_invalid = 0,                    /* invalid value           */
   ied_fioc_open,                           /* open file               */
   ied_fioc_compl_file_read,                /* read complete file      */
   ied_fioc_compl_file_write,               /* write complete file     */
   ied_fioc_file_delete                     /* delete the file         */
};

enum ied_aux_file_io_ret {                  /* return code file IO     */
   ied_fior_ok = 0,                         /* o.k.                    */
   ied_fior_file_not_found,                 /* The system cannot find the file specified. ERROR_FILE_NOT_FOUND */
   ied_fior_open_error,                     /* error from open         */
   ied_fior_param_inv,                      /* input parameters invalid */
   ied_fior_misc                            /* miscellaneous error     */
};

struct dsd_aux_file_io_req_1 {              /* file IO request         */
   enum ied_aux_file_io_command iec_fioc;   /* command for file IO     */
   enum ied_aux_file_io_ret iec_fior;       /* return code file IO     */
   enum ied_dash_open_flags iec_dof;        /* open flags              */
   BOOL       boc_unix_style_fn;            /* filename Unix style     */
   struct dsd_unicode_string dsc_ucs_file_name;  /* name of file       */
   char       *achc_data;                   /* address of data         */
   HL_LONGLONG ilc_len_data;                /* length of data          */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input and output data   */
   int        imc_error;                    /* error returned          */
   BOOL       boc_create_directory;         /* create directory if missing */
};

struct dsd_hl_aux_set_local_user {          /* set local user          */
   enum ied_chid_ret iec_chid_ret;          /* check ident return code */
   struct dsd_unicode_string dsc_ucs_userid;  /* userid requested      */
   struct dsd_unicode_string *adsc_ucs_password;  /* fill with password */
   void **    avpc_usent;                   /* user entry              */
   void **    avpc_usgro;                   /* user-group entry        */
};

struct dsd_hl_aux_ssl_get_server_cert {     /* get address SSL used server certificate */
   int        imc_error;                    /* zero = no error         */
   void *     ac_addr_server_cert;          /* address of server certificate */
   int        imc_len_server_cert;          /* length of server certificate */
};

enum ied_aux_sdh_reload_command {           /* command for SDH reload  */
   ied_asrc_invalid = 0,                    /* invalid value           */
   ied_asrc_define,                         /* define this SDH for reload */
   ied_asrc_undefine,                       /* undefine this SDH for reload */
   ied_asrc_reload                          /* reload saved SDH        */
};

enum ied_aux_sdh_reload_ret {               /* return code manage SDH reload */
   ied_asrr_invalid = 0,                    /* invalid value           */
   ied_asrr_ok,                             /* o.k.                    */
   ied_asrr_param_error,                    /* parameter error         */
   ied_asrr_not_found,                      /* saved SDH not found     */
   ied_asrr_double,                         /* SDH name double         */
   ied_asrr_internal_error                  /* internal error while processing */
};

struct dsd_hl_aux_manage_sdh_reload {       /* manage SDH reload       */
   enum ied_aux_sdh_reload_command iec_asrc;  /* command for SDH reload */
   enum ied_aux_sdh_reload_ret iec_asrr;    /* return code manage SDH reload */
   char       *achc_addr_sdh_name;          /* address of SDH name     */
   int        imc_len_sdh_name;             /* length of SDH name      */
// 21.06.14 KB - pass data not yet implemented
   char       *achc_addr_pass_data;         /* address of data to pass */
   int        imc_len_pass_data;            /* length of data to pass  */
   int        imc_wait_seconds;             /* wait seconds for destroy */
};

#ifdef DEF_HL_INCL_SSL
// forward declarations from hob-encry-1.h
#if !defined XH_INTERFACE
#define HMEM_CTX_DEF
#else
typedef struct ds__hmem_t ds__hmem;
#define HMEM_CTX_DEF ds__hmem * vp__ctx,
#endif
// forward declarations from hob-cert-ext.h
typedef struct X501_DN_t X501_DN;
typedef struct X509CERT_t X509CERT;

struct dsd_aux_get_cs_ssl_addr {            /* get addresses of client-side SSL implementation */
   void *     vpc_csssl_config_id;          /* config Id of client-side SSL */
   int (*amc_cl_registerconfig)( char * achp_configdatabuf, int inp_configdatalen,
                                 char * achp_certdatabuf, int inp_certdatalen,
                                 char * achp_pdwbuf, int inp_pdwlen,
                                 BOOL boc_pwdfileflag,
                                 struct dsd_hl_ocsp_d_1 * adsp_ocspd,
                                 BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ),
                                 void * vpp_userfld,
                                 void ** avpp_config_id,
                                 BOOL bop_use_aux_seeding );
   int (*amc_release_config)( BOOL (* amp_aux) ( void *vpp_userfld, int, void *, int ),
                              void * vpp_userfld,
                              void * vpp_config_id );
   void (*amc_hlcl01)(struct dsd_hl_ssl_c_1 * pXIFCLStructu);
   int (*amc_FromASN1_DNCommonNameToString)(HMEM_CTX_DEF
                                            X501_DN* pNameDesc, char** pDstNameBuf);
   int (*amc_FromASN1CertToCertStruc)(HMEM_CTX_DEF
                                      char SrcBuf[],
                                      int SrcOffset,
                                      int SrcLen,
                                      int CertType,
                                      int SortFlags,
                                      char* Pwd,
                                      int PwdLen,
                                      X509CERT * pCertStruc[]);
   void (*amc_FreeCertStruc)(HMEM_CTX_DEF
                             X509CERT * CertStruc);
};
#endif

typedef void ( * amd_hlclib01 )( struct dsd_hl_clib_1 * );
typedef void ( * amd_call_hrl_1 )( struct dsd_hrl_call_1 * );
typedef void ( * amd_call_phl_1 )( struct dsd_phl_call_1 * );
typedef void ( * amd_call_wspat3_1 )( struct dsd_wspat3_1 * );
typedef void ( * amd_call_bgt_1 )( struct dsd_bgt_call_1 * );

struct dsd_sdh_stack_1 {                    /* Server-Data-Hook stack  */
   struct dsd_sdh_stack_1 *adsc_previous;   /* previous entry in chain */
   struct dsd_sdh_stack_1 *adsc_next;       /* next entry in chain     */
   amd_hlclib01 amc_hlclib01;               /* entry point             */
   void *     ac_ext;                       /* attached buffer pointer */
   void *     ac_conf;                      /* data from configuration */
   void *     ac_param;                     /* parameters              */
};

struct dsd_hl_clib_1 {                      /* HOBLink Copy Library 1  */
   int        inc_func;                     /* called function         */
   int        inc_return;                   /* return code             */
   char *     achc_work_area;               /* addr work-area          */
   int        inc_len_work_area;            /* length work-area        */

   struct dsd_gather_i_1 *adsc_gather_i_1_in;  /* input data           */
   struct dsd_gather_i_1 *adsc_gai1_out_to_client;  /* output data to client */
   struct dsd_gather_i_1 *adsc_gai1_out_to_server;  /* output data to server */

   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     ac_ext;                       /* attached buffer pointer */
   void *     ac_conf;                      /* data from configuration */
   void *     ac_hobwspat3_conf;            /* data from HOB-WSP-AT3 configuration */
   struct dsd_sdh_stack_1 *adsc_sdh_stack_1;  /* Server-Data-Hook stack */
   int        imc_flags_1;                  /* flags of configuration  */
   int        imc_signal;                   /* signals occured         */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   BOOL       boc_callagain;                /* call again this direction */
   BOOL       boc_callrevdir;               /* call on reverse direction */
   BOOL       boc_no_conn_s;                /* do not connect to server */
   BOOL       boc_eof_client;               /* End-of-File Client      */
   BOOL       boc_eof_server;               /* End-of-File Server      */
   BOOL       boc_send_client_blocked;      /* sending to the client is blocked */
   BOOL       boc_notify_send_client_possible;  /* notify SDH when sending to the client is possible */
   BOOL       boc_suspend_recv_client;      /* suspend receiving from the client */
   BOOL       boc_suspend_recv_server;      /* suspend receiving from the server */
   int        imc_sno;                      /* session number          */
   int        imc_trace_level;              /* WSP trace level         */
};

struct dsd_hrl_call_1 {                     /* HTTP-redirect-library Call */
   int        imc_func;                     /* called function         */
   int        imc_return;                   /* return code             */
   char *     achc_work_area;               /* addr work-area          */
   int        inc_len_work_area;            /* length work-area        */

   struct dsd_gather_i_1 *adsc_gather_i_1_in;  /* input data           */
   struct dsd_gather_i_1 *adsc_gather_i_1_out;  /* output data         */

   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     ac_ext;                       /* attached buffer pointer */
   void *     ac_conf;                      /* data from configuration */
#ifdef XYZ1
   struct dsd_sdh_stack_1 *adsc_sdh_stack_1;  /* Server-Data-Hook stack */
#endif
   int        imc_flags_1;                  /* flags of configuration  */
   int        imc_signal;                   /* signals occured         */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   BOOL       boc_callagain;                /* call again this direction */
#ifdef XYZ1
   BOOL       boc_callrevdir;               /* call on reverse direction */
#endif
   BOOL       boc_no_conn_s;                /* do not connect to server */
};

struct dsd_phl_call_1 {                     /* plain-HTTP-library Call */
   int        imc_func;                     /* called function         */
   int        imc_return;                   /* return code             */
   char *     achc_work_area;               /* addr work-area          */
   int        inc_len_work_area;            /* length work-area        */

   struct dsd_gather_i_1 *adsc_gather_i_1_in;  /* input data           */
   struct dsd_gather_i_1 *adsc_gather_i_1_out;  /* output data         */

   char       *achc_url_path;               /* address memory of URL path */
   int        imc_length_url_path;          /* length of URL path      */
   int        imc_stored_url_path;          /* stored part of URL path */

   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     ac_ext;                       /* attached buffer pointer */
   void *     ac_conf;                      /* data from configuration */
#ifdef XYZ1
   struct dsd_sdh_stack_1 *adsc_sdh_stack_1;  /* Server-Data-Hook stack */
#endif
   int        imc_flags_1;                  /* flags of configuration  */
   int        imc_signal;                   /* signals occured         */
   void *     vpc_userfld;                  /* User Field Subroutine   */
#ifdef XYZ1
   BOOL       boc_callagain;                /* call again this direction */
#ifdef XYZ1
   BOOL       boc_callrevdir;               /* call on reverse direction */
#endif
   BOOL       boc_no_conn_s;                /* do not connect to server */
#endif
};

enum ied_bgt_func_def {                     /* background-task functions */
   ied_bgtf_end_session,                    /* called at end of session */
   ied_bgtf_stat,                           /* called for statistic    */
   ied_bgtf_admin                           /* called from administrator */
};

struct dsd_bgt_function_1 {                 /* background-task functions */
   struct dsd_bgt_function_1 *adsc_next;    /* for chaining            */
   int        imc_str_length;               /* length of this structure */
   enum ied_bgt_func_def iec_bgtf;          /* background-task functions */
};

struct dsd_bgt_call_1 {                     /* Background-Task Call    */
   int        imc_func;                     /* called function         */
   int        imc_return;                   /* return code             */
   char *     achc_work_area;               /* addr work-area          */
   int        inc_len_work_area;            /* length work-area        */

   struct dsd_gather_i_1 *adsc_gather_i_1_in;  /* input data           */
   struct dsd_gather_i_1 *adsc_gather_i_1_out;  /* output data         */

   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     ac_ext;                       /* attached buffer pointer */
   void *     ac_conf;                      /* data from configuration */
   struct dsd_bgt_function_1 *adsc_bgt_function_1;  /* called for background-task function */
#ifdef XYZ1
   struct dsd_sdh_stack_1 *adsc_sdh_stack_1;  /* Server-Data-Hook stack */
#endif
   int        imc_flags_1;                  /* flags of configuration  */
   int        imc_signal;                   /* signals occured         */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   BOOL       boc_callagain;                /* call again this direction */
#ifdef XYZ1
   BOOL       boc_callrevdir;               /* call on reverse direction */
#endif
#ifdef XYZ1
   BOOL       boc_no_conn_s;                /* do not connect to server */
#endif
   int        imc_sno;                      /* session number          */
   int        imc_trace_level;              /* WSP trace level         */
};

/* one struct dsd_tcp_data_contr_1 for each TCP record;
   one TCP record on server side contains the TCP header
   as defined in RFC 793                                               */
struct dsd_tcp_data_contr_1 {               /* TCP data control structure */
   struct dsd_tcp_data_contr_1 *adsc_next;  /* for chaining            */
   struct dsd_gather_i_1 *adsc_gai1;        /* data                    */
   int        imc_len_data;                 /* length of the data      */
   unsigned int umc_flags;                  /* flags from TCP header   */
};

enum ied_sdh_tcp_state {                    /* state of TCP connection */
   ied_sts_normal = 0,                      /* normal processing       */
   ied_sts_recv_fin,                        /* FIN received from server */
   ied_sts_recv_rst,                        /* RST received from server */
   ied_sts_timeout                          /* timeout of TCP session  */
};

enum ied_sdh_tcp_flow_control {             /* flow control of TCP connection */
   ied_stfc_normal = 0,                     /* normal processing       */
   ied_stfc_tcp_tunnel_1                    /* inside of TCP tunnel 1  */
};

/* one struct dsd_sdh_tcp_1 is for one TCP half session.
   The server side exchanges TCP headers and user data,
   the client side does exchange only user data without any header.    */
struct dsd_sdh_tcp_1 {                      /* TCP half session        */
   int        imc_func;                     /* called function         */
   int        imc_return;                   /* return code             */
   int        imc_sno;                      /* session number          */
   int        imc_trace_level;              /* WSP trace level         */
   int        imc_tcp_mss_send;             /* TCP maximum segment size (MSS) send direction */
   int        imc_tcp_mss_recv;             /* TCP maximum segment size (MSS) receive */
   BOOL       boc_is_client;                /* this is client that does connect */
   BOOL       boc_syn_extern;               /* SYN is handled externally */
   BOOL       boc_timer_running;            /* timer is currently running */
   BOOL       boc_eof_client;               /* End-of-File Client      */
   BOOL       boc_connection_established;   /* TCP connection with server established */
   BOOL       boc_send_netw_blocked;        /* sending to the network is blocked */
   BOOL       boc_notify_send_netw_possible;  /* notify SDH-TCP when sending to the network is possible */
   enum ied_sdh_tcp_flow_control iec_stfc;  /* flow control of TCP connection */
   enum ied_sdh_tcp_state iec_sts;          /* state of TCP connection */
   unsigned short int usc_port_client;      /* TCP port of client network-byte-order */
   unsigned short int usc_port_server;      /* TCP port of server network-byte-order */
   char *     achc_work_area;               /* address work-area       */
   int        imc_len_work_area;            /* length work-area        */

   struct dsd_tcp_data_contr_1 *adsc_tdc1_in;  /* input data           */
   struct dsd_tcp_data_contr_1 *adsc_tdc1_out_to_client;  /* output data to client */
   struct dsd_tcp_data_contr_1 *adsc_tdc1_out_to_server;  /* output data to server */

   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     ac_ext;                       /* attached buffer pointer */
   int        imc_signal;                   /* signals occured         */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   char       chrc_header_info[32];         /* IP header information needed for checksum */
   int        imc_len_header_info;          /* length of header information, 8 for IPV4 and 32 for IPV6 */
   BOOL       boc_stop_receiving;           /* stop receiving from the server */
   int        imc_queue_sent;               /* bytes TCP packets sent to the server */
   int        imc_queue_buffer;             /* bytes TCP packets buffered for sending to the server */
};

#ifdef DEF_HL_INCL_DOM
#ifndef DEF_HL_INCL_DOM_DONE
#define DEF_HL_INCL_DOM_DONE

#ifndef DEF_HL_INCL_DOM_COMMAND_DONE
#define DEF_HL_INCL_DOM_COMMAND_DONE
enum ied_hlcldom_def { ied_hlcldom_invalid,  /* invalid function       */
                       ied_hlcldom_get_first_child,  /* getFirstChild() */
                       ied_hlcldom_get_next_sibling,  /* getNextSibling() */
                       ied_hlcldom_get_node_type,  /* getNodeType()    */
                       ied_hlcldom_get_node_value,  /* getNodeValue()  */
                       ied_hlcldom_get_node_name,  /* getNodeName()    */
                       ied_hlcldom_get_file_line,  /* get line in file */
                       ied_hlcldom_get_file_column  /* get column in file */
};
#endif

#ifndef DEF_HL_NO_XERCES
struct dsd_hl_clib_dom_conf {               /* structure DOM configuration */
   DOMNode    *adsc_node_conf;              /* part of configuration   */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
   int        imc_flags_1;                  /* flags of configuration  */
   void **    aac_conf;                     /* return data from conf   */
// getFirstChild()
// getNextSibling()
// getNodeType()
// getNodeValue()
// getNodeName()
// XMLString::transcode()
// XMLString::release()
   void * (* amc_call_dom) ( DOMNode *, ied_hlcldom_def );  /* call DOM */
};

struct dsd_bgt_dom_conf {                   /* structure DOM configuration */
   DOMNode    *adsc_node_conf;              /* part of configuration   */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
   int        imc_flags_1;                  /* flags of configuration  */
   void **    aac_conf;                     /* return data from conf   */
   void * (* amc_call_dom) ( DOMNode *, ied_hlcldom_def );  /* call DOM */
   struct dsd_bgt_function_1 *adsc_bgt_function_1;  /* background-task functions */
};

typedef BOOL ( * amd_hlclib_conf )( struct dsd_hl_clib_dom_conf * );
typedef BOOL ( * amd_hrl_conf )( struct dsd_hl_clib_dom_conf * );
typedef BOOL ( * amd_phl_conf )( struct dsd_hl_clib_dom_conf * );
typedef BOOL ( * amd_bgt_conf )( struct dsd_bgt_dom_conf * );

#endif
#endif
#endif

#if defined __cplusplus
extern "C" __declspec( dllimport ) void m_hlclib01( struct dsd_hl_clib_1 * );
#else
extern __declspec( dllimport ) void m_hlclib01( struct dsd_hl_clib_1 * );
#endif // cplusplus

#ifdef HL_UDP_GATE_ENCRY
#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

extern PTYPE BOOL m_udp_gate_encry_init( char *achp_keys, char *achp_encode, char *achp_decode );
extern PTYPE int m_udp_gate_encry_encode( char *achp_out, int imp_len_out,
                                          char *achp_inp, int imp_len_inp,
                                          char *achp_keys, char *achp_encode );
extern PTYPE int m_udp_gate_encry_decode( char *achp_out, int imp_len_out,
                                          char *achp_inp, int imp_len_inp,
                                          char *achp_keys, char *achp_decode );
#endif
