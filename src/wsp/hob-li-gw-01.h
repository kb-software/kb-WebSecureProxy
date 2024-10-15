/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| FILE NAME: hob-li-gw-01.h                                         |*/
/*| -------------                                                     |*/
/*|  IP-Gateway with SSL                                              |*/
/*|  WebSecureProxy                                                   |*/
/*|  Listen-Gateway                                                   |*/
/*|  Header File with data exchanged between nbipgw20 and nbipgw19    |*/
/*|  KB 10.09.11                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  GCC or other Unix C-Compilers                                    |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/** Default name of the Unix domain socket used for communication with the clients */
#define DEFAULT_UDSNAME "/tmp/nbipgw19.uds"
/** Default for the shared secret                                      */
#define DEFAULT_SECRET "SADFACTORYWORKER"

#define D_NAME_UDS_WSP "$HOB-WSP-"
#define D_NAME_UDS_TAIL ".uds"
//#define D_LENGTH_UDS_TAIL 4
#define D_LENGTH_UDS_TAIL (sizeof(D_NAME_UDS_TAIL) - 1)
#define D_LENGTH_UDS_MAX       48

#define D_LI_GW_TOKEN          0X10092011   /* token for start packet  */
#define D_LI_GW_VERSION        0            /* version of listen gateway */
#define D_LIGW_RANDOM_L        20           /* length random listen-gateway - length SHA-1 */
#define D_LIGW_MAX_TIME_RANDOM 5            /* maximum time in seconds that the listen-gateway decrypts the message after sent */
#define D_LIGW_MAX_WSP         16           /* maximum number of WSPs connected */
#define D_LIGW_UDS_WSP_BACKLOG 8            /* backlog Unix domain socket listen */
#define D_LIGW_CLUSTER_BACKLOG 8            /* backlog TCP cluster listen */
#define D_LIGW_MAX_CLUSTER_WSP 16           /* maximum number of cluster listen per WSP */

#ifdef HL_FREEBSD
#ifndef HL_LONGLONG
#define HL_LONGLONG long long int
#endif
#endif

static char chrs_requestheader_query[] = {  /* Request message header  */
   0X48, 0X4F, 0X42, 0X20, 0X4C, 0X49, 0X00, 0X51, 0X00  /* HOB LI - Q */
};

static char chrs_requestheader_response[] = {  /* Request message header */
   0X48, 0X4F, 0X42, 0X20, 0X4C, 0X49, 0X00, 0X52, 0X00  /* HOB LI - R */
};

enum ied_li_gw_query {
   ied_ligwq_start = 0,                     /* start of WSP            */
   ied_ligwq_socket,                        /* create socket           */
   ied_ligwq_cluster,                       /* cluster message         */
#ifdef D_INCL_HOB_TUN
   ied_ligwq_open_tun,                      /* open TUN adapter        */
   ied_ligwq_arproute_add_ipv4,             /* add ARP and route IPV4  */
   ied_ligwq_arproute_del_ipv4              /* del ARP and route IPV4  */
#endif
};

enum ied_li_gw_response {
   ied_ligwr_msg = 0,                       /* message                 */
   ied_ligwr_wsps,                          /* other WSPs              */
   ied_ligwr_resp_socket_ok,                /* create socket succeeded */
   ied_ligwr_resp_socket_failed,            /* create socket failed    */
#ifdef D_INCL_HOB_TUN
   ied_ligwr_resp_open_tun,                 /* open TUN adapter        */
   ied_ligwr_resp_arproute_add_ipv4,        /* add ARP and route IPV4  */
   ied_ligwr_resp_arproute_del_ipv4         /* del ARP and route IPV4  */
#endif
};

enum ied_li_gw_error_command {              /* command which failed    */
   ied_ligwec_socket = 0,                   /* socket failed           */
   ied_ligwec_bind                          /* bind failed             */
};

#ifdef XYZ1
struct dsd_ineta_port_ligw {                /* INETA and port          */
   unsigned char ucc_family;                /* address family          */
   unsigned char ucc_len_ineta;             /* length INETA            */
   unsigned char ucrc_port[ 2 ];            /* port                    */
};
#endif

struct dsd_create_socket_ligw {             /* create a socket         */
   unsigned char ucc_family;                /* address family          */
   unsigned char ucc_socket_type;           /* type of socket          */
   unsigned char ucc_protocol;              /* protocol used           */
   unsigned char ucrc_port[ 2 ];            /* port                    */
};

#ifdef D_INCL_HOB_TUN
struct dsd_ligw_q_open_tun {                /* query open TUN adapter  */
   unsigned char ucc_use_ipv4;              /* use IPV4                */
   unsigned char ucc_use_ipv6;              /* use IPV6                */
   unsigned char ucc_no_ineta_ipv4;         /* number of INETAs IPV4   */
   unsigned char ucc_no_ineta_ipv6;         /* number of INETAs IPV6   */
};

struct dsd_ligw_r_open_tun {                /* response open TUN adapter */
   unsigned char ucc_index_ineta_ipv4;      /* index of INETA IPV4 + 1 */
   unsigned char ucc_index_ineta_ipv6;      /* index of INETA IPV6 + 1 */
   char       chrc_tiface[ IFNAMSIZ ];      /* name of tun interface   */
};

struct dsd_ligw_q_ar_add_ipv4 {             /* add ARP and route IPV4  */
#ifdef HL_LINUX
   int        imc_ifindex_nic;              /* interface number of NIC */
   char       chrc_tiface[ IFNAMSIZ ];      /* name of tun interface   */
   char       chrc_riface[ IFNAMSIZ ];      /* name of real interface  */
   struct sockaddr dsc_rhwaddr;             /* real interface mac addr */
#endif
#ifdef HL_FREEBSD
   char       chrc_soa_dl_tiface[ (sizeof(struct sockaddr_dl) + sizeof(HL_LONGLONG) - 1) & (0 - sizeof(HL_LONGLONG)) ];
   char       chrc_soa_dl_riface[ (sizeof(struct sockaddr_dl) + sizeof(HL_LONGLONG) - 1) & (0 - sizeof(HL_LONGLONG)) ];
   char       chrc_riface[ IFNAMSIZ ];      /* name of real interface  */
#endif
   char       chrc_ineta[4];                /* INETA IPV4              */
};

struct dsd_ligw_q_ar_del_ipv4 {             /* del ARP and route IPV4  */
#ifdef HL_LINUX
   char       chrc_tiface[ IFNAMSIZ ];      /* name of tun interface   */
   char       chrc_riface[ IFNAMSIZ ];      /* name of real interface  */
   struct sockaddr dsc_rhwaddr;             /* real interface mac addr */
#endif
#ifdef HL_FREEBSD
   char       chrc_soa_dl_tiface[ (sizeof(struct sockaddr_dl) + sizeof(HL_LONGLONG) - 1) & (0 - sizeof(HL_LONGLONG)) ];
   char       chrc_soa_dl_riface[ (sizeof(struct sockaddr_dl) + sizeof(HL_LONGLONG) - 1) & (0 - sizeof(HL_LONGLONG)) ];
#endif
   char       chrc_ineta[4];                /* INETA IPV4              */
};
#endif
