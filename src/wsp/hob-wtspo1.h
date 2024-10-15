/* header file for WTS (Windows Terminal Server) Ports,                */
/* created 12.01.07 KB                                                 */
/* copyright (c) HOB Germany 2007                                      */

enum ied_ineta_def {
   ied_ineta_invalid,                       /* invalid function       */
   ied_ineta_any,                           /* take any INETA         */
   ied_ineta_ipv4,                          /* INETA IPV4             */
   ied_ineta_ipv6,                          /* INETA IPV6             */
   ied_ineta_dns_name                       /* DNS name               */
                                            /* DNS name is zero-terminated */
};

union dsd_un_ineta_1 {                      /* union INETA             */
   unsigned int umc_ineta_v4;               /* IPV4                    */
   char       chrc_ineta_v6[16];            /* IPV6                    */
   char       chrc_dns_name[256];           /* DNS name                */
};

struct dsd_ineta_1 {                        /* structure INETA         */
   enum ied_ineta_def iec_ineta;            /* type of INETA           */
   union dsd_un_ineta_1 dsc_un_ineta_1;     /* union INETA             */
};

struct dsd_wtspo_1 {                        /* structure WTS port      */
   int        imc_port_rdp;                 /* port RDP                */
   int        imc_port_ica;                 /* port ICA                */
   int        imc_port_ssl_rdp;             /* port SSL RDP            */
   int        imc_port_ssl_ica;             /* port SSL ICA            */
};

#define DEF_WTSPO1_RDP         1            /* get RDP Port            */
#define DEF_WTSPO1_ICA         2            /* get ICA Port            */
#define DEF_WTSPO1_SSL_RDP     4            /* get SSL RDP Port        */
#define DEF_WTSPO1_SSL_ICA     8            /* get SSL ICA Port        */

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

/* get ports                                                           */
extern PTYPE void m_get_wtspo1_ineta( struct dsd_wtspo_1 *,
                                      struct dsd_ineta_1 *, int );
