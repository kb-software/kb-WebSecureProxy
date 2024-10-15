/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-xsrdpvch1.h                                     |*/
/*| -------------                                                     |*/
/*|  HOB Header file for RDP-Accelerator, Server-Data-Hook            |*/
/*|    Virus checking                                                 |*/
/*|  KB 28.10.07                                                      |*/
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
/*|  Copyright (C) HOB Germany 2015                                   |*/
/*|  Copyright (C) HOB Germany 2016                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  GCC all platforms                                                |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif
#ifndef HL_LONGLONG
#ifndef HL_UNIX
#define HL_LONGLONG LONGLONG
#else
#define HL_LONGLONG long long int
#endif
#endif

enum ied_sdh_ret1 {                         /* return code Server-Data-Hook */
   ied_sdhr1_ok,                            /* everything o.k.         */
   ied_sdhr1_failed,                        /* operation failed        */
   ied_sdhr1_fatal_error                    /* fatal error occured, abend */
};

enum ied_vch_req_def {                      /* virus checking request  */
   ied_vchreq_filename,                     /* filename                */
   ied_vchreq_content,                      /* content of file         */
   ied_vchreq_eof                           /* End-of-File             */
};

enum ied_vch_compl_def {                    /* virus checking completion */
   ied_vchcompl_active,                     /* virus checking active   */
   ied_vchcompl_idle,                       /* nothing to do           */
   ied_vchcompl_ok,                         /* file has no virus       */
   ied_vchcompl_no_server,                  /* the necessary servers not found */
   ied_vchcompl_comm_error,                 /* communication error     */
   ied_vchcompl_vch_inv_resp,               /* invalid response from virus checker */
   ied_vchcompl_vch_timeout,                /* timeout while virus checking */
   ied_vchcompl_virus                       /* file contains virus     */
};

enum ied_vch_stat_def {                     /* virus checking state    */
   ied_vchstat_active = 0,                  /* data not sent yet       */
   ied_vchstat_sent,                        /* data have been sent     */
   ied_vchstat_done                         /* area can be freed       */
};

struct dsd_rdpvch1_config {                 /* configuration           */
   int        imc_trace_level;              /* configured trace level  */
   int        imc_enc2cl;                   /* encryption-to-client    */
   int        imc_comp2se;                  /* compression-to-server   */
   BOOL       boc_disa_ms_clipb;            /* disable MS clipboard    */
   BOOL       boc_disa_ms_ldm;              /* disable MS local-drive-mapping */
   BOOL       boc_disa_hob_ldm;             /* disable HOB local-drive-mapping */
   int        imc_len_ldm_vch_serv;         /* length ldm virus-checking service name */
   HL_LONGLONG ilc_ldm_max_file_size;       /* maximum file-size virus-checking */
};

struct dsd_se_vch_req_1 {                   /* service virus checking request */
   struct dsd_se_vch_req_1 *adsc_next;      /* next in chain           */
   enum ied_vch_req_def iec_vchreq1;        /* request type            */
   enum ied_vch_stat_def iec_stat;          /* state of request        */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* data                    */
};

struct dsd_se_vch_contr_1 {                 /* service virus checking control area */
   struct dsd_se_vch_req_1 *adsc_sevchreq1;  /* chain of requests      */
#ifndef B160415
   BOOL       boc_abend;                    /* process abend           */
#endif
   enum ied_vch_compl_def iec_vchcompl;     /* completion code         */
   HL_LONGLONG ilc_window_1;                /* bytes sent first step   */
   HL_LONGLONG ilc_window_2;                /* bytes sent second step  */
   BOOL       boc_wait_window;              /* wait till window smaller */
   int        imc_max_diff_window;          /* maximum difference window */
   int        imc_len_virus_name;           /* length returned virus name */
   char       chrc_virus_name[ 128 ];       /* output to virus name    */
};

#ifndef HL_RDP_WEBTERM
struct dsd_rdp_vc_1 {                       /* RDP virtual channel     */
   char       byrc_name[8];                 /* name of channel         */
   int        imc_flags;                    /* flags                   */
   unsigned short int usc_vch_no;           /* virtual channel no com  */
   char       chc_hob_vch;                  /* virtual channel HOB special */
   char       chc_tose_segfl;               /* to server segmentation flag */
   char       chc_tose_stat_1;              /* to server status 1      */
   int        imc_tose_stat_2;              /* to server status 2      */
   int        imc_tose_stat_3;              /* to server status 3      */
   int        imc_tose_stat_4;              /* to server status 4      */
   void *     ac_tose_pch_save_1_save;      /* save data from this channel */
};
#endif

struct dsd_rdp_save_vch_1 {                 /* RDP parameters saved virus checking */
   void *     ac_vir_ch_1;                  /* main structure for virus checking */
   void *     ac_tose_pch_save_1_send;      /* send data from this channel */
   void *     ac_frse_pch_save_2_send;      /* send data from this channel */
};

struct dsd_rdp_param_vch_1 {                /* RDP parameters virus checking */
   struct dsd_rdp_save_vch_1 dsc_s1;        /* RDP parameters saved virus checking */
   struct dsd_rdpvch1_config *adsc_conf;    /* data from configuration */
#ifdef B091207B
   struct dsd_rdp_vc_1 *adsc_rdp_vc_hob1;   /* RDP virtual channel HOB1 */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_hob2;   /* RDP virtual channel HOB2 */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_rdpdr;  /* RDP virtual channel rdpdr */
#endif
   struct dsd_stor_sdh_1 *adsc_stor_sdh_1;  /* storage management      */
   BOOL       boc_callrevdir;               /* call on reverse direction */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_1;      /* RDP virtual channel     */
   struct dsd_gather_i_1 *adsc_gather_i_1_in;  /* gather data from channel */
   int        imc_len_vch_input;            /* length of data from channel */
   char       chrc_vch_segfl[2];            /* virtual channel segmentation flags */
// struct dsd_sc_vch_out *adsc_sc_vch_out;  /* send output to virtual channel */
   struct dsd_rdp_vch_io  *adsc_sc_vch_out;  /* IO RDP virtual channel */
   struct dsd_output_area_1 *adsc_output_area_1;  /* output of subroutine */
#ifdef XYZ1
   struct dsd_se_vch_contr_1 dsc_sevchcontr1;  /* service virus checking control area */
#endif
   void *     ac_chain_send_tose;           /* chain of buffers to be sent to the server */
   void *     ac_chain_send_frse;           /* chain of buffers to be sent to the client */
};

#ifndef HL_RDP_WEBTERM
//struct dsd_sc_vch_out {                     /* server sends output to virtual channel */
struct dsd_rdp_vch_io {                     /* IO RDP virtual channel  */
   struct dsd_rdp_vc_1 *adsc_rdp_vc_1;      /* RDP virtual channel     */
// struct dsd_gather_i_1 *adsc_gai1_out;    /* output data             */
   struct dsd_gather_i_1 *adsc_gai1_data;   /* input output data       */
   unsigned int umc_vch_ulen;               /* virtual channel length uncompressed */
   char       chrc_vch_segfl[2];            /* virtual channel segmentation flags */
};
#endif

struct dsd_output_area_1 {                  /* output of subroutine    */
#ifdef B131029
   char       *achc_w1;                     /* lower addr output area  */
   char       *achc_w2;                     /* higher addr output area */
#endif
   char       *achc_lower;                  /* lower addr output area  */
   char       *achc_upper;                  /* higher addr output area */
// struct dsd_gather_i_1 *adsc_gai1_o1;     /* output data             */
   struct dsd_gather_i_1 **aadsc_gai1_out_to_client;  /* output data to client */
   struct dsd_gather_i_1 **aadsc_gai1_out_to_server;  /* output data to server */
};

#ifndef IBIPGW08
extern "C" BOOL m_rdp_vch1_init( struct dsd_rdp_param_vch_1 * );
extern "C" ied_sdh_ret1 m_rdp_vch1_rec_frse( struct dsd_rdp_param_vch_1 * );
extern "C" ied_sdh_ret1 m_rdp_vch1_rec_tose( struct dsd_rdp_param_vch_1 * );
extern "C" ied_sdh_ret1 m_rdp_vch1_get_frse( struct dsd_rdp_param_vch_1 * );
extern "C" ied_sdh_ret1 m_rdp_vch1_get_tose( struct dsd_rdp_param_vch_1 * );
extern "C" void m_rdp_vch1_close( struct dsd_rdp_param_vch_1 * );
#endif
