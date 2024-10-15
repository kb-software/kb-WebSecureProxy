/**
  hob-rdptracer1.h
  Header-File for RDP-Acceletator / RDP-Tracer
  Copyright (C) HOB Germany 2007
  Copyright (C) HOB Germany 2016
  01.05.07 KB
*/
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
/* 5 reserved for DEF_IFUNC_FROMSERVER                                 */
/* 6 reserved for DEF_IFUNC_TOSERVER                                   */

#ifndef DEF_IFUNC_REFLECT
#define DEF_IFUNC_REFLECT          7        // reflect data
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
/* 3 reserved for DEF_IRET_INVDA                                       */

#ifdef B110502
struct dsd_rdp_vc_1 {                       /* RDP virtual channel     */
   char       byrc_name[8];                 /* name of channel         */
   int        imc_flags;                    /* flags                   */
   unsigned short int usc_vch_no;           /* virtual channel no com  */
};
#endif

enum ied_tr_command {                       /* tracer component command */
   ied_trc_invalid,                         /* command is invalid      */
   ied_trc_recv_client,                     /* received from client    */
   ied_trc_recv_server,                     /* received from server    */
   ied_trc_virt_ch,                         /* virtual channels        */
   ied_trc_cl2se_decry,                     /* client to server, decrypted */
   ied_trc_cl2se_r5,                        /* client to server RDP 5, decrypted */
   ied_trc_se2cl_decry,                     /* server to client, decrypted */
   ied_trc_se2cl_r5_pdu,                    /* server to client, RDP 5 PDU */
   ied_trc_server_cert,                     /* server certificate      */
   ied_trc_se2cl_vch,                       /* server to client virtual channel */
   ied_trc_cl2se_vch,                       /* client to server virtual channel */
   ied_trc_se2cl_gen_vch,                   /* server to client virtual channel generated */
   ied_trc_cl2se_gen_vch,                   /* client to server virtual channel generated */
   ied_trc_se2cl_msg,                       /* server to client message */
   ied_trc_cl2se_msg,                       /* client to server message */
   ied_xxx_mpoi_move                        /* move mouse pointer      */
};

struct dsd_call_rdptrac_1 {                 /* call RDP Tracer 1       */
   int        imc_func;                     /* called function         */
   int        imc_return;                   /* return code             */
   int        imc_sno;                      /* session number          */
/* to-do 16.02.15 KB - rename to adsc_caller */
#ifndef HL_RDP_WEBTERM
   struct dsd_hl_clib_1 *adsc_hl_clib_1;    /* HOBLink Copy Library 1  */
#else
   struct dsd_call_wt_rdp_client_1 *adsc_hl_clib_1;  /* HOBLink WebTerm RDP */
#endif
   ied_tr_command iec_tr_command;           /* tracer component command */

   struct dsd_gather_i_1 *adsc_gather_i_1_in;  /* input data           */
   char *     achc_trace_input;             /* addr trace-input        */
   int        imc_len_trace_input;          /* length trace-input      */
   int        imc_disp_field;               /* displacement of field   */
   char       chc_type_disp;                /* type of displacement    */
   int        imc_prot1;                    /* variable field          */
   unsigned short int usc_vch_no;           /* virtual channel no com  */
#ifdef B160330
   char       chrc_vch_segfl[2];            /* virtual channel segmentation flags */
#endif
   char       chrc_vch_flags[4];            /* virtual channel flags   */
   char       chc_prot_r5_pdu_type;         /* RDP 5 PDU type          */

#ifdef B110604
   char *     achc_trace_output;            /* addr trace-output       */
   int        imc_len_trace_output;         /* length trace-output     */
#endif

#ifdef B110502
   BOOL (* amc_write) ( struct dsd_call_rdptrac_1 *, char *, int );  /* write trace output */
#else
   int        imc_trace_level;              /* WSP trace level         */
#endif
   void *     ac_ext;                       /* attached buffer pointer */
   void *     ac_conf;                      /* data from configuration */
};

#if defined __cplusplus
extern "C" void m_hlrdptra1e( struct dsd_call_rdptrac_1 * );
#else
extern void m_hlrdptra1e( struct dsd_call_rdptrac_1 * );
#endif // cplusplus
