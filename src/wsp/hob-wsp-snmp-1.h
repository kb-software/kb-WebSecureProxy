// 15.05.07 KB
// 28.06.08 KB
/**
   needs Unicode definitions,
   for example from hob-xslunic1.h
*/

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

#ifndef HL_LONGLONG
#define HL_LONGLONG long long int
#endif

#ifdef NOT_YET_080628
#define D_WSP_SNMP_TRAP_CONNECTION_MAXCONN       1
#define D_WSP_SNMP_TRAP_CONNECTION_THRESHOLD     2
#define D_WSP_SNMP_TRAP_CPU_TIME                 3
#define D_WSP_SNMP_TRAP_MEMORY                   4
#define D_WSP_SNMP_TRAP_WORKTHR_QUEUE            5
#define D_WSP_SNMP_TRAP_WATCH_SYN                6
#define D_WSP_SNMP_TRAP_RADIUS_QUERY             7

struct dsd_snmp_conf_1 {                    /* SNMP configuration      */
   int        imc_wsp_no;                   /* number of WSP           */
   int        imc_time_repeat_trap;         /* time in seconds         */
   int        imc_cpu_time_percent;         /* percentage of host      */
   HL_LONGLONG ilc_memory_threshold;        /* memory threshold        */
   int        imc_workthr_queue;            /* queue of work-thread    */
   int        imc_watch_syn_no;             /* number of SYN to watch  */
   int        imc_watch_syn_time;           /* time of SYN watch       */
};
#endif

enum ied_wsp_snmp_trap_def {                /* definition of WSP SNMP Traps */
   ied_wsp_snmp_trap_inv = 0,               /* entry invalid           */
   ied_wsp_snmp_trap_cpu_thres,             /* CPU threshold reached   */
   ied_wsp_snmp_trap_mem_thres,             /* memory threshold reached */
   ied_wsp_snmp_trap_workthr_q,             /* workthread queue        */
   ied_wsp_snmp_trap_conn_maxconn,          /* connection maxconn reached */
   ied_wsp_snmp_trap_conn_thresh,           /* connection threshold reached */
   ied_wsp_snmp_trap_radius_query,          /* Radius query reported error */
   ied_wsp_snmp_trap_file_access            /* File Access failed      */
};

struct dsd_wsp_snmp_trap_cpu_thres {        /* CPU threshold           */
   int        imc_load;                     /* current load            */
};

struct dsd_wsp_snmp_trap_mem_thres {        /* memory threshold        */
   HL_LONGLONG ilc_memory;                  /* memory in use           */
};

struct dsd_wsp_snmp_trap_workthr_q {        /* workthread queue        */
   int        imc_queue_length;             /* current queue length    */
};

struct dsd_wsp_snmp_trap_conn_maxconn {     /* connection maxconn reached */
   int        imc_no_conn;                  /* current number of connections */
   struct dsd_unicode_string dsc_conn_name;  /* connection name        */
};

struct dsd_wsp_snmp_trap_conn_thresh {      /* connection threshold reached */
   int        imc_no_conn;                  /* current number of connections */
   struct dsd_unicode_string dsc_conn_name;  /* connection name        */
};

struct dsd_wsp_snmp_trap_radius_query {     /* Radius query reported error */
   struct dsd_unicode_string dsc_radius_conf;  /* name of Radius configuration */
   struct dsd_unicode_string dsc_error_msg;  /* error message          */
};

struct dsd_wsp_snmp_trap_file_access {      /* File Access failed      */
   struct dsd_unicode_string dsc_file_name;  /* file name              */
   int        imc_errno;                    /* error number            */
};

extern PTYPE void m_snmp_trap_1( enum ied_wsp_snmp_trap_def, void * );
