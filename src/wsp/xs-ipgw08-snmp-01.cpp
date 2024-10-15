/*+-------------------------------------------------------------------+*/
/*| xs-ipgw08-snmp-01.cpp                                             |*/
/*| ---------------------                                             |*/
/*| SNMP Trap's encoding (Version 1)                                  |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*| Copyright (C) HOB Germany 2010                                    |*/
/*| Copyright (C) HOB Germany 2012                                    |*/
/*|                                                                   |*/
/*| AUTHOR:                                                           |*/
/*| -------                                                           |*/
/*| Dorian Tanti                                                      |*/
/*|                                                                   |*/
/*| DATE:                                                             |*/
/*| -----                                                             |*/
/*| 22.02.2010 (DD.MM.YYYY)                                           |*/
/*| 01.09.2010 (DD.MM.YYYY) Last update                               |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*| MS Visual Studio .NET 2005 / C++ 8.0                              |*/
/*| MS Linker                                                         |*/
/*|                                                                   |*/
/*| NOTE                                                              |*/
/*| ----                                                              |*/
/*| This cpp file is automatically created with a script. Direct      |*/
/*| changes in this file will be lost when the script is run again.   |*/
/*|                                                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/
#if (defined WIN32) || (defined WIN64)
#include <windows.h>
#else
#include <hob-unix.h>
#endif
#include <hob-xslunic1.h>			//Must be included before hob-wsp-snmp-1.h
#include <hob-wsp-snmp-1.h>

/*+-------------------------------------------------------------------+*/
/*| Defines                                                           |*/
/*+-------------------------------------------------------------------+*/
/* general BER types used by SNMP */
#define LASN1_INTEGER		((unsigned int) 0x02UL)
#define LASN1_OCTETSTRING	((unsigned int) 0x04UL)
#define LASN1_NULL			((unsigned int) 0x05UL)
#define LASN1_OID			((unsigned int) 0x06UL)
#define LASN1_SEQUENCE		((unsigned int) 0x30UL)	 /* constructed */
#define LASN1_UNKNOWN       ((unsigned int) -1)      /* ignore the tag type */
#define LASN1_TIMETICK		((unsigned int) 0x43UL)

#define LASN1_GETREQUET		((unsigned int) 0xA0UL)
#define LASN1_GETNEXTREQUET	((unsigned int) 0xA1UL)
#define GETRESPONSE			((unsigned int) 0xA2UL)
#define SETREQUEST			((unsigned int) 0xA3UL)
#define TRAPV1				((unsigned int) 0xA4UL)
#define GETBULTREQUEST		((unsigned int) 0xA5UL)
#define INFORMREQUEST		((unsigned int) 0xA6UL)
#define	TRAPV2				((unsigned int) 0xA7UL)

/* return values... */
#define LASN1_SUCCESS       ((unsigned int)  0)
#define LASN1_ERROR		    ((unsigned int) -1)

/* Fixed Size Limits*/		//todo: attention
#define HL_BUFFERSIZE          1024
#define HL_MAX_AMT_SEQ         30
#define HL_STR_OID_MAXSIZE     60
#define HL_INT_OID_MAXSIZE     30
#define HL_BYTE_OID_MAXSIZE    50
#define HL_SEQLENLEN_MAXSIZE   4	
#define HL_SEQLEN_MAXSIZE      0x3
#define HL_NOTOVERFLOW		   -1
#define HL_OVERFLOW			   1

//Trap's and their values OIDs
#define HL_SYSUPTIME_OID    "1.3.6.1.2.1.1.3.0"       /* OID of system uptime     */
#define HL_SNMPTRAP_OID       "1.3.6.1.6.3.1.1.4.1.0"   /* OID of snmp trap */
#define HL_WSP_SNMP_TRAP_INV                "1.3.6.1.4.1.6275.200.1.0"
#define HL_WSP_SNMP_TRAP_CPU_THRES                "1.3.6.1.4.1.6275.200.1.1"
#define HL_WSP_SNMP_TRAP_CPU_THRES_IMC_LOAD     "1.3.6.1.4.1.6275.200.1.1.1"
#define HL_WSP_SNMP_TRAP_MEM_THRES                "1.3.6.1.4.1.6275.200.1.2"
#define HL_WSP_SNMP_TRAP_MEM_THRES_ILC_MEMORY     "1.3.6.1.4.1.6275.200.1.2.1"
#define HL_WSP_SNMP_TRAP_WORKTHR_Q                "1.3.6.1.4.1.6275.200.1.3"
#define HL_WSP_SNMP_TRAP_WORKTHR_Q_IMC_QUEUE_LENGTH     "1.3.6.1.4.1.6275.200.1.3.1"
#define HL_WSP_SNMP_TRAP_CONN_MAXCONN                "1.3.6.1.4.1.6275.200.1.4"
#define HL_WSP_SNMP_TRAP_CONN_MAXCONN_IMC_NO_CONN     "1.3.6.1.4.1.6275.200.1.4.1"
#define HL_WSP_SNMP_TRAP_CONN_MAXCONN_DSC_CONN_NAME     "1.3.6.1.4.1.6275.200.1.4.2"
#define HL_WSP_SNMP_TRAP_CONN_THRESH                "1.3.6.1.4.1.6275.200.1.5"
#define HL_WSP_SNMP_TRAP_CONN_THRESH_IMC_NO_CONN     "1.3.6.1.4.1.6275.200.1.5.1"
#define HL_WSP_SNMP_TRAP_CONN_THRESH_DSC_CONN_NAME     "1.3.6.1.4.1.6275.200.1.5.2"
#define HL_WSP_SNMP_TRAP_RADIUS_QUERY                "1.3.6.1.4.1.6275.200.1.6"
#define HL_WSP_SNMP_TRAP_RADIUS_QUERY_DSC_RADIUS_CONF     "1.3.6.1.4.1.6275.200.1.6.1"
#define HL_WSP_SNMP_TRAP_RADIUS_QUERY_DSC_ERROR_MSG     "1.3.6.1.4.1.6275.200.1.6.2"
#define HL_WSP_SNMP_TRAP_FILE_ACCESS                "1.3.6.1.4.1.6275.200.1.7"
#define HL_WSP_SNMP_TRAP_FILE_ACCESS_DSC_FILE_NAME     "1.3.6.1.4.1.6275.200.1.7.1"
#define HL_WSP_SNMP_TRAP_FILE_ACCESS_IMC_ERRNO     "1.3.6.1.4.1.6275.200.1.7.2"


/*+-------------------------------------------------------------------+*/
/*|  Structures														  |*/
/*+-------------------------------------------------------------------+*/
//Structure represnting a SNMP Trap's variable list's variable binds
typedef struct dsd_varbind
{
	struct	dsd_varbind			* dsd_next_variable;			/* Pointr to next Variable NULL for last variable */
	struct dsd_unicode_string	dsd_oid;						/* Object identifier of variable */						
	int							dsd_val_t;						/* value of variable */
} dsd_varbind_t;

//Structure holding common SNMP's message data
typedef struct dsd_snmp_pdu {
    long						il_version;						/* Snmp Version    */		
	struct dsd_unicode_string	dsd_communityname;				/* Community Name */		
	long						il_reqid;					    /* Request id - note: not incremented on replies */
    long						il_errstat;					    /* Error status (non_repeaters in GetBulk) */
    long						il_errindex;				    /* Error index (max_repetitions in GetBulk) */
	struct dsd_unicode_string	dsd_SysUpTime_oid;				/* Community Name */
	struct dsd_unicode_string	dsd_snmpTrap_oid;				/* Community Name */
} dsd_snmp_pdu_t;

//A union holding the system up time integer as 64 bit/2x 32bit
typedef union uptime
{
	unsigned long long   ull_uptime64;
	
#ifdef HL_BIG_ENDIAN
	struct dsd_timeparts
	{
		int unsigned um_high_part;
		int unsigned um_low_part;			
	} ds_timeparts;
#else	
	struct dsd_timeparts
	{	
		int unsigned    um_low_part;
		int unsigned    um_high_part;	
	} ds_timeparts;
#endif
} uptime_t;


/*+-------------------------------------------------------------------+*/
/*| Class functions definitions		                                  |*/
/*+-------------------------------------------------------------------+*/
class dsd_asn_cl
{
// Data
public:
	int     iml_tag;                               // T(ag)
	int     iml_currentpos;	                       // Next writable position in the buffer
	char    chr_buf[HL_BUFFERSIZE];                // Simple buffer	

private:
	int          im_usertag;                       // If not set, use LASN1_SEQUENCE	
	unsigned int umlr_seqsPos[HL_MAX_AMT_SEQ];     // Array holding the first seq of a ASN.1 message
	unsigned int uml_arrayindex;

// Functions
public:
	void    m_init();                               // Constructor dsd_asn_cl()
                                                    // No need destructor  ~dsd_asn_cl() since no mallocs
	int	    m_printf( const char *fmt, ... );

private:
	int	    m_put_tag( int /*tag*/, int /*taglen*/ );
	int	    m_put_len( int /*len*/, int /*lenlen*/ );
	int     m_put_len( int imp_len, int imp_lenlen, int imp_bufferloc);
	int     m_calc_lenlen( int imp_len );
	int	    m_calc_taglen( int imp_tag );

	int     m_put_int ( int /*value*/ );
	int     m_put_timetick ( int /*value*/        ); //;, int /*tag*/ );
	int	    m_put_null( );
	int     m_put_string( struct dsd_unicode_string *ds_src);    //char * /*string value*/, int /*string length*/, ied_charset /*charset*/ );
	int     m_put_oid(struct dsd_unicode_string *ds_src);        //char * /*string value*/, int /*string length*/, ied_charset /*charset*/ );
	int     m_put_octetstring( char * /*string value*/, int /*string length*/                     );

	int	    m_start_seq( int /*tag*/ );
	int     m_end_seq();
	int     m_potentialoverflow(int iml_currentbufposition, int imp_lentoinc);
};	//end of class dsd_asn_cl

/*+-------------------------------------------------------------------+*/
/*| Globals                                                           |*/
/*+-------------------------------------------------------------------+*/

unsigned int	ul_requestID        = 1;
int				in_snmpversion      = 1;                        /* 0 = SNMP v1;   1 = SNMP 2c   */
char			chr_community[]	    = "dor";

extern "C" void	m_send_snmp_trap_1( char *, int );
static int		m_getsystemuptime();

/*+-------------------------------------------------------------------+*/
/*| Global Functions                                                  |*/
/*+-------------------------------------------------------------------+*/
/**
* Sending snmp trap message procedure.
*
* This main function converts param avo_param to a ASN like structure.
* Then it encode it using BER encoding.
* *
* @param1 - ied_wsp_snmp_trap_def ie_type - trap number
* @param2 - void * avo_param - pointer to a structure which holds variable/s that will be send via the trap
*
* @return void
*
*/
extern "C" void  m_snmp_trap_1(ied_wsp_snmp_trap_def ie_type, void * avo_param)
{
	int iml_ret (LASN1_ERROR);

	//declaring the asn1 class
	class	dsd_asn_cl						dsl_asn1;
	//create ASN1 sequences
	dsl_asn1.m_init();
		
	//Initialising Snmp general data's structure
	dsd_snmp_pdu_t      dsl_snmppdu;
	dsl_snmppdu.il_reqid			          = ul_requestID;
	dsl_snmppdu.il_errstat                    = 0;
	dsl_snmppdu.il_errindex                   = 0;
	dsl_snmppdu.il_version                    = in_snmpversion;
    dsl_snmppdu.dsd_communityname.ac_str      = chr_community;
	dsl_snmppdu.dsd_communityname.imc_len_str = (int)strlen((char*)dsl_snmppdu.dsd_communityname.ac_str);
	dsl_snmppdu.dsd_communityname.iec_chs_str = ied_chs_ascii_850;
	dsl_snmppdu.dsd_SysUpTime_oid.ac_str      = HL_SYSUPTIME_OID;
	dsl_snmppdu.dsd_SysUpTime_oid.iec_chs_str = ied_chs_ascii_850;
	dsl_snmppdu.dsd_SysUpTime_oid.imc_len_str = sizeof(HL_SYSUPTIME_OID)-1;	
	dsl_snmppdu.dsd_snmpTrap_oid.ac_str       = HL_SNMPTRAP_OID;
	dsl_snmppdu.dsd_snmpTrap_oid.iec_chs_str  = ied_chs_ascii_850;
	dsl_snmppdu.dsd_snmpTrap_oid.imc_len_str  = sizeof(HL_SNMPTRAP_OID)-1;


   switch(ie_type)
    {
          case ied_wsp_snmp_trap_inv: // entry invalid
         {
          struct dsd_unicode_string dsl_wsp_snmp_trap_inv;
          dsl_wsp_snmp_trap_inv.ac_str = HL_WSP_SNMP_TRAP_INV;
          dsl_wsp_snmp_trap_inv.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_inv.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_INV)-1;

          // encoding data into ASN.1 format
          iml_ret = dsl_asn1.m_printf("{ist{iii{{xT}{xx}}}}",

            dsl_snmppdu.il_version,                /* i - snmp version                                 */
             &dsl_snmppdu.dsd_communityname,       /* s - comunity string                              */
             TRAPV2,                               /* t - type of snmp msg                             */
             dsl_snmppdu.il_reqid,                 /* i - request id                                   */
             dsl_snmppdu.il_errstat,               /* i - error status                                 */
             dsl_snmppdu.il_errindex,              /* i - error index                                  */
             &dsl_snmppdu.dsd_SysUpTime_oid,       /* x - VarBind 1 - OID address of sysUp time        */
             m_getsystemuptime,
             &dsl_snmppdu.dsd_snmpTrap_oid,
             &dsl_wsp_snmp_trap_inv);
          } break;

          case ied_wsp_snmp_trap_cpu_thres: // CPU threshold reached
         {
          dsd_wsp_snmp_trap_cpu_thres* dsd_trap = reinterpret_cast<dsd_wsp_snmp_trap_cpu_thres*>(avo_param);
          struct dsd_unicode_string dsl_wsp_snmp_trap_cpu_thres;
          dsl_wsp_snmp_trap_cpu_thres.ac_str = HL_WSP_SNMP_TRAP_CPU_THRES;
          dsl_wsp_snmp_trap_cpu_thres.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_cpu_thres.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_CPU_THRES)-1;

          struct dsd_unicode_string dsl_wsp_snmp_trap_cpu_thres_imc_load;
          dsl_wsp_snmp_trap_cpu_thres_imc_load.ac_str = HL_WSP_SNMP_TRAP_CPU_THRES_IMC_LOAD;
          dsl_wsp_snmp_trap_cpu_thres_imc_load.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_cpu_thres_imc_load.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_CPU_THRES_IMC_LOAD)-1;

          // encoding data into ASN.1 format
          iml_ret = dsl_asn1.m_printf("{ist{iii{{xT}{xx}{xi}}}}",

            dsl_snmppdu.il_version,                /* i - snmp version                                 */
             &dsl_snmppdu.dsd_communityname,       /* s - comunity string                              */
             TRAPV2,                               /* t - type of snmp msg                             */
             dsl_snmppdu.il_reqid,                 /* i - request id                                   */
             dsl_snmppdu.il_errstat,               /* i - error status                                 */
             dsl_snmppdu.il_errindex,              /* i - error index                                  */
             &dsl_snmppdu.dsd_SysUpTime_oid,       /* x - VarBind 1 - OID address of sysUp time        */
             m_getsystemuptime,
             &dsl_snmppdu.dsd_snmpTrap_oid,
             &dsl_wsp_snmp_trap_cpu_thres,
             &dsl_wsp_snmp_trap_cpu_thres_imc_load,
              dsd_trap->imc_load);
          } break;

          case ied_wsp_snmp_trap_mem_thres: // memory threshold reached
         {
          dsd_wsp_snmp_trap_mem_thres* dsd_trap = reinterpret_cast<dsd_wsp_snmp_trap_mem_thres*>(avo_param);
          struct dsd_unicode_string dsl_wsp_snmp_trap_mem_thres;
          dsl_wsp_snmp_trap_mem_thres.ac_str = HL_WSP_SNMP_TRAP_MEM_THRES;
          dsl_wsp_snmp_trap_mem_thres.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_mem_thres.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_MEM_THRES)-1;

          struct dsd_unicode_string dsl_wsp_snmp_trap_mem_thres_ilc_memory;
          dsl_wsp_snmp_trap_mem_thres_ilc_memory.ac_str = HL_WSP_SNMP_TRAP_MEM_THRES_ILC_MEMORY;
          dsl_wsp_snmp_trap_mem_thres_ilc_memory.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_mem_thres_ilc_memory.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_MEM_THRES_ILC_MEMORY)-1;

          // encoding data into ASN.1 format
          iml_ret = dsl_asn1.m_printf("{ist{iii{{xT}{xx}{xi}}}}",

            dsl_snmppdu.il_version,                /* i - snmp version                                 */
             &dsl_snmppdu.dsd_communityname,       /* s - comunity string                              */
             TRAPV2,                               /* t - type of snmp msg                             */
             dsl_snmppdu.il_reqid,                 /* i - request id                                   */
             dsl_snmppdu.il_errstat,               /* i - error status                                 */
             dsl_snmppdu.il_errindex,              /* i - error index                                  */
             &dsl_snmppdu.dsd_SysUpTime_oid,       /* x - VarBind 1 - OID address of sysUp time        */
             m_getsystemuptime,
             &dsl_snmppdu.dsd_snmpTrap_oid,
             &dsl_wsp_snmp_trap_mem_thres,
             &dsl_wsp_snmp_trap_mem_thres_ilc_memory,
              dsd_trap->ilc_memory);
          } break;

          case ied_wsp_snmp_trap_workthr_q: // workthread queue
         {
          dsd_wsp_snmp_trap_workthr_q* dsd_trap = reinterpret_cast<dsd_wsp_snmp_trap_workthr_q*>(avo_param);
          struct dsd_unicode_string dsl_wsp_snmp_trap_workthr_q;
          dsl_wsp_snmp_trap_workthr_q.ac_str = HL_WSP_SNMP_TRAP_WORKTHR_Q;
          dsl_wsp_snmp_trap_workthr_q.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_workthr_q.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_WORKTHR_Q)-1;

          struct dsd_unicode_string dsl_wsp_snmp_trap_workthr_q_imc_queue_length;
          dsl_wsp_snmp_trap_workthr_q_imc_queue_length.ac_str = HL_WSP_SNMP_TRAP_WORKTHR_Q_IMC_QUEUE_LENGTH;
          dsl_wsp_snmp_trap_workthr_q_imc_queue_length.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_workthr_q_imc_queue_length.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_WORKTHR_Q_IMC_QUEUE_LENGTH)-1;

          // encoding data into ASN.1 format
          iml_ret = dsl_asn1.m_printf("{ist{iii{{xT}{xx}{xi}}}}",

            dsl_snmppdu.il_version,                /* i - snmp version                                 */
             &dsl_snmppdu.dsd_communityname,       /* s - comunity string                              */
             TRAPV2,                               /* t - type of snmp msg                             */
             dsl_snmppdu.il_reqid,                 /* i - request id                                   */
             dsl_snmppdu.il_errstat,               /* i - error status                                 */
             dsl_snmppdu.il_errindex,              /* i - error index                                  */
             &dsl_snmppdu.dsd_SysUpTime_oid,       /* x - VarBind 1 - OID address of sysUp time        */
             m_getsystemuptime,
             &dsl_snmppdu.dsd_snmpTrap_oid,
             &dsl_wsp_snmp_trap_workthr_q,
             &dsl_wsp_snmp_trap_workthr_q_imc_queue_length,
              dsd_trap->imc_queue_length);
          } break;

          case ied_wsp_snmp_trap_conn_maxconn: // connection maxconn reached
         {
          dsd_wsp_snmp_trap_conn_maxconn* dsd_trap = reinterpret_cast<dsd_wsp_snmp_trap_conn_maxconn*>(avo_param);
          struct dsd_unicode_string dsl_wsp_snmp_trap_conn_maxconn;
          dsl_wsp_snmp_trap_conn_maxconn.ac_str = HL_WSP_SNMP_TRAP_CONN_MAXCONN;
          dsl_wsp_snmp_trap_conn_maxconn.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_conn_maxconn.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_CONN_MAXCONN)-1;

          struct dsd_unicode_string dsl_wsp_snmp_trap_conn_maxconn_imc_no_conn;
          dsl_wsp_snmp_trap_conn_maxconn_imc_no_conn.ac_str = HL_WSP_SNMP_TRAP_CONN_MAXCONN_IMC_NO_CONN;
          dsl_wsp_snmp_trap_conn_maxconn_imc_no_conn.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_conn_maxconn_imc_no_conn.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_CONN_MAXCONN_IMC_NO_CONN)-1;

          struct dsd_unicode_string dsl_wsp_snmp_trap_conn_maxconn_dsc_conn_name;
          dsl_wsp_snmp_trap_conn_maxconn_dsc_conn_name.ac_str = HL_WSP_SNMP_TRAP_CONN_MAXCONN_DSC_CONN_NAME;
          dsl_wsp_snmp_trap_conn_maxconn_dsc_conn_name.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_conn_maxconn_dsc_conn_name.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_CONN_MAXCONN_DSC_CONN_NAME)-1;

          // encoding data into ASN.1 format
          iml_ret = dsl_asn1.m_printf("{ist{iii{{xT}{xx}{xi}{xs}}}}",

            dsl_snmppdu.il_version,                /* i - snmp version                                 */
             &dsl_snmppdu.dsd_communityname,       /* s - comunity string                              */
             TRAPV2,                               /* t - type of snmp msg                             */
             dsl_snmppdu.il_reqid,                 /* i - request id                                   */
             dsl_snmppdu.il_errstat,               /* i - error status                                 */
             dsl_snmppdu.il_errindex,              /* i - error index                                  */
             &dsl_snmppdu.dsd_SysUpTime_oid,       /* x - VarBind 1 - OID address of sysUp time        */
             m_getsystemuptime,
             &dsl_snmppdu.dsd_snmpTrap_oid,
             &dsl_wsp_snmp_trap_conn_maxconn,
             &dsl_wsp_snmp_trap_conn_maxconn_imc_no_conn,
              dsd_trap->imc_no_conn,
             &dsl_wsp_snmp_trap_conn_maxconn_dsc_conn_name,
              &dsd_trap->dsc_conn_name);
          } break;

          case ied_wsp_snmp_trap_conn_thresh: // connection threshold reached
         {
          dsd_wsp_snmp_trap_conn_thresh* dsd_trap = reinterpret_cast<dsd_wsp_snmp_trap_conn_thresh*>(avo_param);
          struct dsd_unicode_string dsl_wsp_snmp_trap_conn_thresh;
          dsl_wsp_snmp_trap_conn_thresh.ac_str = HL_WSP_SNMP_TRAP_CONN_THRESH;
          dsl_wsp_snmp_trap_conn_thresh.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_conn_thresh.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_CONN_THRESH)-1;

          struct dsd_unicode_string dsl_wsp_snmp_trap_conn_thresh_imc_no_conn;
          dsl_wsp_snmp_trap_conn_thresh_imc_no_conn.ac_str = HL_WSP_SNMP_TRAP_CONN_THRESH_IMC_NO_CONN;
          dsl_wsp_snmp_trap_conn_thresh_imc_no_conn.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_conn_thresh_imc_no_conn.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_CONN_THRESH_IMC_NO_CONN)-1;

          struct dsd_unicode_string dsl_wsp_snmp_trap_conn_thresh_dsc_conn_name;
          dsl_wsp_snmp_trap_conn_thresh_dsc_conn_name.ac_str = HL_WSP_SNMP_TRAP_CONN_THRESH_DSC_CONN_NAME;
          dsl_wsp_snmp_trap_conn_thresh_dsc_conn_name.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_conn_thresh_dsc_conn_name.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_CONN_THRESH_DSC_CONN_NAME)-1;

          // encoding data into ASN.1 format
          iml_ret = dsl_asn1.m_printf("{ist{iii{{xT}{xx}{xi}{xs}}}}",

            dsl_snmppdu.il_version,                /* i - snmp version                                 */
             &dsl_snmppdu.dsd_communityname,       /* s - comunity string                              */
             TRAPV2,                               /* t - type of snmp msg                             */
             dsl_snmppdu.il_reqid,                 /* i - request id                                   */
             dsl_snmppdu.il_errstat,               /* i - error status                                 */
             dsl_snmppdu.il_errindex,              /* i - error index                                  */
             &dsl_snmppdu.dsd_SysUpTime_oid,       /* x - VarBind 1 - OID address of sysUp time        */
             m_getsystemuptime,
             &dsl_snmppdu.dsd_snmpTrap_oid,
             &dsl_wsp_snmp_trap_conn_thresh,
             &dsl_wsp_snmp_trap_conn_thresh_imc_no_conn,
              dsd_trap->imc_no_conn,
             &dsl_wsp_snmp_trap_conn_thresh_dsc_conn_name,
              &dsd_trap->dsc_conn_name);
          } break;

          case ied_wsp_snmp_trap_radius_query: // Radius query reported error
         {
          dsd_wsp_snmp_trap_radius_query* dsd_trap = reinterpret_cast<dsd_wsp_snmp_trap_radius_query*>(avo_param);
          struct dsd_unicode_string dsl_wsp_snmp_trap_radius_query;
          dsl_wsp_snmp_trap_radius_query.ac_str = HL_WSP_SNMP_TRAP_RADIUS_QUERY;
          dsl_wsp_snmp_trap_radius_query.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_radius_query.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_RADIUS_QUERY)-1;

          struct dsd_unicode_string dsl_wsp_snmp_trap_radius_query_dsc_radius_conf;
          dsl_wsp_snmp_trap_radius_query_dsc_radius_conf.ac_str = HL_WSP_SNMP_TRAP_RADIUS_QUERY_DSC_RADIUS_CONF;
          dsl_wsp_snmp_trap_radius_query_dsc_radius_conf.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_radius_query_dsc_radius_conf.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_RADIUS_QUERY_DSC_RADIUS_CONF)-1;

          struct dsd_unicode_string dsl_wsp_snmp_trap_radius_query_dsc_error_msg;
          dsl_wsp_snmp_trap_radius_query_dsc_error_msg.ac_str = HL_WSP_SNMP_TRAP_RADIUS_QUERY_DSC_ERROR_MSG;
          dsl_wsp_snmp_trap_radius_query_dsc_error_msg.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_radius_query_dsc_error_msg.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_RADIUS_QUERY_DSC_ERROR_MSG)-1;

          // encoding data into ASN.1 format
          iml_ret = dsl_asn1.m_printf("{ist{iii{{xT}{xx}{xs}{xs}}}}",

            dsl_snmppdu.il_version,                /* i - snmp version                                 */
             &dsl_snmppdu.dsd_communityname,       /* s - comunity string                              */
             TRAPV2,                               /* t - type of snmp msg                             */
             dsl_snmppdu.il_reqid,                 /* i - request id                                   */
             dsl_snmppdu.il_errstat,               /* i - error status                                 */
             dsl_snmppdu.il_errindex,              /* i - error index                                  */
             &dsl_snmppdu.dsd_SysUpTime_oid,       /* x - VarBind 1 - OID address of sysUp time        */
             m_getsystemuptime,
             &dsl_snmppdu.dsd_snmpTrap_oid,
             &dsl_wsp_snmp_trap_radius_query,
             &dsl_wsp_snmp_trap_radius_query_dsc_radius_conf,
              &dsd_trap->dsc_radius_conf,
             &dsl_wsp_snmp_trap_radius_query_dsc_error_msg,
              &dsd_trap->dsc_error_msg);
          } break;

          case ied_wsp_snmp_trap_file_access: // File Access failed
         {
          dsd_wsp_snmp_trap_file_access* dsd_trap = reinterpret_cast<dsd_wsp_snmp_trap_file_access*>(avo_param);
          struct dsd_unicode_string dsl_wsp_snmp_trap_file_access;
          dsl_wsp_snmp_trap_file_access.ac_str = HL_WSP_SNMP_TRAP_FILE_ACCESS;
          dsl_wsp_snmp_trap_file_access.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_file_access.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_FILE_ACCESS)-1;

          struct dsd_unicode_string dsl_wsp_snmp_trap_file_access_dsc_file_name;
          dsl_wsp_snmp_trap_file_access_dsc_file_name.ac_str = HL_WSP_SNMP_TRAP_FILE_ACCESS_DSC_FILE_NAME;
          dsl_wsp_snmp_trap_file_access_dsc_file_name.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_file_access_dsc_file_name.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_FILE_ACCESS_DSC_FILE_NAME)-1;

          struct dsd_unicode_string dsl_wsp_snmp_trap_file_access_imc_errno;
          dsl_wsp_snmp_trap_file_access_imc_errno.ac_str = HL_WSP_SNMP_TRAP_FILE_ACCESS_IMC_ERRNO;
          dsl_wsp_snmp_trap_file_access_imc_errno.iec_chs_str = ied_chs_ascii_850;
          dsl_wsp_snmp_trap_file_access_imc_errno.imc_len_str = sizeof(HL_WSP_SNMP_TRAP_FILE_ACCESS_IMC_ERRNO)-1;

          // encoding data into ASN.1 format
          iml_ret = dsl_asn1.m_printf("{ist{iii{{xT}{xx}{xs}{xi}}}}",

            dsl_snmppdu.il_version,                /* i - snmp version                                 */
             &dsl_snmppdu.dsd_communityname,       /* s - comunity string                              */
             TRAPV2,                               /* t - type of snmp msg                             */
             dsl_snmppdu.il_reqid,                 /* i - request id                                   */
             dsl_snmppdu.il_errstat,               /* i - error status                                 */
             dsl_snmppdu.il_errindex,              /* i - error index                                  */
             &dsl_snmppdu.dsd_SysUpTime_oid,       /* x - VarBind 1 - OID address of sysUp time        */
             m_getsystemuptime,
             &dsl_snmppdu.dsd_snmpTrap_oid,
             &dsl_wsp_snmp_trap_file_access,
             &dsl_wsp_snmp_trap_file_access_dsc_file_name,
              &dsd_trap->dsc_file_name,
             &dsl_wsp_snmp_trap_file_access_imc_errno,
              dsd_trap->imc_errno);
          } break;

          default:
                break;
    }

	
    //Calling the function to send the SNMP message
    if (iml_ret == LASN1_SUCCESS)
    {
       m_send_snmp_trap_1(dsl_asn1.chr_buf,dsl_asn1.iml_currentpos);
       ul_requestID = (ul_requestID == 0) ? ul_requestID++ : 1;
    }
} // m_snmp_trap_1()


/**
* Get the system up time in hundredths of seconds
* @return Int (32bit)
*/
static int m_getsystemuptime()
{
	/* uncomment this and the return, if the getsystemuptime is needed
	  milliseconds to hundredths of seconds
	  HL_LONGLONG ilc_uptime = GetTickCount()/10;	
	  uptime_t sysuptime; 					
	  sysuptime.ull_uptime64 = ilc_uptime;
	*/
	return 0; //sysuptime.ds_timeparts.um_high_part;
} //m_getsystemuptime

/** -------------------------------------------
 * private class function:  dsd_asn_cl::m_potentialoverflow()
 *
 * checks iml_currentbufposition + imp_lentoinc, excessed the HL_Buffersize
 *
 * @param [in]    int iml_currentbufposition    int act as index of current next free space in the finalbuffer
 * @param [in]    int imp_lentoinc				the length of how much bytes will be inserted in the finalbuffer
 *
 * @return   int  HL_NOTOVERFLOW    no potential overfall error
 *                HL_OVERFLOW       potential overfall error
 *
 */
int dsd_asn_cl::m_potentialoverflow(int iml_currentbufposition, int imp_lentoinc)
{
	if ((iml_currentbufposition + imp_lentoinc) < HL_BUFFERSIZE)
	{	return HL_NOTOVERFLOW;
	}
	else
	{	return HL_OVERFLOW;
	}
} //m_potentialoverflow()


/** -------------------------------------------
 * class constructor: dsd_asn_cl::m_init()
 *
 * initializes the class dsd_asn_cl
 * @return      void
 */
void dsd_asn_cl::m_init()
{
    this->iml_tag		    = 0;			
	this->iml_currentpos    = 0;
	for (int iml=1; iml < HL_BUFFERSIZE; iml++)
	{
		this->chr_buf[iml]  = 0x0;
	}
	this->uml_arrayindex    = 0;
} // dsd_asn_cl::m_init()


/** -------------------------------------------
 * public class function:  dsd_asn_cl::m_printf()
 *
 * formats an ASN.1 message buffer.
 *
 * @param [in]  const char  *achp_fmt   operation format string
 *
 * @return      int   LASN1_SUCCESS     if everything is ok
 *                    LASN1_ERROR       if an error in the ASN.1 Protocol is detected
 *
 * Remarks:
 * The caller is responsible for the input parameters.
 * They are not tested for validity.
 */

int dsd_asn_cl::m_printf( const char *achp_fmt, ... )
{
    char			*achl_1; //*achl_2, *achl_3;
    int				iml_1; //, iml_2;
    int             iml_rc  (LASN1_SUCCESS);
	int  iml_int;
	struct dsd_unicode_string* ds_src;


    va_list  ava_list;
    va_start(ava_list, achp_fmt);

    for (iml_rc = LASN1_SUCCESS; *achp_fmt && iml_rc == LASN1_SUCCESS; ++achp_fmt)
    {
       switch (*achp_fmt)
       {
        case 'i':   // (i)nteger...
            // create structure with standard tag (LASN1_INTEGER), if no "usertag" was set with 't'
            iml_rc = this->m_put_int( int(va_arg(ava_list, int))/*value*/				); //, this->im_tag/*tag*/ );
            break;
        case 'n':   // (n)ull...
            // create structure with standard tag (LASN1_NULL), if no "usertag" was set with 't'
            iml_rc = this->m_put_null(				); //, this->im_tag/*tag*/ );
            break;
        case 'o':   // (o)ctet string...
            achl_1  = va_arg(ava_list, char *);   // string pointer
            iml_1   = va_arg(ava_list, int);      // string length
            iml_rc = this->m_put_octetstring( achl_1, iml_1				); //, this->im_tag/*tag*/ );
            break;
        case 's':   // (s)tring...
            // create structure with standard tag (LASN1_OCTETSTRING), if no "usertag" was set with 't'
            // achl_1  = va_arg(ava_list, char *);      // string pointer
            // iml_1   = va_arg(ava_list, int);         // string length
            // iel_chs = va_arg(ava_list, ied_charset); // string character set
			ds_src  = va_arg(ava_list, struct dsd_unicode_string*);
            iml_rc = this->m_put_string( ds_src);  //achl_1, iml_1, iel_chs				); //, this->im_tag/*tag*/ );
            break;
        case 't':   // (t)ag for the next element...
            this->iml_tag = va_arg(ava_list, unsigned int);
            this->im_usertag = 1;
            break;
        case '{':   // begin sequence...
            // create structure with standard tag (LASN1_SEQUENCE), if no "usertag" was set with 't'
            iml_rc = this->m_start_seq( this->iml_tag );
            break;
        case '}':   // end sequence...
            // close structure and calculate length of all elements
            iml_rc = this->m_end_seq();
            break;
        case 'x':   // OID
			//achl_1  = va_arg(ava_list, char *);      // string pointer
            //iml_1   = va_arg(ava_list, int);         // string length
            //iel_chs = va_arg(ava_list, ied_charset); // string character set
            ds_src  = va_arg(ava_list, struct dsd_unicode_string*);
			iml_rc = this->m_put_oid(  ds_src);  //achl_1, iml_1, iel_chs				); //, this->im_tag/*tag*/ );
			break;
		case 'T':
			iml_int = int(va_arg(ava_list, int));
			iml_rc = this->m_put_timetick( iml_int/*value*/);// this->im_tag/*tag*/ );
			break;
		default:   // no support for all other functions...
            iml_rc = LASN1_ERROR;
            break;
      } // switch()
	}
    va_end( ava_list );
    return iml_rc;
} // dsd_asn_cl::m_printf()


/** -------------------------------------------
 * private class function:  dsd_asn_cl::m_put_tag()
 *
 * writes an ASN.1-tag in network byte order
 *
 * @param [in]    int   imp_tag     tag bytes
 * @param [in]    int   imp_taglen  number of tag bytes
 *
 * @return   int  LASN1_SUCCESS    if everything is ok
 *                LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:
 * The caller is responsible for the input parameters.
 * They are not tested for validity.
 */
int dsd_asn_cl::m_put_tag( int imp_tag, int imp_taglen )
{
    unsigned char  chrl_nettag[sizeof(int)];

    for (int iml_1 = 0; iml_1 < imp_taglen; ++iml_1)
    {  // build network byte order
        chrl_nettag[(sizeof(unsigned int)-1) - iml_1] = (unsigned char)(imp_tag & 0xffU);
        imp_tag >>= 8;
    }	
	
	if (m_potentialoverflow(this->iml_currentpos, imp_taglen)!= HL_NOTOVERFLOW)	
	    return LASN1_ERROR;
	else
	{    ::memcpy( (void *)(chr_buf + this->iml_currentpos), (const void *)&chrl_nettag[sizeof(int) - imp_taglen], size_t(imp_taglen) );	
	    return LASN1_SUCCESS;
	}

} // dsd_asn_cl::m_put_tag()


/** -------------------------------------------
 * private class function:  dsd_asn_cl::m_put_len()
 *
 * writes an ASN.1-length in network byte order
 *
 * @param [in]    int   imp_len     length bytes
 * @param [in]    int   imp_lenlen  number of length bytes
 * @param [in]    char *achp_buf    destination buffer to write
 *
 * @return   int  LASN1_SUCCESS    if everything is ok
 *                LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:
 * The caller is responsible for the input parameters. They are not tested for
 * validity.
 */
int dsd_asn_cl::m_put_len( int imp_len, int imp_lenlen)
{
    unsigned char chrl_netlen[sizeof(int)];

    // short len if it's less than 128 - one byte with 8th bit =0
    if (imp_lenlen == 1)
	{
	    if (m_potentialoverflow(iml_currentpos, imp_lenlen)!= HL_NOTOVERFLOW)
		    return LASN1_ERROR;
		else
	        this->chr_buf[iml_currentpos] = BYTE(imp_len);	
	}
    else
    {   // long length. 8th bit set to 1, then it gives the length of the length
        // then the next bytes are the actual length
        --imp_lenlen;
	
	    if (m_potentialoverflow(this->iml_currentpos, imp_lenlen)!= HL_NOTOVERFLOW)
	        return LASN1_ERROR;
	    else
		    this->chr_buf[iml_currentpos] = char(0x80 | imp_lenlen);

        // write length bytes in network byte order...
        for (int inl_1 = 0; inl_1 < imp_lenlen; ++inl_1)
        {  // build network byte order
           chrl_netlen[(sizeof(unsigned int)-1) - inl_1] = (unsigned char)(imp_len & 0xffU);
           imp_len >>= 8;
        }

	   if (m_potentialoverflow(this->iml_currentpos, imp_lenlen)!= HL_NOTOVERFLOW)
		   return LASN1_ERROR;
	   else
		   ::memcpy((void *)(this->chr_buf + this->iml_currentpos), (const void *)&chrl_netlen[sizeof(int) - imp_lenlen], imp_lenlen );
    }
    return LASN1_SUCCESS;
}

/** -------------------------------------------
 * private class function:  dsd_asn_cl::m_put_len()
 *
 * writes an ASN.1-length in network byte order
 *
 * @param [in]    int   imp_len     length bytes
 * @param [in]    int   imp_lenlen  number of length bytes
 * @param [in]    char *achp_buf    destination buffer to write
 *
 * @return   int  LASN1_SUCCESS    if everything is ok
 *                LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:
 * The caller is responsible for the input parameters. They are not tested for
 * validity.
 */
int dsd_asn_cl::m_put_len( int imp_len, int imp_lenlen, int imp_bufferloc)
{
    unsigned char chrl_netlen[sizeof(int)];

    // short len if it's less than 128 - one byte giving the len, with bit 8=0
    if (imp_lenlen == 1)
	{
		if (m_potentialoverflow(this->iml_currentpos, imp_lenlen)!= HL_NOTOVERFLOW)
		    return LASN1_ERROR;
	    else
			this->chr_buf[imp_bufferloc] = BYTE(imp_len);
		//to set the 8-bit, thus meaning that there is a series of bytes following representing the lenght
		//+HL_SEQLEN_MAXSIZE, due to the fixed number of length of length.
		
		if (m_potentialoverflow(this->iml_currentpos, imp_lenlen)!= HL_NOTOVERFLOW)
		     return LASN1_ERROR;
	    else
		     this->chr_buf[imp_bufferloc-3] += 0x80 + HL_SEQLEN_MAXSIZE;			
		
	}
    else
    { // long length. 8th bit set to 1, then it gives the length of the length
      // then the next bytes are the actual length
      --imp_lenlen;
      //this->chr_buf[imp_bufferloc] = char(0x80 | imp_lenlen);
      // write length bytes in network byte order...
      for (int inl_1 = 0; inl_1 < imp_lenlen; ++inl_1)
      {  // build network byte order
         chrl_netlen[(sizeof(unsigned int)-1) - inl_1] = (unsigned char)(imp_len & 0xffU);
         imp_len >>= 8;
      }
	  // this->chr_buf + imp_bufferloc - (imp_lenlen-1) = moves the position on which to
	  // write to the bufferloc (end of length), reduce from it, the length of length -1.
	
	   if (m_potentialoverflow(this->iml_currentpos, imp_lenlen)!= HL_NOTOVERFLOW)
		     return LASN1_ERROR;
	  else
	      ::memcpy( (void *)(this->chr_buf + imp_bufferloc - (imp_lenlen-1)), (const void *)&chrl_netlen[sizeof(int) - imp_lenlen], imp_lenlen );
	  		
	  //to set the 8-bit, thus meaning that there is a series of bytes following representing the lenght
	  //+HL_SEQLEN_MAXSIZE, due to the fixed number of length of length.
	
	   this->chr_buf[imp_bufferloc - HL_SEQLEN_MAXSIZE] += 0x80 + HL_SEQLEN_MAXSIZE ;		
    }
	    return LASN1_SUCCESS;
}

/** -------------------------------------------
 * private class function:  dsd_asn_cl::m_put_int()
 *
 * sets an integer in ASN.1-notation
 *
 * @param [in]    int   imp_int    value bytes
 * @param [in]    int   imp_tag    tag byte (LASN1_INTEGER or usertag)
 *
 * @return   int  LASN1_SUCCESS    if everything is ok
 *                LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:
 * The caller is responsible for the input parameters. They are not tested for
 * validity.
 */

int dsd_asn_cl::m_put_int( int imp_int/*value*/          ) //, int imp_tag/*tag*/ )
{
    int            iml_1;               // work variable
    int            iml_taglen, iml_lenlen,iml_len ;
    unsigned int   uml_int, uml_mask;
    unsigned char  chrl_netval[sizeof(int)];
		
    // calculate length of integer value...
    uml_int = imp_int;    // bit fiddling should be done with unsigned values
    // look for first non-all-one byte...
    for (iml_1 = sizeof(int) - 1; iml_1 > 0; --iml_1)
    {  uml_mask = ((unsigned int)0xffU << (iml_1 * 8));
       if (imp_int < 0 /*signed?*/)
       {  // not all ones
          if ((uml_int & uml_mask) != uml_mask)  break;
       }
       else
       { // not all zero
         if (uml_int & uml_mask)  break;
	   }
	}
    // we now have the "leading byte". if the high bit on this byte matches the sign bit,
    // we need to "back up" a byte.
    uml_mask = uml_int & ((unsigned int)0x80U << (iml_1 * 8));
    if ((uml_mask && !(imp_int < 0/*signed?*/)) || ((imp_int < 0/*signed?*/) && !uml_mask))
      ++iml_1;

    // calculate the length of the tag and the length of the length...
	iml_len = iml_1 + 1 ;
    iml_taglen = this->m_calc_taglen( LASN1_INTEGER );
    iml_lenlen = this->m_calc_lenlen( iml_len);

    // write TLV...
	if (this->m_put_tag( LASN1_INTEGER, iml_taglen) == LASN1_ERROR)
		return LASN1_ERROR;
	else
		iml_currentpos += iml_taglen;
	
	if (this->m_put_len( iml_1+1, iml_lenlen) == LASN1_ERROR)
		return LASN1_ERROR;
	else
		iml_currentpos += iml_lenlen;

    for (iml_1 = 0; iml_1 < iml_len; ++iml_1)
    {  // build network byte order
		chrl_netval[(sizeof(unsigned int)-1) - iml_1] = (unsigned char)(uml_int & 0xffU);
       uml_int >>= 8;
    }
	
	 if (m_potentialoverflow(this->iml_currentpos, iml_len) != HL_NOTOVERFLOW)
		 return LASN1_ERROR;
	 else
		 ::memcpy( (void *)(this->chr_buf + this->iml_currentpos), (const void *)&chrl_netval[sizeof(int) - iml_len], iml_len );
   	//move position in buffer - depends on length of value
	iml_currentpos += iml_len;

	return LASN1_SUCCESS;
} // dsd_asn_cl::m_put_int()


/** -------------------------------------------
 * private class function:  dsd_asn_cl::m_put_int()
 *
 * sets an integer in ASN.1-notation
 *
 * @param [in]    int   imp_int    value bytes
 * @param [in]    int   imp_tag    tag byte (LASN1_INTEGER or usertag)
 *
 * @return   int  LASN1_SUCCESS    if everything is ok
 *                LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:
 * The caller is responsible for the input parameters. They are not tested for
 * validity.
 */

int dsd_asn_cl::m_put_timetick( int imp_int/*value*/          ) //, int imp_tag/*tag*/ )
{
    int            iml_1;               // work variable
    int            iml_taglen, iml_lenlen,iml_len ;
    unsigned int   uml_int, uml_mask;
    unsigned char  chrl_netval[sizeof(int)];
		
    // calculate length of integer value...
    uml_int = imp_int;    // bit fiddling should be done with unsigned values
    // look for first non-all-one byte...
    for (iml_1 = sizeof(int) - 1; iml_1 > 0; --iml_1)
    {  uml_mask = ((unsigned int)0xffU << (iml_1 * 8));
       if (imp_int < 0 /*signed?*/)
       {  // not all ones
          if ((uml_int & uml_mask) != uml_mask)  break;
       }
       else
       { // not all zero
         if (uml_int & uml_mask)  break;
	   }
	}
    // we now have the "leading byte". if the high bit on this byte matches the sign bit,
    // we need to "back up" a byte.
    uml_mask = uml_int & ((unsigned int)0x80U << (iml_1 * 8));
    if ((uml_mask && !(imp_int < 0/*signed?*/)) || ((imp_int < 0/*signed?*/) && !uml_mask))
      ++iml_1;

    // calculate the length of the tag and the length of the length...
	iml_len = iml_1 + 1 ;
    iml_taglen = this->m_calc_taglen( LASN1_TIMETICK );
    iml_lenlen = this->m_calc_lenlen( iml_len);

    // write TLV...
    if (this->m_put_tag( LASN1_TIMETICK, iml_taglen) == LASN1_ERROR)
		return LASN1_ERROR;
	else
		iml_currentpos += iml_taglen;

	if (this->m_put_len( iml_1+1, iml_lenlen)== LASN1_ERROR)
		return LASN1_ERROR;
	else	
		iml_currentpos += iml_lenlen;

    for (iml_1 = 0; iml_1 < iml_len; ++iml_1)
    {  // build network byte order
		chrl_netval[(sizeof(unsigned int)-1) - iml_1] = (unsigned char)(uml_int & 0xffU);
       uml_int >>= 8;
    }

	 if (m_potentialoverflow(this->iml_currentpos, iml_len)!= HL_NOTOVERFLOW)
		 return LASN1_ERROR;
	 else
		 ::memcpy( (void *)(this->chr_buf + this->iml_currentpos), (const void *)&chrl_netval[sizeof(int) - iml_len], iml_len );
   	//move position in buffer - depends on length of value
	iml_currentpos += iml_len;

	return LASN1_SUCCESS;
} // dsd_asn_cl::m_put_int()


/** -------------------------------------------
 * private class function:  dsd_asn_cl::m_put_null()
 *
 * sets a null in ASN.1-notation
 *
 * @param [in]    int   imp_tag    tag byte (LASN1_NULL or usertag)
 *
 * @return   int  LASN1_SUCCESS    if everything is ok
 *                LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:
 * The caller is responsible for the input parameters. They are not tested for
 * validity.
 */
int dsd_asn_cl::m_put_null(     )    // int imp_tag )
{
    int  iml_taglen;
    int  iml_lenlen;

	// calculate the length of the tag and the length of the length...
    iml_taglen = this->m_calc_taglen( LASN1_NULL );
    iml_lenlen = this->m_calc_lenlen( 0 ); // value is 0, thus length of value is 0

    // write tlv...
	if (this->m_put_tag( LASN1_NULL, iml_taglen)== LASN1_ERROR)
		return LASN1_ERROR;
	else
		iml_currentpos += iml_taglen;
    	
	if (this->m_put_len( 0, iml_lenlen)== LASN1_ERROR)
		return LASN1_ERROR;
	else	
		iml_currentpos += iml_lenlen;

    return LASN1_SUCCESS;

} // dsd_asn_cl::m_put_null()

/** -------------------------------------------
 * private class function:  dsd_asn_cl::m_put_string()
 *
 * sets an octet string in ASN.1-notation, the string is translated in UTF-8.
 *
 * @param [in]    struct dsd_unicode_string   (which have the string bytes, string length and string charset)
  *
 * @return   int  LASN1_SUCCESS    if everything is ok
 *                LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:
 * MSAD uses a quoted unicode-16 little endian string for the password modification,
 * we must copy this without any changes!
 * The caller is responsible for the input parameters. They are not tested for
 * validity.
 */
int dsd_asn_cl::m_put_string( struct dsd_unicode_string  *ds_src)     //char *astrp_str, int imp_len, ied_charset iep_chs_src)    //, int imp_tag )
{
    int         iml_taglen, iml_lenlen, iml_len;

	//struct dsd_unicode_string   ds_src;	
	//ds_src.ac_str = astrp_str;
	//ds_src.iec_chs_str = iep_chs_src;
	//ds_src.imc_len_str = imp_len;

	if (ds_src->imc_len_str && ds_src->iec_chs_str != ied_chs_utf_8 && ds_src->iec_chs_str != ied_chs_le_utf_16)
    {
		iml_len = ::m_len_vx_ucs( ied_chs_utf_8, ds_src );
        //iml_len = ::m_len_vx_vx( ied_chs_utf_8, (void *)astrp_str, int(imp_len), iep_chs_src );
	    if (iml_len == -1)
		  // error, invalid string format...
		return LASN1_ERROR;
    }
	else
	{	// calculate length of the string...
		iml_len = (ds_src->imc_len_str < 0) ? (int)::strlen( (const char *)ds_src->ac_str ) : ds_src->imc_len_str;
	}

    // calculate the length of the tag and the length of the length...
    iml_taglen = this->m_calc_taglen( LASN1_OCTETSTRING );
    iml_lenlen = this->m_calc_lenlen( iml_len );

    // write TLV...

    if (this->m_put_tag( LASN1_OCTETSTRING, iml_taglen) == LASN1_ERROR)
		return LASN1_ERROR;
	else
		iml_currentpos += iml_taglen;

	if (this->m_put_len( iml_len, iml_lenlen) == LASN1_ERROR)	
		return LASN1_ERROR;
	else
	iml_currentpos += iml_lenlen;

    if (iml_len)
    { // translation to UTF-8 (if necessary)...
      if (ds_src->iec_chs_str != ied_chs_utf_8 && ds_src->iec_chs_str != ied_chs_le_utf_16)
        // translation to UTF-8...
        if (m_potentialoverflow(this->iml_currentpos, iml_len)!= HL_NOTOVERFLOW)
		  return LASN1_ERROR;
		else
		{
		   ::m_cpy_vx_ucs( (void *)(this->chr_buf + this->iml_currentpos), iml_len, ied_chs_utf_8, ds_src );
		}
      else
	  {
		if (m_potentialoverflow(this->iml_currentpos, iml_len)!= HL_NOTOVERFLOW)
		  return LASN1_ERROR;
		else
			::memcpy( (void *)(this->chr_buf + this->iml_currentpos), (const void *)ds_src->ac_str, size_t(iml_len) );
	  }
    }

	iml_currentpos += iml_len;

    return LASN1_SUCCESS;

} // dsd_asn_cl::m_put_string()


/** -------------------------------------------
 * private class function:  dsd_asn_cl::m_put_octetstring()
 *
 * sets an octet string in ASN.1-notation w/o any translation.
 *
 * @param [in]    char       *astrp_str    string bytes
 * @param [in]    int         imp_len      string length
 * @param [in]    int         imp_tag      tag byte (LASN1_OCTETSTRING or usertag)
 *
 * @return   int  LASN1_SUCCESS    if everything is ok
 *                LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:
 * The caller is responsible for the input parameters. They are not tested for
 * validity.
 */
int dsd_asn_cl::m_put_octetstring( char *astrp_str, int imp_len) //, int imp_tag )
{
    int  iml_taglen;
    int  iml_lenlen;

    // we need a valid length of the string...
    if (imp_len < 0 || imp_len == 0)
      return LASN1_ERROR;

    // calculate the length of the tag and the length of the length...
    iml_taglen = this->m_calc_taglen( LASN1_OCTETSTRING );
    iml_lenlen = this->m_calc_lenlen( imp_len);

    // write TLV...
    if (this->m_put_tag( LASN1_OCTETSTRING, iml_taglen) == LASN1_ERROR)
		return LASN1_ERROR;
	else
		iml_currentpos += iml_taglen;
	if (this->m_put_len( imp_len, iml_lenlen) == LASN1_ERROR)
		return LASN1_ERROR;
	else
		iml_currentpos += iml_lenlen;

	if (m_potentialoverflow(this->iml_currentpos, imp_len)!= HL_NOTOVERFLOW)
		 return LASN1_ERROR;
	else
		::memcpy( (void *)(this->chr_buf + this->iml_currentpos), (const void *)astrp_str, imp_len) ;
	
	iml_currentpos += imp_len;
    return LASN1_SUCCESS;
} // dsd_asn_cl::m_put_octetstring()

///** -------------------------------------------
// * private class function:  dsd_asn_cl::m_calc_lenlen()
// *
// * calculate the length of the length bytes in the TLV
// *
// * @param [in]    int   imp_len    length value
// *
// * @return   int  number of bytes in asn.1-length notation
// *
// * Remarks:
// * The caller is responsible for the input parameters. They are not tested for
// * validity.
// */
int dsd_asn_cl::m_calc_lenlen( int imp_len )
{
    //  short length, if it's less than 128 - one byte giving the len, with bit 8=0
    if (imp_len <= (unsigned int)0x7FU)  return 1;

    // long length otherwise - one byte with bit 8 set, giving the length of the length,
    // followed by the length itself
    if (imp_len <= (unsigned int)0xffU)     return 2;
    if (imp_len <= (unsigned int)0xffffU)   return 3;
    if (imp_len <= (unsigned int)0xffffffU) return 4;
    return 5;

} // dsd_asn_cl::m_calc_lenlen()

/** -------------------------------------------
 * private class function:  dsd_asn_cl::m_calc_taglen()
 *
 * calculate the length of the tag bytes in the TLV
 *
 * @param [in]    int   imp_len    tag value
 *
 * @return   int  number of bytes  if everything is ok
 *                LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 * Remarks:
 * The caller is responsible for the input parameters. They are not tested for
 * validity.
 */
int dsd_asn_cl::m_calc_taglen( int imp_tag )
{
    int          iml_1;
    unsigned int uml_mask;

    // find the first non-all-zero byte in the tag..
    for (iml_1 = sizeof(unsigned int) - 1; iml_1 > 0; --iml_1)
    {  uml_mask = ((unsigned int)0xffU << (iml_1 * 8));
       if (imp_tag & uml_mask)
         break;
    }
    return iml_1 + 1;

} // dsd_asn_cl::m_calc_taglen()

/** -------------------------------------------
 * private class function:  dsd_asn_cl::m_start_seq()
 *
 * sets the SEQUENCE_OF tag
 *
 * @param [in]    int  imp_tag    tag byte (LASN1_SEQUENCE or usertag)
 *
 * @return   int  LASN1_SUCCESS   if everything is ok
 *                LASN1_ERROR     if an error in the ASN.1 Protocol is detected
 *
 * Remarks:
 * The caller is responsible for the input parameters. They are not tested for
 * validity.
 */

int dsd_asn_cl::m_start_seq( int imp_tag )
{	
	int iml_lenlen = HL_SEQLENLEN_MAXSIZE;		
	if (uml_arrayindex < HL_MAX_AMT_SEQ)				
		umlr_seqsPos[uml_arrayindex] = iml_currentpos + iml_lenlen;
	else
		return LASN1_ERROR;
	uml_arrayindex++;

	// write TLV...
	imp_tag  =  (imp_tag == 0) ? LASN1_SEQUENCE : imp_tag;

	if (this->m_put_tag( imp_tag, 1) == LASN1_ERROR)
		return LASN1_ERROR;
	else
	{	
		iml_currentpos += 1;
		//make space for length in buffer
		iml_currentpos += iml_lenlen;
		//restore im_tag to 0
		iml_tag = 0;
		return LASN1_SUCCESS;
	}
} // dsd_asn_cl::m_start_seq()


/** -------------------------------------------
 * private class function:  dsd_asn_cl::m_end_seq()
 *
 * ends the SEQUENCE_OF tag and calculate the length of all elements
 *
 * @param [in]    none
 *
 * @return   int  LASN1_SUCCESS   if everything is ok
 *                LASN1_ERROR     if an error in the ASN.1 Protocol is detected
 *
 * Remarks:
 * The caller is responsible for the input parameters. They are not tested for
 * validity.
 */
int dsd_asn_cl::m_end_seq()
{
	int iml_lenofseq = this->iml_currentpos-1 - (umlr_seqsPos[uml_arrayindex-1]); //-1 to avoid couting the position of the length itself
	int iml_lenlen = m_calc_lenlen(iml_lenofseq);	
	this->m_put_len( iml_lenofseq, iml_lenlen, umlr_seqsPos[uml_arrayindex-1]);
	uml_arrayindex--;

    return LASN1_SUCCESS;
} // dsd_asn_cl::m_end_seq()



/** -------------------------------------------
 * A sinmple Power function, instead of using Math.h
 *
 * @param [in]    int      imp_base      the number to be powered
 * @param [in]    int      imp_power     the exponent
 *
 * return		  int	   value of power.
*/

static int power(int imp_base, int imp_power)
{
	int iml_ans = 1;
	for(int iml1 = 1; iml1 <= imp_power; iml1++)
    iml_ans = iml_ans * imp_base;
	return iml_ans;
}
// power()

/** -------------------------------------------
 * private class function:  dsd_asn_cl::m_put_oid()
 *
 * sets an octet string (representing an OID. eg. "1.3.6.1.1636") in ASN.1-notation, the string is translated in UTF-8.
 *
 * @param [in]    struct dsd_unicode_string   (which have the string bytes, string length and string charset)
 *
 * @return   int  LASN1_SUCCESS    if everything is ok
 *                LASN1_ERROR      if an error in the ASN.1 Protocol is detected
 *
 */
int dsd_asn_cl::m_put_oid(struct dsd_unicode_string *ds_src) // char *astrp_str, int imp_len , ied_charset iep_chs_src)   //, int imp_tag )
{
	///-----------------------
	// Encoding OID code:
	///-----------------------
	int iml_len_of_str_array;

	long unsigned int umlr_oid[HL_INT_OID_MAXSIZE]	;	
	byte umlr_byte_oid[HL_BYTE_OID_MAXSIZE]	;	
	char chr_str_utf_oid[HL_STR_OID_MAXSIZE];

	/* Checks the proper legth according to the required character set
	   translation to the required character set if required.			*/
	if (ds_src->imc_len_str && ds_src->iec_chs_str != ied_chs_utf_8)
    {
       iml_len_of_str_array = ::m_len_vx_ucs( ied_chs_utf_8, ds_src );
       if ((iml_len_of_str_array == -1) || (iml_len_of_str_array > HL_STR_OID_MAXSIZE))
          // error, invalid string format...
          return LASN1_ERROR;
       else
		  ::m_cpy_vx_ucs( (void *)(chr_str_utf_oid), iml_len_of_str_array, ied_chs_utf_8,	ds_src );
	}
	else
	{	// calculate length of the string...
		int iml_len_of_str_array  = (ds_src->imc_len_str < 0) ? (int)::strlen( (const char *)ds_src->ac_str ) : ds_src->imc_len_str;
		if (iml_len_of_str_array > HL_STR_OID_MAXSIZE)
		   return LASN1_ERROR;
		else
		   ::memcpy( (void *)(chr_str_utf_oid),(const void *)(ds_src->ac_str), size_t(iml_len_of_str_array));	
	}
	
	chr_str_utf_oid[iml_len_of_str_array] = '\0';

    /* Tokensize the String OID */
	int iml_len_of_int_array = 0;			// length of umlr_oid[] array
	int iml_num_to_input     = 0;           // the integer to be inputted in the array of integers
	int iml_digit_num        = 0;           // number of digits.
	int iml_string_pos		 = 0;           // currentpositio in str_utf_oid
	int iml_power2;

	//the null character must be loop as well
	while (iml_string_pos <= iml_len_of_str_array)
    //while (chr_str_utf_oid[iml_string_pos] != '\0')
	{	
		if  (chr_str_utf_oid[iml_string_pos] >= '0' && chr_str_utf_oid[iml_string_pos] <= '9')
		{	
			iml_num_to_input = (chr_str_utf_oid[iml_string_pos] & 0x0F) + (iml_num_to_input* power(10,1));
			iml_digit_num++;
		}
		// if 'dot' or 'null character', since an oid can be written without the ending 'dot'.
		else if (chr_str_utf_oid[iml_string_pos] == '.' || chr_str_utf_oid[iml_string_pos] == '\0')		
		{				
			umlr_oid[iml_len_of_int_array++] = iml_num_to_input;	
			iml_digit_num = 0;
			iml_num_to_input = 0;
		}
		else
		   // invalid character found!
		   return LASN1_ERROR;
		
		// step to the next...
	    iml_string_pos++;
	};

	
    /* Looping through umlr_oid's integers to encode them into ASN    */
    if (iml_len_of_int_array > HL_INT_OID_MAXSIZE)
	  return LASN1_ERROR;

	// Integrating the first 2 numbers, as required by OID encoding
	umlr_oid[1] = 40 * umlr_oid[0] + umlr_oid[1];
	// Used as a counter to get the lenOfIntArray; Starts from 1, since element 0 is not needed
	int iml1 = 1;			
	// used as a counter for the length of umlr_byte_oid[] array
	int iml_len_of_byte_array = 0;			
	unsigned long int iml_no1, iml_no2;
	int iml_noofbytes;
	int iml2;

	while (iml1 != iml_len_of_int_array)
	{		
		if (umlr_oid[iml1] <= 127)
		{	
		    umlr_byte_oid[iml_len_of_byte_array] = (unsigned char)umlr_oid[iml1];	
			iml_len_of_byte_array++;
		} //end if
		else                                //support until the max size of unsigned long int
		{
			iml_no1 = umlr_oid[iml1];
			iml_noofbytes = 0;
			//calculate of number of bytes required to represent the number
			while (iml_no1 > 127)
			{
				iml_no1 /= 127;
				iml_noofbytes++;
			}			
			//write first byte
			umlr_byte_oid[iml_len_of_byte_array] = (unsigned char)(umlr_oid[iml1] / power(128,iml_noofbytes));
			umlr_byte_oid[iml_len_of_byte_array] += 0x80;
			iml_len_of_byte_array++;

			//remaining bytes
			iml_no1 = umlr_oid[iml1];
			iml_no2 = 0;			
			iml_power2 = 0;

			for (iml2 = iml_noofbytes ; iml2 >= 1 ; iml2--)
			{	
				iml_power2 = power(128,iml2) * (umlr_byte_oid[iml_len_of_byte_array-1]- 0x80);					
				iml_no1 = iml_no1 - iml_power2;
				iml_no2 = (iml_no1/power(128,iml2-1));
				//if not last byte to be written, add 0x80
				if (iml2 != 1)
				  iml_no2 += 0x80;				
				umlr_byte_oid[iml_len_of_byte_array] = (unsigned char)iml_no2;
				iml_len_of_byte_array++;						
			}		
		} //end elseif
		//increase counter. meaning that an element in the im_rl_oid was converted, and the next one can be processed
		iml1++;
	} //end while
	
	///------------
    /// end of OID encoding code
	///------------
	
    ///------------
	// Writing TLV
	///------------

	// calculate the length of the tag, and write Tag
	int iml_tag = LASN1_OID;
    int iml_taglen = this->m_calc_taglen( iml_tag );
  	
	if (this->m_put_tag( iml_tag, iml_taglen) == LASN1_ERROR)
		return LASN1_ERROR;
	else
		iml_currentpos += iml_taglen;

	// calc length of length, and write  length
	int iml_lenlen = this->m_calc_lenlen( iml_len_of_byte_array );
	if (this->m_put_len( iml_len_of_byte_array, iml_lenlen) == LASN1_ERROR)
		return LASN1_ERROR;
	else
		iml_currentpos += iml_lenlen;

	// OID's length was calculated in the OID encoding part
	// Writing the used part of array umlr_byte_oid in the finalbuffer			
	if (m_potentialoverflow(this->iml_currentpos, iml_len_of_byte_array)!= HL_NOTOVERFLOW)
		 return LASN1_ERROR;
	else
		::memcpy((void *)(this->chr_buf + this->iml_currentpos), umlr_byte_oid, iml_len_of_byte_array);

	iml_currentpos +=iml_len_of_byte_array;
    return LASN1_SUCCESS;

} // dsd_asn_cl::m_put_oid()


