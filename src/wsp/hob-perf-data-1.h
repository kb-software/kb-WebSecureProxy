/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROJECT: general                                                  |*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-perf-data-1.h                                   |*/
/*| -------------                                                     |*/
/*|  Load balancing module to collect system data and to calculate    |*/
/*|  the system load according to a specified formula.				  |*/
/*|																	  |*/
/*|	HEADER FILES (files that have to be included in the main source)  |*/
/*| -------------                                                     |*/
/*|	general: iostream        										  |*/
/*| Linux: xercesc/dom/DOMNode.hpp									  |*/
/*|	Windows: wbemcli.h											      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009									  |*/
/*|  Copyright (C) HOB Germany 2010									  |*/
/*|  Copyright (C) HOB Germany 2011									  |*/
/*|  Copyright (C) HOB Germany 2012									  |*/
/*|                                                                   |*/
/*|  19.10.12 Andre Eberwien                                          |*/
/*+-------------------------------------------------------------------+*/

#ifndef _HOB_PERF_DATA_1_H
#define _HOB_PERF_DATA_1_H
typedef unsigned long long ull;

#ifdef HL_LINUX

#ifndef DEF_HL_INCL_DOM
enum ied_hlcldom_def { ied_hlcldom_invalid,  /* invalid function       */
                       ied_hlcldom_get_first_child,  /* getFirstChild() */
                       ied_hlcldom_get_next_sibling,  /* getNextSibling() */
                       ied_hlcldom_get_node_type,  /* getNodeType()    */
                       ied_hlcldom_get_node_value,  /* getNodeValue()  */
                       ied_hlcldom_get_node_name  /* getNodeName()     */
};
#endif



struct dsd_qload1_contr_1 {                 /* control field           */
#ifdef HOBXERCES
   int (* amc_display) ( char *, int );     /* display ASCII           */
   int (* amc_get_no_user) ( void );        /* return current number of users */
   void* (* amc_call_dom) ( DOMNode *, ied_hlcldom_def );  /* call DOM */
   DOMNode* adsc_node_conf;              /* part of configuration   */
#endif
  
};

#endif

// structure of the load value for each parameter. Relative parameters have a value between 0 and 10000,
// absolute parameters have their absolute value per secons.
// The index of the arrays mean the following:
//	0	load in the last minute
//	1	load in the last 5 minutes
//	2	load in the last 10 minutes
//	3	load in the last 15 minutes
//	4	load in the last 30 minutes
struct dsd_server_load
{
	#ifdef HL_FREEBSD
	unsigned int umrl_ints[5];
	unsigned int umrl_memory[5];
	unsigned int umrl_cpu[5];
	unsigned int umrl_ctx_swtch[5];
	unsigned int umrl_cache_misses[5];
	unsigned int umrl_cache_hit_rate[5];
	unsigned int umrl_swapins[5];
	unsigned int umrl_swapouts[5];
	unsigned int umrl_swaptotal[5];
	unsigned int umrl_pageins[5];
	unsigned int umrl_pageouts[5];
	unsigned int umrl_pagetotal[5];
	unsigned int umrl_swap_usage[5];
	unsigned int umrl_threads[5];
	unsigned int umrl_processes[5];
	unsigned int umrl_proc_memory[5];
	unsigned int umrl_proc_pg_fault[5];
	unsigned int umrl_proc_io_read[5];
	unsigned int umrl_proc_io_write[5];
	unsigned int umrl_proc_threads[5];
	unsigned int umrl_proc_utime[5];
	unsigned int umrl_proc_stime[5];
	unsigned int umrl_proc_totaltime[5];
	unsigned int umrl_proc_ctx_invol[5];
	unsigned int umrl_proc_ctx_vol[5];
	unsigned int umrl_proc_cpu[5];
	

	ull ulc_memory;
	ull uhl_proc_threads_cur;
	ull uhl_proc_page_faults_tot;
	ull uhl_proc_io_read_tot;
	ull uhl_proc_io_write_tot;
	ull uhl_proc_user_time;
	ull uhl_proc_system_time;
	ull ulc_cpu_total_time;
	ull uhl_proc_ctx_invol;
	ull uhl_proc_ctx_vol;

	#endif

	#ifdef HL_LINUX
	unsigned int umrl_hd_usage[5];		// hard disk usage (R)
	unsigned int umrl_hd_read[5];		// hard disk I/O (only reading) (A) in Bytes per second
	unsigned int umrl_hd_write[5];		// hard disk I/O (only writing) (A) in Bytes per second
	unsigned int umrl_io_act[5];	// total I/O activity (A) in Bytes per second
	unsigned int umrl_io_time[5];		// time spent for I/O operations (R) in %
	unsigned int umrl_process[5];		// number of processes (A)
	unsigned int umrl_init_process[5];	// number of new processes (A) in new processes per minute
	unsigned int umrl_memory[5];			// memory usage (RAM) (R) in %
	unsigned int umrl_page_util[5];		// swap usage (equal to Pagefile usage in ibpmon01) (R) in %
	unsigned int umrl_page_read[5];		// pageins (A) in pageins per secons
	unsigned int umrl_page_write[5];		// pageouts (A) in pageouts per second
	unsigned int umrl_page_total[5];		// total paging activity (A) in paging activities per second
	unsigned int umrl_swap_read[5];		// swapins (A) in swapped pageins per second
	unsigned int umrl_swap_write[5];		// swapouts (A) in swapped pageouts per second
	unsigned int umrl_swap_act[5];		// total swapping activity (A) in swapped paging activities per second
	unsigned int umrl_min_pg_fault[5];	// minor page faults (without swapping -> results in paging activity) (A) in page faults per second
	unsigned int umrl_maj_pg_fault[5];	// major page faults (with swapping -> results in swapping activity)  (A) in page faults per second
	unsigned int umrl_nic_recv[5];		// network receptions (R) in % of bandwidth
	unsigned int umrl_nic_send[5];		// network transmissions (R) in % of bandwidth
	unsigned int umrl_nic_total[5];		// total network activity (R) in % of bandwidth
	unsigned int umrl_cpu[5];			// cpu load (R) in %
	unsigned int umrl_ints[5];			// interrupts (A) in interrupts per second
	unsigned int umrl_ctx[5];			// context switches (A) in context switches per second
	unsigned int umrl_cpu_proc[5];		// cpu utilization of the main process (R) in %
	
	ull uhl_proc_virt_memory;
	ull uhl_proc_cpu_time;
	ull uhl_proc_io_ops;
	ull uhl_proc_io_bytes;
	
	#endif /* HL_LINUX */

	#ifdef HL_WINALL1
	unsigned int umrl_cache_hit[5];		// cache hit rate (R)
	unsigned int umrl_cache_miss[5];		// cache misses per second (A)
	unsigned int umrl_cpu[5];			// cpu load (R)
	unsigned int umrl_ctx[5];			// context switches per second(A)
	unsigned int umrl_hd_usage[5];		// hard disk utilization of all local drives (R)
	unsigned int umrl_hd_bpr[5];			// Bytes per read during disk activity (A)
	unsigned int umrl_hd_bpw[5];			// Bytes per write during disk activity (A)
	unsigned int umrl_hd_bpt[5];			// Bytes per transfer during disk activity (A)
	unsigned int umrl_hd_read[5];		// HD reading activity in Bytes per second (A)
	unsigned int umrl_hd_write[5];		// HD writing activity in Bytes per second (A)
	unsigned int umrl_ints[5];			// Interrupts per second (A)
	unsigned int umrl_io_act[5];			// IO Activity in bytes per second (A)
	unsigned int umrl_io_time[5];		// cpu time spent for io activities (R)
	unsigned int umrl_memory[5];			// RAM utilization (R)
	unsigned int umrl_net_sent[5];		// network bytes sent per second
	unsigned int umrl_net_recv[5];		// network bytes received per second
	unsigned int umrl_net_total[5];		// total network bytes per second
	unsigned int umrl_nic_total[5];		// total network utilization (R)
	unsigned int umrl_nic_recv[5];		// receiving network activity (R)
	unsigned int umrl_nic_send[5];		// sending network activity (R)
	unsigned int umrl_page_read[5];		// page reading activity in pages per second (A)
	unsigned int umrl_page_write[5];		// page writing activity in pages per second (A)
	unsigned int umrl_page_total[5];		// total paging activity in pages per second (A)
	unsigned int umrl_page_fault[5];		// Page faults per second (A)
	unsigned int umrl_process[5];		// total number of processes (A)
	unsigned int umrl_page_util[5];		// Utilization of the swapfile (R)
	unsigned int umrl_page_file[5];		// Size of the swapfile (A)
	unsigned int umrl_threads[5];		// total number of threads (A)

	unsigned int umrl_proc_threads[5];	// number of threads of the current process (A)
	unsigned int umrl_proc_handles[5];	// number of handles of the current process (A)
	unsigned int umrl_proc_virt_bytes[5];	// number of virtual bytes in use by the current process (A)
	unsigned int umrl_proc_read_ops[5];	// read operations per second (A)
	unsigned int umrl_proc_write_ops[5];	// write operations per second (A)
	unsigned int umrl_proc_read_bytes[5];	// read bytes per second (A)
	unsigned int umrl_proc_write_bytes[5];	// written bytes per second (A)
	unsigned int umrl_proc_total_bytes[5];	// total transferred bytes per second (A)
	unsigned int umrl_proc_pg_fault[5];	// page faults per second	(A)
	unsigned int umrl_proc_mem_abs[5];		// currently used physical memory in bytes (A)
	unsigned int umrl_proc_mem_util[5];		// utilization of physical memory (R)
	unsigned int umrl_proc_cpu[5];			// cpu utilization of the current process

	ULONG uml_proc_curr_threads;	// current number of threads
	ULONG uml_proc_curr_handles;	// current number of handles
	ull	  uhl_proc_virt_bytes;		// current size of the virtual address space the process is using
	ull   uhl_proc_write_operations;	// total number of write operations
	ull   uhl_proc_read_operations;		// total number of read operations
	ull   uhl_proc_read_bytes;			// total number of read bytes
	ull	  uhl_proc_write_bytes;			// total number of written bytes
	ull	  uhl_proc_total_bytes;			// total number of transferred bytes
	ULONG uml_proc_pg_faults;			// total number of page faults
	unsigned int uml_proc_curr_mem;		// total physical memory bytes
	unsigned int uml_proc_curr_mem_util;	// current memory utilization
	ull	  uhl_proc_time_kernel;			// number of 100 ns intervals in kernel mode
	ull   uhl_proc_time_user;			// number of 100 ns intervals in user mode
	#endif /* HL_WINALL1 */
} ;

struct dsd_perf_data
{
#ifdef HL_FREEBSD
	
	ull ulc_memory;
	ull uhl_proc_threads_cur;
	ull uhl_proc_page_faults_tot;
	ull uhl_proc_io_read_tot;
	ull uhl_proc_io_write_tot;
	ull uhl_proc_user_time;
	ull uhl_proc_system_time;
	ull ulc_cpu_total_time;
	ull uhl_proc_ctx_invol;
	ull uhl_proc_ctx_vol;
	unsigned long long ulc_io_total_ops;		// total I/O Operations
	unsigned long long ulc_io_total_bytes;		// total I/O bytes
	
#endif
#ifdef HL_WINALL1
	unsigned long long ulc_io_read_bytes;		// total read bytes
	unsigned long long ulc_io_written_bytes;	// total written bytes
	unsigned long long ulc_io_total_bytes;		// total I/O bytes
	unsigned long long ulc_io_read_ops;		// total read operations
	unsigned long long ulc_io_write_ops;		// total write operations
	unsigned long long ulc_io_total_ops;		// total I/O Operations
	unsigned long long ulc_cpu_kernel_time;		// time in kernel mode (in ms)
	unsigned long long ulc_cpu_user_time;		// time in user mode (in ms)
	unsigned long long ulc_cpu_total_time;		// kernel and user mode combined (in ms)
	unsigned long long ulc_memory;			// process memory consumption (in bytes)
	unsigned int uml_mem_util;				// memory utilization (0 - 10000)
#endif
#ifdef HL_LINUX
	unsigned long long ulc_memory;			// process memory consumption (in bytes)
	unsigned long long ulc_cpu_total_time;		// kernel and user mode combined (in ms)
	unsigned long long ulc_io_total_ops;		// total I/O Operations
	unsigned long long ulc_io_total_bytes;		// total I/O bytes
	unsigned int uml_cpu_util;
#endif
};

// returns the performance data of the current process
int m_get_perf_data( struct dsd_perf_data* );
// writes all performance values into the passed array (NHASN encoding tag1 value1 tag2 ...)
int m_get_perf_array(char*, int);
// set load balancing formula
extern "C" int m_set_lb_formula (char*, const unsigned int ump_length = 0);
// get the current load (result of the monitored values and the lb formula)
extern "C" int m_get_load();
// write the current system load in the passed structure
extern "C" bool m_get_system_load (/*[out]*/ struct dsd_server_load&, bool bop_lock_mutex = true);
	/* start the data collector thread
	 * Input:
	 * amp_sess:		pointer to a function in the main program that returns the number of sessions.
	 * 					If the number of sessions is irrelevant this pointer can be NULL.
	 * bop_log:			write the current load into a logfile if true
	 * imp_interval:	time between two logging activities (in multiples of 10 seconds)
	 * achp_file:		name of the logfile (if empty, it is linlb_DD-MM-YYYY_HH:MM:SS.csv
	 *	Note: If the passed filename is an existing file the load values will be appended
	 * 		  to the file and not overwritten*/

// start the data collector thread, pass a dsd_qload1_contr_1 structure that contains a pointer to a function that returns the number of sessions
// and a function pointer to handle XML navigation
extern "C" bool m_start_monitor_thread_old(
#ifdef HL_LINUX
							struct dsd_qload1_contr_1 * = NULL
#endif
#ifdef HL_WINALL1
							char*	achp_formula = "",
							int     (*amp_sess)() = NULL,
							bool	bop_logging = false,
							char*	achp_logfile = "",
							int		imp_log_interval = 60
#endif
#ifdef HL_FREEBSD
							char*	achp_formula = ""
#endif
								);
extern "C" bool m_start_monitor_thread( void ); 
// stop the data collector thread
extern "C" int m_stop_monitor_thread();
// get a single load parameter value
extern "C" int m_get_parameter_value(int);


#endif /* _HOB-PERF-DATA-1_H */