/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROJECT: VDI                                                      |*/
/*|                                                                   |*/
/*| PROGRAM NAME: xs-lbal-win                                         |*/
/*| -------------                                                     |*/
/*|  Load balancing module to collect system data and to calculate    |*/
/*|  the system load according to a specified formula.				  |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2009									  |*/
/*|  Copyright (C) HOB Germany 2010									  |*/
/*|  Copyright (C) HOB Germany 2011									  |*/
/*|  Copyright (C) HOB Germany 2012									  |*/
/*|  Copyright (C) HOB Germany 2013									  |*/
/*|  Copyright (C) HOB Germany 2014									  |*/
/*|                                                                   |*/
/*|  2.12.14 Andre Eberwien                                           |*/
/*+-------------------------------------------------------------------+*/

#ifdef WIN32
#ifndef HL_WINALL1
#define HL_WINALL1
#endif
#endif
#ifdef WIN64
#ifndef HL_WINALL1
#define HL_WINALL1
#endif
#endif

#define PROCESS_NAME "winlb"
//#define HL_WINALL1
#define _WIN32_DCOM


#ifdef HL_LINUX
#include <sys/types.h>
#include <linux/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/statvfs.h>
#include <linux/socket.h>
#include <netinet/in.h>
#include <sys/vfs.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/wireless.h>
#include <linux/ethtool.h>
#include <pthread.h>
#include <unistd.h>


#ifdef HOBXERCES
#include <xercesc/util/PlatformUtils.hpp>
#include <xercesc/parsers/AbstractDOMParser.hpp>
#include <xercesc/dom/DOMImplementation.hpp>
#include <xercesc/dom/DOMImplementationLS.hpp>
#include <xercesc/dom/DOMImplementationRegistry.hpp>
#include <xercesc/dom/DOMException.hpp>
#include <xercesc/dom/DOMDocument.hpp>
#include <xercesc/dom/DOMNodeList.hpp>
#include <xercesc/dom/DOMNode.hpp>
#include <xercesc/dom/DOMError.hpp>
#include <xercesc/dom/DOMLocator.hpp>
#include <xercesc/dom/DOMErrorHandler.hpp>
#include <xercesc/util/XMLString.hpp>
#endif
#endif /* HL_LINUX */

#ifdef HL_FREEBSD
#include <sys/file.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/types.h>
#include <pthread.h>
#include <unistd.h>
#include <kvm.h>
#endif

#ifdef HL_WINALL1
#include <windows.h>
#include <atlbase.h>
#include <atlconv.h>
#include <comutil.h>
#include <wbemcli.h>
#include <comdef.h>
#include <wbemidl.h>
#endif

#include <stdio.h>
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <vector>
#include <math.h>
#include <errno.h>
#include <cstring>
#include <math.h>
#include <time.h>

/* moved from header file */
/*#ifdef HL_LINUX
	XERCES_CPP_NAMESPACE_USE
	#include <xercesc/dom/DOMNode.hpp>
#endif*/
#ifdef HL_WINALL1
	#include <hob-perf-data-1.h>
#endif
#ifdef HL_LINUX
	#include <hob-perf-data-1.h>
#endif
#ifdef HL_FREEBSD
	#include "hob-perf-data-1.h"
#endif

#define	UPDATE_INTERVAL 10		// interval of updates of the current load (in seconds)
#define TIME_1			60		// 1 Minute
#define TIME_5			300		// 5 Minutes
#define TIME_15			900		// 15 Minutes
#define SIOCETHTOOL     0x8946
#define __LLB__ 		"xs-lbal-win.cpp"


// Tag numbers
#define PERF_TAG_SESSIONS			0
// Linux only variables
#define PERF_TAG_PROCESS_NEW_1		21
#define PERF_TAG_PROCESS_NEW_5		22
#define PERF_TAG_PROCESS_NEW_10		23
#define PERF_TAG_PROCESS_NEW_15		24
#define PERF_TAG_PROCESS_NEW_30		25
// Linux and windows variables
#define PERF_TAG_CPU_1				26
#define PERF_TAG_CPU_5				27
#define PERF_TAG_CPU_10				28
#define PERF_TAG_CPU_15				29
#define PERF_TAG_CPU_30				30

#define PERF_TAG_CTX_1				36
#define PERF_TAG_CTX_5				37
#define PERF_TAG_CTX_10				38
#define PERF_TAG_CTX_15				39
#define PERF_TAG_CTX_30				40

#define PERF_TAG_HARDDISK_1			41
#define PERF_TAG_HARDDISK_5			42
#define PERF_TAG_HARDDISK_10		43
#define PERF_TAG_HARDDISK_15		44
#define PERF_TAG_HARDDISK_30		45

#define PERF_TAG_HD_READ_1			46
#define PERF_TAG_HD_READ_5			47
#define PERF_TAG_HD_READ_10			48
#define PERF_TAG_HD_READ_15			49
#define PERF_TAG_HD_READ_30			50

#define PERF_TAG_HD_WRITE_1			51
#define PERF_TAG_HD_WRITE_5			52
#define PERF_TAG_HD_WRITE_10		53
#define PERF_TAG_HD_WRITE_15		54
#define PERF_TAG_HD_WRITE_30		55

#define PERF_TAG_INT_1				56
#define PERF_TAG_INT_5				57
#define PERF_TAG_INT_10				58
#define PERF_TAG_INT_15				59
#define PERF_TAG_INT_30				60

#define PERF_TAG_IO_ACT_1			61
#define PERF_TAG_IO_ACT_5			62
#define PERF_TAG_IO_ACT_10			63
#define PERF_TAG_IO_ACT_15			64
#define PERF_TAG_IO_ACT_30			65

#define PERF_TAG_IO_TIME_1			66
#define PERF_TAG_IO_TIME_5			67
#define PERF_TAG_IO_TIME_10			68
#define PERF_TAG_IO_TIME_15			69
#define PERF_TAG_IO_TIME_30			70

#define PERF_TAG_MEMORY_1			71
#define PERF_TAG_MEMORY_5			72
#define PERF_TAG_MEMORY_10			73
#define PERF_TAG_MEMORY_15			74
#define PERF_TAG_MEMORY_30			75

#define PERF_TAG_NIC_1				76
#define PERF_TAG_NIC_5				77
#define PERF_TAG_NIC_10				78
#define PERF_TAG_NIC_15				79
#define PERF_TAG_NIC_30				80

#define PERF_TAG_NIC_READ_1			81
#define PERF_TAG_NIC_READ_5			82
#define PERF_TAG_NIC_READ_10		83
#define PERF_TAG_NIC_READ_15		84
#define PERF_TAG_NIC_READ_30		85

#define PERF_TAG_NIC_WRITE_1		86
#define PERF_TAG_NIC_WRITE_5		87
#define PERF_TAG_NIC_WRITE_10		88
#define PERF_TAG_NIC_WRITE_15		89
#define PERF_TAG_NIC_WRITE_30		90

#define PERF_TAG_PROCESS_1			91
#define PERF_TAG_PROCESS_5			92
#define PERF_TAG_PROCESS_10			93
#define PERF_TAG_PROCESS_15			94
#define PERF_TAG_PROCESS_30			95

#define PERF_TAG_SWAP_1				96
#define PERF_TAG_SWAP_5				97
#define PERF_TAG_SWAP_10			98
#define PERF_TAG_SWAP_15			99
#define PERF_TAG_SWAP_30			100

#define PERF_TAG_PAGE_READ_1		101
#define PERF_TAG_PAGE_READ_5		102
#define PERF_TAG_PAGE_READ_10		103
#define PERF_TAG_PAGE_READ_15		104
#define PERF_TAG_PAGE_READ_30		105

#define PERF_TAG_PAGE_TOTAL_1		106
#define PERF_TAG_PAGE_TOTAL_5		107
#define PERF_TAG_PAGE_TOTAL_10		108
#define PERF_TAG_PAGE_TOTAL_15		109
#define PERF_TAG_PAGE_TOTAL_30		110

#define PERF_TAG_PAGE_WRITE_1		111
#define PERF_TAG_PAGE_WRITE_5		112
#define PERF_TAG_PAGE_WRITE_10		113
#define PERF_TAG_PAGE_WRITE_15		114
#define PERF_TAG_PAGE_WRITE_30		115

#define PERF_TAG_PG_FAULT_1			116
#define PERF_TAG_PG_FAULT_5			117
#define PERF_TAG_PG_FAULT_10		118
#define PERF_TAG_PG_FAULT_15		119
#define PERF_TAG_PG_FAULT_30		120

#define PERF_TAG_PG_MAJ_FAULT_1		121
#define PERF_TAG_PG_MAJ_FAULT_5		122
#define PERF_TAG_PG_MAJ_FAULT_10	123
#define PERF_TAG_PG_MAJ_FAULT_15	124
#define PERF_TAG_PG_MAJ_FAULT_30	125

#define PERF_TAG_SWAP_READ_1		126
#define PERF_TAG_SWAP_READ_5		127
#define PERF_TAG_SWAP_READ_10		128
#define PERF_TAG_SWAP_READ_15		129
#define PERF_TAG_SWAP_READ_30		130

#define PERF_TAG_SWAP_TOTAL_1		131
#define PERF_TAG_SWAP_TOTAL_5		132
#define PERF_TAG_SWAP_TOTAL_10		133
#define PERF_TAG_SWAP_TOTAL_15		134
#define PERF_TAG_SWAP_TOTAL_30		135

#define PERF_TAG_SWAP_WRITE_1		136
#define PERF_TAG_SWAP_WRITE_5		137
#define PERF_TAG_SWAP_WRITE_10		138
#define PERF_TAG_SWAP_WRITE_15		139
#define PERF_TAG_SWAP_WRITE_30		140

#define PERF_TAG_NET_SENT_1			141
#define PERF_TAG_NET_SENT_5			142
#define PERF_TAG_NET_SENT_10		143
#define PERF_TAG_NET_SENT_15		144
#define PERF_TAG_NET_SENT_30		145

#define PERF_TAG_NET_RECV_1			146
#define PERF_TAG_NET_RECV_5			147
#define PERF_TAG_NET_RECV_10		148
#define PERF_TAG_NET_RECV_15		149
#define PERF_TAG_NET_RECV_30		150

#define PERF_TAG_NET_TOTAL_1		151
#define PERF_TAG_NET_TOTAL_5		152
#define PERF_TAG_NET_TOTAL_10		153
#define PERF_TAG_NET_TOTAL_15		154
#define PERF_TAG_NET_TOTAL_30		155

//Windows only variables
#define PERF_TAG_CACHE_HIT_1		161
#define PERF_TAG_CACHE_HIT_5		162
#define PERF_TAG_CACHE_HIT_10		163
#define PERF_TAG_CACHE_HIT_15		164
#define PERF_TAG_CACHE_HIT_30		165

#define PERF_TAG_CACHE_MISSES_1		166
#define PERF_TAG_CACHE_MISSES_5		167
#define PERF_TAG_CACHE_MISSES_10	168
#define PERF_TAG_CACHE_MISSES_15	169
#define PERF_TAG_CACHE_MISSES_30	170

#define PERF_TAG_HD_BPR_1			171
#define PERF_TAG_HD_BPR_5			172
#define PERF_TAG_HD_BPR_10			173
#define PERF_TAG_HD_BPR_15			174
#define PERF_TAG_HD_BPR_30			175

#define PERF_TAG_HD_BPT_1			176
#define PERF_TAG_HD_BPT_5			177
#define PERF_TAG_HD_BPT_10			178
#define PERF_TAG_HD_BPT_15			179
#define PERF_TAG_HD_BPT_30			180

#define PERF_TAG_HD_BPW_1			181
#define PERF_TAG_HD_BPW_5			182
#define PERF_TAG_HD_BPW_10			183
#define PERF_TAG_HD_BPW_15			184
#define PERF_TAG_HD_BPW_30			185

#define PERF_TAG_SWAPFILE_1			186
#define PERF_TAG_SWAPFILE_5			187
#define PERF_TAG_SWAPFILE_10		188
#define PERF_TAG_SWAPFILE_15		189
#define PERF_TAG_SWAPFILE_30		190

#define PERF_TAG_THREADS_1			191
#define PERF_TAG_THREADS_5			192
#define PERF_TAG_THREADS_10			193
#define PERF_TAG_THREADS_15			194
#define PERF_TAG_THREADS_30			195

// Performance variables for the own process
#define PERF_TAG_PROC_CPU_1			256
#define PERF_TAG_PROC_CPU_5			257
#define PERF_TAG_PROC_CPU_10		258
#define PERF_TAG_PROC_CPU_15		259
#define PERF_TAG_PROC_CPU_30		260
#define PERF_TAG_PROC_ELAPSED_TIME	261

#define PERF_TAG_PROC_THREADS_1		262		
#define PERF_TAG_PROC_THREADS_5		263
#define PERF_TAG_PROC_THREADS_10	264
#define PERF_TAG_PROC_THREADS_15	265
#define PERF_TAG_PROC_THREADS_30	266
#define PERF_TAG_PROC_THREADS_CURR	267

#define PERF_TAG_PROC_HANDLES_1		268
#define PERF_TAG_PROC_HANDLES_5		269
#define PERF_TAG_PROC_HANDLES_10	270
#define PERF_TAG_PROC_HANDLES_15	271
#define PERF_TAG_PROC_HANDLES_30	272
#define PERF_TAG_PROC_HANDLES_CURR	273

#define PERF_TAG_PROC_VM_1			274
#define PERF_TAG_PROC_VM_5			275
#define PERF_TAG_PROC_VM_10			276
#define PERF_TAG_PROC_VM_15			277
#define PERF_TAG_PROC_VM_30			278
#define PERF_TAG_PROC_VM_CURR		279

#define PERF_TAG_PROC_READ_OP_1		280
#define PERF_TAG_PROC_READ_OP_5		281
#define PERF_TAG_PROC_READ_OP_10	282
#define PERF_TAG_PROC_READ_OP_15	283
#define PERF_TAG_PROC_READ_OP_30	284
#define PERF_TAG_PROC_READ_OP_TOT	285

#define PERF_TAG_PROC_WRITE_OP_1	286
#define PERF_TAG_PROC_WRITE_OP_5	287
#define PERF_TAG_PROC_WRITE_OP_10	288
#define PERF_TAG_PROC_WRITE_OP_15	289
#define PERF_TAG_PROC_WRITE_OP_30	290
#define PERF_TAG_PROC_WRITE_OP_TOT	291

#define PERF_TAG_PROC_READ_BYTES_1		292
#define PERF_TAG_PROC_READ_BYTES_5		293
#define PERF_TAG_PROC_READ_BYTES_10		294
#define PERF_TAG_PROC_READ_BYTES_15		295
#define PERF_TAG_PROC_READ_BYTES_30		296
#define PERF_TAG_PROC_READ_BYTES_TOT	297

#define PERF_TAG_PROC_WRITE_BYTES_1		298
#define PERF_TAG_PROC_WRITE_BYTES_5		299
#define PERF_TAG_PROC_WRITE_BYTES_10	300
#define PERF_TAG_PROC_WRITE_BYTES_15	301
#define PERF_TAG_PROC_WRITE_BYTES_30	302
#define PERF_TAG_PROC_WRITE_BYTES_TOT	303

#define PERF_TAG_PROC_TOTAL_BYTES_1		304
#define PERF_TAG_PROC_TOTAL_BYTES_5		305
#define PERF_TAG_PROC_TOTAL_BYTES_10	306
#define PERF_TAG_PROC_TOTAL_BYTES_15	307
#define PERF_TAG_PROC_TOTAL_BYTES_30	308
#define PERF_TAG_PROC_TOTAL_BYTES_TOT	309

#define PERF_TAG_PROC_PG_FAULT_1		310
#define PERF_TAG_PROC_PG_FAULT_5		311
#define PERF_TAG_PROC_PG_FAULT_10		312
#define PERF_TAG_PROC_PG_FAULT_15		313
#define PERF_TAG_PROC_PG_FAULT_30		314
#define PERF_TAG_PROC_PG_FAULT_TOT		315

#define PERF_TAG_PROC_MEM_ABS_1			316
#define PERF_TAG_PROC_MEM_ABS_5			317
#define PERF_TAG_PROC_MEM_ABS_10		318
#define PERF_TAG_PROC_MEM_ABS_15		319
#define PERF_TAG_PROC_MEM_ABS_30		320
#define PERF_TAG_PROC_MEM_ABS_CURR		321

#define PERF_TAG_PROC_MEM_UTIL_1		322
#define PERF_TAG_PROC_MEM_UTIL_5		323
#define PERF_TAG_PROC_MEM_UTIL_10		324
#define PERF_TAG_PROC_MEM_UTIL_15		325
#define PERF_TAG_PROC_MEM_UTIL_30		326
#define PERF_TAG_PROC_MEM_UTIL_CURR		327

#define PERF_TAG_PROC_TIME_KERNEL		328
#define PERF_TAG_PROC_TIME_USER			329
#define PERF_TAG_PROC_TIME_TOTAL		330



template<class T> int m_convert_number_to_nhasn(T t_number, char* achp_dest, int imp_len)
{
	// measure length
	T t_1 = t_number;
	short isl_length = 0;
	do 
	{
		isl_length++;
		t_1 >>= 7;
	}
	while (t_1 > 0);
	
	int iml_more_bit = 0;
	achp_dest = achp_dest + isl_length;
	do
	{
		*(--achp_dest) = (unsigned char)((t_number & 0x7F) | iml_more_bit);
		iml_more_bit = 0x80;
		t_number >>= 7;
	}
	while (t_number > 0);
	return isl_length;
}

using namespace std;


class c_lb_tree_node;
class c_lb_formula;
class c_formula_token;
class c_variable_list;
template<class T,int i> class c_fifo_array;

// types of formula tokens
enum FT_TYPE
{
	UNKNOWN,
	VARIABLE,
	INFIX_OPERATOR,
	SEPARATOR,
	CONSTANT,
	PREFIX_OPERATOR
};

// Fifo Array class, it is used to store performance data
template<class T,int i> class c_fifo_array
{
	private:
		T dsr_elements[i]; // array (ring buffer)
		int iml_size;		// size of the array
		int iml_valid;	// Number of valid elements	
		int iml_oldest;	// index of the oldest updated array element

		inline int m_positive_mod(int imp_number, bool bop_check_validity = true)
		{
			int iml_ret = (imp_number + iml_size) % iml_size;
			if (!bop_check_validity)
				return iml_ret;
			if (iml_ret > iml_valid)
			{
				return 0;
			}
			else
				return iml_ret;

		}

		inline void m_increase_ring_counter(int imp_step = 1)
		{
			//iml_oldest = (iml_latest + imp_step + iml_size) % iml_size;
			iml_oldest = m_positive_mod(iml_oldest + imp_step, false);
		}

	public:
		c_fifo_array()
		{
			iml_size = i;
			iml_valid = 0;
			iml_oldest = 0;
		}

		// The array will be initialized with the passed argument
		c_fifo_array(T tp_default)
		{
			iml_size = i;
			iml_oldest = 0;
			m_fill_array(tp_default);
			
		}

		~c_fifo_array()
		{
		}

		// fill the array with the passed value
		void m_fill_array(T value, bool bop_set_valid = true)
		{
			for (int iml_temp = 0; iml_temp < iml_size; iml_temp++)
			{
				dsr_elements[iml_temp] = value;
			}
			m_increase_ring_counter(iml_size);
			if (bop_set_valid)
			{
				iml_valid = iml_size;
			}
			else
			{
				iml_valid = 1;
			}
		}

		// get the first n elements
		T** m_get_elements(int imp_number)
		{
			T ret_value[] = new T[imp_number];
			for (int iml_temp = 0; iml_temp< imp_number; iml_temp++)
			{
				ret_value[iml_temp] = dsr_elements[iml_temp];
			}
			return ret_value;
		}

		// get the whole array
		T* m_get_array()
		{
			return dsr_elements;
		}

		// get the average of the latest n elements (only for numbers)
		ull m_get_average(int imp_number)
		{
			ull fdl_ret = 0;
			ull summe = 0;
			if (iml_valid == 0) return 0;

			for (int iml1 = 1 ; iml1 <= imp_number; iml1++)
			{
				if (iml1 < iml_valid)
				{
					summe = summe + (ull) dsr_elements[m_positive_mod(iml_oldest - iml1)];
				}
			}

			if (imp_number > iml_valid)
			{

				fdl_ret = summe/((ull)iml_valid);
			}
			else fdl_ret = summe/((ull)imp_number);

			return fdl_ret;
		}
		
		// get the difference between two values (only for numbers)
		T m_get_difference(int imp_ind_lo, int imp_ind_hi)
		{
			ull fdl_ret = 0;
			fdl_ret = (ull)dsr_elements[m_positive_mod(iml_oldest - imp_ind_lo - 1)] - (ull)dsr_elements[m_positive_mod(iml_oldest - imp_ind_hi - 2)];
			return (T)fdl_ret;
		}
		
		// get the difference between two values in consideration of the time (only for numbers)
		ull m_get_diff_per_sec(int imp_ind_lo, int imp_ind_hi)
		{
//#define NULLPOINTER		  
			if (iml_valid == 0) return 0;
			ull fdl_ret = 0;
			if (imp_ind_hi > iml_valid -1)
			{
				imp_ind_hi = iml_valid -1;	
			}

			fdl_ret = (ull)dsr_elements[m_positive_mod(iml_oldest - imp_ind_lo - 1)] - (ull)dsr_elements[m_positive_mod(iml_oldest - imp_ind_hi)];
			int iml_steps = imp_ind_hi - imp_ind_lo - 1;
			int iml_seconds =  iml_steps * UPDATE_INTERVAL;
#ifdef NULLPOINTER			
			printf("fdl_ret = %llu, iml_seconds = %d, low element = %llu, high element = %llu, iLow = %d, iHigh = %d, iOld = %d\n", fdl_ret, iml_seconds, (ull)dsr_elements[m_positive_mod(iml_oldest -imp_ind_lo - 1)], (ull)dsr_elements[m_positive_mod(iml_oldest - imp_ind_hi)], imp_ind_lo, imp_ind_hi, iml_oldest);
#endif			
			if (iml_seconds > 0)
			{
				return fdl_ret/(ull)iml_seconds;
			}
			else return 0;	
		}
		
		// this version is more precise than the other one and can only be used for Windows Load Balancing
		ull m_get_diff_per_sec(int imp_ind_lo, int imp_ind_hi, c_fifo_array<ull,181>* dsp_timestamp, c_fifo_array<ull,181>* dsp_frequency)
		{
			if (iml_valid == 0) return 0;
			ull uhl_ret = 0;
			if (imp_ind_hi > iml_valid -1)
			{
				imp_ind_hi = iml_valid -1;	
			}
			uhl_ret = (ull)dsr_elements[m_positive_mod(iml_oldest - imp_ind_lo - 1)] - (ull)dsr_elements[m_positive_mod(iml_oldest - imp_ind_hi)];
			double fdl_seconds = (double)( dsp_timestamp->m_get_element(m_positive_mod(iml_oldest - imp_ind_lo - 1)) - dsp_timestamp->m_get_element(m_positive_mod(iml_oldest - imp_ind_hi)) ) / dsp_frequency->m_get_element(0);
			if (fdl_seconds > 0)
			{
				return (ull)(uhl_ret/fdl_seconds);
			}
			else return 0;	
		}

		// add one element to the ring buffer at position iml_oldest
		void m_add_element(T tp_element)
		{
			dsr_elements[iml_oldest] = tp_element;
			m_increase_ring_counter();
			iml_valid++;
		}
		
		int m_get_size()
		{
			return iml_size;
		}
		
		// get element a index imp_index
		T m_get_element(int imp_index)
		{
			return dsr_elements[imp_index];	
		}

		T m_get_latest_element()
		{
			return dsr_elements[m_positive_mod(iml_oldest -1)];
		}
		
		
		T operator[] (int imp_index)
		{
			return dsr_elements[imp_index];	
		}

};

#ifdef HL_LINUX
// struct for procfs data
struct dsd_proc
{
	char* 	achl_file;		// proc filename
	int		iml_line;		// line where the data can be found
	int		iml_element;	// element in iml_line
	
	dsd_proc(char* achp_file, int imp_line, int imp_element)
	{
		achl_file = achp_file;
		iml_line = imp_line;
		iml_element = imp_element;	
	}	
};
#endif /* HL_LINUX */

// structure of server values
struct dsd_server_values
{

#ifdef HL_FREEBSD
	c_fifo_array<ull, 181>	dsl_interrupts;
	c_fifo_array<ull, 181>	dsl_usermem;
	c_fifo_array<ull, 181>	dsl_realmem;
	c_fifo_array<ull, 181>	dsl_cpu_idle;
	c_fifo_array<ull, 181>	dsl_cpu_total;
	c_fifo_array<ull, 181>	dsl_context_switches;
	c_fifo_array<ull, 181>	dsl_cache_misses;
	c_fifo_array<ull, 181>	dsl_cache_checks;
	c_fifo_array<ull, 181>	dsl_pages_in;
	c_fifo_array<ull, 181>	dsl_pages_out;
	c_fifo_array<ull, 181>	dsl_swaps_in;
	c_fifo_array<ull, 181>	dsl_swaps_out;
	c_fifo_array<ull, 181>	dsl_swap_used;
	c_fifo_array<ull, 181>	dsl_swap_total;
	c_fifo_array<ull, 181>	dsl_threads;
	c_fifo_array<ull, 181>	dsl_processes;
	// process variables
	c_fifo_array<ull, 181>	dsl_proc_user_time;
	c_fifo_array<ull, 181>	dsl_proc_system_time;
	c_fifo_array<ull, 181>	dsl_proc_page_faults;
	c_fifo_array<ull, 181>	dsl_proc_io_reads;
	c_fifo_array<ull, 181>	dsl_proc_io_writes;
	c_fifo_array<ull, 181>	dsl_proc_ctx_voluntary;
	c_fifo_array<ull, 181>	dsl_proc_ctx_involuntary;
	c_fifo_array<ull, 181>	dsl_proc_threads;
	c_fifo_array<ull, 181>	dsl_proc_memory;
#endif

#ifdef HL_LINUX
	// values from /proc/diskstats
	c_fifo_array<ull,181>	dsl_read_sectors;	// Number of read sectors (512 Byte)
	c_fifo_array<ull,181>	dsl_written_sectors;// number of written sectors
	c_fifo_array<long,181>	dsl_io_time;		// time spent doing IO (in milliseconds)
	// values from /proc/loadavg
	c_fifo_array<long,181>	dsl_processes;		// number of currently running processes
	c_fifo_array<long,181>	dsl_started_processes;	// number of startet processes since boot
	// values from /proc/meminfo
	c_fifo_array<long,181>	dsl_free_memory;	// free RAM in kilobytes
	c_fifo_array<long,181>	dsl_free_swap;		// free swap space in kilobytes
	// values from /proc/net/dev
	c_fifo_array<ull,181>	dsl_net_rec;		// received network bytes
	c_fifo_array<ull,181>	dsl_net_trans;		// transmitted network bytes
	// values from /proc/vmstat
	c_fifo_array<ull,181>	dsl_page_in;		// number of page ins
	c_fifo_array<ull,181>	dsl_page_out;		// number of page outs
	c_fifo_array<ull,181>	dsl_swap_in;		// number of swapins
	c_fifo_array<ull,181>	dsl_swap_out;		// number of swapouts
	c_fifo_array<ull,181>	dsl_min_pg_faults;	// number of minor page faults
	c_fifo_array<ull,181>	dsl_maj_pg_faults;	// number of major page faults
	// values from /proc/stat
	c_fifo_array<ull,181>	dsl_total_jiffies;	// number of total jiffies
	c_fifo_array<ull,181>	dsl_idle_jiffies;	// number of jiffies in idle time
	c_fifo_array<ull,181>	dsl_interrupts;		// number of interrupts
	c_fifo_array<ull,181>	dsl_ctx_switch;		// number of context switches
	// values from /proc/self/stat
	c_fifo_array<ull,181>	dsl_proc_jiffies;	// number of jiffies used by the process
	ull	uhl_proc_ticks_user;	// clock ticks in user mode
	ull	uhl_proc_ticks_kernel;	// clock ticks in kernel mode
	ull	uhl_proc_virtual_memory;	// virtual memory size
	ull	uhl_proc_io_reads;
	ull	uhl_proc_io_writes;
	ull	uhl_proc_io_read_bytes;
	ull	uhl_proc_io_written_bytes;
	
	// values not from procfs
	c_fifo_array<ull,181>	dsl_free_hd;	// number of free hd space (in bytes)
#endif /* HL_LINUX */
#ifdef HL_WINALL1
	// from Win32_PerfRawData_PerfOs_Cache
	c_fifo_array<LONG, 181>	dsl_cache_copy_read_hits_pc;	// total read hits in cache memory
	c_fifo_array<LONG, 181> dsl_cache_copy_reads_ps;		// total cache copy reads (reference value)
	// from Win32_PerfRawData_PerfDisk_LogicalDisk
	c_fifo_array<ull, 181>	dsl_ldperf_avg_disk_bytes_read;	// total read bytes from disk
	c_fifo_array<ull, 181>	dsl_ldperf_avg_disk_bytes_write;	// total written bytes to disk
	c_fifo_array<ull, 181>	dsl_ldperf_avg_disk_bytes_transfer;	// total transferred bytes to/from disk
	c_fifo_array<LONG, 181>	dsl_ldperf_disk_reads_ps;			// total number of disk reads
	c_fifo_array<LONG, 181> dsl_ldperf_disk_writes_ps;			// total number of disk writes
	c_fifo_array<LONG, 181> dsl_ldperf_disk_transfers_ps;		// total number of disk transfers
	c_fifo_array<ull, 181>	dsl_ldperf_disk_bytes_ps;			// total number of transferred bytes
	c_fifo_array<ull, 181>	dsl_ldperf_disk_time_pc;			// total number of 100 ns intervals spent in IO mode
	// from Win32_LogicalDisk
	c_fifo_array<ull, 181>	dsl_ld_free_space;					// total free space on logical disks in bytes
	// from Win32_PerfRawData_PerfOS_Memory
	c_fifo_array<ull, 181>	dsl_mem_avail_bytes;				// free RAM
	c_fifo_array<LONG, 181> dsl_mem_cache_faults_ps;			// total number of cache misses
	c_fifo_array<LONG, 181> dsl_mem_page_faults_ps;				// total number of page faults
	c_fifo_array<LONG, 181>	dsl_mem_page_input_ps;				// total number of pageins
	c_fifo_array<LONG, 181> dsl_mem_page_output_ps;				// total number of pageouts
	c_fifo_array<LONG, 181> dsl_mem_page_total_ps;				// total paging activity
	// from Win32_PerfRawData_PerfOS_System
	c_fifo_array<LONG, 181> dsl_obj_processes;					// number of processes
	c_fifo_array<LONG, 181> dsl_obj_threads;					// number of threads
	// from Win32_PerfRawData_PerfOS_PagingFile				
	c_fifo_array<LONG, 181> dsl_page_usage_pc;					// 0 -10000 value (% of pagefile usage)
	c_fifo_array<LONG, 181> dsl_page_size;						// total size of the pagefile
	// from Win32_PerfRawData_PerfOS_Processor
	c_fifo_array<LONG, 181> dsl_cpu_int;						// total number of interrupts
	c_fifo_array<ull, 181>	dsl_cpu_idle;						// 100 ns intervals in idle time
	// from Win32_PerfRawData_PerfOS_System
	c_fifo_array<ull, 181>	dsl_sys_ctx;						// total number of context switches
	// from Win32_PerfRawData_PerfProc_Process
	//c_fifo_array<ull, 181>  dsl_pp_proc_time;					// 100 ns intervals of the process executing
	// from Win32_PerfRawData_Tcpip_NetworkInterface
	c_fifo_array<ull, 181>	dsl_net_recv_ps;					// total number of received bytes
	c_fifo_array<ull, 181>  dsl_net_sent_ps;						// total number of sent bytes
	c_fifo_array<ull, 181>	dsl_net_total_ps;					// total number of transmitted bytes
	// from Win32_PerfRawData_PerfProc_Process
	c_fifo_array<ull,181>	dsl_proc_elapsed_time;
	c_fifo_array<LONG,181>	dsl_proc_handles;					// number of process handles
	c_fifo_array<ull,181>	dsl_proc_io_read_bytes;				// total read bytes
	c_fifo_array<ull,181>	dsl_proc_io_read_ops;				// total read operations
	c_fifo_array<ull,181>	dsl_proc_io_write_bytes;			// total written bytes
	c_fifo_array<ull,181>	dsl_proc_io_write_ops;				// total write operations
	c_fifo_array<LONG,181>	dsl_proc_page_faults;				// total number of page faults
	c_fifo_array<ull,181>	dsl_proc_cpu;						// total cpu consumption
	c_fifo_array<LONG,181>	dsl_proc_threads;					// total number of threads
	c_fifo_array<ull,181>	dsl_proc_virt_bytes;				// total number of virtual bytes
	c_fifo_array<ull,181>	dsl_proc_working_set;				// total physical memory consumption in bytes
	
	// timing variables
	c_fifo_array<ull,181>	dsl_timestamp;
	c_fifo_array<ull,181>	dsl_frequency;

	// elapsed time
	ull uhl_proc_kernel_time;
	ull uhl_proc_user_time;
	
#endif /* HL_WINALL1 */
};

// structure of reference values (values that should indicate 100 %)
// Note: none of these values can be 0. This will cause a division by zero error.
struct dsd_reference
{
	#ifdef HL_LINUX
	// for /proc/diskstats
	long	ill_max_disk_bytes_per_sec;	// maximum of bytes per second in disk i/o
	// for /proc/loadavg
	int		iml_max_processes;			// maximum allowed processes
	int 	iml_max_new_proc_pmin;		// maximum of new processes per minute
	// for /proc/meminfo
	long	uhl_memory;				// total RAM in kilobytes
	long	ill_swap_total;				// total swap space in kilobytes
	// for /proc/net/dev
	long	ill_byte_per_sec;			// total bitrate of network interfaces
	// for /proc/vmstat
	long	ill_max_pages_sec_pin;		// maximum of pages per second for pageins
	long 	ill_max_pages_sec_pout;		// maximum of pages per second for pageouts
	long	ill_max_pages_sec_sin;		// maximim of pages per second for swapins
	long	ill_max_pages_sec_sout;		// maximum of pages per second for swapouts
	long	ill_max_min_pg_faults;		// maximum number of minor page faults per second
	long	ill_max_maj_pg_faults;		// maximum number of major page faults per second
	// for /proc/stat
	long	ill_max_interrupts_psec;	// maximum number of interrupts per second
	long	ill_max_ctx_switches;		// maximum number of context switches per second	
	
	int		iml_jps;				// jiffies per second
	int		iml_page;				// page size
	ull		uhl_hd_total;				// total hard disk capacity (in bytes)
	#endif /* HL_LINUX */
	#ifdef HL_WINALL1
	ull		uhl_network_bw;			// current network bandwidth
	ull		uhl_memory;				// total memory
	ull		uhl_disk_space;			// total disk space
	DWORD   dwl_page_size;			// pagesize
	#endif /* HL_WINALL1 */

	// set default values
	dsd_reference()
	{
		#ifdef HL_LINUX
		ill_max_disk_bytes_per_sec	= 70000000;	// 70 MB/s
		iml_max_processes	=	600;
		iml_max_new_proc_pmin = 100;
		uhl_memory = 10000000;		// 10 GB
		ill_swap_total = 10000000;		// 10 GB
		ill_byte_per_sec = 125000000;	// 1 GBit/s
		ill_max_pages_sec_pin = 10000;
		ill_max_pages_sec_pout = 10000;
		ill_max_pages_sec_sin = 3000;
		ill_max_pages_sec_sout = 3000;
		ill_max_min_pg_faults = 10000;
		ill_max_maj_pg_faults = 1000;
		ill_max_interrupts_psec = 12000;	
		ill_max_ctx_switches = 20000;	// max. allowed context switches per second
		iml_jps = 100;
		iml_page = 4096;
		uhl_hd_total = 5000000000000ULL;		// 1 TB
		#endif /* HL_LINUX */
		#ifdef HL_WINALL1
		uhl_network_bw = 1250000000;	// 10 Gbit/s
		uhl_memory = 100000000;			// 100 GB
		uhl_disk_space = 5000000000000ULL;		// 1 TB
		#endif /*HL_WINALL1 */
	}
};



extern "C" int m_hl1_printf( char *aptext, ... );

// String tokenizer
static void m_str_tok(	const string&, vector<string>&);
// get line imp_line from file dsp_file, the line is written in the passed string pointer
static bool m_get_line_from_file(int, char*, /*[out]*/ string*);
// get an array of strings from one line of a file (divided on chp_delimiter)
static bool m_get_line_from_file(int, char*, const string&, /*[out]*/vector<string>&);
// get data from procfs
static string m_get_data(struct dsd_proc);

#ifdef HL_LINUX
/*-- function imported from wireless-tools --*/
 /* Open a socket.
 * Depending on the protocol present, open the right socket. The socket
 * will allow us to talk to the driver.
 */
static int iw_sockets_open(void);
#endif /* HL_LINUX */



// return if the given filename is a device in /dev fs
static bool m_is_dev(char*);
// trim a char*
static string m_trim_char(char*);

// class whose objects represent formula tokens (variables, operators, etc)
class c_formula_token
{
private:
	string strl_text;
	int iml_type;	// types:
						// 0 = unknown
						// 1 = Variable (for example CPU_1)
						// 2 = infix Operator (+,-,*,/)
						// 3 = Separator (,) for min and max
						// 4 = Constant
						// 5 = prefix operator (MIN,MAX,LOG,EXP,SQR)
	int iml_depth;		// depth in the formula tree (number of opening brackets - number of closing brackets before this token)
	int iml_priority;	// priority of the operator (for non-operators this is 0)
						// priorities (decreasing):
						// 0:	not an operator
						// 1:	MAX, MIN, SQR, LOG, EXP
						// 3:	*, /
						// 5:	+, -
						// 7:	,	(separator)
						
public:
	c_formula_token();
	//c_formula_token(const c_formula_token& dsp_token);
	// create a token with the token text, the depth and the token type
	c_formula_token(string, int, int);
	//const c_formula_token& c_formula_token::operator= (const c_formula_token& dsp_token);
	// getter
	string m_get_text();
	int m_get_type();
	int m_get_depth();
	int m_get_prio();
	static bool m_is_digit (char);
	// look if a char is an infix operator
	static bool m_is_simple_operator(char);
	// look if the passed char is a separator
	static bool m_is_separator(char);
	// look if the passed char is a capital letter
	static bool m_is_letter(char);
	static bool m_is_underscore(char);
};

// List of allowed variables (depending on the current os)
class c_variable_list
{
private:
	vector<string>* adsl_var;		// contains all valid strings that represent a LB variable

public:
	c_variable_list();
	// look if the passed string is a valid variable
	bool m_contains(string);
};

// Class for a load balancing formula
class c_lb_formula
{
private:
	// load balancing formula
	string strl_formula;
	// list of allowed variable names
	c_variable_list dsl_var;
	// tokens of the load balancing formula
	vector<c_formula_token> dsl_token;
	//c_formula_token* adsrc_tokens[1024];
	// vector that contains pointers to all tree nodes that represent variables
	vector<c_lb_tree_node*>* dsl_variable_nodes;
	// root node of the formula tree
	c_lb_tree_node* adsl_root;
	// monitor the cpu load of the process
	bool bol_proc_load;

public:
	// constructor of the formula, arguments are the string of the formula and a bool
	// that defines if the cpu load of the process should be monitored.
	c_lb_formula(string strp_formula = "CPU_1" , bool bop_proc_load = true);
	// divide the formula into tokens (variables, operators, separators and constants)
	// and put them into a list of tokens (dsl_token)
	int m_tokenize(string);
	/* test the token vector for further syntax errors that could not be found in the m_tokenize method */
	int m_check_syntax();
	/*	parse a list of tokens and create tree nodes. The function will be called recursively
	*	Each call creates a new node by searching the highest level token in the part of
	*	dsl_token vector between the indices iml_lo and iml_hi (both inclusive). dsp_parent should always
	*	be the current calling node and dsp_child a pointer to the pointer to the node to be created.
	*	After the creation of the new node pointers of the child nodes of the new node are
	*	being created. After that this function will be called recursively to create new
	*	nodes. This will continue until no further tokens are remaining and the tree is
	*	complete. So this function has to be called only once with the following syntax:
	*	m_parse(null,&adsl_root, 0, dsl_token.size()-1)			*/
	int m_parse(c_lb_tree_node*, c_lb_tree_node**, int, int);
	/* parse the passed formula string and create a formula tree if the formula is valid */
	int m_parse_formula(string, bool);
	// set the current variable values in the formula tree
	bool m_set_variables (struct dsd_server_load&);
	// calculate the current load.
	double m_calculate();
	void m_free_tree(c_lb_tree_node*);
	// set default formula
	void m_set_default_formula();
};

// class of a node in the lb formula
class c_lb_tree_node
{
private:
	int iml_type;				// type of node (like token type)
	double fdl_value;				// value for this node (constant or current value of the represented variable)
	int iml_children;			// number of child nodes
	c_lb_tree_node* adsl_parent;	// parent node
	vector<c_lb_tree_node*>* dsl_children;		// vector that contains pointers to all direct childs of this node
	c_formula_token dsl_token;	// corresponding token
public:
	c_lb_tree_node(c_formula_token*, c_lb_tree_node*);
	// set the value of this node
	void m_set_value (double);
	// add a child node
	void m_add_child(c_lb_tree_node*);
	// calculate the value of this node
	double m_operate();
	//free the allocated memory of this node and all subnodes
	void m_free();
	// getter
	c_lb_tree_node* m_get_parent();
	int m_get_type();
	double m_get_value();
	string m_get_text();
	// get depth of the corresponding token
	int m_get_depth();

};

// write the current load into the log file
void m_write_logfile(int);
// Test if all values are between 0 and 10000
static bool m_test_validity (struct dsd_server_load&);

// update reference values that are variable
static bool m_update_memory();
// write the names of all available network interfaces in the passed vector
static bool m_search_nics(vector<string>&);
// write the names of all available wireless network interfaces in the passed vector
static bool m_search_wireless_nics(vector<string>&);
// update the bandwidth of network interfaces
static bool m_update_net();
// update hard disk capacity
static bool m_update_hd();
// update system dependent values
static bool m_update_sysval();
// update reference values
#ifdef HL_LINUX
static bool m_update_references();
#endif
#ifdef HL_WINALL1
static bool m_update_references(const IWbemServices* const adsp_service);
#endif
// initialize the passed structure with 0 (or appropriate other) values in all fifo arrays
#ifdef HL_WINALL1
static void m_init_fifo_arrays (struct dsd_server_values&, const IWbemServices* const adsp_service);
#endif
#ifdef HL_LINUX
static void m_init_fifo_arrays (struct dsd_server_values&);
#endif
// main function of the new thread (collects system data at regular intervals)
static void* m_collect_data(void*);

//#ifdef DEBUG
extern "C" void m_print_load(struct dsd_server_load&);
//#endif /*DEBUG*/
#ifdef HL_WINALL1
static bool m_is_bstr_equal(BSTR strp1, BSTR strp2);
static unsigned long long m_ull_pow (unsigned long long, unsigned long long);
static unsigned long long m_bstr_to_ull (BSTR);
static HRESULT m_get_ull_wmi_value(IWbemClassObject* , LPCWSTR, ull);
static HRESULT m_get_long_wmi_value(IWbemClassObject*, LPCWSTR, LONG);
static HRESULT m_get_bstr_wmi_value(IWbemClassObject*, LPCWSTR, BSTR);
static HRESULT m_get_bstr_wmi_value(IWbemClassObject*, LPCWSTR, char*);
static HRESULT m_establish_wmi_connection(const BSTR, IWbemLocator*, IWbemServices*);
#endif /* HL_WINALL1 */

// global variables
#ifdef HL_LINUX
// lock a semaphore
static struct sembuf dsg_semlock= { 0, -1, SEM_UNDO };
//unlock a semaphore
static struct sembuf dsg_semunlock= {0, 1 , SEM_UNDO };
#endif /* HL_LINUX */

// Pointer to the function that returns the number of sessions
static int (*am_get_sessions)();
#ifdef HL_LINUX
static pthread_t dsg_monitor_thread;				// Data collector thread
static pthread_mutex_t dsg_monitor_thread_mutex;	// Mutex for Data collector thread
#endif
#ifdef HL_FREEBSD
static pthread_t dsg_monitor_thread;				// Data collector thread
static pthread_mutex_t dsg_monitor_thread_mutex;	// Mutex for Data collector thread
#endif
#ifdef HL_WINALL1
static HANDLE a_mon_mutex;
static HANDLE a_mon_thread;
static DWORD  a_mon_thread_id = 0;
static bool bog_wmi_succ = true;
#endif

// system values (only used internally, access only via m_get_server_load)
static struct dsd_server_values 	dsg_values;
// system load
static struct dsd_server_load		dsg_load;
// reference values
static struct dsd_reference		dsg_ref;
static const int imrl_index[5] = { 7 , 31 , 61 , 91 , 181};
// load balancing formula
static string strg_lb_formula;
// write a logfile
static bool bog_lbdata_log = false;	
static int  img_lbdata_log_int = 6;	//multiples of 10 seconds used for logging activities
static string strg_log_file;	// name of the logfile

	
// files found
#ifdef HL_LINUX
static bool bog_diskstats = true;	// /proc/diskstats found
static bool bog_loadavg = true;	// /proc/loadavg found
static bool bog_meminfo = true;	// /proc/meminfo found
static bool bog_netdev = true;		// /proc/net/dev found
static bool bog_vmstat = true;		// /proc/vmstat found
static bool bog_stat = true;		// /proc/stat found
static bool bog_hd = true;			// /proc/mounts
static bool bog_partitions = true;
static bool bog_net = true;		// retrieving ethernet bandwidth was successful (this is false if owner is not root)
static bool bog_self_stat = true;	// /proc/self/stat found

static ull uhg_cps = 0;		// clock cycles per second

static bool bog_root_warning = false;
#endif /* HL_LINUX */

#ifdef HL_WINALL1
static bool bog_wmi_cache = true;
static bool bog_wmi_ldperf = true;
static bool bog_wmi_ld = true;
static bool bog_wmi_mem = true;
static bool bog_wmi_obj = true;
static bool bog_wmi_page = true;
static bool bog_wmi_cpu = true;
static bool bog_wmi_sys = true;
static bool bog_wmi_pp = true;
static bool bog_wmi_net = true;
static bool bog_wmi_proc = true;
static DWORD dwg_win_major_version = 6;
#endif /* HL_WINALL1 */

// is the monitor thread running
static bool bog_mont_running = false;
// load balancing formula
static c_lb_formula* dsg_formula = NULL;
// collect data
static bool bog_collect = false;

#ifdef HL_WINALL1
static DWORD WINAPI m_mon_thread_help(LPVOID)
{
	m_collect_data(NULL);
	return 0;
}
#endif


#ifdef HL_FREEBSD
static int m_sysctl(const char* achp_oid, char* achp_buffer, int imp_buffersize)
{
	// clear buffer
	memset(achp_buffer, 0, imp_buffersize);
	int iml_ret = 1;
	FILE *dsl_in;
    //extern FILE *popen();
	char chrl_command[512];
	int iml_found = 0;
	sprintf(chrl_command, "sysctl -n %s", achp_oid);
	if(!(dsl_in = popen(chrl_command, "r")))
	{
		printf("xs-lbal-win-1: Error: could not call command %s\n", chrl_command);
        return 1;
	}
	while(fgets(achp_buffer, imp_buffersize, dsl_in)!=NULL)
	{
	    iml_ret = 0;
	}
	pclose(dsl_in);
	if(iml_ret)
	{
		printf("xs-lbal-win-1: Warning: Could not get sysctl item %s.\n", achp_oid);
	}
	return iml_ret;
}

static int m_procstat(int imp_pid)
{
	FILE* dsl_procstat_r;
	char chrl_command[512];
	sprintf(chrl_command, "procstat -r %d", imp_pid);
	if(!(dsl_procstat_r = popen(chrl_command, "r")))
	{

		return 1;
	}
	char chrl_buffer[512];
	while(fgets(chrl_buffer, 512, dsl_procstat_r)!=NULL)
	{

		int iml_token_counter = 0;
		char* achl1 = strtok(chrl_buffer, " ");
		c_fifo_array<ull, 181>* adsl_fifo_array = NULL;
		int iml_value_type = 0;		// 1 = int, 2 = time (hh:mm:ss.xxxxx)
		while(achl1)
		{
			adsl_fifo_array = NULL;
			if(iml_token_counter == 2)	// resource name
			{
				do
				{

					if(!strcmp(achl1, "user time"))
					{
						adsl_fifo_array = &(dsg_values.dsl_proc_user_time);
						iml_value_type = 2;
						break;
					}
				}
				while(0);
			}
			if (iml_token_counter == 3)	//	resource value
			{
				if (iml_value_type == 1)
				{
					adsl_fifo_array->m_add_element(strtoull(achl1, NULL, 10));
				}
				else if (iml_value_type == 2)
				{
					ull uhl_microseconds = 0;
					int iml_token_count = 0;
					char* achl2 = strtok(achl1, ":.");
					while(achl2)
					{
						int iml_value = atoi(achl2);
						if (iml_token_count == 0)	// hours
						{
							uhl_microseconds += (iml_value * 3600 * 1000000);
						}
						else if (iml_token_count == 1)	// minutes
						{
							uhl_microseconds += (iml_value * 60 *1000000);
						}
						else if (iml_token_count == 2)	// seconds
						{
							uhl_microseconds += (iml_value * 1000000);
						}
						else if (iml_token_count == 3)	// microseconds
						{
							uhl_microseconds += (ull) iml_value;
						}
						iml_token_count++;
						achl2 = strtok(NULL, ":.");
					}
					adsl_fifo_array->m_add_element(uhl_microseconds);
				}
			}
			iml_token_counter++;
			achl1 = strtok(NULL, " ");
		}
	}
	pclose(dsl_procstat_r);
	return 0;
}
#endif

// String tokenizer
static void m_str_tok(	const string& strp_full,				// string that has to be tokenized
                vector<string>& dsp_tokens)				// Vector of tokens		
{
	// Skip delimiters at beginning.
    string::size_type iml_last_pos = strp_full.find_first_not_of(" ", 0);
    // Find first "non-delimiter".
    string::size_type iml_pos     = strp_full.find_first_of(" ", iml_last_pos);

    while (string::npos != iml_pos || string::npos != iml_last_pos)
    {
        // Found a token, add it to the vector.
        dsp_tokens.push_back(strp_full.substr(iml_last_pos, iml_pos - iml_last_pos));
        // Skip delimiters.  Note the "not_of"
        iml_last_pos = strp_full.find_first_not_of(" ", iml_pos);
        // Find next "non-delimiter"
        iml_pos = strp_full.find_first_of(" ", iml_last_pos);
    }
}

// get line imp_line from file dsp_file, the line is written in the passed string pointer
static bool m_get_line_from_file(int imp_line, char*  dsp_file, /*[out]*/ string* astrp_line)
{
	ifstream dsl_file(dsp_file);
	if(!dsl_file)
	{
		cerr << "WARNING: The file " << dsp_file << " could not be found. The concerned data will be ignored in the load balancing algorithm." << endl;
		astrp_line = NULL;
		return false;
	}
	for (int iml1=0; iml1<imp_line; iml1++)
	{
		getline(dsl_file,*astrp_line);
	}
	
	dsl_file.close();
	return true;
}

// get an array of strings from one line of a file (divided on chp_delimiter)
static bool m_get_line_from_file(int imp_line, char* dsp_file, const string& strp_delimiter, /*[out]*/vector<string>& adsp_line_token)
{
	ifstream dsl_file(dsp_file);
	if(!dsl_file)
	{
		cerr << "WARNING: The file " << dsp_file << " could not be found. The concerned data will be ignored in the load balancing algorithm." << endl;
		adsp_line_token.clear();
		return false;
	}	
	string strl_line;
	for (int iml1=0; iml1<imp_line; iml1++)
	{
		getline(dsl_file,strl_line);
	}
	m_str_tok(strl_line, adsp_line_token);
	dsl_file.close();
	return true;
}
#ifdef HL_WINALL1
static bool m_is_bstr_equal(BSTR strp1, BSTR strp2)
{
	CComBSTR strl_bstr1(strp1);
	CComBSTR strl_bstr2(strp2);
	if (strl_bstr1 == strl_bstr2) return true;
	else return false;
}

static unsigned long long m_ull_pow (unsigned long long uhp_basis, unsigned long long uhp_exponent)
{
	if (uhp_exponent == 0) return 1;
	unsigned long long uhl_result = 1;
	for (unsigned long long i = 0; i < uhp_exponent; i++)
	{
		uhl_result *= uhp_basis;
	}
	return uhl_result;
}

static unsigned long long m_bstr_to_ull (BSTR strp_bstr)
{
	USES_CONVERSION;
	
	const unsigned short usl_buffer_size = 128;
	unsigned long long uhl_result = 0;
	int iml_power_of_ten = 0;

	//LPTSTR achl_value = new TCHAR[64];
	char chrl_value[64];
	strcpy(chrl_value, OLE2A(strp_bstr));
	unsigned int uml_length = strlen(chrl_value);
	if (uml_length == 0)
	{
		uhl_result = 0;
	}
	else
	{
		for (int iml1 = uml_length - 1; iml1>=0; iml1--)
		{
			if (chrl_value[iml1] >= 48)
			{
				uhl_result += (((int)(chrl_value[iml1]) - 48) * m_ull_pow(10,iml_power_of_ten));
			}
			iml_power_of_ten++;
		}
	}
	//delete[] achl_value;
	return uhl_result;
}

static HRESULT m_get_ull_wmi_value(CComPtr<IWbemClassObject> dsl_obj, LPCWSTR strp_property, ull* uhp_value)
{
	HRESULT ill_ret = 0;
	CComVariant dsl_var;
	
	ill_ret = dsl_obj->Get(strp_property, 0, &dsl_var, 0, 0);
	if (SUCCEEDED(ill_ret) && (V_VT(&dsl_var) == VT_BSTR))
	{
		*uhp_value = m_bstr_to_ull(V_BSTR(&dsl_var));
	}
	else
	{
		*uhp_value = 0;
	}
	return ill_ret;
}

static HRESULT m_get_long_wmi_value(CComPtr<IWbemClassObject> dsl_obj, LPCWSTR strp_property, LONG* ill_value)
{
	HRESULT ill_ret = 0;
	CComVariant dsl_var;
	ill_ret = dsl_obj->Get(strp_property, 0, &dsl_var, 0, 0);
	if (SUCCEEDED(ill_ret) && (V_VT(&dsl_var) == VT_I4))
	{
		*ill_value = dsl_var.lVal;
	}
	else
	{
		*ill_value = 0;
	}
	return ill_ret;
}

static HRESULT m_get_bstr_wmi_value(CComPtr<IWbemClassObject> dsl_obj, LPCWSTR strp_property, wchar_t* achp_value, const unsigned int ump_buffersize)
{
	HRESULT ill_ret = 0;
	CComVariant dsl_var;
	
	ill_ret = dsl_obj->Get(strp_property, 0, &dsl_var, 0, 0);
	if (SUCCEEDED(ill_ret) && (V_VT(&dsl_var) == VT_BSTR))
	{
		wchar_t chrl_value[512];// determine the number of bytes required
		memset(chrl_value,0,512);	// do the actual conversion	
		UINT uml_len = SysStringLen(V_BSTR(&dsl_var));
		//int iml_num_chars = WideCharToMultiByte(CP_UTF8,0,V_BSTR(&dsl_var),uml_len,chrl_value,512,NULL,NULL);
		if (uml_len == 0)
		{
			achp_value = L"";
		}
		else
		{
			//strncpy(achp_value, chrl_value, ump_buffersize);
			wcsncpy(achp_value, dsl_var.bstrVal, min(uml_len, ump_buffersize));
		}
	}
	else
	{
		achp_value = L"";
	}
	return ill_ret;
}


#endif /* HL_WINALL1 */
#ifdef HL_LINUX
// get data from procfs
static string m_get_data(struct dsd_proc dsp_proc)
{
	vector<string>* adsl_temp = new vector<string>();
	m_get_line_from_file(dsp_proc.iml_line,
						 dsp_proc.achl_file,
						 " ",
						 *adsl_temp);
	string strl_ret = adsl_temp->at(dsp_proc.iml_element-1);
	return strl_ret;	
}
#endif /* HL_LINUX */


#ifdef HL_LINUX
/*-- function imported from wireless-tools --*/
 /* Open a socket.
 * Depending on the protocol present, open the right socket. The socket
 * will allow us to talk to the driver.
 */
static int iw_sockets_open(void)
{
  static const int families[] = {
    AF_INET, AF_IPX, AF_AX25, AF_APPLETALK
  };
  unsigned int	i;
  int		sock;

  /*
   * Now pick any (exisiting) useful socket family for generic queries
   * Note : don't open all the socket, only returns when one matches,
   * all protocols might not be valid.
   * Workaround by Jim Kaba <jkaba@sarnoff.com>
   * Note : in 99% of the case, we will just open the inet_sock.
   * The remaining 1% case are not fully correct...
   */

  /* Try all families we support */
  for(i = 0; i < sizeof(families)/sizeof(int); ++i)
    {
      /* Try to open the socket, if success returns it */
      sock = socket(families[i], SOCK_DGRAM, 0);
      if(sock >= 0)
	return sock;
  }

  return -1;
}
#endif /* HL_LINUX */

// return if the given filename is a device in /dev fs
static bool m_is_dev(char* achp_name)
{
	
	if(strlen(achp_name) < 4 || strlen(achp_name)>12) return false;
	if (strncmp(achp_name,"rootfs",6) == 0 || strncmp(achp_name,"/dev",4) == 0) return true;
	else return false;
		
}

// create a formula tree node. Pass the token and a pointer to the parent node
c_lb_tree_node::c_lb_tree_node(c_formula_token* adsp_token, c_lb_tree_node* adsp_parent)
{
	dsl_token = *adsp_token;
	adsl_parent = adsp_parent;
	dsl_children = new vector<c_lb_tree_node*>();
	iml_children = 0;
	iml_type = adsp_token->m_get_type();
	if (iml_type == 4)	// node represents a constant
	{
		fdl_value = strtod(adsp_token->m_get_text().c_str(),NULL);
	}
	else fdl_value = 0;
}

// set the value of this node
void c_lb_tree_node::m_set_value (double fdp_value)
{
	fdl_value = fdp_value;
}

// add a child node
void c_lb_tree_node::m_add_child(c_lb_tree_node* adsp_child)
{
	iml_children++;
	dsl_children->push_back(adsp_child);
}

// calculate the value of this node
double c_lb_tree_node::m_operate()
{
	switch (iml_type)
	{
		// if this node represents a constant or a variable --> return the value
		case CONSTANT:
		case VARIABLE:
			return fdl_value;

		// if the node is an infix operator
		case INFIX_OPERATOR:
			if (iml_children != 2)
			{
				return -1;				// invalid number of children
			}
			else
			{
				c_lb_tree_node* dsl_left = dsl_children->at(0);
				c_lb_tree_node* dsl_right = dsl_children->at(1);
				string strl_op = dsl_token.m_get_text();
				// call m_operate on all children and add (subtract, multiply, divide) the results
				if (strl_op.compare("+") == 0)
				{
					return dsl_left->m_operate() + dsl_right->m_operate();
				}	
				else if (strl_op.compare("-") == 0)
				{
					return dsl_left->m_operate() - dsl_right->m_operate();
				}
				else if (strl_op.compare("*") == 0)
				{
					return dsl_left->m_operate() * dsl_right->m_operate();
				}
				else if (strl_op.compare("/") == 0)
				{
					double fdl_right_value = dsl_right->m_operate();
					if (fdl_right_value == 0)		// division by 0
					{
						return 0;
					}
					else return dsl_left->m_operate() / fdl_right_value;
				}
				else return 0;
			}
		// if the node is a prefix operator
		case PREFIX_OPERATOR:
		{	
			if (iml_children < 1)	// invalid number of children
			{
				return -1;
			}
			// get the operator
			string strl_op = dsl_token.m_get_text();
			c_lb_tree_node* dsl_node;					// working variable
			// iterator for all children of this node
			vector<c_lb_tree_node*>::iterator dsl_vit;
			// Operator is max
			if (strl_op.compare("MAX") == 0)
			{
				double fdl_max = 0;
				for (dsl_vit = dsl_children->begin(); dsl_vit!= dsl_children->end(); dsl_vit++)
				{
					dsl_node = *dsl_vit;
					fdl_max = max(fdl_max,dsl_node->m_operate());
				}
				return fdl_max;
			}
			// Operator is min
			else if (strl_op.compare("MIN") == 0)
			{
				double fdl_min = 200000;
				for (dsl_vit = dsl_children->begin(); dsl_vit!= dsl_children->end(); dsl_vit++)
				{
					dsl_node = *dsl_vit;
					fdl_min = min(fdl_min,dsl_node->m_operate());
				}
				return fdl_min;
			}
			// Operator is sqr
			else if (strl_op.compare("SQR") == 0)
			{
				if (iml_children != 1)
				{
					return 0;
				}
				else if (iml_children == 1)
				{
					c_lb_tree_node* dsl_node = dsl_children->at(0);
					fdl_value = dsl_node->m_operate();		// value of the child
					if (fdl_value > 0)
					{
						return sqrt(dsl_node->m_operate());
					}
					// if the value is negative -> no sqr allowed -> return 0
					else return 0;
				}
			}
			// Operator is exp
			else if (strl_op.compare("EXP") == 0)
			{
				if (iml_children < 1 )	// invalid number of children
				{
					return 0;
				}
				else if (iml_children == 1)		// use Eulerian number as base
				{
					c_lb_tree_node* dsl_node = dsl_children->at(0);
					return pow(2.718281,dsl_node->m_operate());
				}
				else if (iml_children >=2)
				{
					c_lb_tree_node* dsl_left_node = dsl_children->at(0);	// base node
					c_lb_tree_node* dsl_right_node = dsl_children->at(1);	// exponent node
					return pow(dsl_left_node->m_operate(),dsl_right_node->m_operate());
				}
			}
			// Operator is log
			else if (strl_op.compare("LOG") == 0)
			{
				if (iml_children < 1)	// invalid number of children
				{
					return 0;
				}
				else if (iml_children == 1)		// use natural logarithm (base Eulerian number (2.718))
				{
					c_lb_tree_node*	dsl_node = dsl_children->at(0);
					return log(dsl_node->m_operate());
				}
				else if (iml_children >=2)	
				{
					c_lb_tree_node* dsl_left_node = dsl_children->at(0);	// value node
					c_lb_tree_node* dsl_right_node = dsl_children->at(1);	// base node
					double fdl_left_value = dsl_left_node->m_operate();
					double fdl_right_value = dsl_right_node->m_operate();
					// both the base and the value you want the logarithm from must be positive other wise 0
					if (fdl_left_value <= 0 || fdl_right_value <= 0)
					{
						return 0;
					}
					double fdl_divisor = log(fdl_right_value);
					if (fdl_divisor != 0)
					{
						return log(fdl_left_value) / fdl_divisor;
					}
					else return 0;
				}
			}
			else return 0;

		}
		// default case is 0 (should not occur)
		default: return 0;
	}
}

//free the allocated memory of this node and all subnodes
void c_lb_tree_node::m_free()
{
	vector<c_lb_tree_node*>::iterator dsl_vit;
	for (dsl_vit = dsl_children->begin(); dsl_vit!= dsl_children->end(); dsl_vit++)
	{
		c_lb_tree_node* dsl_node = *dsl_vit;
		dsl_node->m_free();
	}
	delete this;
}

// getter
c_lb_tree_node* c_lb_tree_node::m_get_parent()
{
	return adsl_parent;
}

int c_lb_tree_node::m_get_type()
{
	return iml_type;
}

double c_lb_tree_node::m_get_value()
{
	return fdl_value;
}

string c_lb_tree_node::m_get_text()
{
	return dsl_token.m_get_text();
}

// get depth of the corresponding token
int c_lb_tree_node::m_get_depth()
{
	return dsl_token.m_get_depth();
}

// create a new load balancing formula object. Pass the string and a bool that indicates if the processor load of the process should be monitored
c_lb_formula::c_lb_formula(string strp_form, bool bop_proc_load )
{
	bol_proc_load = bop_proc_load;
	strl_formula = strp_form;
	//dsl_token = new vector<c_formula_token>();
	dsl_variable_nodes = new vector<c_lb_tree_node*>();
	adsl_root = NULL;
	m_parse_formula(strp_form, false);
}

// divide the formula into tokens (variables, operators, separators and constants)
// and put them into a list of tokens (dsl_token)
int c_lb_formula::m_tokenize(string strp_form)
{
	string strl_work ="";			// working variable
	int iml_length = strp_form.length();	// length of the formula
	int iml_brackets = 0;			// number of opened brackets - number of closed brackets
	// trim the formula (delete white spaces)
	for (int iml1 = 0 ; iml1< iml_length ; iml1++)
	{
		if (strp_form.at(iml1) != ' ')
		{
			strl_work += strp_form.at(iml1);
		}
	}
	iml_length = strl_work.length();		// strl_work is the trimmed lb formula
	// no formula
	if (iml_length == 0)
	{
		m_hl1_printf("xs-lbal-win-%05d - Error 1: The formula has length 0.",__LINE__);
		return 1;
	}
	char chl1;	//working variable
	string strl1 = "";	// current token

	for (int iml1 = 0; iml1 < iml_length; )	// start a search through all characters of the formula
	{
		int iml_rest = iml_length - iml1; // the number of remaining chars until the end of the formula
		chl1 = strl_work.at(iml1);		  // current character
		// test brackets
		// Note: brackets will not be added to the token list. This is not necessary
		//		 because we know the depth of each token in the formula which is given
		//		 by the iml_brackets variable in the c_formula_token constructor
		if (chl1 == '(')		// current character is an opening bracket
		{
			
			if (iml1+1 >= iml_length)
			{
				// formula ends with '('
				m_hl1_printf("xs-lbal-win-%05d - Error 3: The formula ends with an opening bracket.", __LINE__);
				return 3;
			}
			
			if (c_formula_token::m_is_simple_operator(strl_work.at(iml1+1)))
			{	
				// infix operator after a bracket ==> Syntax error
				m_hl1_printf("xs-lbal-win-%05d - Error 2: Syntax error in the formula", __LINE__);
				return 2;
			}

			iml_brackets++;
			iml1++;
			continue;	// goto next character
		}
		if (chl1 == ')')
		{
			if (iml1-1 >= 0 && c_formula_token::m_is_simple_operator(strl_work.at(iml1-1)))
			{	
				// infix operator before a bracket ==> Syntax error
				m_hl1_printf("xs-lbal-win-%05d - Error 4: Syntax error in the formula",__LINE__);
				return 4;
			}
			if (iml1-1 < 0)
			{
				// formula starts with ')'
				m_hl1_printf("xs-lbal-win-%05d - Error 5: The formula begins with a closing bracket",__LINE__);
				return 5;
			}
			iml_brackets--;
			iml1++;
			continue;	// goto next character
		}
		// test simple operators (+,-,*,/)
		if (c_formula_token::m_is_simple_operator(chl1))
		{
			// is the minus an operator (false) or a prefix of a negative number (true)
			bool bol_minus_prefix = false;
			// it is a prefix if there are no previous tokens ...
			if (dsl_token.size() == 0)
			{
				bol_minus_prefix = true;
			}
			// ... or if the previous token is not a constant and not a variable
			else if (dsl_token.back().m_get_type()!=CONSTANT && dsl_token.back().m_get_type()!=VARIABLE)
			{
				bol_minus_prefix = true;
			}

			// if the minus is a prefix ...
			if ( chl1 == '-' && bol_minus_prefix)
			{
				// and the next character is a digit we have a negative number
				if(iml_rest > 1 && c_formula_token::m_is_digit(strl_work.at(iml1+1)))
				{

					strl1 += '-';
					// search for next non digit in the rest of the formula
					int iml_count = 1;
					for (int iml2 = iml1+1; iml2< iml_length; iml2++)
					{
						char chl2 = strl_work.at(iml2); // current char
						if (c_formula_token::m_is_digit(chl2))	// another digit found
						{
							iml_count++;		// increase length
							strl1 += chl2;		// add the digit to the temporary string
						}
						else break;			// end loop if char is not a digit
					}
					iml1 += iml_count;
					// create new token
					dsl_token.push_back(c_formula_token(strl1,iml_brackets, CONSTANT));
					strl1.clear();
					continue;
				}
			}

			// create new token
			dsl_token.push_back(c_formula_token(strl_work.substr(iml1,1),iml_brackets,INFIX_OPERATOR));
			iml1++;
			continue;	// goto next character
		}
		// test separators (,)
		if (c_formula_token::m_is_separator(chl1))
		{
			// create new token
			dsl_token.push_back(c_formula_token(",",iml_brackets,SEPARATOR));
			iml1++;
			continue;	// goto next character
		}
		// test constants (numbers)
		if (c_formula_token::m_is_digit(chl1))	//current char is a digit
		{
			// count length of number
			int iml_count = 1;
			strl1 += chl1;			// add the current digit to the temporary string
			// search for next non digit in the rest of the formula
			for (int iml2 = iml1+1; iml2< iml_length; iml2++)
			{
				char chl2 = strl_work.at(iml2); // current char
				if (c_formula_token::m_is_digit(chl2))	// another digit found
				{
					iml_count++;		// increase length
					strl1 += chl2;		// add the digit to the temporary string
				}
				else break;			// end loop if char is not a digit
			}
			iml1 += iml_count;	// increase the loop counter by the length of the recently found constant
			// create new token
			dsl_token.push_back(c_formula_token(strl1,iml_brackets,CONSTANT));
			strl1.clear();		// clear temporary string
			continue;			// goto next character
		}
		// test complex operators (MAX,MIN)
		// current char is upper case letter and there are more than 5 characters remaining (necesarry for MIN and MAX)
		if (c_formula_token::m_is_letter(chl1) && iml_rest >=5)
		{
			if (strcmp(strl_work.substr(iml1,3).c_str(),"MAX") == 0)		// MAX found
			{
				if (strl_work.at(iml1+3) != '(')	// syntax error (no bracket after MAX)
				{
					m_hl1_printf("xs-lbal-win-%05d - Error 6: Syntax error (no opening bracket after MAX)",__LINE__);
					return 6;
				}
				// create new token
				dsl_token.push_back(c_formula_token("MAX",iml_brackets,PREFIX_OPERATOR));
				iml1 +=3;	// increase loop counter by 3
				continue;	// goto next character
			}
			if (strcmp(strl_work.substr(iml1,3).c_str(),"MIN") == 0)		// MIN found
			{
				if (strl_work.at(iml1+3) != '(')	// syntax error (no bracket after MIN)
				{
					m_hl1_printf("xs-lbal-win-%05d - Error 7: Syntax error (no opening bracket after MIN)",__LINE__);
					return 7;
				}
				//create new token
				dsl_token.push_back(c_formula_token("MIN",iml_brackets,PREFIX_OPERATOR));
				iml1 += 3;	// increase loop counter by 3
				continue;	// goto next character
			}
			if (strcmp(strl_work.substr(iml1,3).c_str(),"LOG") == 0)		// logarithm found
			{
				if (strl_work.at(iml1+3) != '(')	// syntax error (no bracket after LOG)
				{
					m_hl1_printf("xs-lbal-win-%05d - Error 8: Syntax error (no opening bracket after LOG)",__LINE__);
					return 8;
				}
				// create new token
				dsl_token.push_back(c_formula_token("LOG",iml_brackets,PREFIX_OPERATOR));
				iml1 += 3;	// increase loop counter by 3
				continue;
			}
			if (strcmp(strl_work.substr(iml1,3).c_str(),"EXP") == 0)		// exponential function found
			{
				if (strl_work.at(iml1+3) != '(')	// syntax error (no brackets after EXP)
				{
					m_hl1_printf("xs-lbal-win-%05d - Error 9: Syntax error (no opening bracket after EXP)",__LINE__);
					return 9;
				}
				// create new token
				dsl_token.push_back(c_formula_token("EXP",iml_brackets,PREFIX_OPERATOR));
				iml1 += 3;	// increase loop counter by 3
				continue;
			}
			if (strcmp(strl_work.substr(iml1,3).c_str(),"SQR") == 0)		// root found
			{
				if (strl_work.at(iml1+3) != '(')	// syntax error (no brackets after SQR)
				{
					return 16;
				}
				// create new token
				dsl_token.push_back(c_formula_token("SQR",iml_brackets,PREFIX_OPERATOR));
				iml1 +=3;	// increase loop counter by 3
				continue;
			}
		}
		// try to find a variable
		if (c_formula_token::m_is_letter(chl1) && iml_rest >=5)		// variable candidate (because start with letter)
		{
			int iml2 = iml1+1;	// the following character
			strl1 += chl1;		// add the current letter to the working string
			int iml_len_cnt = 1;	// length of the found variable name
			// search for next char that is not a letter, underscore or a digit
			while (iml2 < iml_length)	// until the end of the formula is reached
			{
				if (strl_work.at(iml2) == '_')		// underscore found
				{
					if (iml2+1 >= iml_length)		// formula ends with a '_' ==> syntax error
					{
						m_hl1_printf("xs-lbal-win-%05d - Error 10: Syntax error (invalid last character)",__LINE__);
						return 10;
					}
					else
					{
						strl1 += '_';		// add underscore
						iml_len_cnt++;		// increase loop counter
						iml2++;
						continue;			// goto next character
					}
				}
				else if (c_formula_token::m_is_digit(strl_work.at(iml2)))	// digit found
				{
					char chl2 = strl_work.at(iml2-1);	// char before the current char
					// if the char before the current digit is not an underscore or another digit,
					// this is a syntax error
					if (!c_formula_token::m_is_digit(chl2) && !c_formula_token::m_is_underscore(chl2))
					{
						m_hl1_printf("xs-lbal-win-%05d - Error 11: Syntax error (a digit follows after a letter)",__LINE__);
						return 11;
					}
					else	// digit is syntactically correct at this position
					{
						strl1 += strl_work.at(iml2);	// add digit to working string
						iml_len_cnt++;			// increase variable length counter
						iml2++;
						continue;				// goto next character
					}
				}
				else if (c_formula_token::m_is_letter(strl_work.at(iml2)))	// upper case letter found
				{
					strl1 += strl_work.at(iml2);	// add letter to working string
					iml_len_cnt++;					// increase variable length counter
					iml2++;
					continue;						// goto next character
				}
				// separator or operator found (this means the variable is completed)
				else if (c_formula_token::m_is_simple_operator(strl_work.at(iml2))
					|| c_formula_token::m_is_separator(strl_work.at(iml2))) // end sign of the variable
				{
					break;
				}
				// bracket found
				else if (strl_work.at(iml2) == '(' || strl_work.at(iml2) == ')')
				{
					break;
				}
				// invalid char == > syntax error
				else
				{
					m_hl1_printf("xs-lbal-win-%05d - Error 12: Syntax error (invalid character)",__LINE__);
					return 12;
				}
				iml2++;
			}
			if (dsl_var.m_contains(strl1))		// the found variable is valid
			{
				
				// create new token
				dsl_token.push_back(c_formula_token(strl1,iml_brackets,VARIABLE));
				strl1.clear();
				iml1 += iml_len_cnt;
				continue;
			}
			else
			{
				
				m_hl1_printf("xs-lbal-win-%05d - Error 13: The formula contains invalid variables",__LINE__);
				return 13;					// invalid variable
			}
			strl1.clear();
		}
		m_hl1_printf("xs-lbal-win-%05d - Error 14: LB Formula error: no valid token found",__LINE__);
		return 14;		// no valid token found
	}

	if (iml_brackets != 0)
	{
		m_hl1_printf("xs-lbal-win-%05d - Error 15: Syntax error. Check the number of opening and closing brackets.",__LINE__);
		return 15;		// syntax error
	}
	if (dsl_token.size() == 0)	return 1;	// no tokens found
	return 0;
}

/* test the token vector for further syntax errors that could not be found in the m_tokenize method */
int c_lb_formula::m_check_syntax()
{
	int iml_ret = 0 ;
	int iml_index = -1;						// current index
	int iml_length = dsl_token.size()-1;	// max index
	// return false if the formula starts or ends with a ','
	
	/*if (dsl_token.at(0).m_get_type() == 3 || dsl_token.at(iml_length).m_get_type() == 3)
	{
		m_hl1_printf("xs-lbal-win-%05d - Error 21: Syntax error (invalid character in first or last position.",__LINE__);
		return 21;
	}*/
	// iterate all tokens
	vector<c_formula_token>::iterator dsl_vit;
	for (dsl_vit = dsl_token.begin(); dsl_vit != dsl_token.end(); ++dsl_vit)
	{
		iml_index++;
		// one of the parameters PROC_CPU_n was used. This is not allowed if the process load
		// is not being monitored
		if (dsl_vit->m_get_type() == 1 && !bol_proc_load)
		{
			if (dsl_vit->m_get_text().compare("PROC_CPU_1") == 0 ||
				dsl_vit->m_get_text().compare("PROC_CPU_5") == 0 ||
				dsl_vit->m_get_text().compare("PROC_CPU_10") == 0 ||
				dsl_vit->m_get_text().compare("PROC_CPU_15") == 0 ||
				dsl_vit->m_get_text().compare("PROC_CPU_30") == 0)
			{
				m_hl1_printf("xs-lbal-win-%05d - Error 13: The formula contains invalid variables.",__LINE__);
				return 13;		// invalid variable
			}
		}

		
		// two successive tokens can't be infix operators
		if (iml_index+1 <= iml_length &&  dsl_vit->m_get_type() ==2 && dsl_token.at(iml_index+1).m_get_type() == 2)
		{
			m_hl1_printf("xs-lbal-win-%05d - Error 22: Syntax error (two successive infic operators).",__LINE__);
			return 22;
		}
		// test if predecessor and successor of a separator are valid (variables or constants)
		else if (iml_index > 0 && iml_index < iml_length && dsl_vit->m_get_type() == 3)
		{
			c_formula_token* adsl_prev = &(dsl_token.at(iml_index - 1));	// previous token
			c_formula_token* adsl_next = &(dsl_token.at(iml_index + 1));	// next token
			if (adsl_prev->m_get_type() != 1 && adsl_prev->m_get_type() != 4)
			{
				// previous token is not a valid predecessor for a separator
				m_hl1_printf("xs-lbal-win-%05d - Error 23: Syntax error (invalid separator)",__LINE__);
				return 23;
			}

			if (adsl_next->m_get_type() != 1 && adsl_next->m_get_type() != 4 && adsl_next->m_get_type() != 5)
			{
				// next token is not a valid successor for a separator
				m_hl1_printf("xs-lbal-win-%05d - Error 24: Syntax error (invalid separator)",__LINE__);
				return 24;
			}
		}
	}
	// reset index counter
	iml_index = -1;
	// iterate all tokens
	vector<c_formula_token>::iterator dsl_vit2;
	for (dsl_vit2 = dsl_token.begin(); dsl_vit2 != dsl_token.end(); ++dsl_vit2)
	{
		iml_index++;
		// insert multiplications if a variable follows after a constant
		// the depth of the new token will always be the lower one
		if (iml_index + 1 <= iml_length && ((*dsl_vit2).m_get_type() == 4 || (*dsl_vit2).m_get_type() == 1) && (dsl_token.at(iml_index+1).m_get_type() == 1 || dsl_token.at(iml_index+1).m_get_type() == 5))
		{
			// insert a '*' token
			dsl_token.insert(dsl_vit+1, c_formula_token("*",min((*dsl_vit2).m_get_depth(),dsl_token.at(iml_index+1).m_get_depth()),2));
			// reset iterator
			dsl_vit2 = dsl_token.begin();
		}
	}
	return iml_ret;
}

/*	parse a list of tokens and create tree nodes. The function will be called recursively
*	Each call creates a new node by searching the highest level token in the part of
*	dsl_token vector between the indices iml_lo and iml_hi (both inclusive). dsp_parent should always
*	be the current calling node and dsp_child a pointer to the pointer to the node to be created.
*	After the creation of the new node pointers of the child nodes of the new node are
*	being created. After that this function will be called recursively to create new
*	nodes. This will continue until no further tokens are remaining and the tree is
*	complete. So this function has to be called only once with the following syntax:
*	m_parse(null,&adsl_root, 0, dsl_token.size()-1)			*/
int c_lb_formula::m_parse(c_lb_tree_node* adsp_parent, c_lb_tree_node** adsp_child, int imp_lo, int imp_hi)
{
	int iml_high_prio = -1;		// highest found priority
	int iml_index = 0;			// index of the token that represents the node to be created
	c_formula_token* adsl_token = NULL;	// token used to create the new node
	c_formula_token* adsl1;		// working variable
	
	/*--------------------- find token with highest priority -------------------*/
	if (imp_hi-imp_lo == 0)		// only one token remaining
	{
		adsl_token = &(dsl_token.at(imp_lo));
	}
	else
	{	
		bool bop_opsep = false;	// operator or separator found in the current depth
		// loop over the depth of the tokens
		for (int iml1 = 0; iml1 < 32; iml1++)	
		{
			// loop over the part of the token list that is given by imp_lo and imp_hi
			for (int iml2 = imp_lo; iml2 <= imp_hi; iml2++)
			{
				adsl1 = &(dsl_token.at(iml2));
				int iml_t = adsl1->m_get_type();	// temporary type variable
				if (adsl1->m_get_depth() == iml1 && (iml_t == 2 || iml_t == 3 || iml_t == 5   ))
				{	//Operator or separator found
					bop_opsep = true;
					// if the found operator has higher priority than the current one
					if (adsl1->m_get_prio() > iml_high_prio)
					{
						iml_high_prio = adsl1->m_get_prio();	// set new highest priority
						iml_index = iml2;						// set new index
						adsl_token = adsl1;						// set pointer to most important token
					}
				}
			}
			if (bop_opsep) break;	// an operator was found. we don't have to search for operators
									// with higher iml_depth
		}
	}

	// create new node
	*adsp_child = new c_lb_tree_node(adsl_token,adsp_parent);

	// store the node pointer in a special list for all variables if it is a variable
	if ((*adsp_child)->m_get_type() == 1)
	{
		dsl_variable_nodes->push_back((*adsp_child));
	}

	// if the new node is an infix operator
	if ((*adsp_child)->m_get_type() == INFIX_OPERATOR)
	{
		// create the tokenlist for the children of the current node
		int iml_left_lo = imp_lo;	// lower index of the left child
		int iml_left_hi = iml_index-1;	// upper index of the left child
		int iml_right_lo = iml_index+1;	// lower index of the right child
		int iml_right_hi = imp_hi;		// upper index of the right child
		if (iml_left_hi < iml_left_lo)	// no left child --> Error
		{
			m_hl1_printf("xs-lbal-win-%05d - Error 31: Syntax error (invalid infix operation)",__LINE__);
			return 31;
		}
		if (iml_right_hi < iml_right_lo)	// no right child --> Error
		{
			m_hl1_printf("xs-lbal-win-%05d - Error 32: Syntax error (invalid infix operation)",__LINE__);
			return 32;
		}
		// create pointers for the two child nodes
		c_lb_tree_node* dsl_left_child;
		c_lb_tree_node* dsl_right_child;

		// parse the remaining token list to create the child nodes
		m_parse((*adsp_child),&dsl_left_child,iml_left_lo,iml_left_hi);
		m_parse((*adsp_child),&dsl_right_child,iml_right_lo,iml_right_hi);

		// add the pointers to the list of children
		(*adsp_child)->m_add_child(dsl_left_child);
		(*adsp_child)->m_add_child(dsl_right_child);
	}
	// if the new node is a prefix operator
	else if ((*adsp_child)->m_get_type() == PREFIX_OPERATOR)
	{
		if (iml_index+1 > imp_hi)	// no right child --> Error
		{
			m_hl1_printf("xs-lbal-win-%05d - Error 33: Syntax error (invalid prefix operator)",__LINE__);
			return 33;
		}
		// loop over all remaining tokens
		int iml_lo = iml_index+1;	// index of most left token of the next child
		int iml_hi = iml_index;	// index of most right token of the next child
		int iml_cur_depth = (*adsp_child)->m_get_depth();
		for (int iml1 = iml_index+1; iml1<=imp_hi; iml1++)
		{
			// pointer to the next token
			c_formula_token* dsl_tok = &(dsl_token.at(iml1));
			// if a separator is found and the depth is iml_cur_depth+1 or the end is reached
			if (dsl_tok->m_get_type() == SEPARATOR && dsl_tok->m_get_depth()-iml_cur_depth == 1)
			{
				// create child
				c_lb_tree_node* dsl_child;
				m_parse((*adsp_child),&dsl_child,iml_lo,iml_hi);
				(*adsp_child)->m_add_child(dsl_child);

				iml_lo = iml1+1;	// set new left border for the next child
				iml_hi = iml1;
				continue;
			}
			// if the last token is reached
			if (iml1 == imp_hi)
			{
				// create child
				c_lb_tree_node* dsl_child;
				m_parse((*adsp_child),&dsl_child,iml_lo,imp_hi);
				(*adsp_child)->m_add_child(dsl_child);
				continue;
			}
			iml_hi++;	// increase the index of the right border of the next child
		}
	}
	return 0;
}


/* parse the passed formula string and create a formula tree if the formula is valid. Pass true as second parameter if you only want to test if the formula is valid */
int c_lb_formula::m_parse_formula(string strp_form, bool bop_test = false)
{
	int iml_ret = 0;
	if (dsl_token.size() > 0)
		dsl_token.clear();
		
	dsl_token.reserve(100);
	// try to tokenize the formula
	iml_ret = m_tokenize(strp_form);
	if (iml_ret !=0)
	{
		if (!bop_test)
		{
			if (adsl_root == NULL)
			{
				m_set_default_formula();
			}
		}
		return iml_ret;
	}

	// try to check for syntax errors
	int iml1 = m_check_syntax();
	if (iml1!= 0)
	{
		iml_ret = iml1;
	}

	if (iml_ret != 0)
	{
		if (!bop_test)
		{
			if (adsl_root == NULL)
			{
				m_set_default_formula();
			}
		}
		return iml_ret;
	}

	if (!bop_test)
	{
		if (dsl_variable_nodes->size() > 0)
			dsl_variable_nodes->clear();	// clear the current list of variable nodes
	}
	c_lb_tree_node* adsl_temp = NULL;		// temporary root node
	
	int iml_parse = m_parse(NULL,&adsl_temp, 0, dsl_token.size()-1);
	// parsing was successful
	if (iml_parse == 0 && !bop_test)
	{
		// free memory of the old formula tree
		m_free_tree(adsl_root);
		// set root node to the root of the new formula
		adsl_root = adsl_temp;
		strl_formula = strp_form;
	}
	iml_ret = iml_parse;
	return iml_ret;
}

// set the current variable values in the formula tree
bool c_lb_formula::m_set_variables (struct dsd_server_load& dsp_load)
{
	
	// temporary node
	c_lb_tree_node* dsl_node;
	// iterator for all variable nodes
	vector<c_lb_tree_node*>::iterator dsl_vit;
	// iterate all variable nodes
	for (dsl_vit = dsl_variable_nodes->begin(); dsl_vit != dsl_variable_nodes->end(); dsl_vit++)
	{
		dsl_node = *dsl_vit;
		if (dsl_node->m_get_text().compare("SESSIONS") == 0)
		{
			if (am_get_sessions > 0)
			{
				dsl_node->m_set_value((double) am_get_sessions());
			}
			else dsl_node->m_set_value(0);
			continue;
		}
#ifdef HL_FREEBSD
		
		else if (dsl_node->m_get_text().compare("INT_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ints[0]);
		}
		else if (dsl_node->m_get_text().compare("INT_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ints[1]);
		}
		else if (dsl_node->m_get_text().compare("INT_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ints[2]);
		}
		else if (dsl_node->m_get_text().compare("INT_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ints[3]);
		}
		else if (dsl_node->m_get_text().compare("INT_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ints[4]);
		}

		else if (dsl_node->m_get_text().compare("CACHE_HIT_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_hit_rate[0] /10000);
		}
		else if (dsl_node->m_get_text().compare("CACHE_HIT_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_hit_rate[1] / 10000);
		}
		else if (dsl_node->m_get_text().compare("CACHE_HIT_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_hit_rate[2] / 10000);
		}
		else if (dsl_node->m_get_text().compare("CACHE_HIT_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_hit_rate[3] / 10000);
		}
		else if (dsl_node->m_get_text().compare("CACHE_HIT_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_hit_rate[4] / 10000);
		}

		else if (dsl_node->m_get_text().compare("CPU_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu[0] / 10000);
		}
		else if (dsl_node->m_get_text().compare("CPU_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu[1] / 10000);
		}
		else if (dsl_node->m_get_text().compare("CPU_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu[2] / 10000);
		}
		else if (dsl_node->m_get_text().compare("CPU_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu[3] / 10000);
		}
		else if (dsl_node->m_get_text().compare("CPU_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu[4] / 10000);
		}

		else if (dsl_node->m_get_text().compare("MEMORY_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_memory[0] / 10000);
		}
		else if (dsl_node->m_get_text().compare("MEMORY_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_memory[1] / 10000);
		}
		else if (dsl_node->m_get_text().compare("MEMORY_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_memory[2] / 10000);
		}
		else if (dsl_node->m_get_text().compare("MEMORY_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_memory[3] / 10000);
		}
		else if (dsl_node->m_get_text().compare("MEMORY_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_memory[4] / 10000);
		}

		else if (dsl_node->m_get_text().compare("PROC_CPU_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_cpu[0] / 10000);
		}
		else if (dsl_node->m_get_text().compare("PROC_CPU_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_cpu[1] / 10000);
		}
		else if (dsl_node->m_get_text().compare("PROC_CPU_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_cpu[2] / 10000);
		}
		else if (dsl_node->m_get_text().compare("PROC_CPU_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_cpu[3] / 10000);
		}
		else if (dsl_node->m_get_text().compare("PROC_CPU_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_cpu[4] / 10000);
		}

		else if (dsl_node->m_get_text().compare("PROC_MEM_UTIL_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_memory[0] / 10000);
		}
		else if (dsl_node->m_get_text().compare("PROC_MEM_UTIL_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_memory[1] / 10000);
		}
		else if (dsl_node->m_get_text().compare("PROC_MEM_UTIL_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_memory[2] / 10000);
		}
		else if (dsl_node->m_get_text().compare("PROC_MEM_UTIL_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_memory[3] / 10000);
		}
		else if (dsl_node->m_get_text().compare("PROC_MEM_UTIL_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_memory[4] / 10000);
		}

		else if (dsl_node->m_get_text().compare("PROC_MEM_UTIL_CURR") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.ulc_memory);
		}

		else if (dsl_node->m_get_text().compare("SWAP_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_usage[0] / 10000);
		}
		else if (dsl_node->m_get_text().compare("SWAP_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_usage[1] / 10000);
		}
		else if (dsl_node->m_get_text().compare("SWAP_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_usage[2] / 10000);
		}
		else if (dsl_node->m_get_text().compare("SWAP_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_usage[3] / 10000);
		}
		else if (dsl_node->m_get_text().compare("SWAP_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_usage[4] / 10000);
		}

		else if (dsl_node->m_get_text().compare("CACHE_MISSES_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_misses[0]);
		}
		else if (dsl_node->m_get_text().compare("CACHE_MISSES_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_misses[1]);
		}
		else if (dsl_node->m_get_text().compare("CACHE_MISSES_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_misses[2]);
		}
		else if (dsl_node->m_get_text().compare("CACHE_MISSES_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_misses[3]);
		}
		else if (dsl_node->m_get_text().compare("CACHE_MISSES_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_misses[4]);
		}

		else if (dsl_node->m_get_text().compare("CTX_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ctx_swtch[0]);
		}
		else if (dsl_node->m_get_text().compare("CTX_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ctx_swtch[1]);
		}
		else if (dsl_node->m_get_text().compare("CTX_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ctx_swtch[2]);
		}
		else if (dsl_node->m_get_text().compare("CTX_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ctx_swtch[3]);
		}
		else if (dsl_node->m_get_text().compare("CTX_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ctx_swtch[4]);
		}

		else if (dsl_node->m_get_text().compare("PAGE_READ_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_pageins[0]);
		}
		else if (dsl_node->m_get_text().compare("PAGE_READ_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_pageins[1]);
		}
		else if (dsl_node->m_get_text().compare("PAGE_READ_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_pageins[2]);
		}
		else if (dsl_node->m_get_text().compare("PAGE_READ_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_pageins[3]);
		}
		else if (dsl_node->m_get_text().compare("PAGE_READ_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_pageins[4]);
		}

		else if (dsl_node->m_get_text().compare("PAGE_WRITE_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_pageouts[0]);
		}
		else if (dsl_node->m_get_text().compare("PAGE_WRITE_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_pageouts[1]);
		}
		else if (dsl_node->m_get_text().compare("PAGE_WRITE_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_pageouts[2]);
		}
		else if (dsl_node->m_get_text().compare("PAGE_WRITE_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_pageouts[3]);
		}
		else if (dsl_node->m_get_text().compare("PAGE_WRITE_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_pageouts[4]);
		}

		else if (dsl_node->m_get_text().compare("PAGE_TOTAL_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_pagetotal[0]);
		}
		else if (dsl_node->m_get_text().compare("PAGE_TOTAL_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_pagetotal[1]);
		}
		else if (dsl_node->m_get_text().compare("PAGE_TOTAL_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_pagetotal[2]);
		}
		else if (dsl_node->m_get_text().compare("PAGE_TOTAL_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_pagetotal[3]);
		}
		else if (dsl_node->m_get_text().compare("PAGE_TOTAL_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_pagetotal[4]);
		}

		else if (dsl_node->m_get_text().compare("PROCESS_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_processes[0]);
		}
		else if (dsl_node->m_get_text().compare("PROCESS_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_processes[1]);
		}
		else if (dsl_node->m_get_text().compare("PROCESS_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_processes[2]);
		}
		else if (dsl_node->m_get_text().compare("PROCESS_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_processes[3]);
		}
		else if (dsl_node->m_get_text().compare("PROCESS_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_processes[4]);
		}

		else if (dsl_node->m_get_text().compare("PROC_MEM_ABS_CURR") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.ulc_memory);
		}

		else if (dsl_node->m_get_text().compare("PROC_PG_FAULT_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_pg_fault[0]);
		}
		else if (dsl_node->m_get_text().compare("PROC_PG_FAULT_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_pg_fault[1]);
		}
		else if (dsl_node->m_get_text().compare("PROC_PG_FAULT_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_pg_fault[2]);
		}
		else if (dsl_node->m_get_text().compare("PROC_PG_FAULT_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_pg_fault[3]);
		}
		else if (dsl_node->m_get_text().compare("PROC_PG_FAULT_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_pg_fault[4]);
		}

		else if (dsl_node->m_get_text().compare("PROC_PG_FAULT_TOT") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uhl_proc_page_faults_tot);
		}

		else if (dsl_node->m_get_text().compare("PROC_READ_OP_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_io_read[0]);
		}
		else if (dsl_node->m_get_text().compare("PROC_READ_OP_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_io_read[1]);
		}
		else if (dsl_node->m_get_text().compare("PROC_READ_OP_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_io_read[2]);
		}
		else if (dsl_node->m_get_text().compare("PROC_READ_OP_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_io_read[3]);
		}
		else if (dsl_node->m_get_text().compare("PROC_READ_OP_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_io_read[4]);
		}

		else if (dsl_node->m_get_text().compare("PROC_READ_OP_TOT") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uhl_proc_io_read_tot);
		}

		else if (dsl_node->m_get_text().compare("PROC_THREADS_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_threads[0]);
		}
		else if (dsl_node->m_get_text().compare("PROC_THREADS_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_threads[1]);
		}
		else if (dsl_node->m_get_text().compare("PROC_THREADS_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_threads[2]);
		}
		else if (dsl_node->m_get_text().compare("PROC_THREADS_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_threads[3]);
		}
		else if (dsl_node->m_get_text().compare("PROC_THREADS_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_threads[4]);
		}

		else if (dsl_node->m_get_text().compare("PROC_THREADS_CURR") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uhl_proc_threads_cur);
		}

		else if (dsl_node->m_get_text().compare("PROC_WRITE_OP_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_io_write[0]);
		}
		else if (dsl_node->m_get_text().compare("PROC_WRITE_OP_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_io_write[1]);
		}
		else if (dsl_node->m_get_text().compare("PROC_WRITE_OP_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_io_write[2]);
		}
		else if (dsl_node->m_get_text().compare("PROC_WRITE_OP_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_io_write[3]);
		}
		else if (dsl_node->m_get_text().compare("PROC_WRITE_OP_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_io_write[4]);
		}

		else if (dsl_node->m_get_text().compare("PROC_WRITE_OP_TOT") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uhl_proc_io_write_tot);
		}


		else if (dsl_node->m_get_text().compare("SWAP_READ_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swapins[0]);
		}
		else if (dsl_node->m_get_text().compare("SWAP_READ_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swapins[1]);
		}
		else if (dsl_node->m_get_text().compare("SWAP_READ_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swapins[2]);
		}
		else if (dsl_node->m_get_text().compare("SWAP_READ_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swapins[3]);
		}
		else if (dsl_node->m_get_text().compare("SWAP_READ_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swapins[4]);
		}

		else if (dsl_node->m_get_text().compare("SWAP_WRITE_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swapouts[0]);
		}
		else if (dsl_node->m_get_text().compare("SWAP_WRITE_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swapouts[1]);
		}
		else if (dsl_node->m_get_text().compare("SWAP_WRITE_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swapouts[2]);
		}
		else if (dsl_node->m_get_text().compare("SWAP_WRITE_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swapouts[3]);
		}
		else if (dsl_node->m_get_text().compare("SWAP_WRITE_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swapouts[4]);
		}

		else if (dsl_node->m_get_text().compare("SWAP_TOTAL_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swaptotal[0]);
		}
		else if (dsl_node->m_get_text().compare("SWAP_TOTAL_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swaptotal[1]);
		}
		else if (dsl_node->m_get_text().compare("SWAP_TOTAL_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swaptotal[2]);
		}
		else if (dsl_node->m_get_text().compare("SWAP_TOTAL_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swaptotal[3]);
		}
		else if (dsl_node->m_get_text().compare("SWAP_TOTAL_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swaptotal[4]);
		}

		else if (dsl_node->m_get_text().compare("THREADS_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_threads[0]);
		}
		else if (dsl_node->m_get_text().compare("THREADS_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_threads[1]);
		}
		else if (dsl_node->m_get_text().compare("THREADS_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_threads[2]);
		}
		else if (dsl_node->m_get_text().compare("THREADS_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_threads[3]);
		}
		else if (dsl_node->m_get_text().compare("THREADS_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_threads[4]);
		}

#endif


#ifdef HL_LINUX		
		// umrl_hd_usage
		
		else if (dsl_node->m_get_text().compare("HARDDISK_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_usage[0] /10000 );	
		}
		else if (dsl_node->m_get_text().compare("HARDDISK_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_usage[1] /10000);	
		}
		else if (dsl_node->m_get_text().compare("HARDDISK_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_usage[2] /10000);	
		}
		else if (dsl_node->m_get_text().compare("HARDDISK_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_usage[3] /10000);	
		}
		else if (dsl_node->m_get_text().compare("HARDDISK_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_usage[4] /10000);	
		}
		
		// umrl_io_act
		
		else if (dsl_node->m_get_text().compare("IO_ACT_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_act[0] );	
		}
		else if (dsl_node->m_get_text().compare("IO_ACT_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_act[1] );	
		}
		else if (dsl_node->m_get_text().compare("IO_ACT_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_act[2] );	
		}
		else if (dsl_node->m_get_text().compare("IO_ACT_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_act[3] );	
		}
		else if (dsl_node->m_get_text().compare("IO_ACT_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_act[4] );	
		}	
		
		
		// umrl_io_time
		
		else if (dsl_node->m_get_text().compare("IO_TIME_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_time[0] /10000);	
		}
		else if (dsl_node->m_get_text().compare("IO_TIME_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_time[1] /10000);	
		}
		else if (dsl_node->m_get_text().compare("IO_TIME_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_time[2] /10000);	
		}
		else if (dsl_node->m_get_text().compare("IO_TIME_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_time[3] /10000);	
		}
		else if (dsl_node->m_get_text().compare("IO_TIME_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_time[4] /10000);	
		}		
		
		
		// umrl_process
		
		else if (dsl_node->m_get_text().compare("PROCESS_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_process[0] );	
		}
		else if (dsl_node->m_get_text().compare("PROCESS_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_process[1] );	
		}
		else if (dsl_node->m_get_text().compare("PROCESS_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_process[2] );	
		}
		else if (dsl_node->m_get_text().compare("PROCESS_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_process[3] );	
		}
		else if (dsl_node->m_get_text().compare("PROCESS_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_process[4] );	
		}				
		
		
		// umrl_init_process
		
		else if (dsl_node->m_get_text().compare("PROCESS_NEW_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_init_process[0] );	
		}
		else if (dsl_node->m_get_text().compare("PROCESS_NEW_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_init_process[1] );	
		}
		else if (dsl_node->m_get_text().compare("PROCESS_NEW_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_init_process[2] );	
		}
		else if (dsl_node->m_get_text().compare("PROCESS_NEW_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_init_process[3] );	
		}
		else if (dsl_node->m_get_text().compare("PROCESS_NEW_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_init_process[4] );	
		}			
		
		// umrl_memory
		
		else if (dsl_node->m_get_text().compare("MEMORY_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_memory[0] /10000);	
		}
		else if (dsl_node->m_get_text().compare("MEMORY_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_memory[1] /10000);	
		}
		else if (dsl_node->m_get_text().compare("MEMORY_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_memory[2] /10000);	
		}
		else if (dsl_node->m_get_text().compare("MEMORY_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_memory[3] /10000);	
		}
		else if (dsl_node->m_get_text().compare("MEMORY_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_memory[4] /10000);	
		}		
		
		
		// umrl_hd_read
		
		else if (dsl_node->m_get_text().compare("HD_READ_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_read[0] );	
		}
		else if (dsl_node->m_get_text().compare("HD_READ_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_read[1] );	
		}
		else if (dsl_node->m_get_text().compare("HD_READ_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_read[2] );	
		}
		else if (dsl_node->m_get_text().compare("HD_READ_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_read[3] );	
		}
		else if (dsl_node->m_get_text().compare("HD_READ_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_read[4] );	
		}												
		
		// umrl_hd_write
		
		else if (dsl_node->m_get_text().compare("HD_WRITE_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_write[0] );	
		}
		else if (dsl_node->m_get_text().compare("HD_WRITE_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_write[1] );	
		}
		else if (dsl_node->m_get_text().compare("HD_WRITE_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_write[2] );	
		}
		else if (dsl_node->m_get_text().compare("HD_WRITE_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_write[3] );	
		}
		else if (dsl_node->m_get_text().compare("HD_WRITE_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_write[4] );	
		}														
		
		// umrl_page_util
		
		else if (dsl_node->m_get_text().compare("SWAP_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_util[0] /10000);	
		}
		else if (dsl_node->m_get_text().compare("SWAP_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_util[1] /10000);	
		}
		else if (dsl_node->m_get_text().compare("SWAP_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_util[2] /10000);	
		}
		else if (dsl_node->m_get_text().compare("SWAP_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_util[3] /10000);	
		}
		else if (dsl_node->m_get_text().compare("SWAP_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_util[4] /10000);	
		}		
		
		// umrl_page_read
		
		else if (dsl_node->m_get_text().compare("PAGE_READ_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_read[0] );	
		}
		else if (dsl_node->m_get_text().compare("PAGE_READ_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_read[1] );	
		}
		else if (dsl_node->m_get_text().compare("PAGE_READ_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_read[2] );	
		}
		else if (dsl_node->m_get_text().compare("PAGE_READ_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_read[3] );	
		}
		else if (dsl_node->m_get_text().compare("PAGE_READ_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_read[4] );	
		}		
		
		// umrl_page_write
		
		else if (dsl_node->m_get_text().compare("PAGE_WRITE_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_write[0] );	
		}
		else if (dsl_node->m_get_text().compare("PAGE_WRITE_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_write[1] );	
		}
		else if (dsl_node->m_get_text().compare("PAGE_WRITE_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_write[2] );	
		}
		else if (dsl_node->m_get_text().compare("PAGE_WRITE_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_write[3] );	
		}
		else if (dsl_node->m_get_text().compare("PAGE_WRITE_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_write[4] );	
		}		
		
		// umrl_page_total
		
		else if (dsl_node->m_get_text().compare("PAGE_TOTAL_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_total[0] );	
		}
		else if (dsl_node->m_get_text().compare("PAGE_TOTAL_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_total[1] );	
		}
		else if (dsl_node->m_get_text().compare("PAGE_TOTAL_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_total[2] );	
		}
		else if (dsl_node->m_get_text().compare("PAGE_TOTAL_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_total[3] );	
		}
		else if (dsl_node->m_get_text().compare("PAGE_TOTAL_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_total[4] );	
		}				
		
		// umrl_swap_read
		
		else if (dsl_node->m_get_text().compare("SWAP_READ_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_read[0] );	
		}
		else if (dsl_node->m_get_text().compare("SWAP_READ_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_read[1] );	
		}
		else if (dsl_node->m_get_text().compare("SWAP_READ_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_read[2] );	
		}
		else if (dsl_node->m_get_text().compare("SWAP_READ_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_read[3] );	
		}
		else if (dsl_node->m_get_text().compare("SWAP_READ_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_read[4] );	
		}		
		
		// umrl_swap_write
		
		else if (dsl_node->m_get_text().compare("SWAP_WRITE_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_write[0] );	
		}
		else if (dsl_node->m_get_text().compare("SWAP_WRITE_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_write[1] );	
		}
		else if (dsl_node->m_get_text().compare("SWAP_WRITE_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_write[2] );	
		}
		else if (dsl_node->m_get_text().compare("SWAP_WRITE_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_write[3] );	
		}
		else if (dsl_node->m_get_text().compare("SWAP_WRITE_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_write[4] );	
		}		
		
		// umrl_swap_act
		
		else if (dsl_node->m_get_text().compare("SWAP_TOTAL_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_act[0] );	
		}
		else if (dsl_node->m_get_text().compare("SWAP_TOTAL_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_act[1] );	
		}
		else if (dsl_node->m_get_text().compare("SWAP_TOTAL_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_act[2] );	
		}
		else if (dsl_node->m_get_text().compare("SWAP_TOTAL_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_act[3] );	
		}
		else if (dsl_node->m_get_text().compare("SWAP_TOTAL_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_swap_act[4] );	
		}			
		
		// umrl_min_pg_fault
		
		else if (dsl_node->m_get_text().compare("PG_FAULT_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_min_pg_fault[0] );	
		}
		else if (dsl_node->m_get_text().compare("PG_FAULT_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_min_pg_fault[1] );	
		}
		else if (dsl_node->m_get_text().compare("PG_FAULT_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_min_pg_fault[2] );	
		}
		else if (dsl_node->m_get_text().compare("PG_FAULT_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_min_pg_fault[3] );	
		}
		else if (dsl_node->m_get_text().compare("PG_FAULT_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_min_pg_fault[4] );	
		}				
		
		// umrl_maj_pg_fault
		
		else if (dsl_node->m_get_text().compare("PG_MAJ_FAULT_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_maj_pg_fault[0] );	
		}
		else if (dsl_node->m_get_text().compare("PG_MAJ_FAULT_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_maj_pg_fault[1] );	
		}
		else if (dsl_node->m_get_text().compare("PG_MAJ_FAULT_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_maj_pg_fault[2] );	
		}
		else if (dsl_node->m_get_text().compare("PG_MAJ_FAULT_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_maj_pg_fault[3] );	
		}
		else if (dsl_node->m_get_text().compare("PG_MAJ_FAULT_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_maj_pg_fault[4] );	
		}			
		
		// umrl_nic_recv
		
		else if (dsl_node->m_get_text().compare("NIC_READ_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_recv[0] /10000);	
		}
		else if (dsl_node->m_get_text().compare("NIC_READ_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_recv[1] /10000);	
		}
		else if (dsl_node->m_get_text().compare("NIC_READ_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_recv[2] /10000);	
		}
		else if (dsl_node->m_get_text().compare("NIC_READ_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_recv[3] /10000);	
		}
		else if (dsl_node->m_get_text().compare("NIC_READ_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_recv[4] /10000);	
		}						
		
		// umrl_nic_send
		
		else if (dsl_node->m_get_text().compare("NIC_WRITE_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_send[0] /10000);	
		}
		else if (dsl_node->m_get_text().compare("NIC_WRITE_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_send[1] /10000);	
		}
		else if (dsl_node->m_get_text().compare("NIC_WRITE_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_send[2] /10000);	
		}
		else if (dsl_node->m_get_text().compare("NIC_WRITE_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_send[3] /10000);	
		}
		else if (dsl_node->m_get_text().compare("NIC_WRITE_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_send[4] /10000);	
		}													
		
		// umrl_nic_total
		
		else if (dsl_node->m_get_text().compare("NIC_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_total[0] /10000);	
		}
		else if (dsl_node->m_get_text().compare("NIC_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_total[1] /10000);	
		}
		else if (dsl_node->m_get_text().compare("NIC_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_total[2] /10000);	
		}
		else if (dsl_node->m_get_text().compare("NIC_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_total[3] /10000);	
		}
		else if (dsl_node->m_get_text().compare("NIC_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_total[4] /10000);	
		}			
		
		// umrl_cpu
		
		else if (dsl_node->m_get_text().compare("CPU_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu[0] /10000 );	
		}
		else if (dsl_node->m_get_text().compare("CPU_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu[1] /10000);	
		}
		else if (dsl_node->m_get_text().compare("CPU_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu[2] /10000);	
		}
		else if (dsl_node->m_get_text().compare("CPU_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu[3] /10000);	
		}
		else if (dsl_node->m_get_text().compare("CPU_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu[4] /10000);	
		}	
		
		// umrl_ints
		
		else if (dsl_node->m_get_text().compare("INT_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ints[0] );	
		}
		else if (dsl_node->m_get_text().compare("INT_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ints[1] );	
		}
		else if (dsl_node->m_get_text().compare("INT_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ints[2] );	
		}
		else if (dsl_node->m_get_text().compare("INT_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ints[3] );	
		}
		else if (dsl_node->m_get_text().compare("INT_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ints[4] );	
		}			
		
		// umrl_ctx
		
		else if (dsl_node->m_get_text().compare("CTX_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ctx[0] );	
		}
		else if (dsl_node->m_get_text().compare("CTX_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ctx[1] );	
		}
		else if (dsl_node->m_get_text().compare("CTX_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ctx[2] );	
		}
		else if (dsl_node->m_get_text().compare("CTX_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ctx[3] );	
		}
		else if (dsl_node->m_get_text().compare("CTX_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ctx[4] );	
		}			
		
		// umrl_proc_cpu
		
		else if (dsl_node->m_get_text().compare("PROC_CPU_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu_proc[0] /10000);	
		}							
		else if (dsl_node->m_get_text().compare("PROC_CPU_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu_proc[1] /10000);	
		}
		else if (dsl_node->m_get_text().compare("PROC_CPU_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu_proc[2]	/10000);	
		}
		else if (dsl_node->m_get_text().compare("PROC_CPU_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu_proc[3] /10000);	
		}
		else if (dsl_node->m_get_text().compare("PROC_CPU_30") == 0)
			{
				dsl_node->m_set_value((double)dsp_load.umrl_cpu_proc[4] /10000);	
			}
#endif	/* HL_LINUX */	
#ifdef HL_WINALL1
		// imrl_cache_hit
		if (dsl_node->m_get_text().compare("CACHE_HIT_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_hit[0] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("CACHE_HIT_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_hit[1] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("CACHE_HIT_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_hit[2] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("CACHE_HIT_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_hit[3] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("CACHE_HIT_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_hit[4] /10000 );	
			continue;
		}


		// umrl_cache_miss
		if (dsl_node->m_get_text().compare("CACHE_MISSES_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_miss[0] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("CACHE_MISSES_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_miss[1] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("CACHE_MISSES_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_miss[2]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("CACHE_MISSES_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_miss[3] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("CACHE_MISSES_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cache_miss[4] );	
			continue;
		}


		// umrl_cpu
		if (dsl_node->m_get_text().compare("CPU_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu[0] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("CPU_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu[1] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("CPU_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu[2] /10000 );
			continue;
		}
		if (dsl_node->m_get_text().compare("CPU_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu[3] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("CPU_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_cpu[4] /10000 );	
			continue;
		}

		// umrl_cpu_proc
		if (dsl_node->m_get_text().compare("PROC_CPU_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_cpu[0] /10000 );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_CPU_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_cpu[1] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_CPU_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_cpu[2] /10000 );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_CPU_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_cpu[3] /10000 );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_CPU_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_cpu[4] /10000 );
			continue;
		}


		// umrl_ctx
		if (dsl_node->m_get_text().compare("CTX_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ctx[0] );
			continue;
		}
		if (dsl_node->m_get_text().compare("CTX_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ctx[1] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("CTX_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ctx[2] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("CTX_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ctx[3]);
			continue;
		}
		if (dsl_node->m_get_text().compare("CTX_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ctx[4]);
			continue;
		}

		// umrl_hd_usage
		if (dsl_node->m_get_text().compare("HARDDISK_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_usage[0] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HARDDISK_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_usage[1] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HARDDISK_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_usage[2] /10000 );
			continue;
		}
		if (dsl_node->m_get_text().compare("HARDDISK_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_usage[3] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HARDDISK_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_usage[4] /10000 );	
			continue;
		}

		// umrl_hd_bpr
		if (dsl_node->m_get_text().compare("HD_BPR_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_bpr[0]);	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_BPR_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_bpr[1]);	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_BPR_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_bpr[2]);	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_BPR_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_bpr[3]);	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_BPR_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_bpr[4]);	
			continue;
		}

		// umrl_hd_bpw
		if (dsl_node->m_get_text().compare("HD_BPW_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_bpw[0]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_BPW_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_bpw[1] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_BPW_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_bpw[2]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_BPW_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_bpw[3]);	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_BPW_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_bpw[4] );
			continue;
		}

		// umrl_hd_bpt
		if (dsl_node->m_get_text().compare("HD_BPT_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_bpt[0] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_BPT_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_bpt[1] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_BPT_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_bpt[2]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_BPT_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_bpt[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_BPT_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_bpt[4]);	
			continue;
		}

		// umrl_hd_read
		if (dsl_node->m_get_text().compare("HD_READ_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_read[0]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_READ_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_read[1] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_READ_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_read[2] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_READ_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_read[3] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_READ_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_read[4] );	
			continue;
		}

		// umrl_hd_write
		if (dsl_node->m_get_text().compare("HD_WRITE_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_write[0] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_WRITE_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_write[1] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_WRITE_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_write[2] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_WRITE_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_write[3] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("HD_WRITE_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_hd_write[4]  );	
			continue;
		}

		// umrl_ints
		if (dsl_node->m_get_text().compare("INT_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ints[0]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("INT_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ints[1]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("INT_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ints[2] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("INT_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ints[3]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("INT_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_ints[4] );	
			continue;
		}

		// umrl_io_act
		if (dsl_node->m_get_text().compare("IO_ACT_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_act[0]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("IO_ACT_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_act[1]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("IO_ACT_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_act[2]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("IO_ACT_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_act[3] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("IO_ACT_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_act[4] );
			continue;
		}

		// umrl_io_time
		if (dsl_node->m_get_text().compare("IO_TIME_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_time[0] /10000 );
			continue;
		}
		if (dsl_node->m_get_text().compare("IO_TIME_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_time[1] /10000 );
			continue;
		}
		if (dsl_node->m_get_text().compare("IO_TIME_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_time[2] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("IO_TIME_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_time[3] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("IO_TIME_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_io_time[4] /10000 );	
			continue;
		}

		// umrl_memory
		if (dsl_node->m_get_text().compare("MEMORY_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_memory[0] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("MEMORY_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_memory[1] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("MEMORY_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_memory[2] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("MEMORY_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_memory[3] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("MEMORY_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_memory[4] /10000 );	
			continue;
		}


		// umrl_nic_total
		if (dsl_node->m_get_text().compare("NIC_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_total[0] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("NIC_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_total[1] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("NIC_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_total[2] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("NIC_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_total[3] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("NIC_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_total[4] /10000 );	
			continue;
		}

		// umrl_nic_recv
		if (dsl_node->m_get_text().compare("NIC_READ_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_recv[0] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("NIC_READ_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_recv[1] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("NIC_READ_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_recv[2] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("NIC_READ_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_recv[3] /10000 );
			continue;
		}
		if (dsl_node->m_get_text().compare("NIC_READ_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_recv[4] /10000 );
			continue;
		}

		// umrl_nic_send
		if (dsl_node->m_get_text().compare("NIC_WRITE_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_send[0] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("NIC_WRITE_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_send[1] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("NIC_WRITE_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_send[2] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("NIC_WRITE_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_send[3] /10000 );
			continue;
		}
		if (dsl_node->m_get_text().compare("NIC_WRITE_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_nic_send[4] /10000 );
			continue;
		}

		// umrl_net_sent
		if (dsl_node->m_get_text().compare("NET_SENT_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_net_sent[0]);	
			continue;
		}
		if (dsl_node->m_get_text().compare("NET_SENT_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_net_sent[1]);	
			continue;
		}
		if (dsl_node->m_get_text().compare("NET_SENT_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_net_sent[2] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("NET_SENT_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_net_sent[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("NIC_SENT_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_net_sent[4]);
			continue;
		}

		// umrl_net_recv
		if (dsl_node->m_get_text().compare("NET_RECV_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_net_recv[0]);	
			continue;
		}
		if (dsl_node->m_get_text().compare("NET_RECV_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_net_recv[1]);	
			continue;
		}
		if (dsl_node->m_get_text().compare("NET_RECV_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_net_recv[2] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("NET_RECV_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_net_recv[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("NIC_RECV_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_net_recv[4]);
			continue;
		}

		// umrl_net_total
		if (dsl_node->m_get_text().compare("NET_TOTAL_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_net_total[0]);	
			continue;
		}
		if (dsl_node->m_get_text().compare("NET_TOTAL_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_net_total[1]);	
			continue;
		}
		if (dsl_node->m_get_text().compare("NET_TOTAL_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_net_total[2] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("NET_TOTAL_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_net_total[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("NIC_TOTAL_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_net_total[4]);
			continue;
		}

		// umrl_page_read
		if (dsl_node->m_get_text().compare("PAGE_READ_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_read[0]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("PAGE_READ_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_read[1]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PAGE_READ_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_read[2]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("PAGE_READ_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_read[3]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("PAGE_READ_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_read[4]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_READ_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_read[0]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_READ_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_read[1]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_READ_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_read[2]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_READ_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_read[3]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_READ_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_read[4] );	
			continue;
		}


		// umrl_page_write
		if (dsl_node->m_get_text().compare("PAGE_WRITE_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_write[0]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PAGE_WRITE_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_write[1]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PAGE_WRITE_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_write[2]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("PAGE_WRITE_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_write[3]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("PAGE_WRITE_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_write[4]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_WRITE_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_write[0] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_WRITE_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_write[1]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_WRITE_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_write[2]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_WRITE_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_write[3]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_WRITE_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_write[4]  );	
			continue;
		}


		// umrl_page_total
		if (dsl_node->m_get_text().compare("PAGE_TOTAL_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_total[0]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("PAGE_TOTAL_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_total[1]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PAGE_TOTAL_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_total[2]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PAGE_TOTAL_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_total[3]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("PAGE_TOTAL_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_total[4]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_TOTAL_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_total[0]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_TOTAL_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_total[1]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_TOTAL_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_total[2]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_TOTAL_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_total[3]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_TOTAL_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_total[4]  );
			continue;
		}


		// umrl_page_fault
		if (dsl_node->m_get_text().compare("PG_FAULT_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_fault[0]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("PG_FAULT_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_fault[1]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PG_FAULT_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_fault[2]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PG_FAULT_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_fault[3]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PG_FAULT_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_fault[4]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PG_MAJ_FAULT_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_fault[0]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PG_MAJ_FAULT_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_fault[1] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PG_MAJ_FAULT_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_fault[2]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("PG_MAJ_FAULT_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_fault[3] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PG_MAJ_FAULT_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_fault[4]  );	
			continue;
		}


		// umrl_process
		if (dsl_node->m_get_text().compare("PROCESS_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_process[0]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PROCESS_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_process[1]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROCESS_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_process[2]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PROCESS_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_process[3]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("PROCESS_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_process[4]  );	
			continue;
		}

		// umrl_page_util
		if (dsl_node->m_get_text().compare("SWAP_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_util[0] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_util[1] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_util[2] / 10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_util[3] /10000 );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAP_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_util[4] /10000);
			continue;
		}

		
		// umrl_page_file
		if (dsl_node->m_get_text().compare("SWAPFILE_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_file[0]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAPFILE_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_file[1] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAPFILE_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_file[2]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAPFILE_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_file[3]  );
			continue;
		}
		if (dsl_node->m_get_text().compare("SWAPFILE_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_page_file[4]  );
			continue;
		}

		// umrl_threads
		if (dsl_node->m_get_text().compare("THREADS_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_threads[0]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("THREADS_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_threads[1]  );	
			continue;
		}
		if (dsl_node->m_get_text().compare("THREADS_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_threads[2] );	
			continue;
		}
		if (dsl_node->m_get_text().compare("THREADS_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_threads[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("THREADS_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_threads[4] );	
			continue;
		}

		/*---------------- process variables -----------------*/
		if (dsl_node->m_get_text().compare("PROC_THREADS_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_threads[0] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_THREADS_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_threads[1] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_THREADS_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_threads[2] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_THREADS_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_threads[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_THREADS_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_threads[4] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_THREADS_CURR") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uml_proc_curr_threads );
			continue;
		}

		if (dsl_node->m_get_text().compare("PROC_HANDLES_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_handles[0] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_HANDLES_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_handles[1] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_HANDLES_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_handles[2] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_HANDLES_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_handles[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_HANDLES_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_handles[4] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_HANDLES_CURR") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uml_proc_curr_handles );
			continue;
		}

		if (dsl_node->m_get_text().compare("PROC_VM_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_virt_bytes[0] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_VM_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_virt_bytes[1] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_VM_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_virt_bytes[2] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_VM_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_virt_bytes[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_VM_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_virt_bytes[4] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_VM_CURR") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uhl_proc_virt_bytes );
			continue;
		}

		if (dsl_node->m_get_text().compare("PROC_READ_OP_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_read_ops[0] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_READ_OP_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_read_ops[1] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_READ_OP_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_read_ops[2] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_READ_OP_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_read_ops[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_READ_OP_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_read_ops[4] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_READ_OP_TOT") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uhl_proc_read_operations );
			continue;
		}

		if (dsl_node->m_get_text().compare("PROC_WRITE_OP_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_write_ops[0] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_WRITE_OP_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_write_ops[1] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_WRITE_OP_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_write_ops[2] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_WRITE_OP_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_write_ops[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_WRITE_OP_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_write_ops[4] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_WRITE_OP_TOT") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uhl_proc_write_operations );
			continue;
		}

		if (dsl_node->m_get_text().compare("PROC_READ_BYTES_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_read_bytes[0] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_READ_BYTES_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_read_bytes[1] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_READ_BYTES_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_read_bytes[2] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_READ_BYTES_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_read_bytes[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_READ_BYTES_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_read_bytes[4] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_READ_BYTES_TOT") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uhl_proc_read_bytes );
			continue;
		}

		if (dsl_node->m_get_text().compare("PROC_WRITE_BYTES_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_write_bytes[0] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_WRITE_BYTES_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_write_bytes[1] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_WRITE_BYTES_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_write_bytes[2] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_WRITE_BYTES_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_write_bytes[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_WRITE_BYTES_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_write_bytes[4] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_WRITE_BYTES_TOT") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uhl_proc_write_bytes );
			continue;
		}

		if (dsl_node->m_get_text().compare("PROC_TOTAL_BYTES_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_total_bytes[0] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_TOTAL_BYTES_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_total_bytes[1] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_TOTAL_BYTES_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_total_bytes[2] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_TOTAL_BYTES_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_total_bytes[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_TOTAL_BYTES_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_total_bytes[4] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_TOTAL_BYTES_TOT") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uhl_proc_total_bytes );
			continue;
		}

		if (dsl_node->m_get_text().compare("PROC_PG_FAULT_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_pg_fault[0] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_PG_FAULT_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_pg_fault[1] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_PG_FAULT_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_pg_fault[2] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_PG_FAULT_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_pg_fault[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_PG_FAULT_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_pg_fault[4] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_PG_FAULT_TOT") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uml_proc_pg_faults );
			continue;
		}

		if (dsl_node->m_get_text().compare("PROC_MEM_ABS_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_mem_abs[0] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_MEM_ABS_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_mem_abs[1] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_MEM_ABS_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_mem_abs[2] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_MEM_ABS_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_mem_abs[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_MEM_ABS_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_mem_abs[4] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_MEM_ABS_CURR") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uml_proc_curr_mem );
			continue;
		}

		if (dsl_node->m_get_text().compare("PROC_MEM_UTIL_1") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_mem_util[0] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_MEM_UTIL_5") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_mem_util[1] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_MEM_UTIL_10") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_mem_util[2] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_MEM_UTIL_15") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_mem_util[3] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_MEM_UTIL_30") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.umrl_proc_mem_util[4] );
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_MEM_UTIL_CURR") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uml_proc_curr_mem_util );
			continue;
		}

		if (dsl_node->m_get_text().compare("PROC_TIME_KERNEL") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uhl_proc_time_kernel);
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_TIME_USER") == 0)
		{
			dsl_node->m_set_value((double)dsp_load.uhl_proc_time_user);
			continue;
		}
		if (dsl_node->m_get_text().compare("PROC_TIME_TOTAL") == 0)
		{
			dsl_node->m_set_value((double)(dsp_load.uhl_proc_time_kernel +dsp_load.uhl_proc_time_user ));
			continue;
		}
		dsl_node->m_set_value(0);
#endif /* HL_WINALL1 */
	}
	return true;
}
	
	// calculate the current load.
double c_lb_formula::m_calculate()
{
	if (adsl_root == NULL) return -1;
	else return adsl_root->m_operate();
}

void c_lb_formula::m_free_tree(c_lb_tree_node* dsp_root)
{
	if (dsp_root != NULL)
	{
		dsp_root->m_free();
		dsp_root = NULL;
	}
}

// set default formula
void c_lb_formula::m_set_default_formula()
{
	m_parse_formula("CPU_1");
}

c_formula_token::c_formula_token(){}


/*c_formula_token::c_formula_token(const c_formula_token& dsp_token)
{
	iml_type = dsp_token.iml_type;
	iml_depth = dsp_token.iml_depth;
	iml_priority = dsp_token.iml_priority;
	strl_text = dsp_token.strl_text;
}*/
/*const c_formula_token& c_formula_token::operator= (const c_formula_token& dsp_token)
{
	return *this;
}*/	

// create a token with the token text, the depth and the token type
c_formula_token::c_formula_token(string strp_token, int imp_depth, int imp_type)
{
	iml_type = imp_type;
	iml_depth = imp_depth;
	strl_text = strp_token;
	// set priority
	if (iml_type == INFIX_OPERATOR || iml_type == PREFIX_OPERATOR || iml_type == SEPARATOR)
	{
		if (strl_text.compare("MAX") == 0)
		{
			iml_priority = 1;
		}
		else if (strl_text.compare("MIN") == 0)
		{
			iml_priority = 1;
		}
		else if (strl_text.compare("LOG") == 0)
		{
			iml_priority = 1;
		}
		else if (strl_text.compare("EXP") == 0)
		{
			iml_priority = 1;
		}
		else if (strl_text.compare("SQR") == 0)
		{
			iml_priority = 1;
		}
		else if (strl_text.compare("*") == 0)
		{
			iml_priority = 3;
		}
		else if (strl_text.compare("/") == 0)
		{
			iml_priority = 3;
		}
		else if (strl_text.compare("+") == 0)
		{
			iml_priority = 5;
		}
		else if (strl_text.compare("-") == 0)
		{
			iml_priority = 5;
		}
		else if (strl_text.compare(",") == 0)
		{
			iml_priority = 7;
		}
		else iml_priority = -1;
	}
	else	iml_priority = 0;
}

// getter
string c_formula_token::m_get_text()
{
	return strl_text;
}

int c_formula_token::m_get_type()
{
	return iml_type;
}

int c_formula_token::m_get_depth()
{
	return iml_depth;
}

int c_formula_token::m_get_prio()
{
	return iml_priority;
}

bool c_formula_token::m_is_digit (char chp1)
{

	if (chp1=='0'||chp1=='1'||chp1=='2'||chp1=='3'||chp1=='4'||chp1=='5'||chp1=='6'||chp1=='7'||chp1=='8'||chp1=='9')
	{
		return true;
	}
	if (chp1 =='.')
	{
		return true;
	}
	else return false;
}

// look if a char is an infix operator
bool c_formula_token::m_is_simple_operator(char chp1)
{
	if (chp1=='+'||chp1=='-'||chp1=='*'||chp1=='/')
	{
		return true;
	}
	else return false;
}

// look if the passed char is a separator
bool c_formula_token::m_is_separator(char chp1)
{
	if (chp1==',')
	{
		return true;
	}
	else return false;
}

// look if the passed char is a capital letter
bool c_formula_token::m_is_letter(char chp1)
{
	if (chp1 >=65 && chp1 <=90)
	{
		return true;
	}
	else return false;
}

bool c_formula_token::m_is_underscore(char chp1)
{
	if (chp1 == 95)
	{
		return true;
	}
	else return false;
}

c_variable_list::c_variable_list()
{
	adsl_var = new vector<string>();
	adsl_var->reserve(200);
	adsl_var->push_back("CPU_1");			// this variable is always available to avoid endless loop

#ifdef HL_FREEBSD
	
	adsl_var->push_back("CPU_1");			// CPU load
	adsl_var->push_back("CPU_5");
	adsl_var->push_back("CPU_10");
	adsl_var->push_back("CPU_15");
	adsl_var->push_back("CPU_30");

	adsl_var->push_back("INT_1");
	adsl_var->push_back("INT_5");
	adsl_var->push_back("INT_10");
	adsl_var->push_back("INT_15");
	adsl_var->push_back("INT_30");

	adsl_var->push_back("CACHE_HIT_1");
	adsl_var->push_back("CACHE_HIT_5");
	adsl_var->push_back("CACHE_HIT_10");
	adsl_var->push_back("CACHE_HIT_15");
	adsl_var->push_back("CACHE_HIT_30");

	adsl_var->push_back("MEMORY_1");
	adsl_var->push_back("MEMORY_5");
	adsl_var->push_back("MEMORY_10");
	adsl_var->push_back("MEMORY_15");
	adsl_var->push_back("MEMORY_30");
	
	adsl_var->push_back("PROC_CPU_1");
	adsl_var->push_back("PROC_CPU_5");
	adsl_var->push_back("PROC_CPU_10");
	adsl_var->push_back("PROC_CPU_15");
	adsl_var->push_back("PROC_CPU_30");
	
	adsl_var->push_back("PROC_MEM_UTIL_1");
	adsl_var->push_back("PROC_MEM_UTIL_5");
	adsl_var->push_back("PROC_MEM_UTIL_10");
	adsl_var->push_back("PROC_MEM_UTIL_15");
	adsl_var->push_back("PROC_MEM_UTIL_30");
	
	adsl_var->push_back("SWAP_1");
	adsl_var->push_back("SWAP_5");
	adsl_var->push_back("SWAP_10");
	adsl_var->push_back("SWAP_15");
	adsl_var->push_back("SWAP_30");
	
	adsl_var->push_back("CACHE_MISSES_1");
	adsl_var->push_back("CACHE_MISSES_5");
	adsl_var->push_back("CACHE_MISSES_10");
	adsl_var->push_back("CACHE_MISSES_15");
	adsl_var->push_back("CACHE_MISSES_30");
	
	adsl_var->push_back("CTX_1");
	adsl_var->push_back("CTX_5");
	adsl_var->push_back("CTX_10");
	adsl_var->push_back("CTX_15");
	adsl_var->push_back("CTX_30");
	
	adsl_var->push_back("PAGE_READ_1");
	adsl_var->push_back("PAGE_READ_5");
	adsl_var->push_back("PAGE_READ_10");
	adsl_var->push_back("PAGE_READ_15");
	adsl_var->push_back("PAGE_READ_30");
	
	adsl_var->push_back("PAGE_WRITE_1");
	adsl_var->push_back("PAGE_WRITE_5");
	adsl_var->push_back("PAGE_WRITE_10");
	adsl_var->push_back("PAGE_WRITE_15");
	adsl_var->push_back("PAGE_WRITE_30");
	
	adsl_var->push_back("PAGE_TOTAL_1");
	adsl_var->push_back("PAGE_TOTAL_5");
	adsl_var->push_back("PAGE_TOTAL_10");
	adsl_var->push_back("PAGE_TOTAL_15");
	adsl_var->push_back("PAGE_TOTAL_30");
	
	adsl_var->push_back("PROCESS_1");
	adsl_var->push_back("PROCESS_5");
	adsl_var->push_back("PROCESS_10");
	adsl_var->push_back("PROCESS_15");
	adsl_var->push_back("PROCESS_30");
	
	adsl_var->push_back("PROC_PG_FAULT_1");
	adsl_var->push_back("PROC_PG_FAULT_5");
	adsl_var->push_back("PROC_PG_FAULT_10");
	adsl_var->push_back("PROC_PG_FAULT_15");
	adsl_var->push_back("PROC_PG_FAULT_30");
	
	adsl_var->push_back("PROC_READ_OP_1");
	adsl_var->push_back("PROC_READ_OP_5");
	adsl_var->push_back("PROC_READ_OP_10");
	adsl_var->push_back("PROC_READ_OP_15");
	adsl_var->push_back("PROC_READ_OP_30");
	
	adsl_var->push_back("PROC_THREADS_1");
	adsl_var->push_back("PROC_THREADS_5");
	adsl_var->push_back("PROC_THREADS_10");
	adsl_var->push_back("PROC_THREADS_15");
	adsl_var->push_back("PROC_THREADS_30");
	
	adsl_var->push_back("PROC_WRITE_OP_1");
	adsl_var->push_back("PROC_WRITE_OP_5");
	adsl_var->push_back("PROC_WRITE_OP_10");
	adsl_var->push_back("PROC_WRITE_OP_15");
	adsl_var->push_back("PROC_WRITE_OP_30");
	
	adsl_var->push_back("SWAP_READ_1");
	adsl_var->push_back("SWAP_READ_5");
	adsl_var->push_back("SWAP_READ_10");
	adsl_var->push_back("SWAP_READ_15");
	adsl_var->push_back("SWAP_READ_30");
	
	adsl_var->push_back("SWAP_WRITE_1");
	adsl_var->push_back("SWAP_WRITE_5");
	adsl_var->push_back("SWAP_WRITE_10");
	adsl_var->push_back("SWAP_WRITE_15");
	adsl_var->push_back("SWAP_WRITE_30");
	
	adsl_var->push_back("SWAP_TOTAL_1");
	adsl_var->push_back("SWAP_TOTAL_5");
	adsl_var->push_back("SWAP_TOTAL_10");
	adsl_var->push_back("SWAP_TOTAL_15");
	adsl_var->push_back("SWAP_TOTAL_30");
	
	adsl_var->push_back("THREADS_1");
	adsl_var->push_back("THREADS_5");
	adsl_var->push_back("THREADS_10");
	adsl_var->push_back("THREADS_15");
	adsl_var->push_back("THREADS_30");
	
	adsl_var->push_back("PROC_MEM_ABS_CURR");
	adsl_var->push_back("PROC_PG_FAULT_TOT");
	adsl_var->push_back("PROC_READ_OP_TOT");
	adsl_var->push_back("PROC_THREADS_CURR");
	adsl_var->push_back("PROC_WRITE_OP_TOT");
	adsl_var->push_back("SESSIONS");

#endif
#ifdef HL_LINUX
	adsl_var->push_back("HARDDISK_1");		// hard disk utilization (free/total) average in the last minute
	adsl_var->push_back("HARDDISK_5");		//           "                        average in last 5 minutes
	adsl_var->push_back("HARDDISK_10");		//           "                        average in last 10 minutes
	adsl_var->push_back("HARDDISK_15");		//           "                        average in last 15 minutes
	adsl_var->push_back("HARDDISK_30");		//           "                        average in last 30 minutes
	adsl_var->push_back("IO_ACT_1");		// I/O activity load
	adsl_var->push_back("IO_ACT_5");
	adsl_var->push_back("IO_ACT_10");
	adsl_var->push_back("IO_ACT_15");
	adsl_var->push_back("IO_ACT_30");
	adsl_var->push_back("IO_TIME_1");		// cpu util. for I/O activity
	adsl_var->push_back("IO_TIME_5");
	adsl_var->push_back("IO_TIME_10");
	adsl_var->push_back("IO_TIME_15");
	adsl_var->push_back("IO_TIME_30");
	adsl_var->push_back("PROCESS_1");		// process load
	adsl_var->push_back("PROCESS_5");
	adsl_var->push_back("PROCESS_10");
	adsl_var->push_back("PROCESS_15");
	adsl_var->push_back("PROCESS_30");
	adsl_var->push_back("PROCESS_NEW_1");	// load of new processes
	adsl_var->push_back("PROCESS_NEW_5");
	adsl_var->push_back("PROCESS_NEW_10");
	adsl_var->push_back("PROCESS_NEW_15");
	adsl_var->push_back("PROCESS_NEW_30");
	adsl_var->push_back("MEMORY_1");		// RAM utilization
	adsl_var->push_back("MEMORY_5");
	adsl_var->push_back("MEMORY_10");
	adsl_var->push_back("MEMORY_15");
	adsl_var->push_back("MEMORY_30");
	adsl_var->push_back("HD_READ_1");		// hard disk reading activity
	adsl_var->push_back("HD_READ_5");
	adsl_var->push_back("HD_READ_10");
	adsl_var->push_back("HD_READ_15");
	adsl_var->push_back("HD_READ_30");
	adsl_var->push_back("HD_WRITE_1");		// hard disk writing activity
	adsl_var->push_back("HD_WRITE_5");
	adsl_var->push_back("HD_WRITE_10");
	adsl_var->push_back("HD_WRITE_15");
	adsl_var->push_back("HD_WRITE_30");
	adsl_var->push_back("SWAP_1");			// utilization of the swap partition
	adsl_var->push_back("SWAP_5");
	adsl_var->push_back("SWAP_10");
	adsl_var->push_back("SWAP_15");
	adsl_var->push_back("SWAP_30");
	adsl_var->push_back("PAGE_READ_1");		// page ins
	adsl_var->push_back("PAGE_READ_5");
	adsl_var->push_back("PAGE_READ_10");
	adsl_var->push_back("PAGE_READ_15");
	adsl_var->push_back("PAGE_READ_30");
	adsl_var->push_back("PAGE_WRITE_1");	// page outs
	adsl_var->push_back("PAGE_WRITE_5");
	adsl_var->push_back("PAGE_WRITE_10");
	adsl_var->push_back("PAGE_WRITE_15");
	adsl_var->push_back("PAGE_WRITE_30");
	adsl_var->push_back("PAGE_TOTAL_1");	// total paging activity
	adsl_var->push_back("PAGE_TOTAL_5");
	adsl_var->push_back("PAGE_TOTAL_10");
	adsl_var->push_back("PAGE_TOTAL_15");
	adsl_var->push_back("PAGE_TOTAL_30");
	adsl_var->push_back("SWAP_READ_1");		// swap ins
	adsl_var->push_back("SWAP_READ_5");
	adsl_var->push_back("SWAP_READ_10");
	adsl_var->push_back("SWAP_READ_15");
	adsl_var->push_back("SWAP_READ_30");
	adsl_var->push_back("SWAP_WRITE_1");	// swap outs
	adsl_var->push_back("SWAP_WRITE_5");
	adsl_var->push_back("SWAP_WRITE_10");
	adsl_var->push_back("SWAP_WRITE_15");
	adsl_var->push_back("SWAP_WRITE_30");
	adsl_var->push_back("SWAP_TOTAL_1");	// total swapping activity
	adsl_var->push_back("SWAP_TOTAL_5");
	adsl_var->push_back("SWAP_TOTAL_10");
	adsl_var->push_back("SWAP_TOTAL_15");
	adsl_var->push_back("SWAP_TOTAL_30");
	adsl_var->push_back("PG_FAULT_1");		// minor page faults
	adsl_var->push_back("PG_FAULT_5");
	adsl_var->push_back("PG_FAULT_10");
	adsl_var->push_back("PG_FAULT_15");
	adsl_var->push_back("PG_FAULT_30");
	adsl_var->push_back("PG_MAJ_FAULT_1");	// major page faults
	adsl_var->push_back("PG_MAJ_FAULT_5");
	adsl_var->push_back("PG_MAJ_FAULT_10");
	adsl_var->push_back("PG_MAJ_FAULT_15");
	adsl_var->push_back("PG_MAJ_FAULT_30");
	adsl_var->push_back("NIC_READ_1");		// network load (only receptions)
	adsl_var->push_back("NIC_READ_5");
	adsl_var->push_back("NIC_READ_10");
	adsl_var->push_back("NIC_READ_15");
	adsl_var->push_back("NIC_READ_30");
	adsl_var->push_back("NIC_WRITE_1");		// network load (only transmissions)
	adsl_var->push_back("NIC_WRITE_5");
	adsl_var->push_back("NIC_WRITE_10");
	adsl_var->push_back("NIC_WRITE_15");
	adsl_var->push_back("NIC_WRITE_30");
	adsl_var->push_back("NIC_1");			// total network load
	adsl_var->push_back("NIC_5");
	adsl_var->push_back("NIC_10");
	adsl_var->push_back("NIC_15");
	adsl_var->push_back("NIC_30");
	adsl_var->push_back("CPU_1");			// CPU load
	adsl_var->push_back("CPU_5");
	adsl_var->push_back("CPU_10");
	adsl_var->push_back("CPU_15");
	adsl_var->push_back("CPU_30");
	adsl_var->push_back("INT_1");			// Interrupt load
	adsl_var->push_back("INT_5");
	adsl_var->push_back("INT_10");
	adsl_var->push_back("INT_15");
	adsl_var->push_back("INT_30");
	adsl_var->push_back("CTX_1");			// context switch load
	adsl_var->push_back("CTX_5");
	adsl_var->push_back("CTX_10");
	adsl_var->push_back("CTX_15");
	adsl_var->push_back("CTX_30");
	adsl_var->push_back("PROC_CPU_1");		// CPU load of the process
	adsl_var->push_back("PROC_CPU_5");
	adsl_var->push_back("PROC_CPU_10");
	adsl_var->push_back("PROC_CPU_15");
	adsl_var->push_back("PROC_CPU_30");
	adsl_var->push_back("SESSIONS");		// number of sessions
#endif /* HL_LINUX */
#ifdef HL_WINALL1
	adsl_var->push_back("CACHE_HIT_1");
	adsl_var->push_back("CACHE_HIT_5");
	adsl_var->push_back("CACHE_HIT_10");
	adsl_var->push_back("CACHE_HIT_15");
	adsl_var->push_back("CACHE_HIT_30");
	adsl_var->push_back("CACHE_MISSES_1");
	adsl_var->push_back("CACHE_MISSES_5");
	adsl_var->push_back("CACHE_MISSES_10");
	adsl_var->push_back("CACHE_MISSES_15");
	adsl_var->push_back("CACHE_MISSES_30");
	adsl_var->push_back("CPU_1");
	adsl_var->push_back("CPU_5");
	adsl_var->push_back("CPU_10");
	adsl_var->push_back("CPU_15");
	adsl_var->push_back("CPU_30");
	adsl_var->push_back("PROC_CPU_1");
	adsl_var->push_back("PROC_CPU_5");
	adsl_var->push_back("PROC_CPU_10");
	adsl_var->push_back("PROC_CPU_15");
	adsl_var->push_back("PROC_CPU_30");
	adsl_var->push_back("CTX_1");
	adsl_var->push_back("CTX_5");
	adsl_var->push_back("CTX_10");
	adsl_var->push_back("CTX_15");
	adsl_var->push_back("CTX_30");
	adsl_var->push_back("HARDDISK_1");
	adsl_var->push_back("HARDDISK_5");
	adsl_var->push_back("HARDDISK_10");
	adsl_var->push_back("HARDDISK_15");
	adsl_var->push_back("HARDDISK_30");
	adsl_var->push_back("HD_BPR_1");
	adsl_var->push_back("HD_BPR_5");
	adsl_var->push_back("HD_BPR_10");
	adsl_var->push_back("HD_BPR_15");
	adsl_var->push_back("HD_BPR_30");
	adsl_var->push_back("HD_BPT_1");
	adsl_var->push_back("HD_BPT_5");
	adsl_var->push_back("HD_BPT_10");
	adsl_var->push_back("HD_BPT_15");
	adsl_var->push_back("HD_BPT_30");
	adsl_var->push_back("HD_BPW_1");
	adsl_var->push_back("HD_BPW_5");
	adsl_var->push_back("HD_BPW_10");
	adsl_var->push_back("HD_BPW_15");
	adsl_var->push_back("HD_BPW_30");
	adsl_var->push_back("HD_READ_1");
	adsl_var->push_back("HD_READ_5");
	adsl_var->push_back("HD_READ_10");
	adsl_var->push_back("HD_READ_15");
	adsl_var->push_back("HD_READ_30");
	adsl_var->push_back("HD_WRITE_1");
	adsl_var->push_back("HD_WRITE_5");
	adsl_var->push_back("HD_WRITE_10");
	adsl_var->push_back("HD_WRITE_15");
	adsl_var->push_back("HD_WRITE_30");
	adsl_var->push_back("INT_1");
	adsl_var->push_back("INT_5");
	adsl_var->push_back("INT_10");
	adsl_var->push_back("INT_15");
	adsl_var->push_back("INT_30");
	adsl_var->push_back("IO_ACT_1");
	adsl_var->push_back("IO_ACT_5");
	adsl_var->push_back("IO_ACT_10");
	adsl_var->push_back("IO_ACT_15");
	adsl_var->push_back("IO_ACT_30");
	adsl_var->push_back("IO_TIME_1");
	adsl_var->push_back("IO_TIME_5");
	adsl_var->push_back("IO_TIME_10");
	adsl_var->push_back("IO_TIME_15");
	adsl_var->push_back("IO_TIME_30");
	adsl_var->push_back("MEMORY_1");
	adsl_var->push_back("MEMORY_5");
	adsl_var->push_back("MEMORY_10");
	adsl_var->push_back("MEMORY_15");
	adsl_var->push_back("MEMORY_30");
	adsl_var->push_back("NET_SENT_1");
	adsl_var->push_back("NET_SENT_5");
	adsl_var->push_back("NET_SENT_10");
	adsl_var->push_back("NET_SENT_15");
	adsl_var->push_back("NET_SENT_30");
	adsl_var->push_back("NET_RECV_1");
	adsl_var->push_back("NET_RECV_5");
	adsl_var->push_back("NET_RECV_10");
	adsl_var->push_back("NET_RECV_15");
	adsl_var->push_back("NET_RECV_30");
	adsl_var->push_back("NET_TOTAL_1");
	adsl_var->push_back("NET_TOTAL_5");
	adsl_var->push_back("NET_TOTAL_10");
	adsl_var->push_back("NET_TOTAL_15");
	adsl_var->push_back("NET_TOTAL_30");
	adsl_var->push_back("NIC_1");
	adsl_var->push_back("NIC_5");
	adsl_var->push_back("NIC_10");
	adsl_var->push_back("NIC_15");
	adsl_var->push_back("NIC_30");
	adsl_var->push_back("NIC_READ_1");
	adsl_var->push_back("NIC_READ_5");
	adsl_var->push_back("NIC_READ_10");
	adsl_var->push_back("NIC_READ_15");
	adsl_var->push_back("NIC_READ_30");
	adsl_var->push_back("NIC_WRITE_1");
	adsl_var->push_back("NIC_WRITE_5");
	adsl_var->push_back("NIC_WRITE_10");
	adsl_var->push_back("NIC_WRITE_15");
	adsl_var->push_back("NIC_WRITE_30");
	adsl_var->push_back("PAGE_READ_1");
	adsl_var->push_back("PAGE_READ_5");
	adsl_var->push_back("PAGE_READ_10");
	adsl_var->push_back("PAGE_READ_15");
	adsl_var->push_back("PAGE_READ_30");
	adsl_var->push_back("PAGE_WRITE_1");
	adsl_var->push_back("PAGE_WRITE_5");
	adsl_var->push_back("PAGE_WRITE_10");
	adsl_var->push_back("PAGE_WRITE_15");
	adsl_var->push_back("PAGE_WRITE_30");
	adsl_var->push_back("PAGE_TOTAL_1");
	adsl_var->push_back("PAGE_TOTAL_5");
	adsl_var->push_back("PAGE_TOTAL_10");
	adsl_var->push_back("PAGE_TOTAL_15");
	adsl_var->push_back("PAGE_TOTAL_30");
	adsl_var->push_back("PG_FAULT_1");
	adsl_var->push_back("PG_FAULT_5");
	adsl_var->push_back("PG_FAULT_10");
	adsl_var->push_back("PG_FAULT_15");
	adsl_var->push_back("PG_FAULT_30");
	adsl_var->push_back("PG_MAJ_FAULT_1");
	adsl_var->push_back("PG_MAJ_FAULT_5");
	adsl_var->push_back("PG_MAJ_FAULT_10");
	adsl_var->push_back("PG_MAJ_FAULT_15");
	adsl_var->push_back("PG_MAJ_FAULT_30");
	adsl_var->push_back("PROCESS_1");
	adsl_var->push_back("PROCESS_5");
	adsl_var->push_back("PROCESS_10");
	adsl_var->push_back("PROCESS_15");
	adsl_var->push_back("PROCESS_30");
	adsl_var->push_back("SESSIONS");
	adsl_var->push_back("SWAP_READ_1");
	adsl_var->push_back("SWAP_READ_5");
	adsl_var->push_back("SWAP_READ_10");
	adsl_var->push_back("SWAP_READ_15");
	adsl_var->push_back("SWAP_READ_30");
	adsl_var->push_back("SWAP_WRITE_1");
	adsl_var->push_back("SWAP_WRITE_5");
	adsl_var->push_back("SWAP_WRITE_10");
	adsl_var->push_back("SWAP_WRITE_15");
	adsl_var->push_back("SWAP_WRITE_30");
	adsl_var->push_back("SWAP_TOTAL_1");
	adsl_var->push_back("SWAP_TOTAL_5");
	adsl_var->push_back("SWAP_TOTAL_10");
	adsl_var->push_back("SWAP_TOTAL_15");
	adsl_var->push_back("SWAP_TOTAL_30");
	adsl_var->push_back("SWAPFILE_1");
	adsl_var->push_back("SWAPFILE_5");
	adsl_var->push_back("SWAPFILE_10");
	adsl_var->push_back("SWAPFILE_15");
	adsl_var->push_back("SWAPFILE_30");
	adsl_var->push_back("THREADS_1");
	adsl_var->push_back("THREADS_5");
	adsl_var->push_back("THREADS_10");
	adsl_var->push_back("THREADS_15");
	adsl_var->push_back("THREADS_30");
	adsl_var->push_back("SWAP_1");
	adsl_var->push_back("SWAP_5");
	adsl_var->push_back("SWAP_10");
	adsl_var->push_back("SWAP_15");
	adsl_var->push_back("SWAP_30");
#endif /* HL_WINALL1 */
}

// look if the passed string is a valid variable
bool c_variable_list::m_contains(string strp_var)
{
	bool bol_ret = false;
	vector<string>::iterator dsl_vit;
	for (dsl_vit = adsl_var->begin(); dsl_vit != adsl_var->end(); dsl_vit++)
	{
		if ((*dsl_vit).compare(strp_var) == 0)
		{
			return true;
		}
	}
	return bol_ret;
}

// set load balancing formula
extern "C" int m_set_lb_formula (char* achp_form, const unsigned int ump_length)
{
	int iml_ret = 0;
	unsigned int uml_length = 0;
	if (ump_length > 0)		// needed for backward compatibility with old interface
	{
		uml_length = ump_length;
	}
	else
	{
		uml_length = strlen(achp_form);
	}
	if (!bog_mont_running)
	{
		char* achl_formula = (char*) malloc(uml_length + 1);
		strncpy(achl_formula, achp_form, uml_length);
		achl_formula[uml_length] = '\0';
		dsg_formula = new c_lb_formula(achl_formula);
		free(achl_formula);
	}
	else
	{
		char* achl_formula = (char*) malloc(uml_length + 1);
		strncpy(achl_formula, achp_form, uml_length);
		achl_formula[uml_length] = '\0';
		strg_lb_formula.assign(achl_formula);
		iml_ret = dsg_formula->m_parse_formula(strg_lb_formula);
		if (iml_ret == 0)
		{
			m_hl1_printf("xs-lbal-win-%05d - Assigning a new load balancing formula was successful.",__LINE__);
		}
		free(achl_formula);
	}
	return iml_ret;	
}

#ifdef HL_FREEBSD
static int m_get_token_sum(char* achp_string, ull* uhp_value)
{
	char chrl_to_tokenize[512];
	memcpy(chrl_to_tokenize, achp_string, 512);
	char* achl1 = strtok(chrl_to_tokenize, " ");
	*uhp_value = 0;
	while(achl1)
	{
		*uhp_value += strtoull(achl1, NULL, 10);
		achl1 = strtok(NULL, " ");
	}
	return 0;
}

static int m_get_token(char* achp_string, ull* uhp_value, int imp_index)
{
	char chrl_to_tokenize[512];
	memcpy(chrl_to_tokenize, achp_string, 512);
	char* achl1 = strtok(chrl_to_tokenize, " ");
	int iml_cur_index = 0;
	while(achl1)
	{
		if(imp_index == iml_cur_index)
		{
			*uhp_value = strtoull(achl1, NULL, 10);
			return 0;
		}
		iml_cur_index++;
		achl1 = strtok(NULL, " ");
	}
	return 1;
}
#endif

// get the current load (result of the monitored values and the lb formula)
extern "C" int m_get_load()
{
	// the thread is not running --> return load 0
	if (!bog_mont_running)
	{
		return 0;
	}
	// lock mutex
#ifdef HL_FREEBSD
	pthread_mutex_lock(&dsg_monitor_thread_mutex);
#endif
#ifdef HL_LINUX
	pthread_mutex_lock(&dsg_monitor_thread_mutex);
#endif
#ifdef HL_WINALL1
	HANDLE a_mut = OpenMutexW(SYNCHRONIZE, FALSE, L"MONMUTEX");
#endif

	// fill the structure dsg_load with the values of the current load
	m_get_system_load(dsg_load,false);
	// update the values in the tree nodes of the formula
	dsg_formula->m_set_variables(dsg_load);
	//unlock mutex
#ifdef HL_FREEBSD
	pthread_mutex_unlock(&dsg_monitor_thread_mutex);
#endif
#ifdef HL_LINUX
	pthread_mutex_unlock(&dsg_monitor_thread_mutex);
#endif
#ifdef HL_WINALL1
	ReleaseMutex(a_mut);
	CloseHandle(a_mut);
#endif
	// return the calculation result of the formula tree
	double fdl_ret = dsg_formula->m_calculate();
	fdl_ret *= 10000;
	// correct the load if it is out of range (0 -10000) and write an error message
	if (fdl_ret < 0)		
	{
		m_hl1_printf("xs-lbal-win-%05d - The current load is below 0. Please check if the formula makes sense.",__LINE__);
		return 0;
	}
	if (fdl_ret > 10000)
	{
		m_hl1_printf("xs-lbal-win-%05d - The current load is more than 100 %. Please check if the formula makes sense.",__LINE__);
		return 10000;
	}
	return (int) fdl_ret;
}
		
// write the current load into the log file
void m_write_logfile(int imp_curr_load = 0)
{
	ofstream dsl_logfile;
	dsl_logfile.open(strg_log_file.c_str(),ios::app);
	if(!dsl_logfile.is_open())
	{
		perror("unable to open log file");
		return;	
	}
	time_t dsl_time;
	char* achl_now;
	dsl_time = time(0);
	achl_now = ctime(&dsl_time);
	dsl_logfile << endl;
	dsl_logfile << "Time: ," << achl_now << endl;
	dsl_logfile << "load parameter , last minute, last 5 minutes, last 10 minutes, last 15 minutes, last 30 minutes, unit" << endl;
#ifdef HL_FREEBSD
	dsl_logfile << "Interrupts";
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_ints[iml1];
	}
	dsl_logfile << " , " << "s^(-1)" << endl;
#endif
#ifdef HL_LINUX	
	dsl_logfile << "CPU util.";
	for (int iml1 = 0; iml1<5;iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_cpu[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;
	dsl_logfile << "Interrupts";
	for (int iml1 = 0;iml1<5;iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_ints[iml1];	
	}
	dsl_logfile << " , " << "s^(-1)" << endl;
	dsl_logfile << "Context switches";
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_ctx[iml1];
	}
	dsl_logfile << " , " << "s^(-1)" << endl;
	dsl_logfile << "hd util.";
	for (int iml1 = 0; iml1 < 5;iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_hd_usage[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;		
	dsl_logfile << "hd reading activity";
	for (int iml1 = 0; iml1 <5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_hd_read[iml1];
	}
	dsl_logfile << " , " << "Byte/s" << endl;
	dsl_logfile << "hd writing activity";
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_hd_write[iml1];
	}
	dsl_logfile << " , " << "Byte/s" << endl;
	dsl_logfile << "I/O activity";
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_io_act[iml1];
	}
	dsl_logfile << " , " << "Byte/s" << endl;
	dsl_logfile << "I/O cpu time";
	for (int iml1 = 0; iml1 < 5 ; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_io_time[iml1];
	}
	dsl_logfile << " , " << "% * 100"<< endl;
	dsl_logfile << "processes";
	for (int iml1 = 0; iml1 < 5 ; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_process[iml1];
	}
	dsl_logfile << endl;
	dsl_logfile << "new processes";
	for (int iml1 = 0; iml1 < 5 ; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_init_process[iml1];
	}
	dsl_logfile << " , " << "min^(-1)" << endl;
	dsl_logfile << "memory util.";
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_memory[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;
	dsl_logfile << "swap util.";
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_page_util[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;
	dsl_logfile << "pagein load";
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_page_read[iml1];
	}
	dsl_logfile << " , " << "Pages/s" << endl;
	dsl_logfile << "pageout load";
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_page_write[iml1];
	}
	dsl_logfile << " , " << "Pages/s" << endl;
	dsl_logfile << "paging activity";
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_page_total[iml1];
	}
	dsl_logfile << " , " << "Pages/s" << endl;
	dsl_logfile << "swapin load";
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_swap_read[iml1];
	}
	dsl_logfile << " , " << "Pages/s" << endl;
	dsl_logfile << "swapout load";
	for (int iml1 = 0; iml1 < 5 ; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_swap_write[iml1];
	}
	dsl_logfile << " , " << "Pages/s" << endl;
	dsl_logfile << "swapping activity";
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_swap_act[iml1];
	}
	dsl_logfile << " , " << "Pages/s" << endl;
	dsl_logfile << "minor page faults";
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_min_pg_fault[iml1];
	}
	dsl_logfile << " , " << "s^(-1)" << endl;
	dsl_logfile << "major page faults";
	for (int iml1 = 0; iml1 < 5 ; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_maj_pg_fault[iml1];
	}
	dsl_logfile << " , " << "s^(-1)" << endl;
	dsl_logfile << "network receptions";
	for (int iml1 = 0; iml1 < 5 ; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_nic_recv[iml1];
	}
	dsl_logfile << " , " << "% * 100"<< endl;
	dsl_logfile << "network transmissions";
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_nic_send[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;
	dsl_logfile << "network load";
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_nic_total[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;
	dsl_logfile << "process load";
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_cpu_proc[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;

#endif /* HL_LINUX */	
#ifdef HL_WINALL1
	dsl_logfile << "cache miss rate";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_cache_hit[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;

	dsl_logfile << "cache misses";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_cache_miss[iml1];
	}
	dsl_logfile << " , " << "s^(-1)" << endl;

	dsl_logfile << "CPU util.";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_cpu[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;

	dsl_logfile << "context switches";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_ctx[iml1];
	}
	dsl_logfile << " , " << "s^(-1)" << endl;

	dsl_logfile << "hard disk util.";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_hd_usage[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;

	dsl_logfile << "HD Bytes per read";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_hd_bpr[iml1];
	}
	dsl_logfile << " , " << "Byte" << endl;

	dsl_logfile << "HD Bytes per write";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_hd_bpw[iml1];
	}
	dsl_logfile << " , " << "Byte" << endl;

	dsl_logfile << "HD Bytes per transfer";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_hd_bpt[iml1];
	}
	dsl_logfile << " , " << "Byte" << endl;

	dsl_logfile << "HD reading activity";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_hd_read[iml1];
	}
	dsl_logfile << " , " << "Byte/s" << endl;

	dsl_logfile << "HD writing activity";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_hd_write[iml1];
	}
	dsl_logfile << " , " << "Byte/s" << endl;

	dsl_logfile << "Interrupts";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_ints[iml1];
	}
	dsl_logfile << " , " << "s^(-1)" << endl;

	dsl_logfile << "I/O activity";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_io_act[iml1];
	}
	dsl_logfile << " , " << "Byte/s" << endl;

	dsl_logfile << "I/O cpu load";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_io_time[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;

	dsl_logfile << "Memory util.";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_memory[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;

	dsl_logfile << "Network load (receiving)";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_nic_recv[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;

	dsl_logfile << "Network load (transmitting)";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_nic_send[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;

	dsl_logfile << "Network load";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_nic_total[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;

	dsl_logfile << "Network bytes (transmitting)";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_net_sent[iml1];
	}
	dsl_logfile << " , " << "Byte/s" << endl;

	dsl_logfile << "Network bytes (sending)";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_net_recv[iml1];
	}
	dsl_logfile << " , " << "Byte/s" << endl;

	dsl_logfile << "Network bytes (total)";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_net_total[iml1];
	}
	dsl_logfile << " , " << "Byte/s" << endl;

	dsl_logfile << "Pageins";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_page_read[iml1];
	}
	dsl_logfile << " , " << "Pages/s" << endl;

	dsl_logfile << "Pageouts";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_page_write[iml1];
	}
	dsl_logfile << " , " << "Pages/s" << endl;

	dsl_logfile << "Paging activity";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_page_total[iml1];
	}
	dsl_logfile << " , " << "Pages/s" << endl;

	dsl_logfile << "Page faults";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_page_fault[iml1];
	}
	dsl_logfile << " , " << "s^(-1)" << endl;

	dsl_logfile << "Pagefile util.";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_page_util[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;

	dsl_logfile << "Pagefile size";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_page_file[iml1];
	}
	dsl_logfile << " , " << "Kilobyte" << endl;

	dsl_logfile << "Processes";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_process[iml1];
	}
	dsl_logfile << " , " <<  endl;

	dsl_logfile << "Threads";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_threads[iml1];
	}
	dsl_logfile << " , " << endl;


	dsl_logfile << "process cpu util.";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_proc_cpu[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;


	dsl_logfile << "process threads";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_proc_threads[iml1];
	}
	dsl_logfile << " , " << "Threads" << endl;


	dsl_logfile << "process handles";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_proc_handles[iml1];
	}
	dsl_logfile << " , " << "Handles" << endl;


	dsl_logfile << "process VM util.";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_proc_virt_bytes[iml1];
	}
	dsl_logfile << " , " << "Byte" << endl;

	dsl_logfile << "process read operations";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_proc_read_ops[iml1];
	}
	dsl_logfile << " , " << "Operations" << endl;

	dsl_logfile << "process write operations";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_proc_write_ops[iml1];
	}
	dsl_logfile << " , " << "Operations" << endl;

	dsl_logfile << "process read Bytes";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_proc_read_bytes[iml1];
	}
	dsl_logfile << " , " << "Byte/s" << endl;

	dsl_logfile << "process written bytes";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_proc_write_bytes[iml1];
	}
	dsl_logfile << " , " << "Byte/s" << endl;

	dsl_logfile << "process total bytes";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_proc_total_bytes[iml1];
	}
	dsl_logfile << " , " << "Byte/s" << endl;

	dsl_logfile << "process page faults";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_proc_pg_fault[iml1];
	}
	dsl_logfile << " , " << "Page faults/s" << endl;

	dsl_logfile << "process memory";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_proc_mem_abs[iml1];
	}
	dsl_logfile << " , " << "Byte" << endl;

	dsl_logfile << "process memory util.";
	for(int iml1 = 0; iml1 < 5; iml1++)
	{
		dsl_logfile << " , " << dsg_load.umrl_proc_mem_util[iml1];
	}
	dsl_logfile << " , " << "% * 100" << endl;

	dsl_logfile << "process time in kernel mode , " << dsg_load.uhl_proc_time_kernel / 10000 << "ms" << endl;
	dsl_logfile << "process time in user mode , " << dsg_load.uhl_proc_time_user / 10000 << "ms" << endl;
	dsl_logfile << "total process cpu time, " << (dsg_load.uhl_proc_time_kernel + dsg_load.uhl_proc_time_user) / 10000 << "ms" << endl;

#endif /* HL_WINALL1 */
	if (am_get_sessions > 0)
	{
		dsl_logfile << "sessions";
		dsl_logfile << " , " << am_get_sessions() << endl;
	}
	dsl_logfile << "current load";
	dsl_logfile << " , ";
	ostringstream dsl_ss;
	dsl_ss << (float)((float)imp_curr_load / 100);
	string strl_load = dsl_ss.str();
	strl_load.append(" %");
	dsl_logfile << strl_load << endl;
	dsl_logfile.close();	
}
	
// Test if all values are between 0 and 10000
static bool m_test_validity (struct dsd_server_load& dsp_sl)
{
	bool bo_ret = true;
	for (int iml1 = 0; iml1<5; iml1++)
	{

#ifdef HL_FREEBSD
		if (dsp_sl.umrl_ints[iml1] < 0 )
		{
			dsp_sl.umrl_ints[iml1] = 0;
			bo_ret = false;	
		}	
#endif


#ifdef HL_LINUX		
		// test cpu values
		if (dsp_sl.umrl_cpu[iml1] < 0 || !bog_stat)
		{
			dsp_sl.umrl_cpu[iml1] = 0;
			bo_ret = false;	
		}	
		else if (dsp_sl.umrl_cpu[iml1] > 10000)
		{
			dsp_sl.umrl_cpu[iml1] = 10000;
			bo_ret = false;	
		}
			// test hd load
		if (dsp_sl.umrl_hd_usage[iml1] < 0 || !bog_hd)
		{
			dsp_sl.umrl_hd_usage[iml1] = 0;
			bo_ret = false;	
		}	
		else if (dsp_sl.umrl_hd_usage[iml1] > 10000)
		{
			dsp_sl.umrl_hd_usage[iml1] = 10000;
			bo_ret = false;	
		}
					
		// test hd read
		if (!bog_diskstats || !bog_partitions)
		{
			dsp_sl.umrl_hd_read[iml1] = 0;
			bo_ret = false;	
		}	
		
		// test hd write
		if (!bog_diskstats || !bog_partitions)
		{
			dsp_sl.umrl_hd_write[iml1] = 0;
			bo_ret = false;	
		}	

		
		// test io activity
		if (!bog_diskstats || !bog_partitions)
		{
			dsp_sl.umrl_io_act[iml1] = 0;
			bo_ret = false;	
		}	
		
		// test io time
		if (dsp_sl.umrl_io_time[iml1] < 0 || !bog_diskstats || !bog_partitions)
		{
			dsp_sl.umrl_io_time[iml1] = 0;
			bo_ret = false;	
		}	
		else if (dsp_sl.umrl_io_time[iml1] > 10000)
		{
			dsp_sl.umrl_io_time[iml1] = 10000;
			//bo_ret = false;	
		}
		
		// test process
		if (!bog_loadavg)
		{
			dsp_sl.umrl_process[iml1] = 0;
			bo_ret = false;	
		}	
		
		// test init process
		if ( !bog_loadavg)
		{
			dsp_sl.umrl_init_process[iml1] = 0;
			bo_ret = false;	
		}	
		
		// test memory
		if (dsp_sl.umrl_memory[iml1] < 0 || !bog_meminfo)
		{
			dsp_sl.umrl_memory[iml1] = 0;
			bo_ret = false;	
		}	
		else if (dsp_sl.umrl_memory[iml1] > 10000)
		{
			dsp_sl.umrl_memory[iml1] = 10000;
			bo_ret = false;	
		}
		
		// test swap usage
		if (dsp_sl.umrl_page_util[iml1] < 0 || !bog_meminfo)
		{
			dsp_sl.umrl_page_util[iml1] = 0;
			bo_ret = false;	
		}	
		else if (dsp_sl.umrl_page_util[iml1] > 10000)
		{
			dsp_sl.umrl_page_util[iml1] = 10000;
			bo_ret = false;	
		}					
		
		// test pageins
		if (dsp_sl.umrl_page_read[iml1] < 0 || !bog_vmstat)
		{
			dsp_sl.umrl_page_read[iml1] = 0;
			bo_ret = false;	
		}	
		
		// test pageouts
		if (dsp_sl.umrl_page_write[iml1] < 0|| !bog_vmstat)
		{
			dsp_sl.umrl_page_write[iml1] = 0;
			bo_ret = false;	
		}	
		
		// test page activity
		if (dsp_sl.umrl_page_total[iml1] < 0 || !bog_vmstat)
		{
			dsp_sl.umrl_page_total[iml1] = 0;
			bo_ret = false;	
		}	
		
		// test swapins
		if (dsp_sl.umrl_swap_read[iml1] < 0 || !bog_vmstat)
		{
			dsp_sl.umrl_swap_read[iml1] = 0;
			bo_ret = false;	
		}	
		
		// test swapouts
		if (dsp_sl.umrl_swap_write[iml1] < 0 || !bog_vmstat)
		{
			dsp_sl.umrl_swap_write[iml1] = 0;
			bo_ret = false;	
		}	
		
		// test swap activity
		if (dsp_sl.umrl_swap_act[iml1] < 0 || !bog_vmstat)
		{
			dsp_sl.umrl_swap_act[iml1] = 0;
			bo_ret = false;	
		}	
		
		// test min pg faults
		if (dsp_sl.umrl_min_pg_fault[iml1] < 0 || !bog_vmstat)
		{
			dsp_sl.umrl_min_pg_fault[iml1] = 0;
			bo_ret = false;	
		}	
		
		// test maj pg faults
		if (dsp_sl.umrl_maj_pg_fault[iml1] < 0 || !bog_vmstat)
		{
			dsp_sl.umrl_maj_pg_fault[iml1] = 0;
			bo_ret = false;	
		}	
		
		// test nic receive
		if (dsp_sl.umrl_nic_recv[iml1] < 0 || !bog_netdev || !bog_net)
		{
			dsp_sl.umrl_nic_recv[iml1] = 0;
			bo_ret = false;	
		}	
		else if (dsp_sl.umrl_nic_recv[iml1] > 10000)
		{
			dsp_sl.umrl_nic_recv[iml1] = 10000;
			bo_ret = false;	
		}
		
		// test nic transmit
		if (dsp_sl.umrl_nic_send[iml1] < 0 || !bog_netdev || !bog_net)
		{
			dsp_sl.umrl_nic_send[iml1] = 0;
			bo_ret = false;	
		}	
		else if (dsp_sl.umrl_nic_send[iml1] > 10000)
		{
			dsp_sl.umrl_nic_send[iml1] = 10000;
			bo_ret = false;	
		}
		
		// test nic total
		if (dsp_sl.umrl_nic_total[iml1] < 0 || !bog_netdev || !bog_net)
		{
			dsp_sl.umrl_nic_total[iml1] = 0;
			bo_ret = false;	
		}	
		else if (dsp_sl.umrl_nic_total[iml1] > 10000)
		{
			dsp_sl.umrl_nic_total[iml1] = 10000;
			bo_ret = false;	
		}
		
		// test interrupts
		if (dsp_sl.umrl_ints[iml1] < 0 || !bog_stat)
		{
			dsp_sl.umrl_ints[iml1] = 0;
			bo_ret = false;	
		}	
		
		// test context switches
		if (dsp_sl.umrl_ctx[iml1] < 0 || !bog_stat)
		{
			dsp_sl.umrl_ctx[iml1] = 0;
			bo_ret = false;	
		}	
		
		// test process load
		if (dsp_sl.umrl_cpu_proc[iml1] < 0 || !bog_self_stat)
		{
			dsp_sl.umrl_cpu_proc[iml1] = 0;
			bo_ret = false;
		}
		else if (dsp_sl.umrl_cpu_proc[iml1] > 10000)
		{
			dsp_sl.umrl_cpu_proc[iml1] = 10000;
			bo_ret = false;	
		}
#endif /* HL_LINUX */
#ifdef HL_WINALL1
		// test CACHE_HIT
		if (dsp_sl.umrl_cache_hit[iml1] < 0 || !bog_wmi_cache)
		{
			dsp_sl.umrl_cache_hit[iml1] = 0;
			bo_ret = false;
		}
		else if (dsp_sl.umrl_cache_hit[iml1] > 10000)
		{
			dsp_sl.umrl_cache_hit[iml1] = 10000;
			bo_ret = false;
		}

		// test CPU
		if (dsp_sl.umrl_cpu[iml1] < 0 || !bog_wmi_cpu)
		{
			dsp_sl.umrl_cpu[iml1] = 0;
			bo_ret = false;
		}
		else if (dsp_sl.umrl_cpu[iml1] > 10000)
		{
			dsp_sl.umrl_cpu[iml1] = 10000;
			bo_ret = false;
		}


		// test HARDDISK
		if (dsp_sl.umrl_hd_usage[iml1] < 0 || !bog_wmi_ld || !bog_wmi_ldperf)
		{
			dsp_sl.umrl_hd_usage[iml1] = 0;
			bo_ret = false;
		}
		else if (dsp_sl.umrl_hd_usage[iml1] > 10000)
		{
			dsp_sl.umrl_hd_usage[iml1] = 10000;
			bo_ret = false;
		}

		// test IO_TIME
		if (dsp_sl.umrl_io_time[iml1] < 0 || !bog_wmi_ldperf)
		{
			dsp_sl.umrl_io_time[iml1] = 0;
			bo_ret = false;
		}
		else if (dsp_sl.umrl_io_time[iml1] > 10000)
		{
			dsp_sl.umrl_io_time[iml1] = 10000;
			bo_ret = false;
		}

		// test MEMORY
		if (dsp_sl.umrl_memory[iml1] < 0 || !bog_wmi_mem)
		{
			dsp_sl.umrl_memory[iml1] = 0;
			bo_ret = false;
		}
		else if (dsp_sl.umrl_memory[iml1] > 10000)
		{
			dsp_sl.umrl_memory[iml1] = 10000;
			bo_ret = false;
		}

		// test SWAP
		if (dsp_sl.umrl_page_util[iml1] < 0 || !bog_wmi_page)
		{
			dsp_sl.umrl_page_util[iml1] = 0;
			bo_ret = false;
		}
		else if (dsp_sl.umrl_page_util[iml1] > 10000)
		{
			dsp_sl.umrl_page_util[iml1] = 10000;
			bo_ret = false;
		}

		// test NIC
		if (dsp_sl.umrl_nic_total[iml1] < 0 || !bog_wmi_net)
		{
			dsp_sl.umrl_nic_total[iml1] = 0;
			bo_ret = false;
		}
		else if (dsp_sl.umrl_nic_total[iml1] > 10000)
		{
			dsp_sl.umrl_nic_total[iml1] = 10000;
			bo_ret = false;
		}

		// test NIC_READ
		if (dsp_sl.umrl_nic_recv[iml1] < 0 || !bog_wmi_net)
		{
			dsp_sl.umrl_nic_recv[iml1] = 0;
			bo_ret = false;
		}
		else if (dsp_sl.umrl_nic_recv[iml1] > 10000)
		{
			dsp_sl.umrl_nic_recv[iml1] = 10000;
			bo_ret = false;
		}

		// test NIC_WRITE
		if (dsp_sl.umrl_nic_send[iml1] < 0 || !bog_wmi_net)
		{
			dsp_sl.umrl_nic_send[iml1] = 0;
			bo_ret = false;
		}
		else if (dsp_sl.umrl_nic_send[iml1] > 10000)
		{
			dsp_sl.umrl_nic_send[iml1] = 10000;
			bo_ret = false;
		}
		
		if (dsp_sl.umrl_proc_mem_util[iml1] > 10000)
		{
			dsp_sl.umrl_proc_mem_util[iml1] = 10000;
			bo_ret = false;
		}
#endif

	}
	return bo_ret;	
}	
	
// write the current system load in the passed structure
extern "C" bool m_get_system_load (/*[out]*/ struct dsd_server_load& dsp_sl, bool bop_mutex)
{
#ifdef HL_WINALL1
	HANDLE a_mut;
#endif
	// lock mutex
	if (bop_mutex)	
	{
#ifdef HL_LINUX		
		pthread_mutex_lock(&dsg_monitor_thread_mutex);
#endif
#ifdef HL_WINALL1
	a_mut = OpenMutexW(SYNCHRONIZE, FALSE, L"MONMUTEX");
#endif
	}
	for (int iml1 = 0; iml1 < 5; iml1++)
	{
#ifdef HL_FREEBSD
		// absolute variables
		dsp_sl.umrl_ints[iml1] = (int) (dsg_values.dsl_interrupts.m_get_diff_per_sec(0,imrl_index[iml1]));
		dsp_sl.umrl_ctx_swtch[iml1] =(int) (dsg_values.dsl_context_switches.m_get_diff_per_sec(0, imrl_index[iml1]));
		dsp_sl.umrl_cache_misses[iml1] = (int) (dsg_values.dsl_cache_misses.m_get_diff_per_sec(0, imrl_index[iml1]));
		dsp_sl.umrl_pageins[iml1] = (int) (dsg_values.dsl_pages_in.m_get_diff_per_sec(0, imrl_index[iml1]));
		dsp_sl.umrl_pageouts[iml1] = (int) (dsg_values.dsl_pages_out.m_get_diff_per_sec(0, imrl_index[iml1]));
		dsp_sl.umrl_pagetotal[iml1] = dsp_sl.umrl_pageins[iml1] + dsp_sl.umrl_pageouts[iml1];
		dsp_sl.umrl_swapins[iml1] = (int) (dsg_values.dsl_swaps_in.m_get_diff_per_sec(0, imrl_index[iml1]));
		dsp_sl.umrl_swapouts[iml1] = (int) (dsg_values.dsl_swaps_out.m_get_diff_per_sec(0, imrl_index[iml1]));
		dsp_sl.umrl_swaptotal[iml1] = dsp_sl.umrl_swapins[iml1] + dsp_sl.umrl_swapouts[iml1];
		dsp_sl.umrl_threads[iml1] = (int) (dsg_values.dsl_threads.m_get_average( imrl_index[iml1]));
		dsp_sl.umrl_processes[iml1] = (int) (dsg_values.dsl_processes.m_get_average( imrl_index[iml1]));

		// relative variables
		//try
		{
                        long ill3 = dsg_values.dsl_cpu_total.m_get_difference(0,imrl_index[iml1]);
                        if(ill3 == 0)
                        {
                            cout << "xs-lbal-win-1 Warning: CPU load could not be calculated correctly. Value will be set to 100" << endl;
                            dsp_sl.umrl_cpu[iml1] = 10000;                            
                        }
                        else
                        {
                            dsp_sl.umrl_cpu[iml1] = (int) (10000 - 10000 * dsg_values.dsl_cpu_idle.m_get_difference(0,imrl_index[iml1])  / ill3);
                        }
		}
		//catch (...)
		//{
		//	cout << "xs-lbal-win-1 Warning: CPU load could not be calculated correctly. Value will be set to 100" << endl;
		//	dsp_sl.umrl_cpu[iml1] = 10000;
		//}
		//try
		{
                    long ill3 = dsg_values.dsl_realmem.m_get_average(imrl_index[iml1]);
                    if(ill3 == 0)
                    {
			cout << "xs-lbal-win-1 Warning: memory load could not be calculated correctly. Value will be set to 100" << endl;
			dsp_sl.umrl_memory[iml1] = 10000;                        
                    }
                    else
                    {
                        dsp_sl.umrl_memory[iml1] = (int) (10000 * dsg_values.dsl_usermem.m_get_average(imrl_index[iml1]) / ill3);
                    }
		}
		//catch(...)
		//{

		//}
		//try
		{
                    long ill3 = dsg_values.dsl_cache_checks.m_get_difference(0, imrl_index[iml1]);
                    if(ill3 == 0)
                    {
			cout << "xs-lbal-win-1 Warning: cache hit rate could not be calculated correctly. Value will be set to 100" << endl;
			dsp_sl.umrl_cache_hit_rate[iml1] = 0;                        
                    }
                    else
                    {
                        dsp_sl.umrl_cache_hit_rate[iml1] = (int) (10000 - 10000 * dsg_values.dsl_cache_misses.m_get_difference(0, imrl_index[iml1]) / ill3);
                    }
		}
		//catch(...)
		//{

		//}
		//try
		{
                    long ill3 = dsg_values.dsl_swap_total.m_get_average(imrl_index[iml1]);
                    if(ill3 == 0)
                    {
			cout << "xs-lbal-win-1 Warning: swap usage could not be calculated correctly. Value will be set to 100" << endl;
			dsp_sl.umrl_swap_usage[iml1] = 10000;                        
                    }
                    else
                    {
			dsp_sl.umrl_swap_usage[iml1] = (int) (10000 * dsg_values.dsl_swap_used.m_get_average(imrl_index[iml1]) / ill3);
                    }
		}
		//catch(...)
		//{

		//}

		// process variables
		//try
		{
                    long ill3 = dsg_values.dsl_realmem.m_get_average(imrl_index[iml1]);
                    if(ill3 == 0)
                    {
                        m_hl1_printf("xs-lbal-win-1 Warning: could not calculate memory usage of current process. Value will be set to 100");
                        dsp_sl.umrl_proc_memory[iml1] = 10000;
                    }
                    else
                    {
			dsp_sl.umrl_proc_memory[iml1] = (int) (10000 * dsg_values.dsl_proc_memory.m_get_average(imrl_index[iml1]) * 4096 / ill3);
                    }
		}
		//catch(...)
		//{
			//m_hl1_printf("xs-lbal-win-1 Warning: could not calculate memory usage of current process. Value will be set to 100");
		//}
		dsp_sl.ulc_memory = dsg_values.dsl_proc_memory.m_get_latest_element() * 4096;
		dsp_sl.umrl_proc_pg_fault[iml1] = (int) (dsg_values.dsl_proc_page_faults.m_get_diff_per_sec(0, imrl_index[iml1]));
		dsp_sl.uhl_proc_page_faults_tot = dsg_values.dsl_proc_page_faults.m_get_latest_element();
		dsp_sl.umrl_proc_io_read[iml1] = (int) (dsg_values.dsl_proc_io_reads.m_get_diff_per_sec(0, imrl_index[iml1]));
		dsp_sl.umrl_proc_io_write[iml1] = (int) (dsg_values.dsl_proc_io_writes.m_get_diff_per_sec(0, imrl_index[iml1]));
		dsp_sl.uhl_proc_io_read_tot = dsg_values.dsl_proc_io_reads.m_get_latest_element();
		dsp_sl.uhl_proc_io_write_tot = dsg_values.dsl_proc_io_writes.m_get_latest_element();
		dsp_sl.umrl_proc_threads[iml1] = (int)(dsg_values.dsl_proc_threads.m_get_average(imrl_index[iml1]));
		dsp_sl.uhl_proc_threads_cur = dsg_values.dsl_proc_threads.m_get_latest_element();
		dsp_sl.uhl_proc_user_time = dsg_values.dsl_proc_user_time.m_get_latest_element();	
		dsp_sl.uhl_proc_system_time = dsg_values.dsl_proc_system_time.m_get_latest_element();
		dsp_sl.ulc_cpu_total_time = dsp_sl.uhl_proc_user_time + dsp_sl.uhl_proc_system_time;
                long ill4 = (10000 * (imrl_index[iml1] - 1));
                if(ill4 == 0)
                {
                    m_hl1_printf("xs-lbal-win-1 Warning: could not cpu usage of current process. Value will be set to 100");
                    dsp_sl.umrl_proc_cpu[iml1] = 10000;
                }
                else
                {
                    dsp_sl.umrl_proc_cpu[iml1] = (int)(10000 * (dsg_values.dsl_proc_system_time.m_get_difference(0,imrl_index[iml1]) + dsg_values.dsl_proc_user_time.m_get_difference(0,imrl_index[iml1])) / ill4);
                }
		dsp_sl.umrl_proc_ctx_invol[iml1] = (int) (dsg_values.dsl_proc_ctx_involuntary.m_get_diff_per_sec(0, imrl_index[iml1]));
		dsp_sl.umrl_proc_ctx_vol[iml1]   = (int) (dsg_values.dsl_proc_ctx_voluntary.m_get_diff_per_sec(0, imrl_index[iml1]));
		dsp_sl.uhl_proc_ctx_invol = dsg_values.dsl_proc_ctx_involuntary.m_get_latest_element();
		dsp_sl.uhl_proc_ctx_vol =dsg_values.dsl_proc_ctx_voluntary.m_get_latest_element();
		//dsp_sl.ulc_io_total_ops = dsp_sl.uhl_proc_io_read_tot + dsp_sl.uhl_proc_io_write_tot;
#endif

#ifdef HL_LINUX		
		// set hard disk load
		ull uhl1 = 0;
		
		if (dsg_ref.uhl_hd_total == 0)
		{
			dsp_sl.umrl_hd_usage[iml1] = 0;
		}
		else
		{
			dsp_sl.umrl_hd_usage[iml1] = (int) (10000 * dsg_values.dsl_free_hd.m_get_average(imrl_index[iml1])
										      / dsg_ref.uhl_hd_total);
			dsp_sl.umrl_hd_usage[iml1] = 10000 - dsp_sl.umrl_hd_usage[iml1];
		}

		// set hard disk reading activity	
		dsp_sl.umrl_hd_read[iml1] = (int) (dsg_values.dsl_read_sectors.m_get_diff_per_sec(0,imrl_index[iml1])*512);
									
		// set hard disk writing activity
		dsp_sl.umrl_hd_write[iml1] = (int) (dsg_values.dsl_written_sectors.m_get_diff_per_sec(0,imrl_index[iml1])*512);
								
		// set io time consuption
		dsp_sl.umrl_io_time[iml1] = (int) (10 * dsg_values.dsl_io_time.m_get_diff_per_sec(0,imrl_index[iml1]));
										
		// set process load
		dsp_sl.umrl_process[iml1] = (int) (dsg_values.dsl_processes.m_get_average(imrl_index[iml1]));
										  	
		// set new processes
		dsp_sl.umrl_init_process[iml1] = (int) (60 * dsg_values.dsl_started_processes.m_get_diff_per_sec(0,imrl_index[iml1]));
										
		// set memory usage
		if (dsg_ref.uhl_memory == 0)
		{
			dsp_sl.umrl_memory[iml1] = 0;
		}
		else
		{
			dsp_sl.umrl_memory[iml1] = (int) (10000 * dsg_values.dsl_free_memory.m_get_average(imrl_index[iml1])
											  / dsg_ref.uhl_memory);
			// because the calculated value represents free memory, we have to invert the value
			dsp_sl.umrl_memory[iml1] = 10000 - dsp_sl.umrl_memory[iml1];
		}
			
		// set usage of the swap partition
		if (dsg_ref.ill_swap_total == 0)
		{
			dsp_sl.umrl_page_util[iml1] =0;
		}
		else
		{
			dsp_sl.umrl_page_util[iml1] = (int) (10000 * dsg_values.dsl_free_swap.m_get_average(imrl_index[iml1])
												 / dsg_ref.ill_swap_total);
			// inversion
			dsp_sl.umrl_page_util[iml1] = 10000 - dsp_sl.umrl_page_util[iml1];
		}
		// set pageins
		dsp_sl.umrl_page_read[iml1] = (int) (dsg_values.dsl_page_in.m_get_diff_per_sec(0,imrl_index[iml1]));
											
		// set pageouts
		dsp_sl.umrl_page_write[iml1] = (int) (dsg_values.dsl_page_out.m_get_diff_per_sec(0,imrl_index[iml1]));
											
		// set paging activity
		dsp_sl.umrl_page_total[iml1] = (int) (dsp_sl.umrl_page_read[iml1] +dsp_sl.umrl_page_write[iml1]);
		// set swapins
		dsp_sl.umrl_swap_read[iml1] = (int) (dsg_values.dsl_swap_in.m_get_diff_per_sec(0,imrl_index[iml1]));
											
		// set swapouts
		dsp_sl.umrl_swap_write[iml1] = (int) (dsg_values.dsl_swap_out.m_get_diff_per_sec(0,imrl_index[iml1]));
											
		// set swapping activity
		dsp_sl.umrl_swap_act[iml1] = (int) (dsp_sl.umrl_swap_read[iml1] + dsp_sl.umrl_swap_write[iml1]);
		// set minor page faults
		dsp_sl.umrl_min_pg_fault[iml1] = (int) (dsg_values.dsl_min_pg_faults.m_get_diff_per_sec(0,imrl_index[iml1]));

		// set major page faults
		dsp_sl.umrl_maj_pg_fault[iml1] = (int) (dsg_values.dsl_maj_pg_faults.m_get_diff_per_sec(0,imrl_index[iml1]));
										
		if (dsg_ref.ill_byte_per_sec == 0)
		{
			dsp_sl.umrl_nic_recv[iml1] = 0;
			dsp_sl.umrl_nic_send[iml1] = 0;
		}
		else
		{											
			// set network receiving activity
			dsp_sl.umrl_nic_recv[iml1] = (int) (10000 * dsg_values.dsl_net_rec.m_get_diff_per_sec(0,imrl_index[iml1])
											  / dsg_ref.ill_byte_per_sec);
			// set network transmitting activity
			dsp_sl.umrl_nic_send[iml1] = (int) (10000 * dsg_values.dsl_net_trans.m_get_diff_per_sec(0,imrl_index[iml1])
											    / dsg_ref.ill_byte_per_sec);
		}
		// set total network activity
		dsp_sl.umrl_nic_total[iml1] = dsp_sl.umrl_nic_recv[iml1] + dsp_sl.umrl_nic_send[iml1];
			// set total I/O activity
		dsp_sl.umrl_io_act[iml1] = (int) (dsp_sl.umrl_hd_read[iml1] +
											   dsp_sl.umrl_hd_write[iml1] +
											   dsg_values.dsl_net_trans.m_get_diff_per_sec(0, imrl_index[iml1]) +
											   dsg_values.dsl_net_rec.m_get_diff_per_sec(0, imrl_index[iml1]));
		// set cpu usage
		uhl1 = dsg_values.dsl_total_jiffies.m_get_diff_per_sec(0,imrl_index[iml1]);

		if (uhl1 == 0)
		{
			dsp_sl.umrl_cpu[iml1] = 0;
		}
		else
		{
			dsp_sl.umrl_cpu[iml1] = (int) (10000 * dsg_values.dsl_idle_jiffies.m_get_diff_per_sec(0,imrl_index[iml1])
												  / uhl1);
		
			// because we used idle jiffies we have to invert the value to get the correct load
			dsp_sl.umrl_cpu[iml1] = 10000 - dsp_sl.umrl_cpu[iml1];
		}
		
		// set interrupts
		dsp_sl.umrl_ints[iml1] = (int) (dsg_values.dsl_interrupts.m_get_diff_per_sec(0,imrl_index[iml1]));
									
		// set context switches
		dsp_sl.umrl_ctx[iml1] = (int) (dsg_values.dsl_ctx_switch.m_get_diff_per_sec(0,imrl_index[iml1]));
													 																							   											  	
		// set process cpu utilization
		uhl1 = dsg_values.dsl_total_jiffies.m_get_diff_per_sec(0,imrl_index[iml1]);
		if (uhl1 == 0)
		{
			dsp_sl.umrl_cpu_proc[iml1] = 0;
		}
		else
		{
			dsp_sl.umrl_cpu_proc[iml1] = (int) (10000 * dsg_values.dsl_proc_jiffies.m_get_diff_per_sec(0,imrl_index[iml1])
											   / uhl1);
		}
		
#endif /* HL_LINUX */	
#ifdef HL_WINALL1
		ull uhl1 = 0;
		LONG ill1 = 0;
		// set CACHE_HIT
		ill1 = dsg_values.dsl_cache_copy_reads_ps.m_get_difference(0, imrl_index[iml1]);
		LONG temp;
		if (ill1 == 0)
		{
			dsp_sl.umrl_cache_hit[iml1] = 0;
		}
		else
		{
			temp = dsg_values.dsl_cache_copy_read_hits_pc.m_get_difference(0, imrl_index[iml1]);
			dsp_sl.umrl_cache_hit[iml1] = (unsigned int) (10000 * ((double)dsg_values.dsl_cache_copy_read_hits_pc.m_get_difference(0, imrl_index[iml1]) / (double)ill1));
		}

		// set SWAP
		ill1 = dsg_values.dsl_page_size.m_get_average(imrl_index[iml1]);
		if (ill1 == 0)
		{
			dsp_sl.umrl_page_util[iml1] = 0;
		}
		else
		{
			dsp_sl.umrl_page_util[iml1] = (unsigned int) (10000 * dsg_values.dsl_page_usage_pc.m_get_average(imrl_index[iml1])  / ill1);
		}

		// set NET
		dsp_sl.umrl_net_sent[iml1] = dsg_values.dsl_net_sent_ps.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency));
		dsp_sl.umrl_net_recv[iml1] = dsg_values.dsl_net_recv_ps.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency));
		dsp_sl.umrl_net_total[iml1] = dsg_values.dsl_net_total_ps.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency));

		// set NIC
		if (dsg_ref.uhl_network_bw == 0)
		{
			dsp_sl.umrl_nic_total[iml1] = 0;
			dsp_sl.umrl_nic_recv[iml1] = 0;
			dsp_sl.umrl_nic_send[iml1] = 0;
		}
		else
		{
			// use 80000 as multiplicator to compare bit/s with bit/s instead of byte/s with bit/s
			dsp_sl.umrl_nic_total[iml1] = (unsigned int) (80000 * dsg_values.dsl_net_total_ps.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)) / dsg_ref.uhl_network_bw);
			dsp_sl.umrl_nic_recv[iml1] = (unsigned int) (80000 * dsg_values.dsl_net_recv_ps.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)) / dsg_ref.uhl_network_bw);
			dsp_sl.umrl_nic_send[iml1] = (unsigned int) (80000 * dsg_values.dsl_net_sent_ps.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)) / dsg_ref.uhl_network_bw);
		}

		// set CACHE_MISSES
		dsp_sl.umrl_cache_miss[iml1] = (unsigned int) ( dsg_values.dsl_cache_copy_reads_ps.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)) - dsg_values.dsl_cache_copy_read_hits_pc.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)));
		
		// set CPU
		dsp_sl.umrl_cpu[iml1] = 10000 - (unsigned int) (dsg_values.dsl_cpu_idle.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)) / 1000);

		// set PROC_CPU
		//dsp_sl.umrl_cpu_proc[iml1] = (unsigned int) (dsg_values.dsl_pp_proc_time.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)) / 1000);

		// set CTX
		dsp_sl.umrl_ctx[iml1] = (unsigned int) (dsg_values.dsl_sys_ctx.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)));
#ifdef DEBUG
		if (dsp_sl.umrl_ctx[iml1] < 0)
		{
			int iml2 = 0;
		}

#endif /* DEBUG */

		// set HARDDISK
		if (dsg_ref.uhl_disk_space == 0)
		{
			dsp_sl.umrl_hd_usage[iml1] = 0;
		}
		else
		{
			dsp_sl.umrl_hd_usage[iml1] = 10000 - (unsigned int) (10000 * dsg_values.dsl_ld_free_space.m_get_average(imrl_index[iml1]) / dsg_ref.uhl_disk_space);
		}

		// set HD_BPR
		ill1 = dsg_values.dsl_ldperf_disk_reads_ps.m_get_difference(0, imrl_index[iml1]);
		if (ill1 == 0)
		{
			dsp_sl.umrl_hd_bpr[iml1] = 0;
		}
		else
		{
			dsp_sl.umrl_hd_bpr[iml1] = (unsigned int) ( dsg_values.dsl_ldperf_avg_disk_bytes_read.m_get_difference(0, imrl_index[iml1]) / ill1);
		}

		// set HD_BPW
		ill1 = dsg_values.dsl_ldperf_disk_writes_ps.m_get_difference(0, imrl_index[iml1]);
		if (ill1 == 0)
		{
			dsp_sl.umrl_hd_bpw[iml1] = 0;
		}
		else
		{
			dsp_sl.umrl_hd_bpw[iml1] = (unsigned int) ( dsg_values.dsl_ldperf_avg_disk_bytes_write.m_get_difference(0, imrl_index[iml1]) / ill1);
		}

		// set HD_BPT
		ill1 = dsg_values.dsl_ldperf_disk_transfers_ps.m_get_difference(0, imrl_index[iml1]);
		if (ill1 == 0)
		{
			dsp_sl.umrl_hd_bpt[iml1] = 0;
		}
		else
		{
			dsp_sl.umrl_hd_bpt[iml1] = (unsigned int) (dsg_values.dsl_ldperf_avg_disk_bytes_transfer.m_get_difference(0, imrl_index[iml1]) / ill1);
		}

		// set HD_READ
		dsp_sl.umrl_hd_read[iml1] = (unsigned int) (dsg_values.dsl_ldperf_avg_disk_bytes_read.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)));

		// set HD_WRITE
		dsp_sl.umrl_hd_write[iml1] = (unsigned int) (dsg_values.dsl_ldperf_avg_disk_bytes_write.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)));

		// set IO_ACT
		dsp_sl.umrl_io_act[iml1] = dsp_sl.umrl_hd_read[iml1] + dsp_sl.umrl_hd_write[iml1] + dsg_values.dsl_net_total_ps.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency));

		// set INT
		dsp_sl.umrl_ints[iml1] = (unsigned int) (dsg_values.dsl_cpu_int.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)));

		// set IO_TIME
		dsp_sl.umrl_io_time[iml1] = (unsigned int) (dsg_values.dsl_ldperf_disk_time_pc.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)) / 1000);

		// set MEMORY
		dsp_sl.umrl_memory[iml1] = 10000 - (unsigned int) (10000 * dsg_values.dsl_mem_avail_bytes.m_get_average(imrl_index[iml1]) / dsg_ref.uhl_memory);
		
		// set PAGE_READ / SWAP_READ
		dsp_sl.umrl_page_read[iml1] = (unsigned int) (dsg_values.dsl_mem_page_input_ps.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)));

		// set PAGE_WRITE / SWAP_WRITE
		dsp_sl.umrl_page_write[iml1] = (unsigned int) (dsg_values.dsl_mem_page_output_ps.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)));

		// set PAGE_TOTAL / SWAP_TOTAL
		dsp_sl.umrl_page_total[iml1] = (unsigned int) (dsg_values.dsl_mem_page_total_ps.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)));

		// set PG_FAULT / PG_MAJ_FAULT
		dsp_sl.umrl_page_fault[iml1] = (unsigned int) (dsg_values.dsl_mem_page_faults_ps.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)));

		// set SWAP
		ill1 = dsg_values.dsl_page_size.m_get_average(imrl_index[iml1]);
		if (ill1 == 0)
		{
			dsp_sl.umrl_page_util[iml1] = 0;
		}
		else
		{
			dsp_sl.umrl_page_util[iml1] = (unsigned int) (10000 * dsg_values.dsl_page_usage_pc.m_get_average(imrl_index[iml1]) / ill1);
		}

		// set SWAPFILE
		dsp_sl.umrl_page_file[iml1] = (unsigned int) (dsg_values.dsl_page_size.m_get_average(imrl_index[iml1]) * dsg_ref.dwl_page_size / 1024);

		// set PROCESS
		dsp_sl.umrl_process[iml1] = (unsigned int) ( dsg_values.dsl_obj_processes.m_get_average(imrl_index[iml1]));

		// set THREADS
		dsp_sl.umrl_threads[iml1] = (unsigned int) (dsg_values.dsl_obj_threads.m_get_average(imrl_index[iml1]));

		// set process variables
		dsp_sl.umrl_proc_cpu[iml1] = (unsigned int) (dsg_values.dsl_proc_cpu.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)) / 1000);
		dsp_sl.umrl_proc_threads[iml1] = (unsigned int) (dsg_values.dsl_proc_threads.m_get_average(imrl_index[iml1]));
		dsp_sl.umrl_proc_handles[iml1] = (unsigned int) (dsg_values.dsl_proc_handles.m_get_average(imrl_index[iml1]));
		dsp_sl.umrl_proc_virt_bytes[iml1] = (unsigned int) (dsg_values.dsl_proc_virt_bytes.m_get_average(imrl_index[iml1]));
		dsp_sl.umrl_proc_read_ops[iml1] = (unsigned int) (dsg_values.dsl_proc_io_read_ops.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)));
		dsp_sl.umrl_proc_write_ops[iml1] = (unsigned int) (dsg_values.dsl_proc_io_write_ops.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)));
		unsigned int uml_tmp1 = dsp_sl.umrl_proc_read_bytes[iml1] = (unsigned int) (dsg_values.dsl_proc_io_read_bytes.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)));
		unsigned int uml_tmp2 = dsp_sl.umrl_proc_write_bytes[iml1] = (unsigned int) (dsg_values.dsl_proc_io_write_bytes.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)));
		dsp_sl.umrl_proc_total_bytes[iml1] = uml_tmp1 + uml_tmp2;
		dsp_sl.umrl_proc_pg_fault[iml1] = (unsigned int) (dsg_values.dsl_proc_page_faults.m_get_diff_per_sec(0, imrl_index[iml1], &(dsg_values.dsl_timestamp), &(dsg_values.dsl_frequency)));
		dsp_sl.umrl_proc_mem_util[iml1] = (unsigned int) ((dsg_values.dsl_proc_working_set.m_get_average(imrl_index[iml1]) * 10000 )/ dsg_ref.uhl_memory);
		dsp_sl.umrl_proc_mem_abs[iml1] = (unsigned int) (dsg_values.dsl_proc_working_set.m_get_average(imrl_index[iml1]));
		dsp_sl.uhl_proc_time_kernel = dsg_values.uhl_proc_kernel_time / 10000;
		dsp_sl.uhl_proc_time_user = dsg_values.uhl_proc_user_time / 10000;
											
#endif /* HL_WINALL1 */
	}
#ifdef HL_WINALL1
	dsp_sl.uml_proc_curr_threads = dsg_values.dsl_proc_threads.m_get_latest_element();
	dsp_sl.uml_proc_curr_handles = dsg_values.dsl_proc_handles.m_get_latest_element();
	dsp_sl.uhl_proc_virt_bytes = dsg_values.dsl_proc_virt_bytes.m_get_latest_element();
	dsp_sl.uhl_proc_write_operations = dsg_values.dsl_proc_io_write_ops.m_get_latest_element();
	dsp_sl.uhl_proc_read_operations = dsg_values.dsl_proc_io_read_ops.m_get_latest_element();
	dsp_sl.uhl_proc_write_bytes = dsg_values.dsl_proc_io_write_bytes.m_get_latest_element();
	dsp_sl.uhl_proc_read_bytes = dsg_values.dsl_proc_io_read_bytes.m_get_latest_element();
	dsp_sl.uhl_proc_total_bytes = dsp_sl.uhl_proc_read_bytes + dsp_sl.uhl_proc_write_bytes;
	dsp_sl.uml_proc_pg_faults = dsg_values.dsl_proc_page_faults.m_get_latest_element();
	dsp_sl.uml_proc_curr_mem = dsg_values.dsl_proc_working_set.m_get_latest_element();
	dsp_sl.uml_proc_curr_mem_util = (unsigned int) ( (10000 * dsg_values.dsl_proc_working_set.m_get_element(0)) / dsg_ref.uhl_memory);
#endif
#ifdef HL_LINUX
	dsp_sl.uhl_proc_virt_memory = 0;
	dsp_sl.uhl_proc_cpu_time = 0;
	dsp_sl.uhl_proc_io_ops = 0;
	dsp_sl.uhl_proc_io_bytes = 0;
#endif	

	// test if all values are correct
	bool bo_valid = m_test_validity(dsp_sl);
	// unlock mutex
	if (bop_mutex)
	{
#ifdef HL_LINUX	
		pthread_mutex_unlock(&dsg_monitor_thread_mutex);
#endif
#ifdef HL_WINALL1
		ReleaseMutex(a_mut);
		CloseHandle(a_mut);
#endif
	}
	return bo_valid;
}

// update reference values that are variable
static bool m_update_memory()
{
	bool bo_ret = true;
#ifdef HL_LINUX
	if (!bog_meminfo) return false;
	vector<string>* strp_token = new vector<string>();
	string str_line;
	
	// get total swap and ram
	ifstream dsl_meminfo("/proc/meminfo");
	if (!dsl_meminfo)
	{
		m_hl1_printf("xs-lbal-win-%05d - The file /proc/meminfo could not be found.",__LINE__);
		bo_ret = false;
		bog_meminfo = false;
		dsg_ref.uhl_memory = 10000000;
		dsg_ref.ill_swap_total = 10000000;
		//strp_token = NULL;	
	}
	// read lines from /proc/meminfo
	while (	getline(dsl_meminfo,str_line))
	{
		m_str_tok(str_line, *strp_token);
		if(strp_token->size() < 2)
		{
		    m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/meminfo. Using default values.",__LINE__);
		    dsg_ref.uhl_memory = 10000000;
		    dsg_ref.ill_swap_total = 10000000;
		    strp_token->clear();
		    break;
		}
		
		if (!strcmp(strp_token->at(0).c_str(),"MemTotal:"))
		{
			dsg_ref.uhl_memory = strtol(strp_token->at(1).c_str(),NULL,10);
		}
		else if (!strcmp(strp_token->at(0).c_str(),"SwapTotal:"))
		{
			dsg_ref.ill_swap_total = strtol(strp_token->at(1).c_str(),NULL,10);
		}
		strp_token->clear();
	}
	dsl_meminfo.close();
	delete strp_token;
#endif /* HL_LINUX */	
	return bo_ret;
}
	
// write the names of all available network interfaces into the passed vector
static bool m_search_nics(vector<string>& strp_nic)
{
	bool bo_ret = true;
#ifdef HL_LINUX	
	string str_line;
	vector<string>* strl_token = new vector<string>();
	ifstream dsl_net_dev("/proc/net/dev");
	// file not found
	if (!dsl_net_dev)
	{
		m_hl1_printf("xs-lbal-win-%05d - The file /proc/net/dev could not be found.",__LINE__);
		perror("/proc/net/dev could not be opened: ");
		delete strl_token;
		return false;	
	}
	// the first two lines of /proc/net/dev are not important
	getline(dsl_net_dev,str_line);
	getline(dsl_net_dev,str_line);
	// each further line contains data for one specific network interface
	while(getline(dsl_net_dev,str_line))
	{
		// use the string tokenizer to split the read line
		m_str_tok(str_line,*strl_token);
		if(strl_token->size() < 1)
		{
		    m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/net/dev.",__LINE__);
		    strl_token->clear();
		    break;
		}
		// get the first token which contains the name
		string str_sub = strl_token->at(0);
		// look for the first ':', the substring before will be the name
		int iml1 = str_sub.find_first_of(':');
		str_sub = str_sub.substr(0,iml1);
		// write the name into the vector
		strp_nic.push_back(str_sub);
		strl_token->clear();
	}
	dsl_net_dev.close();
	delete strl_token;
#endif /* HL_LINUX */	
	return bo_ret;
}

// write the names of all available wireless network interfaces in the passed vector
static bool m_search_wireless_nics(vector<string>& strp_wnic)
{
	bool bo_ret = true;
#ifdef HL_LINUX	
	string str_line;
	vector<string>* strl_token = new vector<string>();
	ifstream dsl_net_wl("/proc/net/wireless");	
	if (!dsl_net_wl)
	{
		m_hl1_printf("xs-lbal-win-%05d - The file /proc/net/wireless could not be found.",__LINE__);
		perror("/proc/net/wireless could not be opened: ");
		delete strl_token;
		return false;
	}
	// the first two lines of /proc/net/wireless are not important
	getline(dsl_net_wl,str_line);
	getline(dsl_net_wl,str_line);
	// each further line contains data for one specific network interface
	while(getline(dsl_net_wl,str_line))
	{
		// use the string tokenizer to split the read line
		m_str_tok(str_line,*strl_token);
		if(strl_token->size() < 1)
		{
		    m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/net/wireless.",__LINE__);
		    strl_token->clear();
		    break;
		}
		// get the first token which contains the name
		string str_sub = strl_token->at(0);
		// look for the first ':', the substring before will be the name
		int iml1 = str_sub.find_first_of(':');
		str_sub = str_sub.substr(0,iml1);
		// write the name into the vector
		strp_wnic.push_back(str_sub);
		strl_token->clear();
	}	
	dsl_net_wl.close();
	delete strl_token;
#endif /* HL_LINUX */
	return bo_ret;	
}	
		
// update the bandwidth of network interfaces
static bool m_update_net()
{
	bool bo_ret = true;
	/*----------   update ethernet bandwidth ----------*/
#ifdef HL_LINUX
	struct ifreq dsl_ifr;
	int iml_fd;
	struct ethtool_cmd dsl_ecmd;
	int iml_err;
	int iml_eth_sum = 0;
	// network interface names
	vector<string>* adsl_nics = new vector<string>();
	// get network interfaces
	if (!m_search_nics(*adsl_nics))
	{
		delete adsl_nics;
		return false;
	}
	
	/* Setup our control structures. */
	memset((char*) &dsl_ifr, 0, sizeof(dsl_ifr));
	
	/* for all network interfaces */
	for (unsigned int uml1 = 0; uml1< adsl_nics->size(); uml1++)
	{
		// load the name of the interface
		strcpy(dsl_ifr.ifr_name, adsl_nics->at(uml1).c_str());
								
		/* Open control socket. */
		iml_fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (iml_fd < 0)
		{
			perror("Cannot get control socket");
		}
		dsl_ecmd.cmd = 1;
		dsl_ifr.ifr_data = (caddr_t)&dsl_ecmd;
		
		// try to contact network interface
		if (iml_fd >= 0 && ((iml_err = ioctl(iml_fd,SIOCETHTOOL,&dsl_ifr)) == 0))
		{
			// if the contact was successful add the bandwidth to the sum
			iml_eth_sum +=  (__uint16_t)dsl_ecmd.speed;
		}
		if (errno == 1)		// operation not permitted (if the owner of the process is not root)
		{
			
			bo_ret = false;	
		}
		close(iml_fd);
	}
	if (!bo_ret)
	{
		if (!bog_root_warning)
		{
			//m_hl1_printf("xs-lbal-win-%05d - You are not root. Please restart the program as root, otherwise load balancing may not work properly.",__LINE__);
			bog_root_warning = true;
		}			
	}
			
	/*----------   update wireless bandwidth ----------*/
	long ill_wl_sum = 0;
	// network interface names
	vector<string>* adsl_wnics = new vector<string>();
	m_search_wireless_nics(*adsl_wnics);		
	struct iwreq dsl_wrq;
   	memset((char *) &dsl_wrq, 0, sizeof(struct iwreq));
	/* for all wireless network interfaces */
	for (unsigned int uml1 = 0; uml1< adsl_wnics->size(); uml1++)
	{		
		int iml_skfd;		/* generic raw socket desc.	*/
		  /* Create a channel to the NET kernel. */
 			if((iml_skfd = iw_sockets_open()) < 0)
   		{
     			perror("socket");
     			break;
   		}			
   		// copy nic name
   		strcpy(dsl_wrq.ifr_name, adsl_wnics->at(uml1).c_str());
   		// ask nic for its bandwidth
 		if (ioctl(iml_skfd, SIOCGIWRATE, &dsl_wrq) == 0)
 		{
 			// if successful add the bandwidth to the sum
 			ill_wl_sum += dsl_wrq.u.bitrate.value;
 		}
 		// close socket
 		close(iml_skfd);		
	}
	
	delete adsl_nics;
	delete adsl_wnics;
	
	// combine bandwidth of ethernet and wireless
	long ill_bandwidth = 0;		// total bandwidth in bytes per second
	long ill_bw_eth = 125000 * iml_eth_sum;	// ethernet bandwidth in bytes per second
	long ill_bw_wl = (long)(ill_wl_sum / 8);		// wireless bandwidth in bytes per second
	ill_bandwidth = ill_bw_eth + ill_bw_wl;
	
	if (ill_bandwidth == 0)
	{
		return false;
	}
	else
	{
		dsg_ref.ill_byte_per_sec = ill_bandwidth;	
	}
#endif /* HL_LINUX */	
	return bo_ret;
}
	
// update hard disk capacity
static bool m_update_hd()
{
	bool bo_ret = true;
#ifdef HL_LINUX	
	
	vector<string> dsl_drives;	// mountpoint of drives
	vector<string> dsl_token;
	vector<string> dsl_partitions;	// partitions in /proc partitions
	string str_line;
	
	/*--------------get mounted drives------------*/
	ifstream dsl_part("/proc/partitions");
	// file not found
	if(!dsl_part)
	{
		m_hl1_printf("xs-lbal-win-%05d - The file /proc/partitions could not be found.",__LINE__);
		perror("/proc/partitions could not be opened: ");
		return false;	
	}
	// file found
	else
	{
		//the first two lines are irrelevant
		getline(dsl_part,str_line);
		getline(dsl_part,str_line);
		while(getline(dsl_part,str_line))
		{
			m_str_tok(str_line,dsl_token);
			if(dsl_token.size() < 4)
			{
			    m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/partitions.",__LINE__);
			    dsl_token.clear();
			    break;
			}
			string strl1 = dsl_token.at(3);
			// if the current line represents a hard disk ...	
			if (strl1.length() == 4 && ( !strncmp(strl1.c_str(),"sd",2) || !strncmp(strl1.c_str(),"hd",2)))
			{
				// add the device to the drives vector
				dsl_partitions.push_back("/dev/"+strl1);	
			}
			dsl_token.clear();	
		}	
		// add the rootfs device to the vector (the only partition that is not mounted in /dev)
		dsl_partitions.push_back("rootfs");
	}
	dsl_part.close();
	
	/*------------- search mount points -----------*/
	ifstream dsl_mounts("/proc/mounts");
	// file not found
	if(!dsl_mounts)
	{
		m_hl1_printf("xs-lbal-win-%05d - The file /proc/mounts could not be found. The hard disk load cannot be calculated.",__LINE__);
		perror("/proc/mounts could not be opened: ");
		return false;	
	}
	
	// file found
	else
	{
		vector<string>::iterator ds_vit; 	// iterator for dsl_partitions
		while (getline(dsl_mounts,str_line))
		{
			m_str_tok(str_line,dsl_token);
			if(dsl_token.size() < 1)
			{
			    m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/mounts.",__LINE__);
			    dsl_token.clear();
			    break;
			}			
		
			// look if the device of the current line is contained in
			// the vector of mounted partitions
			for(ds_vit = dsl_partitions.begin(); ds_vit != dsl_partitions.end(); ds_vit++)
			{
				string strl2 = *(ds_vit);
				// partition found
				if(!strcmp(dsl_token.at(0).c_str(),strl2.c_str()))
				{
					// add the mount point of the current device to the vector dsl_drives
					dsl_drives.push_back(dsl_token.at(1));
				}	
			}			
			dsl_token.clear();	
		}
		dsl_mounts.close();
	}
	/*-------------  get drive capacity ----------------*/
	ull uhl1;			// working variable
	ull uhl_cap_sum = 0;	// total capacity (in bytes)
 	struct statvfs dsl_drive_info;        /* structure to contain file system information */
   	int iml_status = 0;      /* local status value */
   	bool bo_err = false;	// did errors occur
   	
	// for each mounted drive
	for (unsigned int uml1 = 0; uml1 < dsl_drives.size(); uml1++)
	{
		// get drive information via statvfs
		iml_status = statvfs(dsl_drives.at(uml1).c_str(),&dsl_drive_info);
		if (iml_status != 0)
		{
			bo_err = true;	
		}
		// read the size of the device from the statvfs struct
		uhl1 = (ull)dsl_drive_info.f_blocks * (ull)dsl_drive_info.f_bsize;
		uhl_cap_sum += uhl1;
	}
	if (uhl_cap_sum == 0 || bo_err)	// could not calculate total disk capacity
	{
		bo_ret = false;
		dsg_ref.uhl_hd_total = 5000000000000ULL;	// set default value (5 Terabyte)
	}
	else
	{
		dsg_ref.uhl_hd_total = uhl_cap_sum;	
	}
#endif /* HL_LINUX */	
	return bo_ret;	
}
	
// update system dependent values
static bool m_update_sysval()
{

	bool bo_ret = true;
#ifdef HL_LINUX
	// get current page size
	int iml_ps = getpagesize();
	if(iml_ps > 0)	dsg_ref.iml_page = iml_ps;
	else
	{
		dsg_ref.iml_page = 4096;
		bo_ret = false;	
	}
	
	/*--------------------- get jiffies per second --------------------*/
	
	/*--------------------- get uptime -----------------*/
	long ill_secs = 0;		// seconds since boot time
	ifstream dsl_uptime("/proc/uptime");
	// file not found
	if(!dsl_uptime)
	{
		
		// set default value
		dsg_ref.iml_jps = 100;
		bo_ret = false;	
	}
	// file found
	else
	{
		// get the first line
		string strl_line;
		getline(dsl_uptime,strl_line);
		// get the first token (which is the uptime in seconds)
		vector<string> dsl_token;
		m_str_tok(strl_line,dsl_token);
		if(dsl_token.size() < 1)
		{
		    m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/uptime. Using default values.",__LINE__);
		    bo_ret = false;
		    dsg_ref.iml_jps = 100;
		    dsl_token.clear();
		    
		}		
		double fll_secs = strtod(dsl_token.at(0).c_str(),NULL);
		ill_secs = (long) fll_secs;
		dsl_uptime.close();	
	}
	
	/*------------------- get jiffies ---*/
	int iml_processors = 0;		// number of processors
	vector<string> dsl_token;
	string strl_cpu;			// first line in the file (contains jiffies of all processors)		
	ifstream dsl_stat("/proc/stat");
	if(!dsl_stat)
	{
		dsg_ref.iml_jps = 100;
		bo_ret = false;	
	}
	else
	{
		string strl_line;
		getline(dsl_stat,strl_cpu);
		while (getline(dsl_stat,strl_line))
		{
			m_str_tok(strl_line,dsl_token);
			if(dsl_token.size() < 1)
			{
			    m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/stat. Using default values[1].",__LINE__);
			    dsg_ref.iml_jps = 100;
			    bo_ret = false;
			    dsl_token.clear();
			    break;
			}			
			const char* achl_cpu = dsl_token.at(0).c_str(); 	
			if (strlen(achl_cpu) == 4 && !strncmp(achl_cpu,"cpu",3))
			{
				iml_processors++;
			}
			dsl_token.clear();
		}	
	
		dsl_stat.close();
	
		long long ihl_jiff_sum = 0;
		m_str_tok(strl_cpu,dsl_token);
		
		if(dsl_token.size() < 5)
		{
		    m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/stat. Using default values[2].",__LINE__);
		    bo_ret = false;
		    dsg_ref.iml_jps = 100;
		    dsl_token.clear();
		    
		}		
		else
		{
		  ihl_jiff_sum += strtoll(dsl_token.at(1).c_str(),NULL,10);
		  ihl_jiff_sum += strtoll(dsl_token.at(2).c_str(),NULL,10);
		  ihl_jiff_sum += strtoll(dsl_token.at(3).c_str(),NULL,10);
		  ihl_jiff_sum += strtoll(dsl_token.at(4).c_str(),NULL,10);
	  
		  int iml_jps = (int)((long long)ihl_jiff_sum / ((long long)ill_secs * (long long)iml_processors));
		  if (iml_jps > 95 && iml_jps < 105)
		  {
			  dsg_ref.iml_jps = 100;
		  }
		  else
		  {
			  dsg_ref.iml_jps = iml_jps+5;
		  }
		}
	}		
#endif /* HL_LINUX */	
	return bo_ret;
}
	
// update reference values
#ifdef HL_LINUX
static bool m_update_references()
#endif
#ifdef HL_FREEBSD
static bool m_update_references()
#endif
#ifdef HL_WINALL1
static bool m_update_references(IWbemServices* adsp_service)
#endif
{
	bool bo_ret = true;
#ifdef HL_LINUX
	bog_net = true;
	if (!m_update_net())	
	{
		bo_ret = false;
		bog_net = false;		// network load will always be 0, because the bandwidth is unknown
								// start the program as root to avoid this
	}
	if (!m_update_memory()) bo_ret = false;
	if (!m_update_hd()) 	bo_ret = false;
	if (!m_update_sysval()) bo_ret = false;
#endif /* HL_LINUX*/
#ifdef HL_WINALL1
	vector<string> dsl_token;
	
	// establish wmi connection
	HRESULT ill_wmi_res;
	do
	{
		CComPtr<IEnumWbemClassObject> dsl_enum_cs = NULL;
		// get reference values
		// 1. total memory
		ill_wmi_res = adsp_service->ExecQuery(L"WQL",L"SELECT * FROM Win32_ComputerSystem", WBEM_FLAG_FORWARD_ONLY, NULL, &dsl_enum_cs);
		if (FAILED(ill_wmi_res))
		{
			m_hl1_printf("xs-lbal-win-%05d-E could not query total ram. (Error: 0x%X)",__LINE__, ill_wmi_res);
			dsg_ref.uhl_memory = 100000000;
		}
		else
		{
			ULONG ul_ret = 0;
			ull uhl_value = 0;
			while(dsl_enum_cs)
			{
				CComPtr<IWbemClassObject> adsl_obj_system;
				ill_wmi_res = dsl_enum_cs->Next(WBEM_INFINITE, 1, &adsl_obj_system, &ul_ret);
				if (ul_ret == 0 || adsl_obj_system == NULL)
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not query total ram. (Error: 0x%X)",__LINE__, ill_wmi_res);
					dsg_ref.uhl_memory = 100000000;
				}
				else
				{
					ill_wmi_res = m_get_ull_wmi_value(adsl_obj_system, L"TotalPhysicalMemory", &uhl_value);
					if (FAILED(ill_wmi_res))
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not query total ram. (Error: 0x%X)",__LINE__, ill_wmi_res);
						dsg_ref.uhl_memory = 100000000;				
					}
					else
					{
						dsg_ref.uhl_memory = uhl_value;
					}
				}
				break;
			}
		}

		// 2. network bandwidth
		CComPtr<IEnumWbemClassObject> adsl_enum_nics;
		ill_wmi_res = adsp_service->ExecQuery(L"WQL",L"SELECT * FROM Win32_PerfRawData_Tcpip_NetworkInterface", WBEM_FLAG_FORWARD_ONLY, NULL, &adsl_enum_nics);
		if (FAILED(ill_wmi_res))
		{
			m_hl1_printf("xs-lbal-win-%05d-E could not get total network bandwidth. (Error: 0x%X)",__LINE__, ill_wmi_res);
			dsg_ref.uhl_network_bw = 1250000000;
		}
		else
		{
			ULONG ul_ret = 0;
			ull uhl_total = 0;
			LONG ill1 = 0;
			ull uhl1 = 0;
			while(adsl_enum_nics)
			{
				CComPtr<IWbemClassObject> adsl_obj_nic;
				ill_wmi_res = adsl_enum_nics->Next(WBEM_INFINITE, 1 , &adsl_obj_nic, &ul_ret);
				if (ul_ret == 0 || adsl_obj_nic == NULL)
				{
					break;
				}
				else
				{
					ill1 = 0;
					if (dwg_win_major_version >= 6)
					{
						ill_wmi_res = m_get_ull_wmi_value(adsl_obj_nic, L"CurrentBandwidth", &uhl1);
					}
					else
					{
						ill_wmi_res = m_get_long_wmi_value(adsl_obj_nic, L"CurrentBandwidth", &ill1);
					}
					if (FAILED(ill_wmi_res))
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not get total network bandwidth. (Error: 0x%X)",__LINE__, ill_wmi_res);
					}
					else
					{
						if (dwg_win_major_version >= 6)
						{
							uhl_total += uhl1;
						}
						else
						{
							uhl_total += ill1;
						}
					}
				}
			}
			dsg_ref.uhl_network_bw = uhl_total;
		}

		// 3. free disk space
		CComPtr<IEnumWbemClassObject> adsl_enum_raw_ld;
		ill_wmi_res = adsp_service->ExecQuery(L"WQL",L"SELECT * FROM Win32_PerfRawData_PerfDisk_LogicalDisk", WBEM_FLAG_FORWARD_ONLY, NULL, &adsl_enum_raw_ld);
		if (FAILED(ill_wmi_res))
		{
			m_hl1_printf("xs-lbal-win-%05d-E could not query logical disks. (Error: 0x%X)",__LINE__, ill_wmi_res);	
			bog_wmi_ldperf = false;
			dsg_ref.uhl_disk_space = 5000000000000ULL;
		}
		else
		{
			ULONG ul_ret = 0;
			ull uhl_size = 0;
			ull uhl_var_value = 0;
			LONG ill_drivetype = 0;
			while (adsl_enum_raw_ld)
			{
				CComPtr<IWbemClassObject> adsl_obj_ld;
				ill_wmi_res = adsl_enum_raw_ld->Next(WBEM_INFINITE, 1, &adsl_obj_ld, &ul_ret);
				if (ul_ret == 0 || adsl_obj_ld == NULL)
				{
					break;
				}

				wchar_t chrl_buf[512];
				ZeroMemory(chrl_buf, 512);
				ill_wmi_res = m_get_bstr_wmi_value(adsl_obj_ld, L"Name", chrl_buf, 512);
				// for each logical disk
				if(wcslen(chrl_buf) <= 2 /*strcmp(chrl_buf, "_Total")*/)
				{
					CComPtr<IWbemClassObject> adsl_disk = NULL;
					//OLECHAR chrl_dev[512];
					OLECHAR chrl_dev[512];
					ZeroMemory(chrl_dev, 512);
					swprintf(chrl_dev, 512, L"Win32_LogicalDisk.DeviceID=\"%s\"", chrl_buf);
					BSTR strl_bstr_dev = ::SysAllocString(chrl_dev);

					ill_wmi_res = adsp_service->GetObject(strl_bstr_dev, WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_disk, NULL);
					::SysFreeString(strl_bstr_dev);
					if (FAILED(ill_wmi_res))
					{
						m_hl1_printf("xs-lbal-win-%05d-E Win32_LogicalDisk could not be found (Device %s). (Error: 0x%X)", __LINE__, chrl_buf, ill_wmi_res);
						bog_wmi_ld = false;
					}
					else
					{
						// only count if drivetype == 3 (only local disks, no network drives or attached external drives or usb sticks)
						ill_wmi_res = m_get_long_wmi_value(adsl_disk, L"DriveType", &ill_drivetype);
						if (SUCCEEDED(ill_wmi_res))
						{
							if (ill_drivetype == 3)
							{
								ill_wmi_res = m_get_ull_wmi_value(adsl_disk, L"Size", &uhl_var_value);
								if (SUCCEEDED(ill_wmi_res))
								{
									uhl_size += uhl_var_value;
								}
								else
								{
									m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_LogicalDisk.Size. (Error: 0x%X)", __LINE__,ill_wmi_res);
								}
								bog_wmi_ld = true;
							}
						}
						else
						{
							m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_LogicalDisk.DriveType. (Error: 0x%X)", __LINE__,ill_wmi_res);
						}
					}
				}
			}
			dsg_ref.uhl_disk_space = uhl_size;
			bog_wmi_ldperf = true;
		}
	}while(FALSE);
		
	// get page size
	SYSTEM_INFO dsl_sysinfo;
	GetSystemInfo(&dsl_sysinfo);
	dsg_ref.dwl_page_size = dsl_sysinfo.dwPageSize;
#endif /* HL_WINALL1 */
	return bo_ret;	
}

// initialize the passed structure with 0 (or appropriate other) values in all fifo arrays
#ifdef HL_WINALL1
static void m_init_fifo_arrays (struct dsd_server_values& dsp_sv, IWbemServices* adsp_service)
#endif
#ifdef HL_LINUX
static void m_init_fifo_arrays (struct dsd_server_values& dsp_sv)
#endif
#ifdef HL_FREEBSD
static void m_init_fifo_arrays (struct dsd_server_values& dsp_sv)
#endif
{
	vector<string> dsl_token;
#ifdef HL_FREEBSD
	char chrl_buffer[512];
	if(!m_sysctl("vm.stats.sys.v_intr", chrl_buffer, 512))
	{
		dsp_sv.dsl_interrupts.m_fill_array(strtoull(chrl_buffer,NULL, 10),false);
	}
	else
	{
		dsp_sv.dsl_interrupts.m_fill_array(0,false);
	}
		
	// context switches
	if(!m_sysctl("vm.stats.sys.v_swtch", chrl_buffer, 512))
	{
		dsp_sv.dsl_context_switches.m_fill_array(strtoull(chrl_buffer,NULL, 10), false);
	}
	else
	{
		dsp_sv.dsl_context_switches.m_fill_array(0, false);
	}
	
	// memory
	if(!m_sysctl("hw.usermem", chrl_buffer, 512))
	{
		dsp_sv.dsl_usermem.m_fill_array(strtoull(chrl_buffer,NULL, 10), false);
	}
	else
	{
		dsp_sv.dsl_usermem.m_fill_array(0, false);
	}
	if(!m_sysctl("hw.realmem", chrl_buffer, 512))
	{
		dsp_sv.dsl_realmem.m_fill_array(strtoull(chrl_buffer,NULL, 10), false);
	}
	else
	{
		dsp_sv.dsl_realmem.m_fill_array(0, false);
	}

	// cpu
	if(!m_sysctl("kern.cp_time", chrl_buffer, 512))
	{
		ull uhl_cpu_idle;
		ull uhl_cpu_total;
		if (!m_get_token(chrl_buffer, &uhl_cpu_idle, 4) && !m_get_token_sum(chrl_buffer, &uhl_cpu_total))
		{
			dsp_sv.dsl_cpu_idle.m_fill_array(strtoull(chrl_buffer,NULL, 10), false);
			dsp_sv.dsl_cpu_total.m_fill_array(strtoull(chrl_buffer,NULL, 10), false);
		}
		else
		{
			printf("xs-lbal-win-1 Warning: Could not get CPU load\n");
		}
	}
	else
	{
		dsp_sv.dsl_cpu_idle.m_fill_array(0, false);
		dsp_sv.dsl_cpu_total.m_fill_array(0, false);
	}

	// cache
	if(!m_sysctl("vfs.cache.nummiss", chrl_buffer, 512))
	{
		dsp_sv.dsl_cache_misses.m_fill_array(strtoull(chrl_buffer,NULL, 10), false);
	}
	else
	{
		dsp_sv.dsl_cache_misses.m_fill_array(0, false);
	}
	if(!m_sysctl("vfs.cache.numchecks", chrl_buffer, 512))
	{
		dsp_sv.dsl_cache_checks.m_fill_array(strtoull(chrl_buffer,NULL, 10), false);
	}
	else
	{
		dsp_sv.dsl_cache_checks.m_fill_array(0, false);
	}

	// swapping
	if(!m_sysctl("vm.stats.vm.v_vnodepgsout", chrl_buffer, 512))
	{
		dsp_sv.dsl_pages_out.m_fill_array(strtoull(chrl_buffer,NULL, 10), false);
	}
	else
	{
		dsp_sv.dsl_pages_out.m_fill_array(0, false);
	}
	if(!m_sysctl("vm.stats.vm.v_vnodepgsin", chrl_buffer, 512))
	{
		dsp_sv.dsl_pages_in.m_fill_array(strtoull(chrl_buffer,NULL, 10), false);
	}
	else
	{
		dsp_sv.dsl_pages_in.m_fill_array(0, false);
	}
	if(!m_sysctl("vm.stats.vm.v_swappgsout", chrl_buffer, 512))
	{
		dsp_sv.dsl_swaps_out.m_fill_array(strtoull(chrl_buffer,NULL, 10), false);
	}
	else
	{
		dsp_sv.dsl_swaps_out.m_fill_array(0, false);
	}
	if(!m_sysctl("vm.stats.vm.v_swappgsin", chrl_buffer, 512))
	{
		dsp_sv.dsl_swaps_in.m_fill_array(strtoull(chrl_buffer,NULL, 10), false);
	}
	else
	{
		dsp_sv.dsl_swaps_in.m_fill_array(0, false);
	}

	// swapfile
	if(!m_sysctl("vm.swap_reserved", chrl_buffer, 512))
	{
		dsp_sv.dsl_swap_used.m_fill_array(strtoull(chrl_buffer,NULL, 10), false);
	}
	else
	{
		dsp_sv.dsl_swap_used.m_fill_array(0, false);
	}
	if(!m_sysctl("vm.swap_total", chrl_buffer, 512))
	{
		dsp_sv.dsl_swap_total.m_fill_array(strtoull(chrl_buffer,NULL, 10), false);
	}
	else
	{
		dsp_sv.dsl_swap_total.m_fill_array(0, false);
	}

	// processes and threads
	kvm_t* adsl_kd;
	int iml_processes = 0;
	int iml_threads = 0;
	adsl_kd = kvm_open(NULL, "/dev/null", NULL, O_RDONLY, "kvm_open");
	struct kinfo_proc* adsl_proc = kvm_getprocs(adsl_kd, KERN_PROC_PROC, 0, &iml_processes);
	kvm_getprocs(adsl_kd, KERN_PROC_ALL, 0, &iml_threads);

	// process data
	int iml_success = 0;
	struct kinfo_proc* adsl_proc_data = kvm_getprocs(adsl_kd, KERN_PROC_PID, getpid(), &iml_success);
	if(iml_success > 0)
	{
		dsg_values.dsl_proc_memory.m_fill_array((ull)adsl_proc_data->ki_rssize, false);
		dsg_values.dsl_proc_page_faults.m_fill_array((ull)adsl_proc_data->ki_rusage.ru_majflt, false);
		dsg_values.dsl_proc_io_reads.m_fill_array((ull)adsl_proc_data->ki_rusage.ru_inblock, false);
		dsg_values.dsl_proc_io_writes.m_fill_array((ull)adsl_proc_data->ki_rusage.ru_oublock, false);
		dsg_values.dsl_proc_threads.m_fill_array((ull)adsl_proc_data->ki_numthreads, false);
		ull uhl_user_time = adsl_proc_data->ki_rusage.ru_utime.tv_sec * 1000 + adsl_proc_data->ki_rusage.ru_utime.tv_usec / 1000;
		ull uhl_sys_time = adsl_proc_data->ki_rusage.ru_stime.tv_sec * 1000 + adsl_proc_data->ki_rusage.ru_stime.tv_usec / 1000;
		dsg_values.dsl_proc_user_time.m_fill_array(uhl_user_time, false);
		dsg_values.dsl_proc_system_time.m_fill_array(uhl_sys_time, false);
		dsg_values.dsl_proc_ctx_involuntary.m_fill_array((ull)adsl_proc_data->ki_rusage.ru_nvcsw, false);
		dsg_values.dsl_proc_ctx_voluntary.m_fill_array((ull)adsl_proc_data->ki_rusage.ru_nivcsw, false);

	}
	else
	{
		m_hl1_printf("xs-lbal-win-%05d - process data could not be found",__LINE__);
	}

	kvm_close(adsl_kd);
	dsp_sv.dsl_processes.m_fill_array((ull)iml_processes, false);
	dsp_sv.dsl_threads.m_fill_array((ull)iml_threads, false);
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
#endif

#ifdef HL_LINUX		
	dsp_sv.dsl_ctx_switch.m_fill_array(0,false);
	dsp_sv.dsl_free_hd.m_fill_array(0,false);
	dsp_sv.dsl_free_memory.m_fill_array(0,false);
	dsp_sv.dsl_free_swap.m_fill_array(0,false);
	

	// get number of idle jiffies since boot
	ifstream dsl_stat("/proc/stat");
	if (!dsl_stat)
	{
		
		bog_stat = false;
		dsp_sv.dsl_idle_jiffies.m_add_element(0);
		dsp_sv.dsl_idle_jiffies.m_add_element(190000000000ULL);	
		dsp_sv.dsl_total_jiffies.m_add_element(0);
		dsp_sv.dsl_total_jiffies.m_add_element(190000000000ULL);
	}
	else
	{
		ull uhl_sum_jiff = 0;
		ull uhl_sum_total_jiff = 0;
		string strl_first;
		string strl_line;
		getline(dsl_stat,strl_first);
		m_str_tok(strl_first,dsl_token);
		if(dsl_token.size() < 8)
		{
		    m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/stat. Using default values.",__LINE__);
		    bog_stat = false;
		    dsp_sv.dsl_idle_jiffies.m_add_element(0);
		    dsp_sv.dsl_idle_jiffies.m_add_element(190000000000ULL);	
		    dsp_sv.dsl_total_jiffies.m_add_element(0);
		    dsp_sv.dsl_total_jiffies.m_add_element(190000000000ULL);
		    
		    
		}		
		uhl_sum_jiff += strtoull(dsl_token.at(4).c_str(),NULL,10);	
		for (int iml1 = 1; iml1 <=7; iml1++)
		{
			uhl_sum_total_jiff += strtoull(dsl_token.at(iml1).c_str(),NULL,10);	
		}
		dsl_token.clear();
		while (getline(dsl_stat,strl_line))
		{
			m_str_tok(strl_line,dsl_token);
			if(dsl_token.size() < 1)
			{
			    m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/stat. Using default values.",__LINE__);
			    bog_stat = false;
			    dsp_sv.dsl_idle_jiffies.m_add_element(0);
			    dsp_sv.dsl_idle_jiffies.m_add_element(190000000000ULL);	
			    dsp_sv.dsl_total_jiffies.m_add_element(0);
			    dsp_sv.dsl_total_jiffies.m_add_element(190000000000ULL);
			    dsl_token.clear();
			    break;
			}
			if (dsl_token.at(0).compare("intr") == 0)
			{
				dsp_sv.dsl_interrupts.m_fill_array(strtoull(dsl_token.at(1).c_str(),NULL,10),false);
			}
			else if (dsl_token.at(0).compare("ctxt") == 0)
			{
				dsp_sv.dsl_ctx_switch.m_fill_array(strtoull(dsl_token.at(1).c_str(),NULL,10),false);	
			}
			dsl_token.clear();	
		}
		dsl_stat.close();	
		dsp_sv.dsl_total_jiffies.m_fill_array(uhl_sum_total_jiff,false);
		dsp_sv.dsl_idle_jiffies.m_fill_array(uhl_sum_jiff,false);
	}

	// get number of jiffies of the process
	m_get_line_from_file(1,"/proc/self/stat","",dsl_token);
	ull uhl_proc_jiff = 0;
	dsp_sv.dsl_proc_jiffies.m_fill_array(uhl_proc_jiff,false);
	if (dsl_token.size() < 23)
	{
	  uhl_proc_jiff += strtoull(dsl_token.at(13).c_str(),NULL,10);
	  uhl_proc_jiff += strtoull(dsl_token.at(14).c_str(),NULL,10);
	  
	  dsp_sv.uhl_proc_ticks_user = strtoull(dsl_token.at(13).c_str(),NULL, 10);
	  dsp_sv.uhl_proc_ticks_kernel = strtoull(dsl_token.at(14).c_str(), NULL, 10);
	  dsp_sv.uhl_proc_virtual_memory = strtoull(dsl_token.at(22).c_str(),NULL, 10);
	}
	dsl_token.clear();

	ifstream dsl_proc_io("/proc/self/io");
	if(dsl_proc_io)
	{
	  string strl_line;
	  while(getline(dsl_proc_io, strl_line))
	  {
	      m_str_tok(strl_line, dsl_token);
	      if(dsl_token.size() < 2)
	      {
		  m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/self/io. Using default values.",__LINE__);
		  dsp_sv.uhl_proc_io_reads = 0;
		  dsp_sv.uhl_proc_io_writes = 0;
		  dsp_sv.uhl_proc_io_read_bytes = 0;
		  dsp_sv.uhl_proc_io_written_bytes = 0;
		  dsl_token.clear();
		  break;
	      }	      
	      if (dsl_token.at(0).compare("syscr:") == 0)
	      {
		dsp_sv.uhl_proc_io_reads = strtoull(dsl_token.at(1).c_str(),NULL,10);
	      }
	      else if (dsl_token.at(0).compare("syscw:") == 0)
	      {
		dsp_sv.uhl_proc_io_writes = strtoull(dsl_token.at(1).c_str(),NULL,10);
	      }
	      else if (dsl_token.at(0).compare("read_bytes:") == 0)
	      {
		
		dsp_sv.uhl_proc_io_read_bytes = strtoull(dsl_token.at(1).c_str(),NULL,10);
	      }
	      else if (dsl_token.at(0).compare("write_bytes:") == 0)
	      {
		dsp_sv.uhl_proc_io_written_bytes = strtoull(dsl_token.at(1).c_str(),NULL,10);
	      }	  
	      dsl_token.clear();
	  }
	  
	  dsl_proc_io.close();
	}
	else
	{
	  dsp_sv.uhl_proc_io_reads = 0;
	  dsp_sv.uhl_proc_io_writes = 0;
	  dsp_sv.uhl_proc_io_read_bytes = 0;
	  dsp_sv.uhl_proc_io_written_bytes = 0;
	}
	
	
	dsl_token.clear();
	//dsp_sv.dsl_idle_jiffies.m_fill_array(0,false);
	dsp_sv.dsl_interrupts.m_fill_array(0,false);
	dsp_sv.dsl_io_time.m_fill_array(0,false);
	dsp_sv.dsl_maj_pg_faults.m_fill_array(0,false);
	dsp_sv.dsl_min_pg_faults.m_fill_array(0,false);
	dsp_sv.dsl_net_rec.m_fill_array(0,false);
	dsp_sv.dsl_net_trans.m_fill_array(0,false);
	dsp_sv.dsl_page_in.m_fill_array(0,false);
	dsp_sv.dsl_page_out.m_fill_array(0,false);
	dsp_sv.dsl_processes.m_fill_array(0,false);
	dsp_sv.dsl_read_sectors.m_fill_array(0,false);
		// get number of started processes since boot		
	m_get_line_from_file(1,"/proc/loadavg","",dsl_token);
	string strl_new_proc = dsl_token.at(4);
	long ill1 = strtol(strl_new_proc.c_str(),NULL,10);
	dsl_token.clear();	
	dsp_sv.dsl_started_processes.m_fill_array(ill1,false);
	
	dsp_sv.dsl_swap_in.m_fill_array(0,false);
	dsp_sv.dsl_swap_out.m_fill_array(0,false);
	// virtual memory
	ifstream dsl_vm("/proc/vmstat");
	if (dsl_vm)
	{
		string strl_line;
		while (getline(dsl_vm,strl_line))
		{
			m_str_tok(strl_line,dsl_token);
			if(dsl_token.size() < 2)
			{
			    m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/vmstat. Using default values.",__LINE__);
			    dsl_token.clear();
			    break;
			}	 			
			if (dsl_token.at(0).compare("pgpgin") == 0)
			{
				dsp_sv.dsl_page_in.m_fill_array(strtoull(dsl_token.at(1).c_str(),NULL,10),false);	
			}
			else if (dsl_token.at(0).compare("pgpgout") == 0)
			{
				dsp_sv.dsl_page_out.m_fill_array(strtoull(dsl_token.at(1).c_str(),NULL,10),false);	
			}
			else if (dsl_token.at(0).compare("pswpin") == 0)
			{
				dsp_sv.dsl_swap_in.m_fill_array(strtoull(dsl_token.at(1).c_str(),NULL,10),false);
			}
			else if (dsl_token.at(0).compare("pswpout") == 0)
			{
				dsp_sv.dsl_swap_out.m_fill_array(strtoull(dsl_token.at(1).c_str(),NULL,10),false);	
			}
			else if (dsl_token.at(0).compare("pgfault") == 0)
			{
				dsp_sv.dsl_min_pg_faults.m_fill_array(strtoull(dsl_token.at(1).c_str(),NULL,10),false);	
			}
			else if (dsl_token.at(0).compare("pgmajfault") == 0)
			{
				dsp_sv.dsl_maj_pg_faults.m_fill_array(strtoull(dsl_token.at(1).c_str(),NULL,10),false);	
			}
			dsl_token.clear();
		}
		dsl_vm.close();	
	}
	else bog_vmstat = false;
	
	dsp_sv.dsl_written_sectors.m_fill_array(0,false);
#endif /* HL_LINUX */	
#ifdef HL_WINALL1
	// some arrays can be initialized with 0
	dsp_sv.dsl_ld_free_space.m_fill_array(0, false);
	dsp_sv.dsl_mem_avail_bytes.m_fill_array(0,false);
	dsp_sv.dsl_obj_processes.m_fill_array(0,false);
	dsp_sv.dsl_obj_threads.m_fill_array(0,false);
	dsp_sv.dsl_page_usage_pc.m_fill_array(0, false);
	do
	{
		LONG ill_var_value = 0;
		ull  uhl_var_value = 0;
		HRESULT ill_wmi_res = 0;

		// 1. Win32_PerfRawData_PerfOS_Cache
		CComPtr<IWbemClassObject> adsl_obj_raw_os_cache;
		ill_wmi_res = adsp_service->GetObject(L"Win32_PerfRawData_PerfOS_Cache=@", WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_obj_raw_os_cache, NULL);
		if (FAILED(ill_wmi_res))
		{
			m_hl1_printf("xs-lbal-win-%05d-E Win32_PerfRawData_PerfOS_Cache=@ could not be found. (Error: 0x%X)", __LINE__,ill_wmi_res);
			bog_wmi_cache = false;
		}
		else
		{
			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_cache,L"CopyReadHitsPercent",&ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_cache_copy_read_hits_pc.m_fill_array(ill_var_value,false);
			}
			else
			{
				dsp_sv.dsl_cache_copy_read_hits_pc.m_fill_array(0,false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Cache.CopyReadHitsPercent. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}
			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_cache,L"CopyReadHitsPercent_Base",&ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_cache_copy_reads_ps.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_cache_copy_reads_ps.m_fill_array(0,false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Cache.CopyReadHitsPercent_Base. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}
			bog_wmi_cache = true;
		}

		// 2. Win32_PerfRawData_PerfDisk_LogicalDisk
		CComPtr<IWbemClassObject> adsl_obj_raw_disk_ld;
		ill_wmi_res = adsp_service->GetObject(L"Win32_PerfRawData_PerfDisk_LogicalDisk.Name=\"_Total\"", WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_obj_raw_disk_ld, NULL);
		if (FAILED(ill_wmi_res))
		{
			m_hl1_printf("xs-lbal-win-%05d-E Win32_PerfRawData_PerfDisk_LogicalDisk.Name=\"_Total\" could not be found. (Error: 0x%X)", __LINE__,ill_wmi_res);
			bog_wmi_ldperf = false;
		}
		else
		{
			ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_disk_ld, L"AvgDiskBytesPerRead", &uhl_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_ldperf_avg_disk_bytes_read.m_fill_array(uhl_var_value, false);
			}
			else
			{
				dsp_sv.dsl_ldperf_avg_disk_bytes_read.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.AvgDiskBytesPerRead. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_disk_ld, L"AvgDiskBytesPerWrite", &uhl_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_ldperf_avg_disk_bytes_write.m_fill_array(uhl_var_value, false);
			}
			else
			{
				dsp_sv.dsl_ldperf_avg_disk_bytes_write.m_fill_array(0,false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.AvgDiskBytesPerWrite. (Error: 0x%X)", __LINE__, ill_wmi_res);
			}

			ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_disk_ld, L"AvgDiskBytesPerTransfer", &uhl_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_ldperf_avg_disk_bytes_transfer.m_fill_array(uhl_var_value, false);
			}
			else
			{
				dsp_sv.dsl_ldperf_avg_disk_bytes_transfer.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.AvgDiskBytesPerTransfer. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_disk_ld, L"DiskReadsPerSec", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_ldperf_disk_reads_ps.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_ldperf_disk_reads_ps.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.DiskReadsPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_disk_ld, L"DiskWritesPerSec", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_ldperf_disk_writes_ps.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_ldperf_disk_writes_ps.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.DiskWritesPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_disk_ld, L"DiskTransfersPerSec", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_ldperf_disk_transfers_ps.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_ldperf_disk_transfers_ps.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.DiskTransfersPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_disk_ld, L"DiskBytesPerSec", &uhl_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_ldperf_disk_bytes_ps.m_fill_array(uhl_var_value, false);
			}
			else
			{
				dsp_sv.dsl_ldperf_disk_bytes_ps.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.DiskBytesPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_disk_ld, L"PercentDiskTime", &uhl_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_ldperf_disk_time_pc.m_fill_array(uhl_var_value, false);
			}
			else
			{
				dsp_sv.dsl_ldperf_disk_time_pc.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.PercentDiskTime. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}
			bog_wmi_ldperf = true;
		}
		// 3. Win32_PerfRawData_PerfOS_Memory
		CComPtr<IWbemClassObject> adsl_obj_raw_os_memory;
		ill_wmi_res = adsp_service->GetObject(L"Win32_PerfRawData_PerfOS_Memory=@", WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_obj_raw_os_memory, NULL);
		if (FAILED(ill_wmi_res))
		{
			m_hl1_printf("xs-lbal-win-%05d-E Win32_PerfRawData_PerfOS_Memory=@ could not be found. (Error: 0x%X)", __LINE__,ill_wmi_res);
			bog_wmi_mem = false;
		}
		else
		{
			ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_os_memory, L"AvailableBytes", &uhl_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_mem_avail_bytes.m_fill_array(uhl_var_value, false);
			}
			else
			{
				dsp_sv.dsl_mem_avail_bytes.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Memory.AvailableBytes. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_memory, L"CacheFaultsPerSec", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_mem_cache_faults_ps.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_mem_cache_faults_ps.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Memory.CacheFaultsPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_memory, L"PageFaultsPerSec", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_mem_page_faults_ps.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_mem_page_faults_ps.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Memory.PageFaultsPerSec. (Error: 0x%X)", __LINE__, ill_wmi_res);
			}

			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_memory, L"PagesInputPerSec", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_mem_page_input_ps.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_mem_page_input_ps.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Memory.PagesInputPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_memory, L"PagesOutputPerSec", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_mem_page_output_ps.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_mem_page_output_ps.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Memory.PagesOutputPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_memory, L"PagesPerSec", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_mem_page_total_ps.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_mem_page_total_ps.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Memory.PagesPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}
			
			bog_wmi_mem = true;
		}

		// 4. Win32_PerfRawData_PerfOS_PagingFile
		int iml_number_of_page_files = 0;
		IEnumWbemClassObject* adsl_pagefile_enum = NULL;
		ill_wmi_res = adsp_service->ExecQuery(bstr_t("WQL"),bstr_t("SELECT * FROM Win32_PerfRawData_PerfOS_PagingFile WHERE Name != \"_Total\""), WBEM_FLAG_FORWARD_ONLY, NULL, &adsl_pagefile_enum);
		if (SUCCEEDED(ill_wmi_res))
		{
			while (true)
			{
				CComPtr<IWbemClassObject> dsl_pagefile;
				ULONG uml_ret = 0;
				ill_wmi_res = adsl_pagefile_enum->Next(WBEM_INFINITE, 1, &dsl_pagefile, &uml_ret);
				if (SUCCEEDED(ill_wmi_res) && ill_wmi_res != S_FALSE)
				{
					iml_number_of_page_files++;
				}
				else break;
			}
			adsl_pagefile_enum->Release();
		}
		else
		{
			m_hl1_printf("xs-lbal-win-%05d-E Could not query page files. (Error: 0x%X)",__LINE__, ill_wmi_res);
		}
		

		CComPtr<IWbemClassObject> adsl_obj_raw_os_page;
		ill_wmi_res = adsp_service->GetObject(L"Win32_PerfRawData_PerfOS_PagingFile.Name=\"_Total\"", WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_obj_raw_os_page, NULL);
		if (FAILED(ill_wmi_res) || iml_number_of_page_files == 0)
		{
			if (iml_number_of_page_files > 0)
			{
				m_hl1_printf("xs-lbal-win-%05d-E Win32_PerfRawData_PerfOS_PagingFile.Name=\"_Total\" could not be found. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}
			dsp_sv.dsl_page_usage_pc.m_fill_array(0, false);
			dsp_sv.dsl_page_size.m_fill_array(0, false);
		}
		else
		{
			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_page, L"PercentUsage", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_page_usage_pc.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_page_usage_pc.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_PagingFile.PercentUsage. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_page, L"PercentUsage_Base", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_page_size.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_page_size.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_PagingFile.PercentUsage_Base. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			bog_wmi_page = true;
		}

		// 5. Win32_PerfRawData_PerfOS_System
		CComPtr<IWbemClassObject> adsl_obj_raw_os_system;
		ill_wmi_res = adsp_service->GetObject(L"Win32_PerfRawData_PerfOS_System=@", WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_obj_raw_os_system, NULL);
		if (FAILED(ill_wmi_res))
		{
			m_hl1_printf("xs-lbal-win-%05d-E Win32_PerfRawData_PerfOS_System=@ could not be found. (Error 0x%X)", __LINE__, ill_wmi_res);
			bog_wmi_obj = false;
		}
		else
		{
			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_system, L"Processes", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_obj_processes.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_obj_processes.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_System.Processes. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_system, L"Threads", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_obj_threads.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_obj_threads.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_System.Threads. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}
			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_system, L"ContextSwitchesPerSec", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_sys_ctx.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_sys_ctx.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_System.ContextSwitchesPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			bog_wmi_sys = true;

			bog_wmi_obj = true;
		}

		// 6. Win32_PerfRawData_PerfOS_Processor
		CComPtr<IWbemClassObject> adsl_obj_raw_os_processor;
		ill_wmi_res = adsp_service->GetObject(L"Win32_PerfRawData_PerfOS_Processor.Name=\"_Total\"", WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_obj_raw_os_processor, NULL);
		if (FAILED(ill_wmi_res))
		{
			m_hl1_printf("xs-lbal-win-%05d-E Win32_PerfRawData_PerfOS_Processor.Name=\"_Total\" could not be found. (Error: 0x%X)", __LINE__,ill_wmi_res);
			bog_wmi_cpu = false;
		}
		else
		{
			ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_processor, L"InterruptsPerSec", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_cpu_int.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_cpu_int.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Processor.InterruptsPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_os_processor, L"PercentIdleTime", &uhl_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_cpu_idle.m_fill_array(uhl_var_value, false);
			}
			else
			{
				dsp_sv.dsl_cpu_idle.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Processor.PercentIdleTime. (Error: 0x%X)", __LINE__,ill_wmi_res);
			}

			dsp_sv.dsl_frequency.m_fill_array(0,false);
			dsp_sv.dsl_timestamp.m_fill_array(0,false);

			bog_wmi_cpu = true;
		}


		// 8. Win32_PerfRawData_PerfProc_Process
		// Get WMI performance object of the local process
		
		IEnumWbemClassObject* adsl_perfproc_enum;
		CComPtr<IWbemClassObject> dsl_wmiobj_current_process = NULL;
		
		DWORD dwl_pid = GetCurrentProcessId();
		//strl_wql_query_process.assign(L"SELECT * FROM Win32_PerfRawData_PerfProc_Process WHERE IDProcess = ");
		wchar_t chrl_buffer[512];
		ZeroMemory(chrl_buffer, 512);
		swprintf(chrl_buffer, L"SELECT * FROM Win32_PerfRawData_PerfProc_Process WHERE IDProcess = %d", dwl_pid);
		//strl_wql_query_process.append(chrl_pid_buffer);
		BSTR strl_bstr_query = ::SysAllocString(chrl_buffer);
				
		
		ill_wmi_res = adsp_service->ExecQuery(L"WQL",strl_bstr_query, WBEM_FLAG_FORWARD_ONLY, NULL, &adsl_perfproc_enum);
		::SysFreeString(strl_bstr_query);
		if (SUCCEEDED(ill_wmi_res))
		{
			ULONG uml_ret = 0;
			dsl_wmiobj_current_process.Release();
			ill_wmi_res = adsl_perfproc_enum->Next(WBEM_INFINITE, 1, &dsl_wmiobj_current_process, &uml_ret);
			if (FAILED(ill_wmi_res))
			{
				m_hl1_printf("Unable to get wmi performance object of the current process. Process ID: %d. (Error: 0x%X)", dwl_pid,ill_wmi_res);
				dsl_wmiobj_current_process = NULL;	
			}
			adsl_perfproc_enum->Release();
		}
		else
		{
			m_hl1_printf("Unable to find the wmi performance object of the current process. Process ID: %d. (Error: 0x%X)", dwl_pid, ill_wmi_res);
		}
		if (dsl_wmiobj_current_process)
		{
			ill_wmi_res = m_get_ull_wmi_value(dsl_wmiobj_current_process, L"ElapsedTime", &uhl_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_proc_elapsed_time.m_fill_array(uhl_var_value, false);
			}
			else
			{
				dsp_sv.dsl_proc_elapsed_time.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.ElapsedTime. (Error 0x%X)", __LINE__, ill_wmi_res);
			}

			ill_wmi_res = m_get_long_wmi_value(dsl_wmiobj_current_process, L"HandleCount", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_proc_handles.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_proc_handles.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.HandleCount. (Error 0x%X)", __LINE__, ill_wmi_res);
			}

			ill_wmi_res = m_get_ull_wmi_value(dsl_wmiobj_current_process, L"IOReadBytesPerSec", &uhl_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_proc_io_read_bytes.m_fill_array(uhl_var_value, false);
			}
			else
			{
				dsp_sv.dsl_proc_io_read_bytes.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.IOReadBytesPerSec. (Error 0x%X)", __LINE__, ill_wmi_res);
			}

			ill_wmi_res = m_get_ull_wmi_value(dsl_wmiobj_current_process, L"IOReadOperationsPerSec", &uhl_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_proc_io_read_ops.m_fill_array(uhl_var_value, false);
			}
			else
			{
				dsp_sv.dsl_proc_io_read_ops.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.IOReadOperationsPerSec. (Error 0x%X)", __LINE__, ill_wmi_res);
			}

			ill_wmi_res = m_get_ull_wmi_value(dsl_wmiobj_current_process, L"IOWriteBytesPerSec", &uhl_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_proc_io_write_bytes.m_fill_array(uhl_var_value, false);
			}
			else
			{
				dsp_sv.dsl_proc_io_write_bytes.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.IOWriteBytesPerSec. (Error 0x%X)", __LINE__, ill_wmi_res);
			}

			ill_wmi_res = m_get_ull_wmi_value(dsl_wmiobj_current_process, L"IOWriteOperationsPerSec", &uhl_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_proc_io_write_ops.m_fill_array(uhl_var_value, false);
			}
			else
			{
				dsp_sv.dsl_proc_io_write_ops.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.IOWriteOperationsPerSec. (Error 0x%X)", __LINE__, ill_wmi_res);
			}

			ill_wmi_res = m_get_long_wmi_value(dsl_wmiobj_current_process, L"PageFaultsPerSec", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_proc_page_faults.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_proc_page_faults.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.PageFaultsPerSec. (Error 0x%X)", __LINE__, ill_wmi_res);
			}

			ill_wmi_res = m_get_ull_wmi_value(dsl_wmiobj_current_process, L"PercentProcessorTime", &uhl_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_proc_cpu.m_fill_array(uhl_var_value, false);
			}
			else
			{
				dsp_sv.dsl_proc_cpu.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.PercentProcessorTime. (Error 0x%X)", __LINE__, ill_wmi_res);
			}

			ill_wmi_res = m_get_long_wmi_value(dsl_wmiobj_current_process, L"ThreadCount", &ill_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_proc_threads.m_fill_array(ill_var_value, false);
			}
			else
			{
				dsp_sv.dsl_proc_threads.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.ThreadCount. (Error 0x%X)", __LINE__, ill_wmi_res);
			}

			ill_wmi_res = m_get_ull_wmi_value(dsl_wmiobj_current_process, L"VirtualBytes", &uhl_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_proc_virt_bytes.m_fill_array(uhl_var_value, false);
			}
			else
			{
				dsp_sv.dsl_proc_virt_bytes.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.VirtualBytes. (Error 0x%X)", __LINE__, ill_wmi_res);
			}

			ill_wmi_res = m_get_ull_wmi_value(dsl_wmiobj_current_process, L"WorkingSet", &uhl_var_value);
			if (SUCCEEDED(ill_wmi_res))
			{
				dsp_sv.dsl_proc_working_set.m_fill_array(uhl_var_value, false);
			}
			else
			{
				dsp_sv.dsl_proc_working_set.m_fill_array(0, false);
				m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.WorkingSet. (Error 0x%X)", __LINE__, ill_wmi_res);
			}

			bog_wmi_proc = true;
		}
		else
		{
			m_hl1_printf("WMI Object of the current process exist. Performance data of the current process can not be monitored until a restart of the monitor thread");
			bog_wmi_proc = false;
			dsg_values.dsl_proc_cpu.m_fill_array(0,false);
			dsg_values.dsl_proc_elapsed_time.m_fill_array(0,false);
			dsg_values.dsl_proc_handles.m_fill_array(0, false);
			dsg_values.dsl_proc_io_read_bytes.m_fill_array(0, false);
			dsg_values.dsl_proc_io_read_ops.m_fill_array(0, false);
			dsg_values.dsl_proc_io_write_bytes.m_fill_array(0, false);
			dsg_values.dsl_proc_io_write_ops.m_fill_array(0, false);
			dsg_values.dsl_proc_page_faults.m_fill_array(0, false);
			dsg_values.dsl_proc_threads.m_fill_array(0, false);
			dsg_values.dsl_proc_virt_bytes.m_fill_array(0, false);
			dsg_values.dsl_proc_working_set.m_fill_array(0, false);
		}
		

	#ifdef OLD_CALCULATION
		DWORD dwl_id = GetCurrentProcessId();

		HANDLE a_proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwl_id);
		ull uhl_proc_time = 0;
		if (a_proc == NULL)
		{
			bog_wmi_pp = false;
			m_hl1_printf("xs-lbal-win-%05d-E could not get handle of the current process" , __LINE__);
		}
		else
		{
			FILETIME dsl_user;
			FILETIME dsl_kernel;
			FILETIME dsl1;
			FILETIME dsl2;
			if (GetProcessTimes(a_proc,&dsl1, &dsl2, &dsl_kernel, &dsl_user))
			{
				bog_wmi_pp = true;
				ULARGE_INTEGER dsl_un1;
				ULARGE_INTEGER dsl_un2;
				dsl_un1.HighPart = dsl_kernel.dwHighDateTime;
				dsl_un1.LowPart = dsl_kernel.dwLowDateTime;
				dsl_un2.HighPart = dsl_user.dwHighDateTime;
				dsl_un2.LowPart = dsl_user.dwLowDateTime;
				uhl_proc_time += dsl_un1.QuadPart;
				uhl_proc_time += dsl_un2.QuadPart;
			}
			else
			{
				bog_wmi_pp = false;
				m_hl1_printf("xs-lbal-win-%05d-E could not get process times of the current process", __LINE__);
			}
		}
		dsp_sv.dsl_pp_proc_time.m_fill_array(uhl_proc_time, false);
		CloseHandle(a_proc);
	#endif

		// 9. Win32_PerfRawData_Tcpip_NetworkInterface
		IEnumWbemClassObject* adsl_enum1 = NULL;
		ill_wmi_res = adsp_service->ExecQuery(L"WQL",L"SELECT * FROM Win32_PerfRawData_Tcpip_NetworkInterface", WBEM_FLAG_FORWARD_ONLY, NULL, &adsl_enum1);
		if (FAILED(ill_wmi_res))
		{
			m_hl1_printf("xs-lbal-win-%05d-E could not query network interfaces. (Error: 0x%X)",__LINE__,ill_wmi_res);	
			bog_wmi_net = false;
		}
		else
		{
			ULONG ul_ret = 0;
			ull uhl_tot = 0;
			ull uhl_recv = 0;
			ull uhl_sent = 0;
			while(adsl_enum1)
			{
				CComPtr<IWbemClassObject> adsl_obj_nic;
				ill_wmi_res = adsl_enum1->Next(WBEM_INFINITE, 1, &adsl_obj_nic, &ul_ret);
				if (ul_ret == 0|| adsl_obj_nic == NULL)
				{
					break;
				}

				ill_wmi_res = m_get_ull_wmi_value(adsl_obj_nic, L"BytesTotalPerSec", &uhl_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					uhl_tot += uhl_var_value;
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_Tcpip_NetworkInterface.BytesTotalPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}

				if (dwg_win_major_version >= 6)
				{
					ill_wmi_res = m_get_ull_wmi_value(adsl_obj_nic, L"BytesReceivedPerSec", &uhl_var_value);
				}
				else
				{
					ill_wmi_res = m_get_long_wmi_value(adsl_obj_nic,L"BytesReceivedPerSec", &ill_var_value);
				}
				if (SUCCEEDED(ill_wmi_res))
				{
					if (dwg_win_major_version >= 6)
					{
						uhl_recv += uhl_var_value;
					}
					else
					{
						uhl_recv += ill_var_value;
					}
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_Tcpip_NetworkInterface.BytesReceivedPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}

				if (dwg_win_major_version >= 6)
				{
					ill_wmi_res = m_get_ull_wmi_value(adsl_obj_nic, L"BytesSentPerSec", &uhl_var_value);
				}
				else
				{
					ill_wmi_res = m_get_long_wmi_value(adsl_obj_nic,L"BytesSentPerSec", &ill_var_value);
				}
				if (SUCCEEDED(ill_wmi_res))
				{
					if (dwg_win_major_version >= 6)
					{
						uhl_sent += uhl_var_value;
					}
					else
					{
						uhl_sent += ill_var_value;
					}
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_Tcpip_NetworkInterface.BytesSentPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}
			}
			dsp_sv.dsl_net_recv_ps.m_fill_array(uhl_recv, false);
			dsp_sv.dsl_net_sent_ps.m_fill_array(uhl_sent, false);
			dsp_sv.dsl_net_total_ps.m_fill_array(uhl_tot, false);

			bog_wmi_net = true;
			adsl_enum1->Release();
		}
		

		// 10. Win32_LogicalDisk
		IEnumWbemClassObject* adsl_enum2 = NULL;
		ill_wmi_res = adsp_service->ExecQuery(L"WQL",L"SELECT * FROM Win32_PerfRawData_PerfDisk_LogicalDisk", WBEM_FLAG_FORWARD_ONLY, NULL, &adsl_enum2);
		if (FAILED(ill_wmi_res))
		{
			m_hl1_printf("xs-lbal-win-%05d-E could not query logical disks. (Error: 0x%X)",__LINE__,ill_wmi_res);	
			bog_wmi_ldperf = false;
		}
		else
		{
			ULONG ul_ret = 0;
			ull uhl_free = 0;
			LONG ill_drivetype = 0;
			while (adsl_enum2)
			{
				CComPtr<IWbemClassObject> adsl_obj_disk;
				ill_wmi_res = adsl_enum2->Next(WBEM_INFINITE, 1, &adsl_obj_disk, &ul_ret);
				if (ul_ret == 0 || adsl_obj_disk == NULL)
				{
					break;
				}
				wchar_t chrl_buf[512];
				ZeroMemory(chrl_buf, 512);
				ill_wmi_res = m_get_bstr_wmi_value(adsl_obj_disk, L"Name", chrl_buf, 512);
				if (wcslen(chrl_buf) <= 2 /*strcmp("_Total", chrl_buf)*/)
				{
					CComPtr<IWbemClassObject> adsl_disk = NULL;
					OLECHAR chrl_dev[512];
					ZeroMemory(chrl_dev, 512);
					swprintf(chrl_dev, L"Win32_LogicalDisk.DeviceID=\"%s\"", chrl_buf);
					
					adsl_disk.Release();
					BSTR strl_bstr_dev = ::SysAllocString(chrl_dev);
					ill_wmi_res = adsp_service->GetObject(strl_bstr_dev, WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_disk, NULL);
					::SysFreeString(strl_bstr_dev);
					if (FAILED(ill_wmi_res))
					{
						m_hl1_printf("xs-lbal-win-%05d-E Win32_LogicalDisk could not be found (Device %s). (Error: 0x%X)", __LINE__, chrl_buf,ill_wmi_res);
						bog_wmi_ld = false;
					}
					else
					{
						ill_wmi_res = m_get_long_wmi_value(adsl_disk, L"DriveType", &ill_drivetype);
						if (SUCCEEDED(ill_wmi_res))
						{
							if (ill_drivetype == 3)
							{
								ill_wmi_res = m_get_ull_wmi_value(adsl_disk, L"FreeSpace", &uhl_var_value);
								if (SUCCEEDED(ill_wmi_res))
								{
									uhl_free += uhl_var_value;
								}
								else
								{
									m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_LogicalDisk.FreeSpace (Device %s). (Error: 0x%X)", __LINE__, chrl_buf,ill_wmi_res);
								}
							}
							bog_wmi_ld = true;
						}
						else
						{
							m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_LogicalDisk.DriveType (Device %s). (Error: 0x%X)", __LINE__, chrl_buf,ill_wmi_res);
						}
					}
				}
			}
			dsp_sv.dsl_ld_free_space.m_fill_array(uhl_free, false);

			bog_wmi_ldperf = true;
			adsl_enum2->Release();
		}
		
	}
	while (0);
#endif /* HL_WINALL1 */

}



// main function of the new thread (collects system data at regular intervals)
static void* m_collect_data(void*)
{
	// initialize the fifo arrays
#ifdef HL_WINALL1	
	IWbemServices* adsl_service = NULL;
	IWbemLocator* adsl_loc = NULL;
	// establish wmi connection
	HRESULT ill_wmi_res;
	ill_wmi_res =  CoInitializeEx(0, COINIT_MULTITHREADED);
	if (FAILED(ill_wmi_res))
	{
		m_hl1_printf("Failed to initialize COM library. Error code = 0x%X", ill_wmi_res);
		return NULL;
	}
	
	
	//ill_wmi_res = adsl_loc.CoCreateInstance(CLSID_WbemLocator);
	ill_wmi_res = CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (void**) &adsl_loc);
	if (ill_wmi_res != S_OK || adsl_loc == NULL)
	{
		m_hl1_printf("Failed to create IWbemLocator object. Error code = 0x%X", ill_wmi_res);
		return NULL;
	}

	
	//BSTR strl_namespace = SysAllocString(L"root\\cimv2");
	ill_wmi_res = adsl_loc->ConnectServer(BSTR(L"root\\cimv2"), NULL, NULL, 0, NULL, 0, 0, &adsl_service);
	//SysFreeString(strl_namespace);
	if (ill_wmi_res != S_OK || adsl_service == NULL)
	{
		m_hl1_printf("Could not connect to wmi server. Error code = 0x%X", ill_wmi_res);
		return NULL;
	}
	ill_wmi_res = CoSetProxyBlanket(adsl_service, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
	if (ill_wmi_res != S_OK)
	{
		m_hl1_printf( "Could not set proxy blanket. Error code = 0x%X", ill_wmi_res);
		return NULL;
	}
#endif
#ifdef HL_WINALL1
	m_init_fifo_arrays(dsg_values, adsl_service);
	m_update_references(adsl_service);
#endif	
#ifdef HL_LINUX
	m_init_fifo_arrays(dsg_values);
	m_update_references();
#endif	
#ifdef HL_FREEBSD
	m_init_fifo_arrays(dsg_values);
	m_update_references();
#endif

	// working variable
	string strl_line;
	// token of a read line
	vector<string> dsl_token;
	int iml_counter = 0;
	int iml_total_counter = 0;
	int iml_log_counter = 0;
	bool bol_collect = true;

	while(bog_collect && bol_collect)
	{

			// lock mutex
	#ifdef HL_FREEBSD
		pthread_mutex_lock(&dsg_monitor_thread_mutex);
	#endif
	#ifdef HL_LINUX
			pthread_mutex_lock(&dsg_monitor_thread_mutex);
	#endif
	#ifdef HL_WINALL1
		HANDLE a_mut = OpenMutexW(SYNCHRONIZE, FALSE, L"MONMUTEX");
	#endif
	#ifdef HL_FREEBSD
		char chrl_buffer[512];
		
		// interrupts
		if(!m_sysctl("vm.stats.sys.v_intr", chrl_buffer, 512))
		{
			dsg_values.dsl_interrupts.m_add_element(strtoull(chrl_buffer, NULL, 10));
		}

		// context switches
		if(!m_sysctl("vm.stats.sys.v_swtch", chrl_buffer, 512))
		{
			dsg_values.dsl_context_switches.m_add_element(strtoull(chrl_buffer, NULL, 10));
		}

		// memory
		if(!m_sysctl("hw.realmem", chrl_buffer, 512))
		{
			dsg_values.dsl_realmem.m_add_element(strtoull(chrl_buffer, NULL, 10));
		}
		if(!m_sysctl("hw.usermem", chrl_buffer, 512))
		{
			dsg_values.dsl_usermem.m_add_element(strtoull(chrl_buffer, NULL, 10));
		}

		// cpu
		if(!m_sysctl("kern.cp_time", chrl_buffer, 512))
		{
			ull uhl_cpu_idle = 0;
			ull uhl_cpu_total = 0;
			if (!m_get_token(chrl_buffer, &uhl_cpu_idle, 4) && !m_get_token_sum(chrl_buffer, &uhl_cpu_total))
			{
				dsg_values.dsl_cpu_idle.m_add_element(uhl_cpu_idle);
				dsg_values.dsl_cpu_total.m_add_element(uhl_cpu_total);
			}
			else
			{
				printf("xs-lbal-win-1 Warning: Could not get CPU load\n");
			}
		}

		// cache
		if(!m_sysctl("vfs.cache.nummiss", chrl_buffer, 512))
		{
			dsg_values.dsl_cache_misses.m_add_element(strtoull(chrl_buffer, NULL, 10));
		}
		if(!m_sysctl("vfs.cache.numchecks", chrl_buffer, 512))
		{
			dsg_values.dsl_cache_checks.m_add_element(strtoull(chrl_buffer, NULL, 10));
		}

		// swapping
		if(!m_sysctl("vm.stats.vm.v_vnodepgsout", chrl_buffer, 512))
		{
			dsg_values.dsl_pages_out.m_add_element(strtoull(chrl_buffer, NULL, 10));
		}
		if(!m_sysctl("vm.stats.vm.v_vnodepgsin", chrl_buffer, 512))
		{
			
			dsg_values.dsl_pages_in.m_add_element(strtoull(chrl_buffer, NULL, 10));
		}
		if(!m_sysctl("vm.stats.vm.v_swappgsout", chrl_buffer, 512))
		{
			dsg_values.dsl_swaps_out.m_add_element(strtoull(chrl_buffer, NULL, 10));
		}
		if(!m_sysctl("vm.stats.vm.v_swappgsin", chrl_buffer, 512))
		{
			dsg_values.dsl_swaps_in.m_add_element(strtoull(chrl_buffer, NULL, 10));
		}

		// swapfile
		if(!m_sysctl("vm.swap_reserved", chrl_buffer, 512))
		{
			dsg_values.dsl_swap_used.m_add_element(strtoull(chrl_buffer, NULL, 10));
		}
		if(!m_sysctl("vm.swap_total", chrl_buffer, 512))
		{
			dsg_values.dsl_swap_total.m_add_element(strtoull(chrl_buffer, NULL, 10));
		}
 
		// processes and threads
		kvm_t* adsl_kd;
		int iml_processes = 0;
		int iml_threads = 0;
		adsl_kd = kvm_open(NULL, "/dev/null", NULL, O_RDONLY, "kvm_open");
		struct kinfo_proc* adsl_proc = kvm_getprocs(adsl_kd, KERN_PROC_PROC, 0, &iml_processes);
		kvm_getprocs(adsl_kd, KERN_PROC_ALL, 0, &iml_threads);
		
		dsg_values.dsl_processes.m_add_element((ull)iml_processes);
		dsg_values.dsl_threads.m_add_element((ull)iml_threads);

		// process data
		int iml_success = 0;
		struct kinfo_proc* adsl_proc_data = kvm_getprocs(adsl_kd, KERN_PROC_PID, getpid(), &iml_success);
		if(iml_success > 0)
		{
			dsg_values.dsl_proc_memory.m_add_element((ull)adsl_proc_data->ki_rssize);
			dsg_values.dsl_proc_page_faults.m_add_element((ull)adsl_proc_data->ki_rusage.ru_majflt);
			dsg_values.dsl_proc_io_reads.m_add_element((ull)adsl_proc_data->ki_rusage.ru_inblock);
			dsg_values.dsl_proc_io_writes.m_add_element((ull)adsl_proc_data->ki_rusage.ru_oublock);
			dsg_values.dsl_proc_threads.m_add_element((ull)adsl_proc_data->ki_numthreads);
			ull uhl_user_time = adsl_proc_data->ki_rusage.ru_utime.tv_sec * 1000000 + adsl_proc_data->ki_rusage.ru_utime.tv_usec;
			ull uhl_sys_time = adsl_proc_data->ki_rusage.ru_stime.tv_sec * 1000000 + adsl_proc_data->ki_rusage.ru_stime.tv_usec;

			dsg_values.dsl_proc_user_time.m_add_element(uhl_user_time / 1000);
			dsg_values.dsl_proc_system_time.m_add_element(uhl_sys_time / 1000);
			dsg_values.dsl_proc_ctx_involuntary.m_add_element((ull)adsl_proc_data->ki_rusage.ru_nvcsw);
			dsg_values.dsl_proc_ctx_voluntary.m_add_element((ull)adsl_proc_data->ki_rusage.ru_nivcsw);

		}
		else
		{
			m_hl1_printf("xs-lbal-win-%05d - process data could not be found",__LINE__);
		}	

		kvm_close(adsl_kd);

	#endif

	#ifdef HL_LINUX
			/*------------------- 1. Hard Disk Load ----------------------*/
			/*-------------- 1.1 get mounted drives------------*/
			vector<string> dsl_drives;	// mountpoint of drives
			ifstream dsl_mounts("/proc/mounts");
			if(!dsl_mounts)
			{
				m_hl1_printf("xs-lbal-win-%05d - The file /proc/mounts could not be found",__LINE__);
				perror("/proc/mounts could not be opened: ");
				// fill array of free hd space with 0, so the load will always be 0
				dsg_values.dsl_free_hd.m_fill_array(0,true);	
				bog_hd = false;
			}
			else bog_hd = true;
			while (getline(dsl_mounts,strl_line))
			{
				m_str_tok(strl_line,dsl_token);
				if(dsl_token.size() < 2)
				{
					m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/mounts. Using default values.",__LINE__);
					dsg_values.dsl_free_hd.m_fill_array(0,true);	
					bog_hd = false;
					dsl_token.clear();
					break;
				}	 			
				if(m_is_dev(const_cast<char*>(dsl_token.at(0).c_str())))
				{
					dsl_drives.push_back(dsl_token.at(1));	
				}
				dsl_token.clear();	
			}
			dsl_mounts.close();			
			dsl_token.clear();	
			
			/*------------- 1.2 get free disk space ----------------*/
			ull uhl1;			// working variable
			ull uhl_free_sum = 0;	// free capacity (in bytes)
 			struct statvfs dsl_drive_info;        /* structure to contain file system information */
   			int iml_hd_free_status = 0;      /* local status value */
   			bool bo_hd_free_err = false;	// did errors occur
	   	
			// for each mounted drive
			for (unsigned int uml1 = 0; uml1 < dsl_drives.size(); uml1++)
			{
				// get drive information via statvfs
				iml_hd_free_status = statvfs(dsl_drives.at(uml1).c_str(),&dsl_drive_info);
				if (iml_hd_free_status != 0)
				{
					bo_hd_free_err = true;	
				}
				// read the size of the device from the statvfs struct
				uhl1 = (ull)dsl_drive_info.f_bfree * (ull)dsl_drive_info.f_bsize;
				uhl_free_sum += uhl1;
			}
					
			if (bo_hd_free_err)	// could not calculate free disk space
			{
				dsg_values.dsl_free_hd.m_fill_array(0,true);	// set all fifo array elements to 0
			}
			else
			{
				dsg_values.dsl_free_hd.m_add_element(uhl_free_sum);	
			}
						
			/*-----------------------2 Processes ------------------------------*/
			ifstream dsl_loadavg("/proc/loadavg");
			if(!dsl_loadavg)
			{
				m_hl1_printf("xs-lbal-win-%05d - The file /proc/loadavg could not be found.",__LINE__);
				perror("/proc/loadavg could not be found: ");
				dsg_values.dsl_processes.m_fill_array(0,true);
				dsg_values.dsl_started_processes.m_fill_array(0,true);	
				bog_loadavg = false;
			}
			else
			{
				bog_loadavg = true;
				getline(dsl_loadavg,strl_line);
				m_str_tok(strl_line,dsl_token);
				if(dsl_token.size() < 5)
				{
					m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/loadavg. Using default values.",__LINE__);
					dsg_values.dsl_processes.m_fill_array(0,true);
					dsg_values.dsl_started_processes.m_fill_array(0,true);	
					bog_loadavg = false;
					dsl_token.clear();
					break;
				}
				else
				{
					int iml1 = dsl_token.at(3).find_first_of ('/');
					string strl_proc = dsl_token.at(3).substr(iml1+1);
					string strl_new_proc = dsl_token.at(4);
					dsg_values.dsl_started_processes.m_add_element(strtol(strl_new_proc.c_str(),NULL,10));
					dsg_values.dsl_processes.m_add_element(strtol(strl_proc.c_str(),NULL,10));
				}
				dsl_token.clear();	
			}
			dsl_loadavg.close();
			
			/*---------------------- 3 hard disk activity -----------------------------*/
			ull uhl_rs_sum = 0;	// sum of read sectors
			ull uhl_ws_sum = 0;	// sum of written sectors
			long ill_io_time_total = 0;		// sum of milliseconds spent for I/O activities
			
			
			/*---- 3.1  get physical hard disks -----*/
			vector<string> ds_phys_disk;	// vector of device names (only physical)
			ifstream ds_partitions("/proc/partitions");
			// file not found
			if(!ds_partitions)
			{
				m_hl1_printf("xs-lbal-win-%05d - The file /proc/partitions could not be found.",__LINE__);
				perror("/proc/partitions could not be opened: ");
				// fill the concerned fifo arrays with zeros
				dsg_values.dsl_read_sectors.m_fill_array(0,false);
				dsg_values.dsl_written_sectors.m_fill_array(0,false);
				dsg_values.dsl_io_time.m_fill_array(0,false);	
				bog_partitions = false;
			}
			// file found
			else
			{
				bog_partitions = true;
				// the first two lines are irrelevant
				getline(ds_partitions,strl_line);
				getline(ds_partitions,strl_line);
				while (getline(ds_partitions,strl_line))
				{
					m_str_tok(strl_line,dsl_token);
					if(dsl_token.size() < 4)
					{
						m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/partitions. Using default values.",__LINE__);
						dsg_values.dsl_read_sectors.m_fill_array(0,false);
						dsg_values.dsl_written_sectors.m_fill_array(0,false);
						dsg_values.dsl_io_time.m_fill_array(0,false);	
						bog_partitions = false;
						dsl_token.clear();
						break;
					}				
					// store the device name of the current line
					string strl1 = dsl_token.at(3);
					// if the name starts with hd or sd and has a length of 3 it is a physical device
					if (strl1.length() == 3 &&
						(strncmp(strl1.c_str(),"sd",2) == 0 || strncmp(strl1.c_str(),"hd",2) == 0))
					{
						// add the device that is represented by the current line
						ds_phys_disk.push_back(strl1);	
					}
					dsl_token.clear();	
				}
			}
			ds_partitions.close();
			/*-------- 3.2 read stats of all physical disks -----------*/
			ifstream ds_diskstats("/proc/diskstats");
			// file not found
			if(!ds_diskstats)
			{
				m_hl1_printf("xs-lbal-win-%05d - The file /proc/diskstats could not be found.",__LINE__);
				perror("/proc/diskstats could not be opened: ");
				dsg_values.dsl_read_sectors.m_fill_array(0,false);
				dsg_values.dsl_written_sectors.m_fill_array(0,false);
				dsg_values.dsl_io_time.m_fill_array(0,false);		
				bog_diskstats = false;			
			}
			// file found
			else
			{
				bog_diskstats = true;
				// iterator for the vector of physical devices
				vector<string>::iterator ds_vit;
				while (getline(ds_diskstats,strl_line))
				{
					m_str_tok(strl_line,dsl_token);
					// search only in lines with enough tokens for a real physical device
					// this is done for performance reasons
					if (dsl_token.size() > 13)		
					{
						// look if the device of the current line is contained in
						// the vector of our physical devices
						for(ds_vit = ds_phys_disk.begin(); ds_vit != ds_phys_disk.end(); ds_vit++)
						{
							string strl1 = *(ds_vit);
							// device found
							if(!strcmp(dsl_token.at(2).c_str(),strl1.c_str()))
							{
								//add the current values to the sums
								uhl_rs_sum += strtoull(dsl_token.at(5).c_str(),NULL,10);
								uhl_ws_sum += strtoull(dsl_token.at(9).c_str(),NULL,10);
								ill_io_time_total += strtoull(dsl_token.at(12).c_str(), NULL,10);
							}	
						}
					}

					dsl_token.clear();	
				}
				dsg_values.dsl_read_sectors.m_add_element(uhl_rs_sum);
				dsg_values.dsl_written_sectors.m_add_element(uhl_ws_sum);
				dsg_values.dsl_io_time.m_add_element(ill_io_time_total);
				ds_diskstats.close();
			}

			
			/*-------------------4 RAM and swap-----------------------------*/
			ifstream dsl_meminfo("/proc/meminfo");
			// file not found
			if (!dsl_meminfo)
			{
				m_hl1_printf("xs-lbal-win-%05d - The file /proc/meminfo could not be found.",__LINE__);
				perror("/proc/meminfo could not be found: ");
				// set all fifo array values to zero
				dsg_values.dsl_free_memory.m_fill_array(0,false);
				dsg_values.dsl_free_swap.m_fill_array(0,false);	
				bog_meminfo = false;
			}
			// file found
			else
			{
				bog_meminfo = true;
				// read all entries
				while(getline(dsl_meminfo,strl_line))	
				{
					m_str_tok(strl_line,dsl_token);
					if(dsl_token.size() < 2)
					{
						m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/meminfo. Using default values.",__LINE__);
						dsg_values.dsl_free_memory.m_fill_array(0,false);
						dsg_values.dsl_free_swap.m_fill_array(0,false);	
						bog_meminfo = false;
						dsl_token.clear();
						break;
					}
					// if first string in line is "MemFree:" ...
					if (dsl_token.at(0) == "MemFree:")
					{
						// ... read the value and write it to the global structure
						dsg_values.dsl_free_memory.m_add_element(strtol(dsl_token.at(1).c_str(),NULL,10));	
					}
					if (dsl_token.at(0) == "SwapFree:")
					{
						dsg_values.dsl_free_swap.m_add_element(strtol(dsl_token.at(1).c_str(),NULL,10));
					}
					dsl_token.clear();
				}
				dsl_meminfo.close();
			}
			
			/*----------------- 5 Network traffic ----------------------------*/
			ull uhl_sum_rec = 0;		// received bytes of all network interfaces
			ull uhl_sum_trans = 0;		// transmitted bytes of all network interfaces
			
			ifstream dsl_net("/proc/net/dev");
			// file not found
			if (!dsl_net)
			{
				m_hl1_printf("xs-lbal-win-%05d - The file /proc/net/dev could not be found.",__LINE__);
				perror("/proc/net/dev could not be opened: ");
				// set all fifo array values to zero
				dsg_values.dsl_net_rec.m_fill_array(0,false);
				dsg_values.dsl_net_trans.m_fill_array(0,false);	
				bog_netdev = false;
			}
			// file found
			else
			{
				bog_netdev = true;
				// the first two lines are irrelevant
				getline(dsl_net,strl_line);
				getline(dsl_net,strl_line);
				// for each network interface
				while (getline(dsl_net,strl_line))
				{
					m_str_tok(strl_line,dsl_token);
					string strl_trans;	// string of transmitted bytes
					string strl_rec;	// string of received bytes
					
					if(dsl_token.size() < 10)
					{
						m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/net/dev. Using default values.",__LINE__);
						dsg_values.dsl_net_rec.m_fill_array(0,false);
						dsg_values.dsl_net_trans.m_fill_array(0,false);	
						bog_netdev = false;
						dsl_token.clear();
						break;
					}
					// if the first string in the current line ends with ':' (default)
					if(dsl_token.at(0)[dsl_token.at(0).size()-1]==':')
					{
						// read the appropriate values and add them to the sum
						uhl_sum_rec += strtoull(dsl_token.at(1).c_str(),NULL,10);
						uhl_sum_trans += strtoull(dsl_token.at(9).c_str(),NULL,10);
					}
					// the first string's last char is not ':' (the 2nd column is formatted
					// to contain at most 8 digits (that means a maximum of 100 MB network
					// activity. If it is more than 100 MB the string that contains
					// the received bytes is concatenated with the name of the interface,
					// for example "wlan0:226578406". In this case the first string
					// of the line has to be splitted after the ':'. The index
					// of the string that contains the amount of transmitted bytes
					// is decreased by one in this case.
					else
					{
						uhl_sum_trans += strtoull(dsl_token.at(8).c_str(),NULL,10);
						string strl1 = dsl_token.at(0);
						int    iml1 = strl1.find_first_of(":");
						strl1 = strl1.substr(iml1+1);
						uhl_sum_rec += strtoull(strl1.c_str(),NULL,10);
							
					}
					dsl_token.clear();
				}	
				dsl_net.close();
				dsg_values.dsl_net_rec.m_add_element(uhl_sum_rec);
				dsg_values.dsl_net_trans.m_add_element(uhl_sum_trans);
			}
			
			/*--------------------- 6 CPU, context switches, interrupts ---------------*/
			ifstream dsl_stat("/proc/stat");
			// file not found
			if (!dsl_stat)
			{
				m_hl1_printf("xs-lbal-win-%05d - The file /proc/stat could not be found.",__LINE__);
				perror("/proc/stat could not be opened: ");
				dsg_values.dsl_idle_jiffies.m_fill_array(0,false);
				dsg_values.dsl_ctx_switch.m_fill_array(0,false);
				dsg_values.dsl_interrupts.m_fill_array(0,false);
				bog_stat = false;
			}
			else
			{
				bog_stat = true;
				// read lines of file
				while (getline(dsl_stat,strl_line))
				{
					m_str_tok(strl_line,dsl_token);
					// cpu jiffies
					if (dsl_token.at(0).compare("cpu") == 0)
					{
						// idle jiffies
						ull uhl1 = strtoull(dsl_token.at(4).c_str(),NULL,10);
						// total jiffies
						ull uhl2 = 0;
						for (int iml1 = 1; iml1 <=7; iml1++)
						{
							uhl2 += strtoull(dsl_token.at(iml1).c_str(),NULL,10);
						}
						dsg_values.dsl_idle_jiffies.m_add_element(uhl1);	
						dsg_values.dsl_total_jiffies.m_add_element(uhl2);
					}
					// interrupts
					else if (dsl_token.at(0).compare("intr") == 0)
					{
						dsg_values.dsl_interrupts.m_add_element(strtoull(dsl_token.at(1).c_str(),NULL,10));
					}
					// context switches
					else if (dsl_token.at(0).compare("ctxt") == 0)
					{
						dsg_values.dsl_ctx_switch.m_add_element(strtoull(dsl_token.at(1).c_str(),NULL,10));	
					}
					dsl_token.clear();
				}
				dsl_stat.close();
			}
			
			/*------------------------ 7 Virtual Memory ----------------------*/
			ifstream dsl_vm("/proc/vmstat");
			if (!dsl_vm)
			{
				m_hl1_printf("xs-lbal-win-%05d - The file /proc/vmstat could not be found.",__LINE__);
				perror ("/proc/vmstat could not be opened: ");
				bog_vmstat = false;
			}
			else
			{
				bog_vmstat = true;
				// read lines
				while (getline(dsl_vm,strl_line))
				{
					m_str_tok(strl_line,dsl_token);
					if(dsl_token.size() < 2)
					{
						m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/vmstat.",__LINE__);
						bog_vmstat = false;
						dsl_token.clear();
						break;
					}
					// page ins found
					if (dsl_token.at(0).compare("pgpgin") == 0)
					{
						dsg_values.dsl_page_in.m_add_element(strtoull(dsl_token.at(1).c_str(),NULL,10));	
					}
					// page outs found
					else if (dsl_token.at(0).compare("pgpgout") == 0)
					{
						dsg_values.dsl_page_out.m_add_element(strtoull(dsl_token.at(1).c_str(),NULL,10));	
					}
					// swap ins found
					else if (dsl_token.at(0).compare("pswpin") == 0)
					{
						dsg_values.dsl_swap_in.m_add_element(strtoull(dsl_token.at(1).c_str(),NULL,10));	
					}
					// swap outs found
					else if (dsl_token.at(0).compare("pswpout") == 0)
					{
						dsg_values.dsl_swap_out.m_add_element(strtoull(dsl_token.at(1).c_str(),NULL,10));	
					}
					// minor page faults
					else if (dsl_token.at(0).compare("pgfault") == 0)
					{
						dsg_values.dsl_min_pg_faults.m_add_element(strtoull(dsl_token.at(1).c_str(),NULL,10));	
					}
					// major page faults
					else if (dsl_token.at(0).compare("pgmajfault") == 0)
					{
						dsg_values.dsl_maj_pg_faults.m_add_element(strtoull(dsl_token.at(1).c_str(),NULL,10));	
					}
					dsl_token.clear();	
				}
				dsl_vm.close();	
			}	
			/*--------------------- 8 Process load -------------------*/
			ifstream dsl_selfstat("/proc/self/stat");
			if (!dsl_selfstat)
			{
				bog_self_stat = false;	
				m_hl1_printf("xs-lbal-win-%05d - The file /proc/self/stat could not be found",__LINE__);
				perror("/proc/self/stat could not be opened: ");
			}
			else
			{
				bog_self_stat = true;	
				// read the first line
				getline(dsl_selfstat, strl_line);
				m_str_tok(strl_line,dsl_token);
				
				if(dsl_token.size() < 23)
				{
					m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/self/stat.",__LINE__);
					bog_self_stat = false;
					dsl_token.clear();
				}
				else
				{
				  ull uhl_proc_jiff = 0;
				  // get jiffies in user mode
				  uhl_proc_jiff += strtoull(dsl_token.at(13).c_str(),NULL,10);
				  // get jiffies in kernel mode
				  uhl_proc_jiff += strtoull(dsl_token.at(14).c_str(),NULL,10);
				  // add the calculated value to the fifo array
				  dsg_values.dsl_proc_jiffies.m_add_element(uhl_proc_jiff);
				  
				  dsg_values.uhl_proc_ticks_user = strtoull(dsl_token.at(13).c_str(),NULL, 10);
				  dsg_values.uhl_proc_ticks_kernel = strtoull(dsl_token.at(14).c_str(), NULL, 10);
				  dsg_values.uhl_proc_virtual_memory = strtoull(dsl_token.at(22).c_str(),NULL, 10);			
				  
				  dsl_token.clear();
				}
				dsl_selfstat.close();
			}


		
			ifstream dsl_proc_io("/proc/self/io");
			if(dsl_proc_io)
			{
			  string strl_line;
			  while(getline(dsl_proc_io, strl_line))
			  {
				  m_str_tok(strl_line, dsl_token);
				  if(dsl_token.size() < 2)
				  {
				  m_hl1_printf("xs-lbal-win-%05d - could not tokenize line from /proc/self/io. Using default values.",__LINE__);
				   dsg_values.uhl_proc_io_reads = 0;
				  dsg_values.uhl_proc_io_writes = 0;
				  dsg_values.uhl_proc_io_read_bytes = 0;
				  dsg_values.uhl_proc_io_written_bytes = 0;
				  dsl_token.clear();
				  break;
				  }		      
				  if (dsl_token.at(0).compare("syscr:") == 0)
				  {
				dsg_values.uhl_proc_io_reads = strtoull(dsl_token.at(1).c_str(),NULL,10);
				  }
				  else if (dsl_token.at(0).compare("syscw:") == 0)
				  {
				dsg_values.uhl_proc_io_writes = strtoull(dsl_token.at(1).c_str(),NULL,10);
				  }
				  else if (dsl_token.at(0).compare("read_bytes:") == 0)
				  {
				dsg_values.uhl_proc_io_read_bytes = strtoull(dsl_token.at(1).c_str(),NULL,10);
				  }
				  else if (dsl_token.at(0).compare("write_bytes:") == 0)
				  {
				dsg_values.uhl_proc_io_written_bytes = strtoull(dsl_token.at(1).c_str(),NULL,10);
				  }	  
				  dsl_token.clear();
			  }
			  
			  dsl_proc_io.close();
			}
			else
			{
			  dsg_values.uhl_proc_io_reads = 0;
			  dsg_values.uhl_proc_io_writes = 0;
			  dsg_values.uhl_proc_io_read_bytes = 0;
			  dsg_values.uhl_proc_io_written_bytes = 0;
			}
			

	#endif /* HL_LINUX */			
	#ifdef HL_WINALL1

		{
				// variables used for querying the wmi object of the local process
			string strl_wql_query_process;

			DWORD dwl_procid = GetCurrentProcessId();
			wchar_t chrl_proc_path[256];
			ZeroMemory(chrl_proc_path, 256);
			swprintf(chrl_proc_path, L"Win32_Process.Handle=\"%d\"", dwl_procid);



			LONG ill_var_value = 0;
			ull  uhl_var_value = 0;

			// Get WMI performance object of the local process
			//CComPtr<IEnumWbemClassObject> dsl_perfproc_enum = NULL;
			CComPtr<IWbemClassObject> dsl_wmiobj_current_process = NULL;
			DWORD dwl_pid = GetCurrentProcessId();
			strl_wql_query_process.assign("SELECT * FROM Win32_PerfRawData_PerfProc_Process WHERE IDProcess = ");
			char chrl_pid_buffer[16];
			sprintf(chrl_pid_buffer, "%d", dwl_pid);
			strl_wql_query_process.append(chrl_pid_buffer);
			CComBSTR dsl_wql_query_process(strl_wql_query_process.c_str());




			/* ------------------- 1. Win32_PerfRawData_PerfOS_Cache ---------------------- */
			CComPtr<IWbemClassObject> adsl_obj_raw_os_cache;
			ill_wmi_res = adsl_service->GetObject(L"Win32_PerfRawData_PerfOS_Cache=@", WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_obj_raw_os_cache, NULL);
			if (FAILED(ill_wmi_res))
			{
				m_hl1_printf("xs-lbal-win-%05d-E Win32_PerfRawData_PerfOS_Cache=@ could not be found. (Error: 0x%X)", __LINE__,ill_wmi_res);
				bog_wmi_cache = false;
			}
			else
			{
				ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_cache,L"CopyReadHitsPercent",&ill_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_cache_copy_read_hits_pc.m_add_element(ill_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Cache.CopyReadHitsPercent. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}
				m_get_long_wmi_value(adsl_obj_raw_os_cache,L"CopyReadHitsPercent_Base",&ill_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_cache_copy_reads_ps.m_add_element(ill_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Cache.CopyReadHitsPercent_Base. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}
				bog_wmi_cache = true;
			}	
			

			/* ----------------- 2. Win32_PerfRawData_PerfDisk_LogicalDisk --------------------- */
			// 2. Win32_PerfRawData_PerfDisk_LogicalDisk
			{
				ull uhl_avg_disk_bytes_per_read = 0;
				ull uhl_avg_disk_bytes_per_write = 0;
				ull uhl_avg_disk_bytes_per_transfer = 0;
				LONG ill_avg_disk_reads_per_sec = 0;
				LONG ill_avg_disk_writes_per_sec = 0;
				LONG ill_avg_disk_transfers_per_sec = 0;
				ull uhl_disk_bytes_per_sec = 0;
				ull uhl_percent_disk_time = 0;
				
				// list of all logical disks
				IEnumWbemClassObject* adsl_enum = NULL;
				
				
				
				ill_wmi_res = adsl_service->ExecQuery(L"WQL",L"SELECT * FROM Win32_LogicalDisk WHERE Drivetype = 3", WBEM_FLAG_FORWARD_ONLY, NULL, &adsl_enum);
				if (FAILED(ill_wmi_res))
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not query logical disks. (Error: 0x%X)",__LINE__,ill_wmi_res);	
					bog_wmi_ldperf = false;
				}
				else
				{

					ULONG ul_ret = 0;
					LONG ill_drivetype = 0;
					while (adsl_enum)
					{
						CComPtr<IWbemClassObject> adsl_obj_logical_disk;
						ill_wmi_res = adsl_enum->Next(WBEM_INFINITE, 1, &adsl_obj_logical_disk, &ul_ret);
						if (ul_ret == 0 || adsl_obj_logical_disk == NULL)
						{	
							// no more disks
							break;
						}
						
						ill_wmi_res = m_get_long_wmi_value(adsl_obj_logical_disk, L"DriveType", &ill_drivetype);
						if (FAILED(ill_wmi_res))
						{
							m_hl1_printf("xs-lbal-win-%05d-E unable to get drive type. (Error: 0x%X)",__LINE__,ill_wmi_res);
							break;
						}
						// if a local drive was found
						if (ill_drivetype == 3)
						{	
							wchar_t chrl_buf[16];
							ZeroMemory(chrl_buf, 16);
							ill_wmi_res = m_get_bstr_wmi_value(adsl_obj_logical_disk, L"DeviceID", chrl_buf, 16);
							if (FAILED(ill_wmi_res))
							{
								m_hl1_printf("xs-lbal-win-%05d-E unable to get device id. (Error: 0x%X)",__LINE__, ill_wmi_res);
								break;
							}
							OLECHAR chrl_object_path[512];
							ZeroMemory(chrl_object_path, 512);
							swprintf(chrl_object_path, L"Win32_PerfRawData_PerfDisk_LogicalDisk.Name=\"%S\"", chrl_buf);
							//wstring strl_object_path = L"Win32_PerfRawData_PerfDisk_LogicalDisk.Name=\"" + (wstring)chrl_buf + L"\"";
							CComPtr<IWbemClassObject> adsl_obj_spec_disk;
							BSTR strl_bstr_path = ::SysAllocString(chrl_object_path);
							ill_wmi_res = adsl_service->GetObject(strl_bstr_path, WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_obj_spec_disk, NULL);
							::SysFreeString(strl_bstr_path);
							if (FAILED(ill_wmi_res))
							{
								m_hl1_printf("xs-lbal-win-%05d-E unable to get date from device %s. (Error: 0x%X)",__LINE__,chrl_buf,ill_wmi_res);
								break;
							}
							// get data from local disk
							ill_wmi_res = m_get_ull_wmi_value(adsl_obj_spec_disk, L"AvgDiskBytesPerRead", &uhl_var_value);
							if (SUCCEEDED(ill_wmi_res))
							{
								uhl_avg_disk_bytes_per_read += uhl_var_value;
							}
							else
							{
								m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.AvgDiskBytesPerRead from device %s. (Error: 0x%X)", __LINE__, chrl_buf,ill_wmi_res);
							}

							ill_wmi_res = m_get_ull_wmi_value(adsl_obj_spec_disk, L"AvgDiskBytesPerWrite", &uhl_var_value);
							if (SUCCEEDED(ill_wmi_res))
							{
								uhl_avg_disk_bytes_per_write += uhl_var_value;
							}
							else
							{
								m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.AvgDiskBytesPerWrite from device %s. (Error: 0x%X)", __LINE__, chrl_buf,ill_wmi_res);
							}

							ill_wmi_res = m_get_ull_wmi_value(adsl_obj_spec_disk, L"AvgDiskBytesPerTransfer", &uhl_var_value);
							if (SUCCEEDED(ill_wmi_res))
							{
								uhl_avg_disk_bytes_per_transfer += uhl_var_value;
							}
							else
							{
								m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.AvgDiskBytesPerTransfer from device %s. (Error: 0x%X)", __LINE__, chrl_buf,ill_wmi_res);
							}

							ill_wmi_res = m_get_long_wmi_value(adsl_obj_spec_disk, L"DiskReadsPerSec", &ill_var_value);
							if (SUCCEEDED(ill_wmi_res))
							{
								ill_avg_disk_reads_per_sec += ill_var_value;
							}
							else
							{
								m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.DiskReadsPerSec from device %s. (Error: 0x%X)", __LINE__, chrl_buf,ill_wmi_res);
							}

							ill_wmi_res = m_get_long_wmi_value(adsl_obj_spec_disk, L"DiskWritesPerSec", &ill_var_value);
							if (SUCCEEDED(ill_wmi_res))
							{
								ill_avg_disk_writes_per_sec += ill_var_value;
							}
							else
							{
								m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.DiskWritesPerSec from device %s. (Error: 0x%X)", __LINE__,chrl_buf,ill_wmi_res);
							}

							ill_wmi_res = m_get_long_wmi_value(adsl_obj_spec_disk, L"DiskTransfersPerSec", &ill_var_value);
							if (SUCCEEDED(ill_wmi_res))
							{
								ill_avg_disk_transfers_per_sec += ill_var_value;
							}
							else
							{
								m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.DiskTransfersPerSec from device %s. (Error: 0x%X)", __LINE__, chrl_buf,ill_wmi_res);
							}

							ill_wmi_res = m_get_ull_wmi_value(adsl_obj_spec_disk, L"DiskBytesPerSec", &uhl_var_value);
							if (SUCCEEDED(ill_wmi_res))
							{
								uhl_disk_bytes_per_sec += uhl_var_value;
							}
							else
							{
								m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.DiskBytesPerSec from device %s. (Error: 0x%X)", __LINE__, chrl_buf,ill_wmi_res);
							}

							ill_wmi_res = m_get_ull_wmi_value(adsl_obj_spec_disk, L"PercentDiskTime", &uhl_var_value);
							if (SUCCEEDED(ill_wmi_res))
							{
								uhl_percent_disk_time += uhl_var_value;
							}
							else
							{
								m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfDisk_LogicalDisk.PercentDiskTime from device %s. (Error: 0x%X)", __LINE__, chrl_buf,ill_wmi_res);
							}
							bog_wmi_ldperf = true;
						}
					}
					// add cumulated valued to arrays
					dsg_values.dsl_ldperf_avg_disk_bytes_read.m_add_element(uhl_avg_disk_bytes_per_read);
					dsg_values.dsl_ldperf_avg_disk_bytes_write.m_add_element(uhl_avg_disk_bytes_per_write);
					dsg_values.dsl_ldperf_avg_disk_bytes_transfer.m_add_element(uhl_avg_disk_bytes_per_transfer);
					dsg_values.dsl_ldperf_disk_reads_ps.m_add_element(ill_avg_disk_reads_per_sec);
					dsg_values.dsl_ldperf_disk_writes_ps.m_add_element(ill_avg_disk_writes_per_sec);
					dsg_values.dsl_ldperf_disk_transfers_ps.m_add_element(ill_avg_disk_transfers_per_sec);
					dsg_values.dsl_ldperf_disk_bytes_ps.m_add_element(uhl_disk_bytes_per_sec);
					dsg_values.dsl_ldperf_disk_time_pc.m_add_element(uhl_percent_disk_time);
					adsl_enum->Release();
				}
				
			}
			/* -------------- 3. Win32_PerfRawData_PerfOS_Memory ----------------------- */
			CComPtr<IWbemClassObject> adsl_obj_raw_os_memory;
			ill_wmi_res = adsl_service->GetObject(L"Win32_PerfRawData_PerfOS_Memory=@", WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_obj_raw_os_memory, NULL);
			if (FAILED(ill_wmi_res))
			{
				m_hl1_printf("xs-lbal-win-%05d-E Win32_PerfRawData_PerfOS_Memory=@ could not be found. (Error: 0x%X)", __LINE__,ill_wmi_res);
				bog_wmi_mem = false;
			}
			else
			{
				ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_os_memory, L"AvailableBytes", &uhl_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_mem_avail_bytes.m_add_element(uhl_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Memory.AvailableBytes. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}

				ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_memory, L"CacheFaultsPerSec", &ill_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_mem_cache_faults_ps.m_add_element(ill_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Memory.CacheFaultsPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}

				ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_memory, L"PageFaultsPerSec", &ill_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_mem_page_faults_ps.m_add_element(ill_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Memory.PageFaultsPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}

				ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_memory, L"PagesInputPerSec", &ill_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_mem_page_input_ps.m_add_element(ill_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Memory.PagesInputPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}

				ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_memory, L"PagesOutputPerSec", &ill_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_mem_page_output_ps.m_add_element(ill_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Memory.PagesOutputPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}

				ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_memory, L"PagesPerSec", &ill_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_mem_page_total_ps.m_add_element(ill_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Memory.PagesPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}
				bog_wmi_mem = true;
			}

			/* ------------------------ 4. Win32_PerfRawData_PerfOS_PagingFile ------------------------- */
			int iml_number_of_page_files = 0;
			IEnumWbemClassObject* adsl_pagefile_enum = NULL;
			ill_wmi_res = adsl_service->ExecQuery(L"WQL", L"SELECT * FROM Win32_PerfRawData_PerfOS_PagingFile WHERE Name != \"_Total\"", WBEM_FLAG_FORWARD_ONLY, NULL, &adsl_pagefile_enum);
			if (SUCCEEDED(ill_wmi_res))
			{
				while (true)
				{
					CComPtr<IWbemClassObject> dsl_pagefile;
					ULONG uml_ret = 0;
					
					ill_wmi_res = adsl_pagefile_enum->Next(WBEM_INFINITE, 1, &dsl_pagefile, &uml_ret);
					if (SUCCEEDED(ill_wmi_res) && ill_wmi_res != S_FALSE)
					{
						iml_number_of_page_files++;
					}
					else break;
				}
				adsl_pagefile_enum->Release();
			}
			CComPtr<IWbemClassObject> adsl_obj_raw_os_pf;
			ill_wmi_res = adsl_service->GetObject(L"Win32_PerfRawData_PerfOS_PagingFile.Name=\"_Total\"", WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_obj_raw_os_pf, NULL);
			if (FAILED(ill_wmi_res) || iml_number_of_page_files == 0)
			{
				if (iml_number_of_page_files > 0)
				{
					m_hl1_printf("xs-lbal-win-%05d-E Win32_PerfRawData_PerfOS_PagingFile.Name=\"_Total\" could not be found. (Error: 0x%X)", __LINE__,ill_wmi_res);
					bog_wmi_page = false;
				}
				else
				{
					dsg_values.dsl_page_size.m_add_element(0);
					dsg_values.dsl_page_usage_pc.m_add_element(0);
				}
			}
			else
			{
				ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_pf, L"PercentUsage", &ill_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_page_usage_pc.m_add_element(ill_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_PagingFile.PercentUsage. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}

				ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_pf, L"PercentUsage_Base", &ill_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_page_size.m_add_element(ill_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_PagingFile.PercentUsage_Base. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}
				bog_wmi_page = true;
			}
			
			/* ---------------------- 5. Win32_PerfRawData_PerfOS_System ----------------------- */
			CComPtr<IWbemClassObject> adsl_obj_raw_os_system;
			ill_wmi_res = adsl_service->GetObject(L"Win32_PerfRawData_PerfOS_System=@", WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_obj_raw_os_system, NULL);
			if (FAILED(ill_wmi_res))
			{
				m_hl1_printf("xs-lbal-win-%05d-E Win32_PerfRawData_PerfOS_System=@ could not be found. (Error: 0x%X)", __LINE__,ill_wmi_res);
				bog_wmi_obj = false;
			}
			else
			{
				ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_system, L"Processes", &ill_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_obj_processes.m_add_element(ill_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_System.Processes. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}

				ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_system, L"Threads", &ill_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_obj_threads.m_add_element(ill_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_System.Threads. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}
				ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_system, L"ContextSwitchesPerSec", &ill_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_sys_ctx.m_add_element(ill_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_System.ContextSwitchesPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}

				bog_wmi_sys = true;
				bog_wmi_obj = true;
			}

			/* -------------------- 6. Win32_PerfRawData_PerfOS_Processor --------------------------- */
			CComPtr<IWbemClassObject> adsl_obj_raw_os_processor;
			ill_wmi_res = adsl_service->GetObject(L"Win32_PerfRawData_PerfOS_Processor.Name=\"_Total\"", WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_obj_raw_os_processor, NULL);
			if (FAILED(ill_wmi_res))
			{
				m_hl1_printf("xs-lbal-win-%05d-E Win32_PerfRawData_PerfOS_Processor.Name=\"_Total\" could not be found. (Error: 0x%X)", __LINE__,ill_wmi_res);
				bog_wmi_cpu = false;
			}
			else
			{
				ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_os_processor, L"InterruptsPerSec", &ill_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_cpu_int.m_add_element(ill_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Processor.InterruptsPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}

				ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_os_processor, L"PercentIdleTime", &uhl_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_cpu_idle.m_add_element(uhl_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Processor.PercentIdleTime. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}

				ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_os_processor, L"TimeStamp_PerfTime", &uhl_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_timestamp.m_add_element(uhl_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Processor.TimeStamp_PerfTime. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}

				ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_os_processor, L"Frequency_PerfTime", &uhl_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.dsl_frequency.m_add_element(uhl_var_value);
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfOS_Processor.Frequency_PerfTime. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}

				bog_wmi_cpu = true;
			}

			/* ------------------- 8. Win32_PerfRawData_PerfProc_Process ------------------- */
			IEnumWbemClassObject* adsl_enum_raw_process;
			ill_wmi_res = adsl_service->ExecQuery(L"WQL",dsl_wql_query_process, WBEM_FLAG_FORWARD_ONLY, NULL, &adsl_enum_raw_process);
			if (SUCCEEDED(ill_wmi_res))
			{
				ULONG uml_ret = 0;
				CComPtr<IWbemClassObject> adsl_obj_raw_process;	
				ill_wmi_res = adsl_enum_raw_process->Next(WBEM_INFINITE, 1, &adsl_obj_raw_process, &uml_ret);
				if (FAILED(ill_wmi_res) || adsl_obj_raw_process == NULL)
				{
					m_hl1_printf("Unable to get wmi performance object of the current process. Process ID: %d. (Error: 0x%X)", dwl_pid,ill_wmi_res);
					bog_wmi_proc = false;
					dsg_values.dsl_proc_cpu.m_add_element(0);
					dsg_values.dsl_proc_elapsed_time.m_add_element(0);
					dsg_values.dsl_proc_handles.m_add_element(0);
					dsg_values.dsl_proc_io_read_bytes.m_add_element(0);
					dsg_values.dsl_proc_io_read_ops.m_add_element(0);
					dsg_values.dsl_proc_io_write_bytes.m_add_element(0);
					dsg_values.dsl_proc_io_write_ops.m_add_element(0);
					dsg_values.dsl_proc_page_faults.m_add_element(0);
					dsg_values.dsl_proc_threads.m_add_element(0);
					dsg_values.dsl_proc_virt_bytes.m_add_element(0);
					dsg_values.dsl_proc_working_set.m_add_element(0);
				}
				else
				{
					ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_process, L"ElapsedTime", &uhl_var_value);
					if (SUCCEEDED(ill_wmi_res))
					{
						dsg_values.dsl_proc_elapsed_time.m_add_element(uhl_var_value);
					}
					else
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.ElapsedTime. Error %x", __LINE__, ill_wmi_res);
					}

					ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_process, L"HandleCount", &ill_var_value);
					if (SUCCEEDED(ill_wmi_res))
					{
						dsg_values.dsl_proc_handles.m_add_element(ill_var_value);
					}
					else
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.HandleCount. Error %x", __LINE__, ill_wmi_res);
					}

					ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_process, L"IOReadBytesPerSec", &uhl_var_value);
					if (SUCCEEDED(ill_wmi_res))
					{
						dsg_values.dsl_proc_io_read_bytes.m_add_element(uhl_var_value);
					}
					else
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.IOReadBytesPerSec. Error %x", __LINE__, ill_wmi_res);
					}

					ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_process, L"IOReadOperationsPerSec", &uhl_var_value);
					if (SUCCEEDED(ill_wmi_res))
					{
						dsg_values.dsl_proc_io_read_ops.m_add_element(uhl_var_value);
					}
					else
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.IOReadOperationsPerSec. Error %x", __LINE__, ill_wmi_res);
					}

					ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_process, L"IOWriteBytesPerSec", &uhl_var_value);
					if (SUCCEEDED(ill_wmi_res))
					{
						dsg_values.dsl_proc_io_write_bytes.m_add_element(uhl_var_value);
					}
					else
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.IOWriteBytesPerSec. Error %x", __LINE__, ill_wmi_res);
					}

					ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_process, L"IOWriteOperationsPerSec", &uhl_var_value);
					if (SUCCEEDED(ill_wmi_res))
					{
						dsg_values.dsl_proc_io_write_ops.m_add_element(uhl_var_value);
					}
					else
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.IOWriteOperationsPerSec. Error %x", __LINE__, ill_wmi_res);
					}

					ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_process, L"PageFaultsPerSec", &ill_var_value);
					if (SUCCEEDED(ill_wmi_res))
					{
						dsg_values.dsl_proc_page_faults.m_add_element(ill_var_value);
					}
					else
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.PageFaultsPerSec. Error %x", __LINE__, ill_wmi_res);
					}

					ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_process, L"PercentProcessorTime", &uhl_var_value);
					if (SUCCEEDED(ill_wmi_res))
					{
						dsg_values.dsl_proc_cpu.m_add_element(uhl_var_value);
					}
					else
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.PercentProcessorTime. Error %x", __LINE__, ill_wmi_res);
					}

					ill_wmi_res = m_get_long_wmi_value(adsl_obj_raw_process, L"ThreadCount", &ill_var_value);
					if (SUCCEEDED(ill_wmi_res))
					{
						dsg_values.dsl_proc_threads.m_add_element(ill_var_value);
					}
					else
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.ThreadCount. Error %x", __LINE__, ill_wmi_res);
					}

					ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_process, L"VirtualBytes", &uhl_var_value);
					if (SUCCEEDED(ill_wmi_res))
					{
						dsg_values.dsl_proc_virt_bytes.m_add_element(uhl_var_value);
					}
					else
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.VirtualBytes. Error %x", __LINE__, ill_wmi_res);
					}

					ill_wmi_res = m_get_ull_wmi_value(adsl_obj_raw_process, L"WorkingSet", &uhl_var_value);
					if (SUCCEEDED(ill_wmi_res))
					{
						dsg_values.dsl_proc_working_set.m_add_element(uhl_var_value);
					}
					else
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_PerfProc_Process.WorkingSet. Error %x", __LINE__, ill_wmi_res);
					}
					bog_wmi_proc = true;
				}
				adsl_enum_raw_process->Release();
			}
			else
			{
				m_hl1_printf("Unable to find the wmi performance object of the current process. Process ID: %d", dwl_pid);
				bog_wmi_proc = false;
				dsg_values.dsl_proc_cpu.m_add_element(0);
				dsg_values.dsl_proc_elapsed_time.m_add_element(0);
				dsg_values.dsl_proc_handles.m_add_element(0);
				dsg_values.dsl_proc_io_read_bytes.m_add_element(0);
				dsg_values.dsl_proc_io_read_ops.m_add_element(0);
				dsg_values.dsl_proc_io_write_bytes.m_add_element(0);
				dsg_values.dsl_proc_io_write_ops.m_add_element(0);
				dsg_values.dsl_proc_page_faults.m_add_element(0);
				dsg_values.dsl_proc_threads.m_add_element(0);
				dsg_values.dsl_proc_virt_bytes.m_add_element(0);
				dsg_values.dsl_proc_working_set.m_add_element(0);
			}
			

			/* ------------------ 8b. Win32_Process --------------------*/
			CComPtr<IWbemClassObject> adsl_obj_own_process;
			ill_wmi_res = adsl_service->GetObject(chrl_proc_path, WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_obj_own_process, NULL);
			if (FAILED(ill_wmi_res))
			{
				m_hl1_printf("xs-lbal-win-%05d-E could not the Win32_Process object of the current process. (Error: 0x%X)",__LINE__,ill_wmi_res);	
			}
			else
			{
				ill_wmi_res = m_get_ull_wmi_value(adsl_obj_own_process,L"KernelModeTime",&uhl_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.uhl_proc_kernel_time = uhl_var_value;
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_Process.KernelModeTime. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}
				ill_wmi_res = m_get_ull_wmi_value(adsl_obj_own_process,L"UserModeTime",&uhl_var_value);
				if (SUCCEEDED(ill_wmi_res))
				{
					dsg_values.uhl_proc_user_time = uhl_var_value;
				}
				else
				{
					m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_Process.UserModeTime. (Error: 0x%X)", __LINE__,ill_wmi_res);
				}
			}

			/* ------------------ 9. Win32_PerfRawData_Tcpip_NetworkInterface --------------------- */
			IEnumWbemClassObject* adsl_enum1 = NULL;
			ill_wmi_res = adsl_service->ExecQuery(L"WQL",L"SELECT * FROM Win32_PerfRawData_Tcpip_NetworkInterface", WBEM_FLAG_FORWARD_ONLY, NULL, &adsl_enum1);
			if (FAILED(ill_wmi_res))
			{
				m_hl1_printf("xs-lbal-win-%05d-E could not query network interfaces. (Error: 0x%X)",__LINE__,ill_wmi_res);	
				bog_wmi_net = false;
			}
			else
			{
				ULONG ul_ret = 0;
				ull uhl_tot = 0;
				ull uhl_recv = 0;
				ull uhl_sent = 0;
				while(adsl_enum1)
				{
					CComPtr<IWbemClassObject> adsl_obj_nic;
					ill_wmi_res = adsl_enum1->Next(WBEM_INFINITE, 1, &adsl_obj_nic, &ul_ret);
					if (ul_ret == 0 || adsl_obj_nic == NULL)
					{
						break;
					}

					ill_wmi_res = m_get_ull_wmi_value(adsl_obj_nic, L"BytesTotalPerSec", &uhl_var_value);
					if (SUCCEEDED(ill_wmi_res))
					{
						uhl_tot += uhl_var_value;
					}
					else
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_Tcpip_NetworkInterface.BytesTotalPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
					}

					if (dwg_win_major_version >= 6)
					{
						ill_wmi_res = m_get_ull_wmi_value(adsl_obj_nic, L"BytesReceivedPerSec", &uhl_var_value);
					}
					else
					{
						ill_wmi_res = m_get_long_wmi_value(adsl_obj_nic, L"BytesReceivedPerSec", &ill_var_value);
					}
					if (SUCCEEDED(ill_wmi_res))
					{
						if (dwg_win_major_version >= 6)
						{
							uhl_recv += uhl_var_value;
						}
						else
						{
							uhl_recv += ill_var_value;
						}
					}
					else
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_Tcpip_NetworkInterface.BytesReceivedPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
					}

					if (dwg_win_major_version >= 6)
					{
						ill_wmi_res = m_get_ull_wmi_value(adsl_obj_nic, L"BytesSentPerSec", &uhl_var_value);
					}
					else
					{
						ill_wmi_res = m_get_long_wmi_value(adsl_obj_nic, L"BytesSentPerSec", &ill_var_value);
					}
					if (SUCCEEDED(ill_wmi_res))
					{
						if (dwg_win_major_version >= 6)
						{
							uhl_sent += uhl_var_value;
						}
						else
						{
							uhl_sent += ill_var_value;
						}
					}
					else
					{
						m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_PerfRawData_Tcpip_NetworkInterface.BytesSentPerSec. (Error: 0x%X)", __LINE__,ill_wmi_res);
					}
				}
				dsg_values.dsl_net_recv_ps.m_add_element(uhl_recv);
				dsg_values.dsl_net_sent_ps.m_add_element(uhl_sent);
				dsg_values.dsl_net_total_ps.m_add_element(uhl_tot);

				bog_wmi_net = true;
				adsl_enum1->Release();
			}
			

			/* ------------------- 10. Win32_LogicalDisk --------------------  */
			IEnumWbemClassObject* adsl_enum2 = NULL;
			ill_wmi_res = adsl_service->ExecQuery(L"WQL",L"SELECT * FROM Win32_PerfRawData_PerfDisk_LogicalDisk", WBEM_FLAG_FORWARD_ONLY, NULL, &adsl_enum2);
			if (FAILED(ill_wmi_res))
			{
				m_hl1_printf("xs-lbal-win-%05d-E could not query logical disks. (Error: 0x%X)",__LINE__,ill_wmi_res);	
				bog_wmi_ldperf = false;
			}
			else
			{
				ULONG ul_ret = 0;
				ull uhl_free = 0;
				LONG ill_drivetype = 0;
				while (adsl_enum2)
				{
					CComPtr<IWbemClassObject> adsl_obj_disk;
					ill_wmi_res = adsl_enum2->Next(WBEM_INFINITE, 1, &adsl_obj_disk, &ul_ret);
					if (ul_ret == 0 || adsl_obj_disk == 0)
					{
						break;
					}
					wchar_t chrl_buf[512];
					ZeroMemory(chrl_buf, 512);
					ill_wmi_res = m_get_bstr_wmi_value(adsl_obj_disk, L"Name", chrl_buf, 512);
					
					if (wcslen(chrl_buf) == 2 /*strcmp("_Total", chrl_buf)*/)
					{
						CComPtr<IWbemClassObject> adsl_disk = NULL;
						OLECHAR chrl_dev[512];
						ZeroMemory(chrl_dev, 512);
						swprintf(chrl_dev, L"Win32_LogicalDisk.DeviceID=\"%s\"", chrl_buf);
						
						BSTR strl_bstr_dev = ::SysAllocString(chrl_dev);

						ill_wmi_res = adsl_service->GetObject(strl_bstr_dev, WBEM_FLAG_RETURN_WBEM_COMPLETE, NULL, &adsl_disk, NULL);
						::SysFreeString(strl_bstr_dev);
						if (FAILED(ill_wmi_res))
						{
							m_hl1_printf("xs-lbal-win-%05d-E Win32_LogicalDisk could not be found (Device %s). (Error: 0x%X)", __LINE__, chrl_buf,ill_wmi_res);
							bog_wmi_ld = false;
						}
						else
						{
							ill_wmi_res = m_get_long_wmi_value(adsl_disk, L"DriveType", &ill_drivetype);
							if (SUCCEEDED(ill_wmi_res))
							{
								if (ill_drivetype == 3)
								{
									ill_wmi_res = m_get_ull_wmi_value(adsl_disk, L"FreeSpace", &uhl_var_value);
									if (SUCCEEDED(ill_wmi_res))
									{
										uhl_free += uhl_var_value;
									}
									else
									{
										m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_LogicalDisk.FreeSpace. (Error: 0x%X)", __LINE__,ill_wmi_res);
									}
								}
								bog_wmi_ld = true;
							}
							else
							{
								m_hl1_printf("xs-lbal-win-%05d-E could not get property Win32_LogicalDisk.Drivetype (Device %s). (Error: 0x%X)", __LINE__, chrl_buf,ill_wmi_res);
							}
						}
					}
				}
				dsg_values.dsl_ld_free_space.m_add_element(uhl_free);
				bog_wmi_ldperf = true;
				adsl_enum2->Release();
			}
			
		}
end_of_collect:
		
#endif /* HL_WINALL1 */
		// update references after 15 * UPDATE_INTERVAL
		iml_counter++;
		iml_total_counter++;
		if (iml_counter == 15)
		{
			iml_counter = 0;
#ifdef HL_WINALL1			
			m_update_references(adsl_service);	
#endif			
#ifdef HL_LINUX			
			m_update_references();	
#endif	
#ifdef HL_FREEBSD
			m_update_references();
#endif
		}

		// unlock mutex
#ifdef HL_LINUX		
		pthread_mutex_unlock(&dsg_monitor_thread_mutex);
		if (bog_collect)
		{
			sleep(UPDATE_INTERVAL);
		}
#endif
#ifdef HL_FREEBSD
		pthread_mutex_unlock(&dsg_monitor_thread_mutex);
		if (bog_collect)
		{
			sleep(UPDATE_INTERVAL);
		}
#endif
#ifdef HL_WINALL1
		ReleaseMutex(a_mut);
		CloseHandle(a_mut);
		if (bog_collect)
		{
			//Sleep(10);
			// TODO :ändern
			Sleep(1000 * UPDATE_INTERVAL);
		}
#endif
		// write to logfile
		iml_log_counter++;
		if (iml_log_counter == img_lbdata_log_int)
		{
			iml_log_counter = 0;
			if (bog_lbdata_log)
			{
				m_write_logfile(m_get_load());
			}	
		}
	
	}
#ifdef HL_WINALL1
	adsl_service->Release();
	adsl_loc->Release();
	adsl_service = NULL;
	adsl_loc = NULL;
	CoUninitialize();
#endif	

#ifdef HL_LINUX
	pthread_exit(NULL);	
#endif
#ifdef HL_FREEBSD
	pthread_exit(NULL);	
#endif
	return 0;
}
	
	/* start the data collector thread
	 * Input:
	 * adsp_contr:		structure that contains function pointers to a function in the main program that returns the number of sessions
	 * 					and to a function for xml navigation. It also contains the load-balancing supernode.*/
extern "C" bool m_start_monitor_thread_old(
#ifdef HL_LINUX
							struct dsd_qload1_contr_1* adsp_contr
#endif
#ifdef HL_WINALL1
							char*	achp_formula,
							int     (*amp_sess)(),
							bool	bop_logging,
							char*	achp_logfile,
							int		imp_log_interval
#endif
#ifdef HL_FREEBSD
							char*	achp_formula
#endif
							)

{
	int iml_err = 0;
	bog_mont_running = true;
	bog_collect = true;
	char* achl_file = "";
#ifdef HL_WINALL1
	achl_file = achp_logfile;
	am_get_sessions = amp_sess;
	if (dsg_formula)
	{
		if (strlen(achp_formula) > 0)
		{
			m_set_lb_formula(achp_formula, strlen(achp_formula));
		}
		
	}
	else
	{
		if (strlen(achp_formula) > 0)
		{
			dsg_formula = new c_lb_formula(achp_formula);
		}
		else
		{
			dsg_formula = new c_lb_formula("CPU_1");
		}
	}
	if (imp_log_interval < 10)
	{
		img_lbdata_log_int = 1;
	}
	img_lbdata_log_int = floor((float)imp_log_interval / 10);
	bog_lbdata_log = bop_logging;
	// get windows version
	OSVERSIONINFO dsl_version_info;
	ZeroMemory(&dsl_version_info, sizeof(OSVERSIONINFO));
	dsl_version_info.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
	bool bol1 = GetVersionEx(&dsl_version_info);
	if (bol1)
	{
		dwg_win_major_version = dsl_version_info.dwMajorVersion;
	}
	else
	{
		// default is server 2003
		dwg_win_major_version = 5;
	}
#endif

#ifdef HL_FREEBSD
		img_lbdata_log_int = 6;
		bog_lbdata_log = false;
		strg_log_file = "";
		if (dsg_formula)
		{
			if (strlen(achp_formula) > 0)
			{
				m_set_lb_formula(achp_formula, strlen(achp_formula));
			}
			
		}
		else
		{
			if (strlen(achp_formula) > 0)
			{
				dsg_formula = new c_lb_formula(achp_formula);
			}
			else
			{
				dsg_formula = new c_lb_formula("CPU_1");
			}
		}
		
#endif

#ifdef HL_LINUX

	uhg_cps =sysconf(_SC_CLK_TCK);
     
	if (!adsp_contr)
	{	
	
		strg_lb_formula = "CPU_1";
		img_lbdata_log_int = 6;
		bog_lbdata_log = false;
		strg_log_file = "";
		dsg_formula = new c_lb_formula(strg_lb_formula);
	}
	else
	{
	  
#ifdef HOBXERCES			  
		// parse XML file
		// XML Tags
		XMLCh* adsl_tag_formula = XMLString::transcode("formula");
		XMLCh* adsl_tag_logging = XMLString::transcode("logging");
		XMLCh* adsl_tag_logfile = XMLString::transcode("logfile");
		XMLCh* adsl_tag_interval = XMLString::transcode("log-interval");
		
		// parse passed xml node
		DOMNode* adsl_node_main;
		DOMNode* adsl_node_elem;
		DOMNode* adsl_node_text;
		
		// initialized variables
		bool bol_formula_found = false;
		
		// get main node
		adsl_node_main = adsp_contr->adsc_node_conf;
		
		int iml_it = 0;
		//loop
		while (true)
		{
			char* achl_value;	
			string str_trimmed_value;
			if (!adsl_node_main)
			{
				if (adsp_contr->amc_display)
				{
					adsp_contr->amc_display("xs-lbal-win l%05d m_start_monitor_thread_old() no passed XML node.", __LINE__);
				}
				break;	
			}
			if (iml_it == 0)
			{
				
				adsl_node_elem = (DOMNode*) adsp_contr->amc_call_dom(adsl_node_main, ied_hlcldom_get_first_child);
				
			}
			else
			{
				adsl_node_elem = (DOMNode*) adsp_contr->amc_call_dom(adsl_node_elem, ied_hlcldom_get_next_sibling);
			}
			
			
			if (adsl_node_elem == NULL)
			{
				break;
			}
			iml_it++;
			// get the node name and type
			if (((int)adsp_contr->amc_call_dom(adsl_node_elem, ied_hlcldom_get_node_type)) != DOMNode::ELEMENT_NODE)
			{
				// invalid configuration
				//adsp_contr->amc_display("xs-lbal-win l%05d m_start_monitor_thread_old() invalid configuration. Subnode of <load-balancing> is not an element node",__LINE__);
				continue;	
			}
			XMLCh* adsl_nodename = (XMLCh*) adsp_contr->amc_call_dom(adsl_node_elem, ied_hlcldom_get_node_name);
			// get child node
			adsl_node_text = (DOMNode*) adsp_contr->amc_call_dom(adsl_node_elem, ied_hlcldom_get_first_child);
			if (adsl_node_text)
			{
				if (((int)adsp_contr->amc_call_dom(adsl_node_text, ied_hlcldom_get_node_type)) != DOMNode::TEXT_NODE)
				{
					adsp_contr->amc_display("xs-lbal-win l%05d m_start_monitor_thread_old() invalid node type.",__LINE__);	
				
				}
				else	// get node value
				{
					XMLCh* adsl_value = (XMLCh*) adsp_contr->amc_call_dom(adsl_node_text, ied_hlcldom_get_node_value);
					if (adsl_value)
					{
						achl_value = XMLString::transcode(adsl_value);
						str_trimmed_value = m_trim_char(achl_value);
					}
					
				}
			}
			else
			{
				adsp_contr->amc_display("xs-lbal-win l%05d m_start_monitor_thread_old() element node has no text subnode.", __LINE__);	
			}
			if(XMLString::equals(adsl_nodename, adsl_tag_formula))
			{
				if (achl_value)
				{
					dsg_formula = new c_lb_formula(str_trimmed_value);			
				}
				else
				{
					adsp_contr->amc_display("xs-lbal-win l%05d m_start_monitor_thread_old() no formula found. Using default formula.", __LINE__);
					dsg_formula = new c_lb_formula("CPU_1");	
				}
				bol_formula_found = true;
			}
			else if (XMLString::equals(adsl_nodename, adsl_tag_logging))
			{
				if (achl_value)
				{
					if (strcmp(str_trimmed_value.c_str(),"yes")==0)
					{
						bog_lbdata_log = true;
					}
					else
					{
						bog_lbdata_log = false;
					}
				}
			}
			else if (XMLString::equals(adsl_nodename, adsl_tag_logfile))
			{
				if (achl_value)
				{
					achl_file = const_cast<char*> (str_trimmed_value.c_str());
				}
				else
				{	
					adsp_contr->amc_display("xs-lbal-win l%05d m_start_monitor_thread_old() no logfile configuration found. Using default logfile", __LINE__);	
				}
				
			}
			else if (XMLString::equals(adsl_nodename, adsl_tag_interval))
			{
				if (achl_value)
				{
					long ill1 = strtol(str_trimmed_value.c_str(), NULL, 10);
					if (ill1 < 10)
					{
						img_lbdata_log_int = 1;
					}
					else
					{
						int iml1 = (int)ill1;
						img_lbdata_log_int = floor(iml1 / 10);
					}				
				}
				else
				{
					adsp_contr->amc_display("xs-lbal-win l%05d m_start_monitor_thread_old() no log interval found. Using default.", __LINE__);	
				}
				
			}
			else
			{
				// invalid configuration
				adsp_contr->amc_display("xs-lbal-win l%05d m_start_monitor_thread_old() invalid configuration. Unknown subnode of <load-balancing> ",__LINE__);
				continue;
			}
		}
		am_get_sessions = adsp_contr->amc_get_no_user;
		if (!bol_formula_found)
		{
			dsg_formula = new c_lb_formula("CPU_1");
		}
#endif		
	}
#endif
	
	// create the default logfile name
	if (strcmp("",achl_file) == 0 && bog_lbdata_log)
	{
		time_t dsl_time;
		tm* adsl_now;
		dsl_time = time(0);
		adsl_now = localtime(&dsl_time);
		char chr_buff[8];
		string strl_fn;
#ifdef HL_LINUX		
		strl_fn = "lb_";
#endif
#ifdef HL_WINALL1
		strl_fn = "lb_";
#endif
#ifdef HPUX
		strl_fn = "lb_";
#endif
		sprintf(chr_buff,"%d",adsl_now->tm_year+1900);
		strl_fn.append(chr_buff);
		strl_fn.append("-");
		sprintf(chr_buff,"%d",adsl_now->tm_mon+1);
		if (adsl_now->tm_mon+1 < 10)
		{
			strl_fn.append("0");
		}
		strl_fn.append(chr_buff);
		strl_fn.append("-");
		sprintf(chr_buff,"%d",adsl_now->tm_mday);
		if (adsl_now->tm_mday < 10)
		{
			strl_fn.append("0");
		}
		strl_fn.append(chr_buff);
		
		strl_fn.append("_");
		sprintf(chr_buff,"%d",adsl_now->tm_hour);
		if (adsl_now->tm_hour < 10)
		{
			strl_fn.append("0");
		}
		strl_fn.append(chr_buff);
		//strl_fn.append(":");
		sprintf(chr_buff,"%d",adsl_now->tm_min);
		if (adsl_now->tm_min < 10)
		{
			strl_fn.append("0");
			strl_fn.append(chr_buff);	
		}
		else	strl_fn.append(chr_buff);
		//strl_fn.append(":");
		sprintf(chr_buff,"%d",adsl_now->tm_sec);
		if (adsl_now->tm_sec < 10)
		{
			strl_fn.append("0");
			strl_fn.append(chr_buff);
		}
		else	strl_fn.append(chr_buff);
		strl_fn.append(".csv");
		strg_log_file.assign(strl_fn);
	}
	else
	{
		strg_log_file.assign(achl_file);
	}
	
	//initialize mutex
#ifdef HL_LINUX
	pthread_mutex_init(&dsg_monitor_thread_mutex,NULL);
#endif
#ifdef HL_WINALL1
	a_mon_mutex = CreateMutexW(NULL, FALSE, L"MONMUTEX");
#endif
	// start the thread
#ifdef HL_LINUX
	
	iml_err = pthread_create(&dsg_monitor_thread, NULL ,m_collect_data, NULL);
#endif
#ifdef HL_FREEBSD
	
	iml_err = pthread_create(&dsg_monitor_thread, NULL ,m_collect_data, NULL);
#endif
#ifdef HL_WINALL1
	//PTHREAD_START_ROUTINE
	a_mon_thread = CreateThread(NULL, 0, m_mon_thread_help, NULL, 0, NULL);
	if (a_mon_thread)
	{
		iml_err = 0;
	}
	else iml_err = 1;
#endif
	return (iml_err == 0);
}
	
// stop the data collector thread
extern "C" int m_stop_monitor_thread()
{
	int iml_err = 0;
	bog_mont_running = false;
	bog_collect = false;
	// cancel thread
#ifdef HL_LINUX
	iml_err = pthread_cancel(dsg_monitor_thread);
	// destroy mutex
	pthread_mutex_destroy(&dsg_monitor_thread_mutex);
#endif
#ifdef HL_WINALL1
	Sleep(500);
#endif
	return iml_err;
}

extern "C" bool m_start_monitor_thread()
{
	return m_start_monitor_thread_old();
}

// get the performance values of the current process
int m_get_perf_data( struct dsd_perf_data* dsp_perf )
{
	// the thread is not running --> return load 0
	if (!bog_mont_running)
	{
		return 1;
	}

#ifdef HL_WINALL1
	HANDLE a_mut = OpenMutexW(SYNCHRONIZE, FALSE, L"MONMUTEX");
#endif
#ifdef HL_FREEBSD
	
	dsp_perf->ulc_memory				= dsg_values.dsl_proc_memory.m_get_latest_element() * 4096;
	dsp_perf->uhl_proc_threads_cur		= dsg_values.dsl_proc_threads.m_get_latest_element();	
	dsp_perf->uhl_proc_page_faults_tot	= dsg_values.dsl_proc_page_faults.m_get_latest_element();
	dsp_perf->uhl_proc_io_read_tot		= dsg_values.dsl_proc_io_reads.m_get_latest_element();
	dsp_perf->uhl_proc_io_write_tot		= dsg_values.dsl_proc_io_writes.m_get_latest_element();	
	dsp_perf->ulc_io_total_ops			= dsp_perf->uhl_proc_io_read_tot + dsp_perf->uhl_proc_io_write_tot;
	dsp_perf->uhl_proc_user_time		= dsg_values.dsl_proc_user_time.m_get_latest_element();	;
	dsp_perf->uhl_proc_system_time		= dsg_values.dsl_proc_system_time.m_get_latest_element();	
	dsp_perf->ulc_cpu_total_time		= dsp_perf->uhl_proc_user_time + dsp_perf->uhl_proc_system_time;
	dsp_perf->uhl_proc_ctx_invol		= dsg_values.dsl_proc_ctx_involuntary.m_get_latest_element();	
	dsp_perf->uhl_proc_ctx_vol			= dsg_values.dsl_proc_ctx_voluntary.m_get_latest_element();	;
	dsp_perf->ulc_io_total_bytes = 0;
#endif
#ifdef HL_WINALL1
	dsp_perf->ulc_cpu_kernel_time	= dsg_values.uhl_proc_kernel_time / 10000;
	dsp_perf->ulc_cpu_user_time		= dsg_values.uhl_proc_user_time / 10000;
	dsp_perf->ulc_cpu_total_time	= dsp_perf->ulc_cpu_kernel_time + dsp_perf->ulc_cpu_user_time;
	dsp_perf->ulc_memory		= dsg_values.dsl_proc_working_set.m_get_latest_element() * 4096;
	dsp_perf->ulc_io_read_bytes	= dsg_values.dsl_proc_io_read_bytes.m_get_latest_element();
	dsp_perf->ulc_io_written_bytes	= dsg_values.dsl_proc_io_write_bytes.m_get_latest_element();
	dsp_perf->ulc_io_total_bytes	= dsp_perf->ulc_io_read_bytes + dsp_perf->ulc_io_written_bytes;
	dsp_perf->ulc_io_read_ops		= dsg_values.dsl_proc_io_read_ops.m_get_latest_element();
	dsp_perf->ulc_io_write_ops		= dsg_values.dsl_proc_io_write_ops.m_get_latest_element();
	dsp_perf->ulc_io_total_ops		= dsp_perf->ulc_io_read_ops + dsp_perf->ulc_io_write_ops;
	dsp_perf->uml_mem_util		= (unsigned int) ( (10000 * dsg_values.dsl_proc_working_set.m_get_latest_element()) / dsg_ref.uhl_memory);
#endif
#ifdef HL_LINUX
	dsp_perf->uml_cpu_util =   ((unsigned int) dsg_values.dsl_total_jiffies.m_get_diff_per_sec(0,7) == 0) ? 10000 : ( 1000 * dsg_values.dsl_proc_jiffies.m_get_latest_element()) / dsg_values.dsl_total_jiffies.m_get_diff_per_sec(0,7);
	dsp_perf->ulc_memory = dsg_values.uhl_proc_virtual_memory;
	dsp_perf->ulc_io_total_ops = dsg_values.uhl_proc_io_reads + dsg_values.uhl_proc_io_writes;
	dsp_perf->ulc_io_total_bytes = dsg_values.uhl_proc_io_read_bytes + dsg_values.uhl_proc_io_written_bytes;
	if (uhg_cps == 0)
	{
	  dsp_perf->ulc_cpu_total_time = 0;
	}
	else
	{
	  dsp_perf->ulc_cpu_total_time = (1000 * (dsg_values.uhl_proc_ticks_user + dsg_values.uhl_proc_ticks_kernel)) / uhg_cps;
	}


#endif
	
#ifdef HL_WINALL1
	ReleaseMutex(a_mut);
	CloseHandle(a_mut);
#endif
	return 0;
}

inline int m_perf_array_help (char** achp_dest,char* achp_source, int* aimp_ret, int* aimp_tot)
{
	memcpy(*achp_dest, achp_source, *aimp_ret);
	if (*aimp_ret > 0)
	{
		*aimp_tot += *aimp_ret;
		*achp_dest += *aimp_ret;
		return 0;
	}
	else return 1;
}

int m_get_perf_array(char* achp_data, int imp_length)
{
	struct dsd_server_load dsl_perf;
	m_get_system_load(dsl_perf);
	
	int iml_len = 0;
	int iml1 = 0;
	// temporary buffer
	char* achl_buffer = (char*) malloc(4096);
	char* achl_buffer_start = achl_buffer;
	char chrl_nhasn[32];
	// copy values to temporary buffer
	iml1 = m_convert_number_to_nhasn(PERF_TAG_SESSIONS, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	if (am_get_sessions)
	{
		iml1 = m_convert_number_to_nhasn(am_get_sessions(), chrl_nhasn, 32);
	}
	else
	{
		iml1 = m_convert_number_to_nhasn(0, chrl_nhasn, 32);
	}
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;	
// TODO: bessere Lösung
#ifdef HL_FREEBSD
	iml1 = m_convert_number_to_nhasn(PERF_TAG_CPU_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cpu[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CPU_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cpu[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CPU_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cpu[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CPU_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cpu[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CPU_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cpu[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_CTX_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ctx_swtch[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CTX_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ctx_swtch[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CTX_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ctx_swtch[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CTX_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ctx_swtch[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CTX_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ctx_swtch[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_INT_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ints[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_INT_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ints[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_INT_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ints[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_INT_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ints[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_INT_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ints[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_MEMORY_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_memory[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_MEMORY_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_memory[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_MEMORY_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_memory[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_MEMORY_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_memory[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_MEMORY_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_memory[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROCESS_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_processes[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROCESS_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_processes[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROCESS_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_processes[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROCESS_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_processes[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROCESS_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_processes[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_usage[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_usage[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_usage[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_usage[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_usage[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_READ_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_pageins[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_READ_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_pageins[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_READ_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_pageins[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_READ_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_pageins[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_READ_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_pageins[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_TOTAL_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_pagetotal[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_TOTAL_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_pagetotal[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_TOTAL_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_pagetotal[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_TOTAL_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_pagetotal[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_TOTAL_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_pagetotal[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_WRITE_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_pageouts[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_WRITE_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_pageouts[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_WRITE_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_pageouts[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_WRITE_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_pageouts[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_WRITE_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_pageouts[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_READ_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swapins[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_READ_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swapins[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_READ_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swapins[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_READ_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swapins[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_READ_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swapins[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_TOTAL_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swaptotal[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_TOTAL_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swaptotal[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_TOTAL_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swaptotal[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_TOTAL_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swaptotal[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_TOTAL_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swaptotal[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_WRITE_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swapouts[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_WRITE_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swapouts[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_WRITE_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swapouts[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_WRITE_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swapouts[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_WRITE_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swapouts[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_HIT_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_hit_rate[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_HIT_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_hit_rate[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_HIT_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_hit_rate[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_HIT_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_hit_rate[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_HIT_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_hit_rate[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_MISSES_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_misses[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_MISSES_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_misses[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_MISSES_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_misses[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_MISSES_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_misses[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_MISSES_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_misses[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_THREADS_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_threads[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_THREADS_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_threads[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_THREADS_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_threads[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_THREADS_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_threads[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_THREADS_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_threads[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_CPU_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_cpu[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_CPU_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_cpu[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_CPU_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_cpu[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_CPU_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_cpu[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_CPU_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_cpu[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_ELAPSED_TIME, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.ulc_cpu_total_time, chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_THREADS_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_threads[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_THREADS_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_threads[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_THREADS_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_threads[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_THREADS_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_threads[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_THREADS_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_threads[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_THREADS_CURR, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uhl_proc_threads_cur, chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_OP_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_io_read[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_OP_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_io_read[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_OP_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_io_read[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_OP_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_io_read[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_OP_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_io_read[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_OP_TOT, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uhl_proc_io_read_tot, chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;



	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_OP_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_io_write[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_OP_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_io_write[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_OP_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_io_write[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_OP_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_io_write[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_OP_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_io_write[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_OP_TOT, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uhl_proc_io_write_tot, chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_PG_FAULT_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_pg_fault[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_PG_FAULT_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_pg_fault[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_PG_FAULT_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_pg_fault[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_PG_FAULT_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_pg_fault[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_PG_FAULT_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_pg_fault[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_PG_FAULT_TOT, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uhl_proc_page_faults_tot, chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_UTIL_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_memory[0], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_UTIL_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_memory[1], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_UTIL_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_memory[2], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_UTIL_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_memory[3], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_UTIL_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_memory[4], chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_UTIL_CURR, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.ulc_memory, chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_TIME_KERNEL, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uhl_proc_system_time, chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_TIME_USER, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uhl_proc_user_time, chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_TIME_TOTAL, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.ulc_cpu_total_time, chrl_nhasn, 32);
	if(m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

#endif

#ifdef HL_LINUX
	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROCESS_NEW_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_init_process[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;		

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROCESS_NEW_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_init_process[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;	

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROCESS_NEW_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_init_process[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;	

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROCESS_NEW_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_init_process[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;	

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROCESS_NEW_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_init_process[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;	
#endif

#ifndef HL_FREEBSD
	iml1 = m_convert_number_to_nhasn(PERF_TAG_CPU_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cpu[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;	
	
	iml1 = m_convert_number_to_nhasn(PERF_TAG_CPU_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cpu[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;	

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CPU_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cpu[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;	

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CPU_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cpu[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;	

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CPU_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cpu[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;	


	iml1 = m_convert_number_to_nhasn(PERF_TAG_CTX_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ctx[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;	
	
	iml1 = m_convert_number_to_nhasn(PERF_TAG_CTX_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ctx[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;	

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CTX_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ctx[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;	

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CTX_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ctx[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;	

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CTX_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ctx[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;	
	

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HARDDISK_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_usage[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HARDDISK_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_usage[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HARDDISK_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_usage[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HARDDISK_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_usage[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HARDDISK_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_usage[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_READ_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_read[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_READ_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_read[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_READ_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_read[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_READ_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_read[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_READ_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_read[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_WRITE_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_write[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_WRITE_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_write[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_WRITE_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_write[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_WRITE_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_write[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_WRITE_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_write[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_INT_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ints[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_INT_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ints[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_INT_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ints[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_INT_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ints[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_INT_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_ints[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_IO_ACT_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_io_act[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_IO_ACT_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_io_act[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_IO_ACT_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_io_act[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_IO_ACT_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_io_act[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_IO_ACT_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_io_act[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_IO_TIME_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_io_time[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_IO_TIME_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_io_time[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_IO_TIME_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_io_time[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_IO_TIME_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_io_time[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_IO_TIME_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_io_time[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_MEMORY_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_memory[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_MEMORY_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_memory[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_MEMORY_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_memory[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_MEMORY_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_memory[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_MEMORY_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_memory[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_NIC_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_nic_total[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NIC_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_nic_total[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NIC_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_nic_total[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NIC_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_nic_total[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NIC_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_nic_total[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_NIC_READ_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_nic_recv[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NIC_READ_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_nic_recv[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NIC_READ_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_nic_recv[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NIC_READ_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_nic_recv[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NIC_READ_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_nic_recv[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_NIC_WRITE_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_nic_send[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NIC_WRITE_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_nic_send[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NIC_WRITE_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_nic_send[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NIC_WRITE_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_nic_send[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NIC_WRITE_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_nic_send[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROCESS_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_process[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROCESS_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_process[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROCESS_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_process[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROCESS_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_process[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROCESS_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_process[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_util[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_util[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_util[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_util[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_util[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_READ_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_read[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_READ_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_read[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_READ_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_read[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_READ_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_read[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_READ_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_read[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_TOTAL_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_total[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_TOTAL_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_total[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_TOTAL_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_total[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_TOTAL_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_total[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_TOTAL_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_total[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_WRITE_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_write[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_WRITE_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_write[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_WRITE_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_write[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_WRITE_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_write[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PAGE_WRITE_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_write[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
#endif

#ifdef HL_WINALL1
	iml1 = m_convert_number_to_nhasn(PERF_TAG_PG_FAULT_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_fault[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PG_FAULT_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_fault[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PG_FAULT_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_fault[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PG_FAULT_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_fault[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PG_FAULT_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_fault[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
#endif

#ifdef HL_LINUX
	iml1 = m_convert_number_to_nhasn(PERF_TAG_PG_FAULT_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_min_pg_fault[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PG_FAULT_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_min_pg_fault[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PG_FAULT_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_min_pg_fault[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PG_FAULT_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_min_pg_fault[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PG_FAULT_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_min_pg_fault[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PG_MAJ_FAULT_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_maj_pg_fault[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PG_MAJ_FAULT_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_maj_pg_fault[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PG_MAJ_FAULT_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_maj_pg_fault[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PG_MAJ_FAULT_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_maj_pg_fault[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PG_MAJ_FAULT_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_maj_pg_fault[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_READ_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_read[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_READ_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_read[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_READ_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_read[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_READ_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_read[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_READ_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_read[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_TOTAL_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_act[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_TOTAL_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_act[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_TOTAL_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_act[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_TOTAL_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_act[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_TOTAL_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_act[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_WRITE_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_write[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_WRITE_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_write[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_WRITE_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_write[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_WRITE_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_write[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAP_WRITE_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_swap_write[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
#endif

#ifdef HL_WINALL1
	iml1 = m_convert_number_to_nhasn(PERF_TAG_NET_SENT_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_net_sent[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NET_SENT_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_net_sent[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NET_SENT_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_net_sent[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NET_SENT_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_net_sent[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NET_SENT_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_net_sent[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_NET_RECV_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_net_recv[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NET_RECV_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_net_recv[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NET_RECV_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_net_recv[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NET_RECV_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_net_recv[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NET_RECV_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_net_recv[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_NET_TOTAL_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_net_total[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NET_TOTAL_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_net_total[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NET_TOTAL_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_net_total[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NET_TOTAL_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_net_total[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_NET_TOTAL_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_net_total[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_HIT_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_hit[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_HIT_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_hit[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_HIT_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_hit[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_HIT_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_hit[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_HIT_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_hit[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_MISSES_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_miss[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_MISSES_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_miss[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_MISSES_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_miss[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_MISSES_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_miss[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_CACHE_MISSES_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_cache_miss[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_BPR_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_bpr[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_BPR_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_bpr[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_BPR_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_bpr[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_BPR_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_bpr[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_BPR_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_bpr[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_BPT_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_bpt[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_BPT_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_bpt[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_BPT_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_bpt[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_BPT_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_bpt[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_BPT_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_bpt[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_BPW_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_bpw[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_BPW_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_bpw[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_BPW_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_bpw[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_BPW_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_bpw[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_HD_BPW_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_hd_bpw[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAPFILE_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_file[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAPFILE_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_file[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAPFILE_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_file[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAPFILE_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_file[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_SWAPFILE_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_page_file[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_THREADS_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_threads[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_THREADS_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_threads[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_THREADS_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_threads[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_THREADS_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_threads[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_THREADS_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_threads[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	
	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_CPU_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_cpu[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	
	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_CPU_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_cpu[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	
	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_CPU_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_cpu[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	
	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_CPU_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_cpu[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	
	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_CPU_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_cpu[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_THREADS_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_threads[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_THREADS_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_threads[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_THREADS_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_threads[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_THREADS_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_threads[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_THREADS_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_threads[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_THREADS_CURR, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uml_proc_curr_threads, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_HANDLES_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_handles[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_HANDLES_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_handles[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_HANDLES_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_handles[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_HANDLES_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_handles[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_HANDLES_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_handles[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_HANDLES_CURR, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uml_proc_curr_handles, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_VM_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_virt_bytes[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_VM_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_virt_bytes[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_VM_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_virt_bytes[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_VM_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_virt_bytes[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_VM_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_virt_bytes[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_VM_CURR, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uhl_proc_virt_bytes, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_OP_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_read_ops[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_OP_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_read_ops[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_OP_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_read_ops[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_OP_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_read_ops[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_OP_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_read_ops[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_OP_TOT, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uhl_proc_read_operations, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_OP_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_write_ops[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_OP_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_write_ops[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_OP_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_write_ops[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_OP_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_write_ops[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_OP_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_write_ops[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_OP_TOT, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uhl_proc_write_operations, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_BYTES_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_read_bytes[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_BYTES_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_read_bytes[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_BYTES_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_read_bytes[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_BYTES_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_read_bytes[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_BYTES_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_read_bytes[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_READ_BYTES_TOT, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uhl_proc_read_bytes, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_BYTES_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_write_bytes[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_BYTES_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_write_bytes[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_BYTES_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_write_bytes[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_BYTES_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_write_bytes[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_BYTES_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_write_bytes[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_WRITE_BYTES_TOT, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uhl_proc_write_bytes, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_TOTAL_BYTES_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_total_bytes[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_TOTAL_BYTES_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_total_bytes[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_TOTAL_BYTES_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_total_bytes[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_TOTAL_BYTES_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_total_bytes[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_TOTAL_BYTES_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_total_bytes[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_TOTAL_BYTES_TOT, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uhl_proc_total_bytes, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_PG_FAULT_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_pg_fault[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_PG_FAULT_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_pg_fault[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_PG_FAULT_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_pg_fault[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_PG_FAULT_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_pg_fault[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_PG_FAULT_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_pg_fault[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_PG_FAULT_TOT, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uml_proc_pg_faults, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_ABS_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_mem_abs[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_ABS_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_mem_abs[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_ABS_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_mem_abs[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_ABS_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_mem_abs[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_ABS_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_mem_abs[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_ABS_CURR, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uml_proc_curr_mem, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;


	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_UTIL_1, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_mem_util[0], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_UTIL_5, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_mem_util[1], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_UTIL_10, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_mem_util[2], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_UTIL_15, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_mem_util[3], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_UTIL_30, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.umrl_proc_mem_util[4], chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_MEM_UTIL_CURR, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uml_proc_curr_mem_util, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1)	goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_TIME_KERNEL, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uhl_proc_time_kernel, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_TIME_USER, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uhl_proc_time_user, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;

	iml1 = m_convert_number_to_nhasn(PERF_TAG_PROC_TIME_TOTAL, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
	iml1 = m_convert_number_to_nhasn(dsl_perf.uhl_proc_time_user + dsl_perf.uhl_proc_time_kernel, chrl_nhasn, 32);
	if (m_perf_array_help(&achl_buffer, chrl_nhasn, &iml1, &iml_len) == 1) goto perror1;
#endif
	if (iml_len <= imp_length)
	{
		memcpy (achp_data, achl_buffer_start, iml_len);
		free (achl_buffer_start);
		return iml_len;
	}
	else 
	{
		free(achl_buffer_start);
		return imp_length - iml_len;
	}

perror1:
	free (achl_buffer_start);

	return -1;
}

//#ifdef DEBUG
void m_print_load(struct dsd_server_load& load)
{
	cout << endl << "current load: " << endl;
	cout << "---------------------------------------------------------------------------------" << endl;
	printf("%-24s  %8s%8s%8s%8s%8s %8s\n","Parameter","1","5","10","15","30","Minuten");
	printf("---------------------------------------------------------------------------------\n");
#ifdef HL_FREEBSD
	printf("%-24s  %8d%8d%8d%8d%8d\n","CPU",load.umrl_cpu[0],load.umrl_cpu[1],load.umrl_cpu[2],load.umrl_cpu[3],load.umrl_cpu[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Memory",load.umrl_memory[0],load.umrl_memory[1],load.umrl_memory[2],load.umrl_memory[3],load.umrl_memory[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Interrupts",load.umrl_ints[0],load.umrl_ints[1],load.umrl_ints[2],load.umrl_ints[3],load.umrl_ints[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Context Switches",load.umrl_ctx_swtch[0],load.umrl_ctx_swtch[1],load.umrl_ctx_swtch[2],load.umrl_ctx_swtch[3],load.umrl_ctx_swtch[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Cache Hit Rate",load.umrl_cache_hit_rate[0],load.umrl_cache_hit_rate[1],load.umrl_cache_hit_rate[2],load.umrl_cache_hit_rate[3],load.umrl_cache_hit_rate[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Cache Misses",load.umrl_cache_misses[0],load.umrl_cache_misses[1],load.umrl_cache_misses[2],load.umrl_cache_misses[3],load.umrl_cache_misses[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Pageins",load.umrl_pageins[0],load.umrl_pageins[1],load.umrl_pageins[2],load.umrl_pageins[3],load.umrl_pageins[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Pageouts",load.umrl_pageouts[0],load.umrl_pageouts[1],load.umrl_pageouts[2],load.umrl_pageouts[3],load.umrl_pageouts[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Total Pages",load.umrl_pagetotal[0],load.umrl_pagetotal[1],load.umrl_pagetotal[2],load.umrl_pagetotal[3],load.umrl_pagetotal[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Swapins",load.umrl_swapins[0],load.umrl_swapins[1],load.umrl_swapins[2],load.umrl_swapins[3],load.umrl_swapins[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Swapouts",load.umrl_swapouts[0],load.umrl_swapouts[1],load.umrl_swapouts[2],load.umrl_swapouts[3],load.umrl_swapouts[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Total Swapping",load.umrl_swaptotal[0],load.umrl_swaptotal[1],load.umrl_swaptotal[2],load.umrl_swaptotal[3],load.umrl_swaptotal[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Swap Usage",load.umrl_swap_usage[0],load.umrl_swap_usage[1],load.umrl_swap_usage[2],load.umrl_swap_usage[3],load.umrl_swap_usage[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Threads",load.umrl_threads[0],load.umrl_threads[1],load.umrl_threads[2],load.umrl_threads[3],load.umrl_threads[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Processes",load.umrl_processes[0],load.umrl_processes[1],load.umrl_processes[2],load.umrl_processes[3],load.umrl_processes[4]);
	printf("\n");
	printf("%-24s  %8d%8d%8d%8d%8d\n","Proc memory ",load.umrl_proc_memory[0],load.umrl_proc_memory[1],load.umrl_proc_memory[2],load.umrl_proc_memory[3],load.umrl_proc_memory[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Proc page faults",load.umrl_proc_pg_fault[0],load.umrl_proc_pg_fault[1],load.umrl_proc_pg_fault[2],load.umrl_proc_pg_fault[3],load.umrl_proc_pg_fault[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Proc io reads",load.umrl_proc_io_read[0],load.umrl_proc_io_read[1],load.umrl_proc_io_read[2],load.umrl_proc_io_read[3],load.umrl_proc_io_read[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Proc io writes",load.umrl_proc_io_write[0],load.umrl_proc_io_write[1],load.umrl_proc_io_write[2],load.umrl_proc_io_write[3],load.umrl_proc_io_write[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Proc threads",load.umrl_proc_threads[0],load.umrl_proc_threads[1],load.umrl_proc_threads[2],load.umrl_proc_threads[3],load.umrl_proc_threads[4]);
	//printf("%-24s  %8d%8d%8d%8d%8d\n","Proc user time",load.umrl_proc_utime[0],load.umrl_proc_utime[1],load.umrl_proc_utime[2],load.umrl_proc_utime[3],load.umrl_proc_utime[4]);
	//printf("%-24s  %8d%8d%8d%8d%8d\n","Proc system time",load.umrl_proc_stime[0],load.umrl_proc_stime[1],load.umrl_proc_stime[2],load.umrl_proc_stime[3],load.umrl_proc_stime[4]);
	//printf("%-24s  %8d%8d%8d%8d%8d\n","Proc total time",load.umrl_proc_totaltime[0],load.umrl_proc_totaltime[1],load.umrl_proc_totaltime[2],load.umrl_proc_totaltime[3],load.umrl_proc_totaltime[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Proc CPU",load.umrl_proc_cpu[0],load.umrl_proc_cpu[1],load.umrl_proc_cpu[2],load.umrl_proc_cpu[3],load.umrl_proc_cpu[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Proc CTX vol",load.umrl_proc_ctx_vol[0],load.umrl_proc_ctx_vol[1],load.umrl_proc_ctx_vol[2],load.umrl_proc_ctx_vol[3],load.umrl_proc_ctx_vol[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Proc CTX invol",load.umrl_proc_ctx_invol[0],load.umrl_proc_ctx_invol[1],load.umrl_proc_ctx_invol[2],load.umrl_proc_ctx_invol[3],load.umrl_proc_ctx_invol[4]);
	printf("%-24s  %12lld\n","Proc memory", load.ulc_memory);
	printf("%-24s  %12lld\n","Proc threads", load.uhl_proc_threads_cur);
	printf("%-24s  %12lld\n","Proc page faults", load.uhl_proc_page_faults_tot);
	printf("%-24s  %12lld\n","Proc reads", load.uhl_proc_io_read_tot);
	printf("%-24s  %12lld\n","Proc writes", load.uhl_proc_io_write_tot);
	printf("%-24s  %12lld\n","Proc user time", load.uhl_proc_user_time);
	printf("%-24s  %12lld\n","Proc system time", load.uhl_proc_system_time);
	printf("%-24s  %12lld\n","Proc total time", load.ulc_cpu_total_time);
	printf("%-24s  %12lld\n","Proc ctx invol", load.uhl_proc_ctx_invol);
	printf("%-24s  %12lld\n","Proc ctx vol", load.uhl_proc_ctx_vol);




#endif
#ifdef HL_LINUX	
	printf("%-24s  %8d%8d%8d%8d%8d\n","Disk Usage",load.umrl_hd_usage[0],load.umrl_hd_usage[1],load.umrl_hd_usage[2],load.umrl_hd_usage[3],load.umrl_hd_usage[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Disk read",load.umrl_hd_read[0],load.umrl_hd_read[1],load.umrl_hd_read[2],load.umrl_hd_read[3],load.umrl_hd_read[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Disk write",load.umrl_hd_write[0],load.umrl_hd_write[1],load.umrl_hd_write[2],load.umrl_hd_write[3],load.umrl_hd_write[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","I/O Activity",load.umrl_io_act[0],load.umrl_io_act[1],load.umrl_io_act[2],load.umrl_io_act[3],load.umrl_io_act[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","I/O Time",load.umrl_io_time[0],load.umrl_io_time[1],load.umrl_io_time[2],load.umrl_io_time[3],load.umrl_io_time[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Processes",load.umrl_process[0],load.umrl_process[1],load.umrl_process[2],load.umrl_process[3],load.umrl_process[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","new processes",load.umrl_init_process[0],load.umrl_init_process[1],load.umrl_init_process[2],load.umrl_init_process[3],load.umrl_init_process[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Memory usage",load.umrl_memory[0],load.umrl_memory[1],load.umrl_memory[2],load.umrl_memory[3],load.umrl_memory[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Swap usage",load.umrl_page_util[0],load.umrl_page_util[1],load.umrl_page_util[2],load.umrl_page_util[3],load.umrl_page_util[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","pageins",load.umrl_page_read[0],load.umrl_page_read[1],load.umrl_page_read[2],load.umrl_page_read[3],load.umrl_page_read[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","pageouts",load.umrl_page_write[0],load.umrl_page_write[1],load.umrl_page_write[2],load.umrl_page_write[3],load.umrl_page_write[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","paging activity",load.umrl_page_total[0],load.umrl_page_total[1],load.umrl_page_total[2],load.umrl_page_total[3],load.umrl_page_total[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","swapins",load.umrl_swap_read[0],load.umrl_swap_read[1],load.umrl_swap_read[2],load.umrl_swap_read[3],load.umrl_swap_read[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","swapouts",load.umrl_swap_write[0],load.umrl_swap_write[1],load.umrl_swap_write[2],load.umrl_swap_write[3],load.umrl_swap_write[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","swapping activity",load.umrl_swap_act[0],load.umrl_swap_act[1],load.umrl_swap_act[2],load.umrl_swap_act[3],load.umrl_swap_act[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","minor page faults",load.umrl_min_pg_fault[0],load.umrl_min_pg_fault[1],load.umrl_min_pg_fault[2],load.umrl_min_pg_fault[3],load.umrl_min_pg_fault[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","major page faults",load.umrl_maj_pg_fault[0],load.umrl_maj_pg_fault[1],load.umrl_maj_pg_fault[2],load.umrl_maj_pg_fault[3],load.umrl_maj_pg_fault[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Network receptions",load.umrl_nic_recv[0],load.umrl_nic_recv[1],load.umrl_nic_recv[2],load.umrl_nic_recv[3],load.umrl_nic_recv[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Network transmissions",load.umrl_nic_send[0],load.umrl_nic_send[1],load.umrl_nic_send[2],load.umrl_nic_send[3],load.umrl_nic_send[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","network load",load.umrl_nic_total[0],load.umrl_nic_total[1],load.umrl_nic_total[2],load.umrl_nic_total[3],load.umrl_nic_total[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","CPU load",load.umrl_cpu[0],load.umrl_cpu[1],load.umrl_cpu[2],load.umrl_cpu[3],load.umrl_cpu[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Interrupts",load.umrl_ints[0],load.umrl_ints[1],load.umrl_ints[2],load.umrl_ints[3],load.umrl_ints[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Context switches",load.umrl_ctx[0],load.umrl_ctx[1],load.umrl_ctx[2],load.umrl_ctx[3],load.umrl_ctx[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Process load", load.umrl_cpu_proc[0],load.umrl_cpu_proc[1],load.umrl_cpu_proc[2],load.umrl_cpu_proc[3],load.umrl_cpu_proc[4]);
#endif /* HL_LINUX */
#ifdef HL_WINALL1
	printf("%-24s  %8d%8d%8d%8d%8d\n","Cache Hit Rate",			load.umrl_cache_hit[0],		load.umrl_cache_hit[1],		load.umrl_cache_hit[2],		load.umrl_cache_hit[3],		load.umrl_cache_hit[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Cache misses",			load.umrl_cache_miss[0],	load.umrl_cache_miss[1],	load.umrl_cache_miss[2],	load.umrl_cache_miss[3],	load.umrl_cache_miss[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","CPU Util.",				load.umrl_cpu[0],			load.umrl_cpu[1],			load.umrl_cpu[2],			load.umrl_cpu[3],			load.umrl_cpu[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Context switch rate",	load.umrl_ctx[0],			load.umrl_ctx[1],			load.umrl_ctx[2],			load.umrl_ctx[3],			load.umrl_ctx[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Hard Disk Util.",		load.umrl_hd_usage[0],		load.umrl_hd_usage[1],		load.umrl_hd_usage[2],		load.umrl_hd_usage[3],		load.umrl_hd_usage[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Bytes per read",			load.umrl_hd_bpr[0],		load.umrl_hd_bpr[1],		load.umrl_hd_bpr[2],		load.umrl_hd_bpr[3],		load.umrl_hd_bpr[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Bytes per write",		load.umrl_hd_bpw[0],		load.umrl_hd_bpw[1],		load.umrl_hd_bpw[2],		load.umrl_hd_bpw[3],		load.umrl_hd_bpw[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Bytes per transfer",		load.umrl_hd_bpt[0],		load.umrl_hd_bpt[1],		load.umrl_hd_bpt[2],		load.umrl_hd_bpt[3],		load.umrl_hd_bpt[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","HD read bytes",			load.umrl_hd_read[0],		load.umrl_hd_read[1],		load.umrl_hd_read[2],		load.umrl_hd_read[3],		load.umrl_hd_read[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","HD written bytes",		load.umrl_hd_write[0],		load.umrl_hd_write[1],		load.umrl_hd_write[2],		load.umrl_hd_write[3],		load.umrl_hd_write[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Interrupt rate",			load.umrl_ints[0],			load.umrl_ints[1],			load.umrl_ints[2],			load.umrl_ints[3],			load.umrl_ints[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","I/O Activity",			load.umrl_io_act[0],		load.umrl_io_act[1],		load.umrl_io_act[2],		load.umrl_io_act[3],		load.umrl_io_act[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","I/O Time",				load.umrl_io_time[0],		load.umrl_io_time[1],		load.umrl_io_time[2],		load.umrl_io_time[3],		load.umrl_io_time[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Memory Util.",			load.umrl_memory[0],		load.umrl_memory[1],		load.umrl_memory[2],		load.umrl_memory[3],		load.umrl_memory[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Network total",			load.umrl_nic_total[0],		load.umrl_nic_total[1],		load.umrl_nic_total[2],		load.umrl_nic_total[3],		load.umrl_nic_total[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Network receptions",		load.umrl_nic_recv[0],		load.umrl_nic_recv[1],		load.umrl_nic_recv[2],		load.umrl_nic_recv[3],		load.umrl_nic_recv[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Network transmissions",	load.umrl_nic_send[0],		load.umrl_nic_send[1],		load.umrl_nic_send[2],		load.umrl_nic_send[3],		load.umrl_nic_send[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Network bytes (sent)",	load.umrl_net_sent[0],		load.umrl_net_sent[1],		load.umrl_net_sent[2],		load.umrl_net_sent[3],		load.umrl_net_sent[4]);	
	printf("%-24s  %8d%8d%8d%8d%8d\n","Network bytes (recv)",	load.umrl_net_recv[0],		load.umrl_net_recv[1],		load.umrl_net_recv[2],		load.umrl_net_recv[3],		load.umrl_net_recv[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Network bytes (tot)",	load.umrl_net_total[0],		load.umrl_net_total[1],		load.umrl_net_total[2],		load.umrl_net_total[3],		load.umrl_net_total[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Pageins",				load.umrl_page_read[0],		load.umrl_page_read[1],		load.umrl_page_read[2],		load.umrl_page_read[3],		load.umrl_page_read[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Pageouts",				load.umrl_page_write[0],	load.umrl_page_write[1],	load.umrl_page_write[2],	load.umrl_page_write[3],	load.umrl_page_write[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Paging activity",		load.umrl_page_total[0],	load.umrl_page_total[1],	load.umrl_page_total[2],	load.umrl_page_total[3],	load.umrl_page_total[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Page fault rate",		load.umrl_page_fault[0],	load.umrl_page_fault[1],	load.umrl_page_fault[2],	load.umrl_page_fault[3],	load.umrl_page_fault[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Swap util.",				load.umrl_page_util[0],		load.umrl_page_util[1],		load.umrl_page_util[2],		load.umrl_page_util[3],		load.umrl_page_util[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","pagefile size",			load.umrl_page_file[0],		load.umrl_page_file[1],		load.umrl_page_file[2],		load.umrl_page_file[3],		load.umrl_page_file[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Processes",				load.umrl_process[0],		load.umrl_process[1],		load.umrl_process[2],		load.umrl_process[3],		load.umrl_process[4]);
	printf("%-24s  %8d%8d%8d%8d%8d\n","Threads",				load.umrl_threads[0],		load.umrl_threads[1],		load.umrl_threads[2],		load.umrl_threads[3],		load.umrl_threads[4]);
	printf("-------------------\n");
	printf("%-24s  %8d%8d%8d%8d%8d\n","Process load",			load.umrl_proc_cpu[0],		load.umrl_proc_cpu[1],		load.umrl_proc_cpu[2],		load.umrl_proc_cpu[3],		load.umrl_proc_cpu[4]);
	printf("%-24s  %8d%8d%8d%8d%8d%8d\n","P Threads",			load.umrl_proc_threads[0],	load.umrl_proc_threads[1],	load.umrl_proc_threads[2],	load.umrl_proc_threads[3],	load.umrl_proc_threads[4],	load.uml_proc_curr_threads);
	printf("%-24s  %8d%8d%8d%8d%8d%8d\n","P Handles",			load.umrl_proc_handles[0],	load.umrl_proc_handles[1],	load.umrl_proc_handles[2],	load.umrl_proc_handles[3],	load.umrl_proc_handles[4],	load.uml_proc_curr_handles);
	printf("%-24s  %8d%8d%8d%8d%8d%8lld\n","P VM Bytes",			load.umrl_proc_virt_bytes[0],	load.umrl_proc_virt_bytes[1],	load.umrl_proc_virt_bytes[2],	load.umrl_proc_virt_bytes[3],	load.umrl_proc_virt_bytes[4],	load.uhl_proc_virt_bytes);
	printf("%-24s  %8d%8d%8d%8d%8d%8lld\n","P Read Ops",			load.umrl_proc_read_ops[0],	load.umrl_proc_read_ops[1],	load.umrl_proc_read_ops[2],	load.umrl_proc_read_ops[3],	load.umrl_proc_read_ops[4],	load.uhl_proc_read_operations);
	printf("%-24s  %8d%8d%8d%8d%8d%8lld\n","P Read Bytes",		load.umrl_proc_read_bytes[0],	load.umrl_proc_read_bytes[1],	load.umrl_proc_read_bytes[2],	load.umrl_proc_read_bytes[3],	load.umrl_proc_read_bytes[4],	load.uhl_proc_read_bytes);
	printf("%-24s  %8d%8d%8d%8d%8d%8lld\n","P Write Ops",			load.umrl_proc_write_ops[0],	load.umrl_proc_write_ops[1],	load.umrl_proc_write_ops[2],	load.umrl_proc_write_ops[3],	load.umrl_proc_write_ops[4],	load.uhl_proc_write_operations);
	printf("%-24s  %8d%8d%8d%8d%8d%8lld\n","P Write Bytes",		load.umrl_proc_write_bytes[0],	load.umrl_proc_write_bytes[1],	load.umrl_proc_write_bytes[2],	load.umrl_proc_write_bytes[3],	load.umrl_proc_write_bytes[4],	load.uhl_proc_write_bytes);
	printf("%-24s  %8d%8d%8d%8d%8d%8lld\n","P Total Bytes",		load.umrl_proc_total_bytes[0],	load.umrl_proc_total_bytes[1],	load.umrl_proc_total_bytes[2],	load.umrl_proc_total_bytes[3],	load.umrl_proc_total_bytes[4],	load.uhl_proc_total_bytes);
	printf("%-24s  %8d%8d%8d%8d%8d%8d\n","P Page Faults",		load.umrl_proc_pg_fault[0],		load.umrl_proc_pg_fault[1],	load.umrl_proc_pg_fault[2],	load.umrl_proc_pg_fault[3],	load.umrl_proc_pg_fault[4],	load.uml_proc_pg_faults);
	printf("%-24s  %8d%8d%8d%8d%8d%8d\n","P Memory",			load.umrl_proc_mem_abs[0],	load.umrl_proc_mem_abs[1],	load.umrl_proc_mem_abs[2],	load.umrl_proc_mem_abs[3],	load.umrl_proc_mem_abs[4], load.uml_proc_curr_mem);
	printf("%-24s  %8d%8d%8d%8d%8d%8d\n","P Mem Util",			load.umrl_proc_mem_util[0],	load.umrl_proc_mem_util[1],	load.umrl_proc_mem_util[2],	load.umrl_proc_mem_util[3],	load.umrl_proc_mem_util[4], load.uml_proc_curr_mem_util);
	printf("%-24s  %12lld\n","P Kernel time", load.uhl_proc_time_kernel);
	printf("%-24s  %12lld\n","P User time", load.uhl_proc_time_user);
	printf("%-24s  %12lld\n","P Total time", load.uhl_proc_time_kernel+ load.uhl_proc_time_user);
#endif /* HL_WINALL1 */
	if (am_get_sessions > 0 )
	{
		printf("%-24s  %8d\n","Sessions",am_get_sessions());
	}
	printf("\n\n");
}
//#endif /*DEBUG*/

// trim a char*
static string m_trim_char(char* achp_totrim)
{
	string str_to_trim(achp_totrim);
	string str_ret;
	if (strlen(achp_totrim) == 0)
	{
		str_ret = "";
		return str_ret;
	}
	int iml_first_nws = str_to_trim.find_first_not_of(" \t\n");
	int iml_last_nws = str_to_trim.find_last_not_of(" \n\t");
	if (iml_first_nws < 0)
	{
		str_ret = "";
		return str_ret;
	}
	str_ret = str_to_trim.substr(iml_first_nws,iml_last_nws - iml_first_nws + 1);
	//iml_last_nws = str_ret.find_last_not_of(" \n\t");
	return str_ret;	
}
