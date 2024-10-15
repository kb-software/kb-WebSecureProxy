// Gather tools for AUX system
// Author: Stefan Martin
// Date: 08.09.2017
#ifndef __HOB_TK_GATHER_TOOLS_01_H__
#define __HOB_TK_GATHER_TOOLS_01_H__

#if !HOB_TK_NO_INCLUDE
#ifdef HL_UNIX
#include <hob-unix01.h>
#include <stdarg.h>
#include <sys/types.h>
#else
#include <Windows.h>
#endif
#include <stddef.h>
#include <stdint.h>
#include <hob-tk-aux-tools-01.h>
#endif

#ifdef _MSC_VER
#define HL_ALIGN(x) __declspec(align(x))
#define HL_ALIGNOF(x) (sizeof(x) != 0 ? __alignof(x) : 0)
#else
#define HL_ALIGN(x) __attribute__((aligned (x)))
#define HL_ALIGNOF(x) __alignof__(x)
#endif
#define HL_MIN(a,b) (((a)<(b))?(a):(b))
#define HL_MAX(a,b) (((a)>(b))?(a):(b))

#ifndef DEF_HL_STR_G_I_1
#define DEF_HL_STR_G_I_1
struct dsd_gather_i_1 {                     /* gather input data       */
   struct dsd_gather_i_1 *adsc_next;        /* next in chain           */
   char *     achc_ginp_cur;                /* current position        */
   char *     achc_ginp_end;                /* end of input data       */
};
#endif

struct dsd_managed_workarea {
	struct dsd_managed_workarea* adsc_next;
	//struct dsd_workarea* adsc_next;
	int inc_usage_count;
};

struct dsd_gather_i_2 {
	struct dsd_gather_i_1 dsc_base;
	void* adsc_owner;
};

struct dsd_gather_i_3 {
	struct dsd_gather_i_1 dsc_base;
	void* adsc_owner;
	struct dsd_gather_i_3* adsc_prev;
};

struct dsd_slist_element {
	struct dsd_slist_element* adsc_next;
};

struct dsd_fifo {
	struct dsd_slist_element* adsc_first;
	struct dsd_slist_element** aads_tailp;
	void (*amp_free_cb)(struct dsd_slist_element* adsp_g, void* avop_userfld);
};

/*struct dsd_workarea_context {
	char* adsc_wa_cur;
	char* achc_lower;
	char* achc_upper;
};*/

struct dsd_workarea_allocator {
	struct dsd_aux_helper* adsc_aux;
	char* adsc_wa_cur;
	char* achc_lower;
	char* achc_upper;
};

struct dsd_gather_i_1_pos {
	struct dsd_gather_i_1* adsc_gather;
	char* achc_pos;
};

struct dsd_unicode_string_gather_pos {
   enum ied_charset iec_chs_str;            /* character set string    */
	int        imc_len_str;                  /* length string in elements */
	struct dsd_gather_i_1_pos dsc_data;
};

struct dsd_gather_i_1_fifo {
	struct dsd_gather_i_1* adsc_first;
	struct dsd_gather_i_1** aads_tailp;
	void (*amp_free_cb)(struct dsd_gather_i_1_fifo* adsp_list, struct dsd_gather_i_1* adsp_g);
};

struct dsd_gather_i_1_fifo_aux {
	struct dsd_gather_i_1_fifo dsc_base;
	struct dsd_aux_helper* adsc_aux;
};

struct dsd_gather_i_3_list {
	struct dsd_gather_i_3 dsc_head;
	void (*amc_free_cb)(struct dsd_gather_i_3_list* adsp_list, struct dsd_gather_i_3* adsp_g);
};

struct dsd_gather_i_3_itr {
	struct dsd_gather_i_3* adsc_cur;
	struct dsd_gather_i_3* adsc_head;
};

struct dsd_workarea_chain {
	struct dsd_aux_helper* adsc_aux;
	struct dsd_managed_workarea* adsc_workarea_1;
};

struct dsd_data_block {
	struct dsd_slist_element dsc_slist_elem;
	struct dsd_gather_i_1* adsc_data;
	//struct dsd_aux_helper* adsc_wa_aux;
	struct dsd_workarea_chain dsc_workareas;
	char* adsc_wa1;
	char* adsc_wa2;
};

#endif /*!__HOB_TK_GATHER_TOOLS_01_H__*/
