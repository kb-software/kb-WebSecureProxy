// Auxiliary tools for AUX-Callback
// Author: Stefan Martin
// Date: 08.09.2017
#ifndef __HOB_TK_AUX_TOOLS_01_H__
#define __HOB_TK_AUX_TOOLS_01_H__

#if !HOB_TK_NO_INCLUDE
#ifdef HL_UNIX
#include <hob-unix01.h>
#include <stdarg.h>
#include <sys/types.h>
#else
#include <Windows.h>
#endif
#include <stdint.h>
#include <hob-avl03.h>
#ifndef LEN_SECURE_XOR_PWD
// hack: missing header guards in hob-xsclib01.h
#include <hob-xsclib01.h>
#endif
#endif

#include <stddef.h>

#define HL_UPCAST(d, f, p) ((d*)(((char*)p)-offsetof(d, f)))
#define HL_LOCAL_SCOPE extern inline

struct dsd_aux_helper {
	BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
};

struct dsd_aux_timer_entry {
	HL_LONGLONG ilc_epoch_end;               /* epoch timer set         */
	BOOL boc_attached;
	struct dsd_htree1_avl_entry dsc_avl_entry;
};

struct dsd_aux_timer_handler {
	struct dsd_htree1_avl_cntl dsc_avl_cntl;
};

struct dsd_aux_timer_peek {
	HL_LONGLONG ilc_epoch_now;
	struct dsd_aux_timer_entry* adsc_entry;
};

HL_LOCAL_SCOPE void m_aux_timer_handler_init(struct dsd_aux_timer_handler* adsp_this);
HL_LOCAL_SCOPE BOOL m_aux_timer_handler_add(struct dsd_aux_timer_handler* adsp_this, struct dsd_aux_helper* dsp_call, struct dsd_aux_timer_entry* adsp_entry, int inp_millis);
HL_LOCAL_SCOPE BOOL m_aux_timer_handler_remove(struct dsd_aux_timer_handler* adsp_this, struct dsd_aux_helper* dsp_call, struct dsd_aux_timer_entry* adsp_entry);
HL_LOCAL_SCOPE BOOL m_aux_timer_handler_peek_start(struct dsd_aux_timer_handler* adsp_this, struct dsd_aux_helper* dsp_call, struct dsd_aux_timer_peek* adsp_peek);
HL_LOCAL_SCOPE BOOL m_aux_timer_handler_peek_next(struct dsd_aux_timer_handler* adsp_this, struct dsd_aux_helper* dsp_call, struct dsd_aux_timer_peek* adsp_peek);
HL_LOCAL_SCOPE BOOL m_aux_timer_handler_peek_end(struct dsd_aux_timer_handler* adsp_this, struct dsd_aux_helper* dsp_call, struct dsd_aux_timer_peek* adsp_peek);

/* subroutine for output to console                                    */
HL_LOCAL_SCOPE int m_aux_printf( struct dsd_aux_helper* dsp_call, const char *achptext, ... );

#endif /*!__HOB_TK_AUX_TOOLS_01_H__*/
