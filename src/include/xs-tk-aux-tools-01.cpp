// Auxiliary tools for AUX-Callback
// Author: Stefan Martin
// Date: 08.09.2017
#ifndef __HOB_TK_AUX_TOOLS_01_CPP__
#define __HOB_TK_AUX_TOOLS_01_CPP__

#if !HOB_TK_NO_INCLUDE
#include <hob-tk-aux-tools-01.h>
#endif

HL_LOCAL_SCOPE int m_htree1_avl_cmp_timer_entry(
	void *, struct dsd_htree1_avl_entry* adsp_e1,
   struct dsd_htree1_avl_entry* adsp_e2)
{
	struct dsd_aux_timer_entry* adsl_e1 = HL_UPCAST(struct dsd_aux_timer_entry, dsc_avl_entry, adsp_e1);
	struct dsd_aux_timer_entry* adsl_e2 = HL_UPCAST(struct dsd_aux_timer_entry, dsc_avl_entry, adsp_e2);
	HL_LONGLONG ill_diff = adsl_e1->ilc_epoch_end - adsl_e2->ilc_epoch_end;
	if(ill_diff < 0)
		return -1;
	if(ill_diff > 0)
		return +1;
	if(adsl_e1 < adsl_e2)
		return -1;
	if(adsl_e1 > adsl_e2)
		return +1;
	return 0;
}

HL_LOCAL_SCOPE void m_aux_timer_handler_init(struct dsd_aux_timer_handler* adsp_this) {
	m_htree1_avl_init(adsp_this, &adsp_this->dsc_avl_cntl, &m_htree1_avl_cmp_timer_entry);
}

HL_LOCAL_SCOPE BOOL m_aux_timer_handler_add(struct dsd_aux_timer_handler* adsp_this, struct dsd_aux_helper* dsp_call, struct dsd_aux_timer_entry* adsp_entry, int inp_millis) {
	if(adsp_entry->boc_attached)
		return FALSE;
	HL_LONGLONG ill_time;
	BOOL bol_ret = dsp_call->amc_aux(dsp_call->vpc_userfld, DEF_AUX_GET_T_MSEC, &ill_time, sizeof(ill_time));
	if(!bol_ret)
		return FALSE;
	adsp_entry->ilc_epoch_end = ill_time + inp_millis;
	struct dsd_htree1_avl_work dsl_avl_work;
	bol_ret = m_htree1_avl_search(adsp_this, &adsp_this->dsc_avl_cntl,
                                 &dsl_avl_work,
											&adsp_entry->dsc_avl_entry);
	if(!bol_ret)
		return FALSE;
	if(dsl_avl_work.adsc_found != NULL && dsl_avl_work.adsc_found == &adsp_entry->dsc_avl_entry)
		return FALSE;
	bol_ret = m_htree1_avl_insert(adsp_this, &adsp_this->dsc_avl_cntl,
                                 &dsl_avl_work,
											&adsp_entry->dsc_avl_entry);
	if(!bol_ret)
		return FALSE;
	adsp_entry->boc_attached = TRUE;
	bol_ret = m_htree1_avl_getnext(adsp_this, &adsp_this->dsc_avl_cntl,
                                  &dsl_avl_work, TRUE);
	if(!bol_ret)
		return FALSE;
	if(dsl_avl_work.adsc_found != &adsp_entry->dsc_avl_entry)
		return TRUE;
	int inl_millis = adsp_entry->ilc_epoch_end - ill_time;
	if(inl_millis < 0)
		inl_millis = 0;
	bol_ret = dsp_call->amc_aux(dsp_call->vpc_userfld, DEF_AUX_TIMER1_SET, NULL, inl_millis);
	if(!bol_ret)
		return FALSE;
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_aux_timer_handler_remove(struct dsd_aux_timer_handler* adsp_this, struct dsd_aux_helper* dsp_call, struct dsd_aux_timer_entry* adsp_entry) {
	if(!adsp_entry->boc_attached)
		return TRUE;
	struct dsd_htree1_avl_work dsl_avl_work;
	BOOL bol_ret = m_htree1_avl_search(adsp_this, &adsp_this->dsc_avl_cntl,
                                 &dsl_avl_work,
											&adsp_entry->dsc_avl_entry);
	if(!bol_ret)
		return FALSE;
	if(dsl_avl_work.adsc_found == NULL)
		return FALSE;

	struct dsd_htree1_avl_work dsl_avl_work2;
	bol_ret = m_htree1_avl_getnext(adsp_this, &adsp_this->dsc_avl_cntl,
                                  &dsl_avl_work2, TRUE);
	if(!bol_ret)
		return FALSE;
	BOOL bol_is_first = (dsl_avl_work2.adsc_found == &adsp_entry->dsc_avl_entry);
	bol_ret = m_htree1_avl_delete(adsp_this, &adsp_this->dsc_avl_cntl,
                                 &dsl_avl_work);
	if(!bol_ret)
		return FALSE;
	adsp_entry->boc_attached = FALSE;
	if(!bol_is_first)
		return TRUE;
	bol_ret = m_htree1_avl_getnext(adsp_this, &adsp_this->dsc_avl_cntl,
                                  &dsl_avl_work, TRUE);
	if(!bol_ret)
		return FALSE;
	if(dsl_avl_work.adsc_found == NULL) {
		bol_ret = dsp_call->amc_aux(dsp_call->vpc_userfld, DEF_AUX_TIMER1_REL, NULL, 0);
		if(!bol_ret)
			return FALSE;
		return TRUE;
	}
	HL_LONGLONG ill_time;
	bol_ret = dsp_call->amc_aux(dsp_call->vpc_userfld, DEF_AUX_GET_T_MSEC, &ill_time, sizeof(ill_time));
	if(!bol_ret)
		return FALSE;
	struct dsd_aux_timer_entry* adsl_first = HL_UPCAST(struct dsd_aux_timer_entry, dsc_avl_entry, dsl_avl_work.adsc_found);
	if(adsl_first->ilc_epoch_end <= adsp_entry->ilc_epoch_end)
		return TRUE;
	int inl_millis = adsl_first->ilc_epoch_end - ill_time;
	if(inl_millis < 0)
		inl_millis = 0;
	bol_ret = dsp_call->amc_aux(dsp_call->vpc_userfld, DEF_AUX_TIMER1_SET, NULL, inl_millis);
	if(!bol_ret)
		return FALSE;
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_aux_timer_handler_peek_start(
	struct dsd_aux_timer_handler* adsp_this, struct dsd_aux_helper* dsp_call, struct dsd_aux_timer_peek* adsp_peek)
{
	HL_LONGLONG ill_time;
	BOOL bol_ret = dsp_call->amc_aux(dsp_call->vpc_userfld, DEF_AUX_GET_T_MSEC, &ill_time, sizeof(ill_time));
	if(!bol_ret)
		return FALSE;
	adsp_peek->ilc_epoch_now = ill_time;
	adsp_peek->adsc_entry = NULL;
	return m_aux_timer_handler_peek_next(adsp_this, dsp_call, adsp_peek);
}

HL_LOCAL_SCOPE BOOL m_aux_timer_handler_peek_next(struct dsd_aux_timer_handler* adsp_this, struct dsd_aux_helper* dsp_call, struct dsd_aux_timer_peek* adsp_peek) {
	struct dsd_htree1_avl_work dsl_avl_work;
	BOOL bol_ret = m_htree1_avl_getnext(adsp_this, &adsp_this->dsc_avl_cntl,
                                  &dsl_avl_work, TRUE);
	if(!bol_ret)
		return FALSE;
	if(dsl_avl_work.adsc_found == NULL) {
		adsp_peek->adsc_entry = NULL;
		return TRUE;
	}
	struct dsd_aux_timer_entry* adsl_first = HL_UPCAST(struct dsd_aux_timer_entry, dsc_avl_entry, dsl_avl_work.adsc_found);
	if(adsl_first->ilc_epoch_end > adsp_peek->ilc_epoch_now) {
		adsp_peek->adsc_entry = NULL;
		return TRUE;
	}
	bol_ret = m_htree1_avl_delete(adsp_this, &adsp_this->dsc_avl_cntl,
                                 &dsl_avl_work);
	if(!bol_ret)
		return FALSE;
	adsl_first->boc_attached = FALSE;
	adsp_peek->adsc_entry = adsl_first;
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_aux_timer_handler_peek_end(
	struct dsd_aux_timer_handler* adsp_this, struct dsd_aux_helper* dsp_call, struct dsd_aux_timer_peek* adsp_peek)
{
	struct dsd_htree1_avl_work dsl_avl_work;
	BOOL bol_ret = m_htree1_avl_getnext(adsp_this, &adsp_this->dsc_avl_cntl,
                                  &dsl_avl_work, TRUE);
	if(!bol_ret)
		return FALSE;
	if(dsl_avl_work.adsc_found == NULL) {
		return TRUE;
	}
	struct dsd_aux_timer_entry* adsl_first = HL_UPCAST(struct dsd_aux_timer_entry, dsc_avl_entry, dsl_avl_work.adsc_found);
	int inl_millis = adsl_first->ilc_epoch_end - adsp_peek->ilc_epoch_now;
	if(inl_millis < 0)
		inl_millis = 0;
	bol_ret = dsp_call->amc_aux(dsp_call->vpc_userfld, DEF_AUX_TIMER1_SET, NULL, inl_millis);
	if(!bol_ret)
		return FALSE;
	return TRUE;
}

/* subroutine for output to console                                    */
HL_LOCAL_SCOPE int m_aux_printf( struct dsd_aux_helper* dsp_call, const char *achptext, ... ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   va_list    dsl_argptr;
   char       chrl_out1[512];

   va_start( dsl_argptr, achptext );
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achptext, dsl_argptr );
   va_end( dsl_argptr );
   bol1 = (*dsp_call->amc_aux)( dsp_call->vpc_userfld,
                                       DEF_AUX_CONSOLE_OUT,  /* output to console */
                                       chrl_out1, iml1 );
   return iml1;
} /* end m_aux_printf() */

#endif /*!__HOB_TK_AUX_TOOLS_01_CPP__*/
