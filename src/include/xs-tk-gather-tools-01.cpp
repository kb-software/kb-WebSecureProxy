// Gather tools for AUX system
// Author: Stefan Martin
// Date: 08.09.2017

#ifndef _XS_TK_GATHER_TOOLS_CPP_
#define _XS_TK_GATHER_TOOLS_CPP_

#if !HOB_TK_NO_INCLUDE
#include <hob-tk-gather-tools-01.h>
#ifndef LEN_SECURE_XOR_PWD
// hack: missing header guards in hob-xsclib01.h
#include <hob-xsclib01.h>
#endif
// hack: missing header guards in hob-xslunic1.h
#ifndef MAX_IDNAPART_LENGTH
#include <hob-xslunic1.h>
#endif
#include <assert.h>
#include <stdio.h>
#endif


#define SM_MINIFY_WORKAREAS 0

HL_LOCAL_SCOPE void m_fifo_init(struct dsd_fifo* adsp_fifo) {
	adsp_fifo->adsc_first = NULL;
	adsp_fifo->aads_tailp = &adsp_fifo->adsc_first;
}

HL_LOCAL_SCOPE void m_fifo_reset(struct dsd_fifo* adsp_fifo, void* avop_userfld) {
	struct dsd_slist_element* adsl_cur = adsp_fifo->adsc_first;
	while(adsl_cur != NULL) {
		struct dsd_slist_element* adsl_next = adsl_cur->adsc_next;
		adsp_fifo->amp_free_cb(adsl_cur, avop_userfld);
        adsl_cur = adsl_next;
    }
	adsp_fifo->adsc_first = NULL;
	adsp_fifo->aads_tailp = &adsp_fifo->adsc_first;
}

HL_LOCAL_SCOPE void m_fifo_destroy(struct dsd_fifo* adsp_fifo, void* avop_userfld) {
	m_fifo_reset(adsp_fifo, avop_userfld);
}

HL_LOCAL_SCOPE void m_fifo_append(struct dsd_fifo* adsp_fifo, struct dsd_slist_element* adsp_elem) {
	adsp_elem->adsc_next = NULL;
	*adsp_fifo->aads_tailp = adsp_elem;
	adsp_fifo->aads_tailp = &adsp_elem->adsc_next;
}

HL_LOCAL_SCOPE dsd_slist_element* m_fifo_remove_first(struct dsd_fifo* adsp_fifo) {
	dsd_slist_element* adsl_elem = adsp_fifo->adsc_first;
	if(adsl_elem == NULL)
		return adsl_elem;
	adsp_fifo->adsc_first = adsl_elem->adsc_next;
	if(adsp_fifo->adsc_first != NULL)
		return adsl_elem;
	adsp_fifo->aads_tailp = &adsp_fifo->adsc_first;
	return adsl_elem;
}

#if 0
HL_LOCAL_SCOPE void m_wa_allocator_release_wa(struct dsd_workarea_allocator* adsp_wa, struct dsd_managed_workarea* adsc_wa_cur) {
	adsc_wa_cur->inc_usage_count--;
	if(adsc_wa_cur->inc_usage_count > 0)
		return;
	struct dsd_aux_helper* adsl_aux_helper = (struct dsd_aux_helper*)adsp_wa->adsc_aux;
	void* avol_ptr = adsc_wa_cur;
	adsl_aux_helper->amc_aux(adsl_aux_helper->vpc_userfld, DEF_AUX_MEMFREE, &avol_ptr, 0);
}
#endif

HL_LOCAL_SCOPE void m_wa_allocator_init(struct dsd_workarea_allocator* adsp_wa) {
	memset(adsp_wa, 0, sizeof(*adsp_wa));
}

HL_LOCAL_SCOPE size_t m_wa_allocator_available(struct dsd_workarea_allocator* adsp_wa) {
	return adsp_wa->achc_upper - adsp_wa->achc_lower;
}

HL_LOCAL_SCOPE char* m_wa_allocator_share_inc(struct dsd_workarea_allocator* adsp_wa) {
	if(m_wa_allocator_available(adsp_wa) <= 0) {
		char* achl_wa_cur = adsp_wa->adsc_wa_cur;
		adsp_wa->adsc_wa_cur = NULL;
		adsp_wa->achc_lower = NULL;
		adsp_wa->achc_upper = NULL;
		return achl_wa_cur;
	}
	if(!adsp_wa->adsc_aux->amc_aux(
		adsp_wa->adsc_aux->vpc_userfld, DEF_AUX_MARK_WORKAREA_INC, adsp_wa->adsc_wa_cur, 0))
		return NULL;
	return adsp_wa->adsc_wa_cur;
}

HL_LOCAL_SCOPE void m_wa_allocator_release(struct dsd_workarea_allocator* adsp_wa, struct dsd_workarea_allocator* adsp_context) {
	adsp_context->adsc_aux = adsp_wa->adsc_aux;
	adsp_context->adsc_wa_cur = adsp_wa->adsc_wa_cur;
	adsp_context->achc_lower = adsp_wa->achc_lower;
	adsp_context->achc_upper = adsp_wa->achc_upper;
	adsp_wa->adsc_wa_cur = NULL;
	adsp_wa->achc_lower = NULL;
	adsp_wa->achc_upper = NULL;
}

HL_LOCAL_SCOPE void m_wa_allocator_swap(struct dsd_workarea_allocator* adsp_wa, struct dsd_workarea_allocator* adsp_context) {
	struct dsd_workarea_allocator dsl_tmp = *adsp_wa;
	*adsp_wa = *adsp_context;
	*adsp_context = dsl_tmp;
}

HL_LOCAL_SCOPE BOOL m_wa_allocator_alloc(struct dsd_workarea_allocator* adsp_wa, size_t szp_size, size_t szp_align) {
	if(adsp_wa->adsc_aux == NULL)
		return FALSE;
	//HeapValidate(GetProcessHeap(), 0, NULL);
	if(adsp_wa->adsc_wa_cur != NULL) {
		if(!adsp_wa->adsc_aux->amc_aux(adsp_wa->adsc_aux->vpc_userfld, DEF_AUX_MARK_WORKAREA_DEC, adsp_wa->adsc_wa_cur, 0))
			return FALSE;
		adsp_wa->adsc_wa_cur = NULL;
		adsp_wa->achc_lower = NULL;
		adsp_wa->achc_upper = NULL;
	}
	dsd_aux_get_workarea dsl_aux_get_workarea;
	dsl_aux_get_workarea.imc_len_work_area = szp_size + szp_align - 1;
	if(!adsp_wa->adsc_aux->amc_aux(adsp_wa->adsc_aux->vpc_userfld, DEF_AUX_GET_WORKAREA, &dsl_aux_get_workarea, sizeof(dsl_aux_get_workarea)))
		return FALSE;
	adsp_wa->adsc_wa_cur = dsl_aux_get_workarea.achc_work_area;
	adsp_wa->achc_lower = dsl_aux_get_workarea.achc_work_area;
	adsp_wa->achc_upper = dsl_aux_get_workarea.achc_work_area + dsl_aux_get_workarea.imc_len_work_area;
	return TRUE;
}

HL_LOCAL_SCOPE char* m_wa_allocator_alloc_lower(struct dsd_workarea_allocator* adsp_wa, size_t szp_size, size_t szp_align) {
LBL_AGAIN:
	char* achl_lower = adsp_wa->achc_lower;
	achl_lower = (char*)(((size_t)achl_lower + (szp_align-1)) & ~(szp_align-1));
	char* achl_lower2 = achl_lower + szp_size;
	if(achl_lower2 <= adsp_wa->achc_upper) {
		adsp_wa->achc_lower = achl_lower2;
		return achl_lower;
	}
	if(!m_wa_allocator_alloc(adsp_wa, szp_size, szp_align))
		return NULL;
	goto LBL_AGAIN;
}

HL_LOCAL_SCOPE char* m_wa_allocator_alloc_upper(struct dsd_workarea_allocator* adsp_wa, size_t szp_size, size_t szp_align) {
LBL_AGAIN:
	char* achl_upper = adsp_wa->achc_upper - szp_size;
	achl_upper = (char*)(((size_t)achl_upper) & ~(szp_align-1));
	if((achl_upper-adsp_wa->achc_lower) >= 0) {
		adsp_wa->achc_upper = achl_upper;
		return achl_upper;
	}
	if(!m_wa_allocator_alloc(adsp_wa, szp_size, szp_align))
		return NULL;
	goto LBL_AGAIN;
}

HL_LOCAL_SCOPE char* m_wa_allocator_reserve_lower(struct dsd_workarea_allocator* adsp_wa, size_t szp_size, size_t szp_align) {
LBL_AGAIN:
	char* achl_lower = adsp_wa->achc_lower;
	achl_lower = (char*)(((size_t)achl_lower + (szp_align-1)) & ~(szp_align-1));
	char* achl_lower2 = achl_lower + szp_size;
	if(achl_lower2 <= adsp_wa->achc_upper) {
		return achl_lower;
	}
	if(!m_wa_allocator_alloc(adsp_wa, szp_size, szp_align))
		return NULL;
	goto LBL_AGAIN;
}

HL_LOCAL_SCOPE char* m_wa_allocator_reserve_upper(struct dsd_workarea_allocator* adsp_wa, size_t szp_size, size_t szp_align) {
LBL_AGAIN:
	char* achl_upper = adsp_wa->achc_upper - szp_size;
	achl_upper = (char*)(((size_t)achl_upper) & ~(szp_align-1));
	if((achl_upper-adsp_wa->achc_lower) >= 0) {
		return achl_upper;
	}
	if(!m_wa_allocator_alloc(adsp_wa, szp_size, szp_align))
		return NULL;
	goto LBL_AGAIN;
}

HL_LOCAL_SCOPE BOOL m_wa_allocator_destroy(struct dsd_workarea_allocator* adsp_wa) {
	if(adsp_wa->adsc_wa_cur != NULL) {
		if(!adsp_wa->adsc_aux->amc_aux(adsp_wa->adsc_aux->vpc_userfld, DEF_AUX_MARK_WORKAREA_DEC, adsp_wa->adsc_wa_cur, 0))
			return FALSE;
		adsp_wa->adsc_wa_cur = NULL;
	}
	adsp_wa->achc_lower = NULL;
	adsp_wa->achc_upper = NULL;
	return TRUE;
}

HL_LOCAL_SCOPE void m_wa_allocator_commit_lower(struct dsd_workarea_allocator* adsp_wa, char* achp_addr) {
	assert(achp_addr >= adsp_wa->achc_lower && achp_addr <= adsp_wa->achc_upper);
	adsp_wa->achc_lower = achp_addr;
}

HL_LOCAL_SCOPE void m_wa_allocator_commit_upper(struct dsd_workarea_allocator* adsp_wa, char* achp_addr) {
	assert(achp_addr >= adsp_wa->achc_lower && achp_addr <= adsp_wa->achc_upper);
	adsp_wa->achc_upper = achp_addr;
}

HL_LOCAL_SCOPE int m_gather_i_1_count_data_len(const struct dsd_gather_i_1* adsp_g) {
    int inl_count = 0;
    while(adsp_g != NULL) {
        inl_count += adsp_g->achc_ginp_end-adsp_g->achc_ginp_cur;
        adsp_g = adsp_g->adsc_next;
    }
    return inl_count;
}

HL_LOCAL_SCOPE int m_gather_i_1_count_data_len2(const struct dsd_gather_i_1* adsp_g, const struct dsd_gather_i_1** aadsp_last) {
    int inl_count = 0;
    const dsd_gather_i_1* adsl_last = adsp_g;
	while(adsp_g != NULL) {
        inl_count += adsp_g->achc_ginp_end-adsp_g->achc_ginp_cur;
		adsl_last = adsp_g;
        adsp_g = adsp_g->adsc_next;
	}
	if (aadsp_last != NULL) {
		*aadsp_last = adsl_last;
	}
    return inl_count;
}

HL_LOCAL_SCOPE int m_gather_i_1_pos_count_data_len(const struct dsd_gather_i_1_pos* adsp_g) {
	if(adsp_g->adsc_gather == NULL)
		return 0;
	int inl_count = m_gather_i_1_count_data_len(adsp_g->adsc_gather);
	int inl_offset = adsp_g->achc_pos-adsp_g->adsc_gather->achc_ginp_cur;
	return inl_count-inl_offset;
}

HL_LOCAL_SCOPE void m_gather_i_1_pos_to_gather(const struct dsd_gather_i_1_pos* adsp_g, struct dsd_gather_i_1* adsp_out) {
	if(adsp_g->adsc_gather == NULL) {
		adsp_out->achc_ginp_cur = NULL;
		adsp_out->achc_ginp_end = NULL;
		adsp_out->adsc_next = NULL;
		return;
	}
	adsp_out->achc_ginp_cur = adsp_g->achc_pos;
	adsp_out->achc_ginp_end = adsp_g->adsc_gather->achc_ginp_end;
	adsp_out->adsc_next = adsp_g->adsc_gather->adsc_next;
}

HL_LOCAL_SCOPE void m_gather_i_1_pos_from_gather(struct dsd_gather_i_1_pos* adsp_g, struct dsd_gather_i_1* adsp_in) {
	adsp_g->adsc_gather = adsp_in;
	adsp_g->achc_pos = adsp_in->achc_ginp_cur;
}

HL_LOCAL_SCOPE BOOL m_gather_i_1_ensure_available(const struct dsd_gather_i_1* adsp_g, size_t szp_len) {
   if(szp_len <= 0)
		return TRUE;
	size_t szl_count = 0;
	while(adsp_g != NULL) {
      szl_count += adsp_g->achc_ginp_end-adsp_g->achc_ginp_cur;
		if(szl_count >= szp_len)
			return TRUE;
      adsp_g = adsp_g->adsc_next;
   }
   return FALSE;
}

HL_LOCAL_SCOPE struct dsd_gather_i_1* m_gather_i_1_skip_processed(struct dsd_gather_i_1* adsp_g) {
    while(adsp_g != NULL) {
        if(adsp_g->achc_ginp_cur < adsp_g->achc_ginp_end)
            break;
        adsp_g = adsp_g->adsc_next;
    }
    return adsp_g;
}

HL_LOCAL_SCOPE BOOL m_aux_console_out( struct dsd_aux_helper* adsp_aux, const char *achp_buff, int implength ) {
	adsp_aux = NULL;
   static const char chrstrans[] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variable */
   char       byl1;                         /* working-variable        */
   char       chrlwork1[ 76 ];              /* buffer to print         */

   iml1 = 0;
   while (iml1 < implength) {
     iml2 = iml1 + 16;
     if (iml2 > implength) iml2 = implength;
     for ( iml3 = 4; iml3 < 75; iml3++ ) {
       chrlwork1[iml3] = ' ';
     }
     chrlwork1[58] = '*';
     chrlwork1[75] = '*';
     iml3 = 4;
     do {
       iml3--;
       chrlwork1[ iml3 ] = chrstrans[ (iml1 >> ((4 - 1 - iml3) << 2)) & 0X0F ];
     } while (iml3 > 0);
     iml4 = 6;                              /* start hexa digits here  */
     iml5 = 59;                             /* start ASCII here        */
     iml6 = 4;                              /* times normal            */
     do {
       byl1 = achp_buff[ iml1++ ];
       chrlwork1[ iml4++ ] = chrstrans[ (byl1 >> 4) & 0X0F ];
       chrlwork1[ iml4++ ] = chrstrans[ byl1 & 0X0F ];
       iml4++;
       if (byl1 > 0X20) {
         chrlwork1[ iml5 ] = byl1;
       }
       iml5++;
       iml6--;
       if (iml6 == 0) {
         iml4++;
         iml6 = 4;
       }
     } while (iml1 < iml2);
//   printf( "%.*s\n", sizeof(chrlwork1), chrlwork1 );
	 if(adsp_aux && !adsp_aux->amc_aux(adsp_aux->vpc_userfld, DEF_AUX_CONSOLE_OUT, chrlwork1, sizeof(chrlwork1) ))
		 return FALSE;
	 if(!adsp_aux)
		printf( "%.*s\n", (int)sizeof(chrlwork1), chrlwork1 );
   }
// fflush( stdout );
   return TRUE;
} /* end m_console_out()                                            */

/** dump gather to console                                             */
HL_LOCAL_SCOPE BOOL m_aux_dump_gather(struct dsd_aux_helper* adsp_aux, struct dsd_gather_i_1 *adsp_gather_i_1_in, int inp_limit) {  /* input data */
	adsp_aux = NULL;
   static const char chrstrans[] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variable */
   char       byl1;                         /* working-variable        */
   struct dsd_gather_i_1 *adsl_gai1_w1;     /* working-variable        */
   char       *achl_cur;                    /* position in gather      */
   char       byrlwork1[ 76 ];              /* buffer to print         */
	int        inl_limit = inp_limit;

   adsl_gai1_w1 = adsp_gather_i_1_in;
   if (adsl_gai1_w1 == NULL) return TRUE;
   achl_cur = adsl_gai1_w1->achc_ginp_cur;
   iml1 = 0;
   do {
     while (achl_cur >= adsl_gai1_w1->achc_ginp_end) {
       adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
       if (adsl_gai1_w1 == NULL) break;
       achl_cur = adsl_gai1_w1->achc_ginp_cur;
     }
     if (adsl_gai1_w1 == NULL) break;
     iml2 = iml1 + 16;
     for ( iml3 = 4; iml3 < 75; iml3++ ) {
       byrlwork1[iml3] = ' ';
     }
     byrlwork1[58] = '*';
     byrlwork1[75] = '*';
     iml3 = 4;
     do {
       iml3--;
       byrlwork1[ iml3 ] = chrstrans[ (iml1 >> ((4 - 1 - iml3) << 2)) & 0X0F ];
     } while (iml3 > 0);
     iml4 = 6;                              /* start hexa digits here  */
     iml5 = 59;                             /* start ASCII here        */
     iml6 = 4;                              /* times normal            */
     do {
       while (achl_cur >= adsl_gai1_w1->achc_ginp_end) {
         adsl_gai1_w1 = adsl_gai1_w1->adsc_next;
         if (adsl_gai1_w1 == NULL) break;
         achl_cur = adsl_gai1_w1->achc_ginp_cur;
       }
       if (adsl_gai1_w1 == NULL) break;
		 if(inp_limit >= 0) {
			 if(inl_limit <= 0) {
				 adsl_gai1_w1 = NULL;
				 goto LBL_DONE;
			 }
			 inl_limit--;
		 }
       byl1 = *achl_cur++;
       iml1++;
       byrlwork1[ iml4++ ] = chrstrans[ (byl1 >> 4) & 0X0F ];
       byrlwork1[ iml4++ ] = chrstrans[ byl1 & 0X0F ];
       iml4++;
       if (byl1 > 0X20) {
         byrlwork1[ iml5 ] = byl1;
       }
       iml5++;
       iml6--;
       if (iml6 == 0) {
         iml4++;
         iml6 = 4;
       }
     } while (iml1 < iml2);
LBL_DONE:
	 if(adsp_aux && !adsp_aux->amc_aux(adsp_aux->vpc_userfld, DEF_AUX_CONSOLE_OUT, byrlwork1, sizeof(byrlwork1) ))
		 return FALSE;
	 if(!adsp_aux)
		printf( "%.*s\n", (int)sizeof(byrlwork1), byrlwork1 );
   } while (adsl_gai1_w1);
   return TRUE;
} /* end m_dump_gather()                                               */

HL_LOCAL_SCOPE void m_gather_i_1_ref_inc(struct dsd_gather_i_1* adsp_g1, void* avop_userfld) {
	struct dsd_aux_helper* adsl_aux_helper = (struct dsd_aux_helper*)avop_userfld;
	adsl_aux_helper->amc_aux(adsl_aux_helper->vpc_userfld, DEF_AUX_MARK_WORKAREA_INC, adsp_g1, 0);
	adsl_aux_helper->amc_aux(adsl_aux_helper->vpc_userfld, DEF_AUX_MARK_WORKAREA_INC, adsp_g1->achc_ginp_cur, 0);
}

HL_LOCAL_SCOPE void m_gather_i_1_ref_dec(struct dsd_gather_i_1* adsp_g1, void* avop_userfld) {
	struct dsd_aux_helper* adsl_aux_helper = (struct dsd_aux_helper*)avop_userfld;
	adsl_aux_helper->amc_aux(adsl_aux_helper->vpc_userfld, DEF_AUX_MARK_WORKAREA_DEC, adsp_g1, 0);
	adsl_aux_helper->amc_aux(adsl_aux_helper->vpc_userfld, DEF_AUX_MARK_WORKAREA_DEC, adsp_g1->achc_ginp_cur, 0);
}

HL_LOCAL_SCOPE void m_gather_i_2_ref_inc(struct dsd_gather_i_2* adsp_g2, void* avop_userfld) {
	if(adsp_g2->adsc_owner == NULL)
		return;
	struct dsd_aux_helper* adsl_aux_helper = (struct dsd_aux_helper*)avop_userfld;
	adsl_aux_helper->amc_aux(adsl_aux_helper->vpc_userfld, DEF_AUX_MARK_WORKAREA_INC, adsp_g2->adsc_owner, 0);
}

HL_LOCAL_SCOPE void m_free_gather_i_2(struct dsd_gather_i_2* adsp_g2, struct dsd_aux_helper* adsp_aux_helper) {
	if(adsp_g2->adsc_owner == NULL)
		return;
	void* avol_wa = adsp_g2->adsc_owner;
	adsp_g2->adsc_owner = NULL;
	adsp_aux_helper->amc_aux(adsp_aux_helper->vpc_userfld, DEF_AUX_MARK_WORKAREA_DEC, avol_wa, 0);
}

HL_LOCAL_SCOPE void m_gather_i_2_ref_inc(struct dsd_gather_i_1* adsp_g1, void* avop_userfld) {
	struct dsd_gather_i_2* adsp_g2 = (struct dsd_gather_i_2*)adsp_g1;
	if(adsp_g2->adsc_owner == NULL)
		return;
	struct dsd_aux_helper* adsl_aux_helper = (struct dsd_aux_helper*)avop_userfld;
	adsl_aux_helper->amc_aux(adsl_aux_helper->vpc_userfld, DEF_AUX_MARK_WORKAREA_INC, adsp_g2->adsc_owner, 0);
}

HL_LOCAL_SCOPE void m_gather_i_2_ref_dec(struct dsd_gather_i_1* adsp_g1, void* avop_userfld) {
	struct dsd_gather_i_2* adsp_g2 = (struct dsd_gather_i_2*)adsp_g1;
	if(adsp_g2->adsc_owner == NULL)
		return;
	struct dsd_aux_helper* adsl_aux_helper = (struct dsd_aux_helper*)avop_userfld;
	adsl_aux_helper->amc_aux(adsl_aux_helper->vpc_userfld, DEF_AUX_MARK_WORKAREA_DEC, adsp_g2->adsc_owner, 0);
}

HL_LOCAL_SCOPE void m_gather_fifo_free_nothing(struct dsd_gather_i_1_fifo* adsp_list, struct dsd_gather_i_1* adsp_g) {
}

HL_LOCAL_SCOPE void m_gather_fifo_init(struct dsd_gather_i_1_fifo* adsp_fifo) {
	adsp_fifo->adsc_first = NULL;
	adsp_fifo->aads_tailp = &adsp_fifo->adsc_first;
	adsp_fifo->amp_free_cb = &m_gather_fifo_free_nothing;
}

HL_LOCAL_SCOPE void m_gather_fifo_reset(struct dsd_gather_i_1_fifo* adsp_fifo) {
	struct dsd_gather_i_1* adsl_cur = adsp_fifo->adsc_first;
	while(adsl_cur != NULL) {
		struct dsd_gather_i_1* adsl_next = adsl_cur->adsc_next;
		adsp_fifo->amp_free_cb(adsp_fifo, adsl_cur);
        adsl_cur = adsl_next;
    }
	adsp_fifo->adsc_first = NULL;
	adsp_fifo->aads_tailp = &adsp_fifo->adsc_first;
}

HL_LOCAL_SCOPE void m_gather_fifo_destroy(struct dsd_gather_i_1_fifo* adsp_fifo) {
	m_gather_fifo_reset(adsp_fifo);
}

HL_LOCAL_SCOPE struct dsd_gather_i_1* m_gather_fifo_get_last(struct dsd_gather_i_1_fifo* adsp_fifo) {
	if(adsp_fifo->adsc_first == NULL)
		return NULL;
	return HL_UPCAST(dsd_gather_i_1, adsc_next, adsp_fifo->aads_tailp);
}

HL_LOCAL_SCOPE void m_gather_fifo_append(struct dsd_gather_i_1_fifo* adsp_fifo, struct dsd_gather_i_1* adsp_elem) {
	*adsp_fifo->aads_tailp = adsp_elem;
	adsp_fifo->aads_tailp = &adsp_elem->adsc_next;
}

HL_LOCAL_SCOPE void m_gather_fifo_append_list(struct dsd_gather_i_1_fifo* adsp_fifo, struct dsd_gather_i_1* adsp_first, struct dsd_gather_i_1* adsp_last) {
	if(adsp_first == NULL)
		return;
	*adsp_fifo->aads_tailp = adsp_first;
	adsp_fifo->aads_tailp = &adsp_last->adsc_next;
}

HL_LOCAL_SCOPE void m_gather_fifo_append_list(struct dsd_gather_i_1_fifo* adsp_fifo, struct dsd_gather_i_1_fifo* adsp_list) {
	m_gather_fifo_append_list(adsp_fifo, adsp_list->adsc_first, m_gather_fifo_get_last(adsp_list));
	adsp_list->adsc_first = NULL;
	adsp_list->aads_tailp = &adsp_list->adsc_first;
}

HL_LOCAL_SCOPE void m_gather_fifo_append_list2(struct dsd_gather_i_1_fifo* adsp_fifo, struct dsd_gather_i_1* adsp_elem) {
	if(adsp_elem == NULL)
		return;
	struct dsd_gather_i_1* adsl_last = adsp_elem;
	while(adsl_last->adsc_next != NULL)
		adsl_last = adsl_last->adsc_next;
	*adsp_fifo->aads_tailp = adsp_elem;
	adsp_fifo->aads_tailp = &adsl_last->adsc_next;
}

HL_LOCAL_SCOPE void m_gather_fifo_append_fifo(struct dsd_gather_i_1_fifo* adsp_fifo, struct dsd_gather_i_1_fifo* adsp_add) {
	m_gather_fifo_append_list(adsp_fifo, adsp_add->adsc_first, m_gather_fifo_get_last(adsp_add));
	m_gather_fifo_init(adsp_add);
}

HL_LOCAL_SCOPE struct dsd_gather_i_1* m_gather_fifo_free_processed(struct dsd_gather_i_1_fifo* adsp_fifo) {
	struct dsd_gather_i_1* adsl_cur = adsp_fifo->adsc_first;
	while(adsl_cur != NULL) {
        if(adsl_cur->achc_ginp_cur < adsl_cur->achc_ginp_end) {
			adsp_fifo->adsc_first = adsl_cur;
            return adsl_cur;
		}
		struct dsd_gather_i_1* adsl_next = adsl_cur->adsc_next;
		adsp_fifo->amp_free_cb(adsp_fifo, adsl_cur);
        adsl_cur = adsl_next;
    }
	adsp_fifo->adsc_first = NULL;
	adsp_fifo->aads_tailp = &adsp_fifo->adsc_first;
    return adsl_cur;
}

typedef void (*amd_gather_i_1_cb_t)(struct dsd_gather_i_1* adsp_g, void* avop_userfld);

HL_LOCAL_SCOPE void m_gather_fifo_foreach(struct dsd_gather_i_1_fifo* adsp_list, amd_gather_i_1_cb_t amp_cb, void* avop_userfld) {
	struct dsd_gather_i_1* adsl_cur = adsp_list->adsc_first;
	while(adsl_cur != NULL) {
		struct dsd_gather_i_1* adsl_next = adsl_cur->adsc_next;
		amp_cb(adsl_cur, avop_userfld);
        adsl_cur = adsl_next;
    }
}

HL_LOCAL_SCOPE void m_gather_fifo_aux_free(struct dsd_gather_i_1_fifo* adsp_list, struct dsd_gather_i_1* adsp_g) {
	struct dsd_gather_i_2* adsl_g2 = (struct dsd_gather_i_2*)adsp_g;
	if(adsl_g2->adsc_owner == NULL)
		return;
	struct dsd_aux_helper* adsl_aux_helper = ((struct dsd_gather_i_1_fifo_aux*)adsp_list)->adsc_aux;
	m_free_gather_i_2(adsl_g2, adsl_aux_helper);
}

HL_LOCAL_SCOPE void m_gather3_list_free_nothing(struct dsd_gather_i_3_list* adsp_list, struct dsd_gather_i_3* adsp_g) {
}

HL_LOCAL_SCOPE void m_gather3_list_init(struct dsd_gather_i_3_list* adsp_fifo) {
	adsp_fifo->dsc_head.adsc_owner = NULL;
	adsp_fifo->dsc_head.dsc_base.achc_ginp_cur = NULL;
	adsp_fifo->dsc_head.dsc_base.achc_ginp_end = NULL;
	adsp_fifo->dsc_head.dsc_base.adsc_next = &adsp_fifo->dsc_head.dsc_base;
	adsp_fifo->dsc_head.adsc_prev = &adsp_fifo->dsc_head;
	adsp_fifo->amc_free_cb = &m_gather3_list_free_nothing;
}

HL_LOCAL_SCOPE BOOL m_gather3_list_get_first(struct dsd_gather_i_3_list* adsp_fifo, struct dsd_gather_i_3_itr* adsp_itr) {
	struct dsd_gather_i_3* adsl_cur = (struct dsd_gather_i_3*)adsp_fifo->dsc_head.dsc_base.adsc_next;
	if(adsl_cur == &adsp_fifo->dsc_head) {
		adsp_itr->adsc_head = NULL;
		adsp_itr->adsc_cur = NULL;
		return FALSE;
	}
	adsp_itr->adsc_cur = adsl_cur;
	adsp_itr->adsc_head = &adsp_fifo->dsc_head;
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gather3_list_get_last(struct dsd_gather_i_3_list* adsp_fifo, struct dsd_gather_i_3_itr* adsp_itr) {
	struct dsd_gather_i_3* adsl_cur = (struct dsd_gather_i_3*)adsp_fifo->dsc_head.adsc_prev;
	if(adsl_cur == &adsp_fifo->dsc_head) {
		adsp_itr->adsc_head = NULL;
		adsp_itr->adsc_cur = NULL;
		return FALSE;
	}
	adsp_itr->adsc_cur = adsl_cur;
	adsp_itr->adsc_head = &adsp_fifo->dsc_head;
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gather3_list_get_itr(struct dsd_gather_i_3_list* adsp_fifo, struct dsd_gather_i_3* adsp_elem, struct dsd_gather_i_3_itr* adsp_itr) {
	if(adsp_elem->dsc_base.adsc_next == NULL)
		return FALSE;
	if(adsp_elem->adsc_prev == NULL)
		return FALSE;
	adsp_itr->adsc_cur = adsp_elem;
	adsp_itr->adsc_head = &adsp_fifo->dsc_head;
#if 0
	if(adsp_elem == &adsp_fifo->dsc_head) {
		adsp_itr->adsc_cur = NULL;
		return TRUE;
	}
#endif
	return TRUE;
}

HL_LOCAL_SCOPE void m_gather3_list_destroy(struct dsd_gather_i_3_list* adsp_fifo) {
	struct dsd_gather_i_3* adsl_cur = (struct dsd_gather_i_3*)adsp_fifo->dsc_head.dsc_base.adsc_next;
	while(adsl_cur != &adsp_fifo->dsc_head) {
		struct dsd_gather_i_3* adsl_next = (struct dsd_gather_i_3*)adsl_cur->dsc_base.adsc_next;
		adsp_fifo->amc_free_cb(adsp_fifo, adsl_cur);
        adsl_cur = adsl_next;
    }
	adsp_fifo->dsc_head.dsc_base.adsc_next = &adsp_fifo->dsc_head.dsc_base;
	adsp_fifo->dsc_head.adsc_prev = &adsp_fifo->dsc_head;
}

HL_LOCAL_SCOPE void m_gather3_list_release(struct dsd_gather_i_3_list* adsp_fifo) {
	adsp_fifo->dsc_head.adsc_prev->dsc_base.adsc_next = NULL;
	((struct dsd_gather_i_3*)adsp_fifo->dsc_head.dsc_base.adsc_next)->adsc_prev = NULL;
	adsp_fifo->dsc_head.dsc_base.adsc_next = &adsp_fifo->dsc_head.dsc_base;
	adsp_fifo->dsc_head.adsc_prev = &adsp_fifo->dsc_head;
}

HL_LOCAL_SCOPE void m_gather3_list_release(struct dsd_gather_i_3_list* adsp_list, struct dsd_gather_i_1_fifo* adsp_receiver) {
	struct dsd_gather_i_3_itr dsl_first;
	if(!m_gather3_list_get_first(adsp_list, &dsl_first))
		return;
	struct dsd_gather_i_3_itr dsl_last;
	if(!m_gather3_list_get_last(adsp_list, &dsl_last))
		return;
	m_gather3_list_release(adsp_list);
	m_gather_fifo_append_list(adsp_receiver, &dsl_first.adsc_cur->dsc_base, &dsl_last.adsc_cur->dsc_base);
}

HL_LOCAL_SCOPE void m_gather3_list_append(struct dsd_gather_i_3_list* adsp_fifo, struct dsd_gather_i_3* adsp_elem) {
	adsp_elem->dsc_base.adsc_next = &adsp_fifo->dsc_head.dsc_base;
	adsp_elem->adsc_prev = adsp_fifo->dsc_head.adsc_prev;
	adsp_fifo->dsc_head.adsc_prev->dsc_base.adsc_next = &adsp_elem->dsc_base;
	adsp_fifo->dsc_head.adsc_prev = adsp_elem;
}

HL_LOCAL_SCOPE void m_gather3_list_prepend(struct dsd_gather_i_3_list* adsp_fifo, struct dsd_gather_i_3* adsp_elem) {
	struct dsd_gather_i_3* adsl_first = ((struct dsd_gather_i_3*)adsp_fifo->dsc_head.dsc_base.adsc_next);
	adsp_elem->dsc_base.adsc_next = &adsl_first->dsc_base;
	adsp_elem->adsc_prev = &adsp_fifo->dsc_head;
	adsl_first->adsc_prev = adsp_elem;
	adsp_fifo->dsc_head.dsc_base.adsc_next = &adsp_elem->dsc_base;
}

HL_LOCAL_SCOPE void m_gather3_list_remove(struct dsd_gather_i_3_list* adsp_fifo, struct dsd_gather_i_3* adsp_elem) {
	assert(adsp_elem != &adsp_fifo->dsc_head);
	struct dsd_gather_i_3* adsl_prev = adsp_elem->adsc_prev;
	struct dsd_gather_i_3* adsl_next = ((struct dsd_gather_i_3*)adsp_elem->dsc_base.adsc_next);
	adsl_prev->dsc_base.adsc_next = &adsl_next->dsc_base;
	adsl_next->adsc_prev = adsl_prev;
	adsp_elem->adsc_prev = NULL;
	adsp_elem->dsc_base.adsc_next = NULL;
}

HL_LOCAL_SCOPE BOOL m_gather3_itr_next(struct dsd_gather_i_3_itr* adsp_itr) {
	struct dsd_gather_i_3* adsl_cur = (struct dsd_gather_i_3*)adsp_itr->adsc_cur->dsc_base.adsc_next;
	if(adsl_cur == adsp_itr->adsc_head) {
		adsp_itr->adsc_cur = NULL;
		return FALSE;
	}
	adsp_itr->adsc_cur = adsl_cur;
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gather3_itr_prev(struct dsd_gather_i_3_itr* adsp_itr) {
	struct dsd_gather_i_3* adsl_cur = adsp_itr->adsc_cur->adsc_prev;
	if(adsl_cur == adsp_itr->adsc_head) {
		adsp_itr->adsc_cur = NULL;
		return FALSE;
	}
	adsp_itr->adsc_cur = adsl_cur;
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gather3_itr_remove(struct dsd_gather_i_3_itr* adsp_itr) {
	struct dsd_gather_i_3* adsl_cur = adsp_itr->adsc_cur;
	if(adsl_cur == adsp_itr->adsc_head) {
		return FALSE;
	}
	struct dsd_gather_i_3* adsl_prev = adsl_cur->adsc_prev;
	struct dsd_gather_i_3* adsl_next = ((struct dsd_gather_i_3*)adsl_cur->dsc_base.adsc_next);
	adsl_prev->dsc_base.adsc_next = &adsl_next->dsc_base;
	adsl_next->adsc_prev = adsl_prev;
	adsl_cur->adsc_prev = NULL;
	adsl_cur->dsc_base.adsc_next = NULL;
	return TRUE;
}

#if 0
HL_LOCAL_SCOPE void m_gather3_list_append_list(struct dsd_gather_i_2_list* adsp_fifo, struct dsd_gather_i_2* adsp_elem) {
	if(adsp_elem == NULL)
		return;
	struct dsd_gather_i_1* adsl_last = adsp_elem;
	while(adsl_last->adsc_next != NULL)
		adsl_last = adsl_last->adsc_next;
	*adsp_fifo->aads_tailp = adsp_elem;
	adsp_fifo->aads_tailp = &adsl_last->adsc_next;
}
#endif

HL_LOCAL_SCOPE struct dsd_managed_workarea* m_wa_chain_alloc(struct dsd_workarea_chain* adsp_wa_chain, size_t szp_size) {
	struct dsd_aux_helper* adsl_aux = adsp_wa_chain->adsc_aux; 
	struct dsd_managed_workarea* adsl_workarea_1_w1;
	if(!adsl_aux->amc_aux(adsl_aux->vpc_userfld, DEF_AUX_MEMGET, &adsl_workarea_1_w1, sizeof(struct dsd_managed_workarea) + szp_size))
		return NULL;
	adsl_workarea_1_w1->inc_usage_count = 1;
    adsl_workarea_1_w1->adsc_next = adsp_wa_chain->adsc_workarea_1;
    adsp_wa_chain->adsc_workarea_1 = adsl_workarea_1_w1;  /* set new chain */
	return adsl_workarea_1_w1;
}

HL_LOCAL_SCOPE BOOL m_wa_chain_free_wa(struct dsd_workarea_chain* adsp_wa_chain, struct dsd_managed_workarea* adsp_wa) {
	struct dsd_aux_helper* adsl_aux = adsp_wa_chain->adsc_aux; 
	adsp_wa->inc_usage_count--;
	if(adsp_wa->inc_usage_count > 0)
		return TRUE;
	if(!adsl_aux->amc_aux(adsl_aux->vpc_userfld, DEF_AUX_MEMFREE, &adsp_wa, 0))
		return FALSE;
	return TRUE;
}

HL_LOCAL_SCOPE void m_free_data_block(struct dsd_slist_element* adsp_g, void* avop_userfld) {
	struct dsd_data_block* adsl_g2 = HL_UPCAST(struct dsd_data_block, dsc_slist_elem, adsp_g);
	struct dsd_aux_helper* adsl_aux_helper = (struct dsd_aux_helper*)avop_userfld;
	//void* avol_wa = adsl_g2->adsc_owner;
	//adsl_g2->adsc_owner = NULL;
	//adsl_aux_helper->amc_aux(adsl_aux_helper->vpc_userfld, DEF_AUX_MARK_WORKAREA_DEC, avol_wa, 0);
	dsd_managed_workarea* adsl_wa = adsl_g2->dsc_workareas.adsc_workarea_1;
	while(adsl_wa != NULL) {
		dsd_managed_workarea* adsl_wa2 = adsl_wa->adsc_next;
		m_wa_chain_free_wa(&adsl_g2->dsc_workareas, adsl_wa);
		adsl_wa = adsl_wa2;
	}
	if(adsl_g2->adsc_wa1 != NULL)
		adsl_aux_helper->amc_aux(adsl_aux_helper->vpc_userfld, DEF_AUX_MARK_WORKAREA_DEC, adsl_g2->adsc_wa1, 0);
	adsl_aux_helper->amc_aux(adsl_aux_helper->vpc_userfld, DEF_AUX_MARK_WORKAREA_DEC, adsl_g2->adsc_wa2, 0);
}

HL_LOCAL_SCOPE BOOL m_subaux_wa_allocator_intern( void * vpp_userfld, int imp_func, void * ap_param, int imp_length ) {
   struct dsd_workarea_chain* ADSL_CONN_1_G = ((struct dsd_workarea_chain *) vpp_userfld);
   struct dsd_aux_helper* adsl_aux = ADSL_CONN_1_G->adsc_aux; 
   switch (imp_func) {                      /* depend on function      */
     case DEF_AUX_GET_WORKAREA:             /* get additional work area */
     {
       if (imp_length != sizeof(struct dsd_aux_get_workarea)) return FALSE;
	   dsd_aux_get_workarea* ADSL_AUX_GET_WORKAREA = ((struct dsd_aux_get_workarea *) ap_param);
       struct dsd_managed_workarea* adsl_workarea_1_w1;
#if SM_MINIFY_WORKAREAS
	   int inl_size = 256 - sizeof(struct dsd_managed_workarea);
#else
	   int inl_size = 4096 - sizeof(struct dsd_managed_workarea);
#endif
	   if(ADSL_AUX_GET_WORKAREA->imc_len_work_area > inl_size)
		   inl_size = ADSL_AUX_GET_WORKAREA->imc_len_work_area;
	   adsl_workarea_1_w1 = m_wa_chain_alloc(ADSL_CONN_1_G, inl_size);
	   if(adsl_workarea_1_w1 == NULL)
		   return FALSE;
       ADSL_AUX_GET_WORKAREA->achc_work_area = (char *) (ADSL_CONN_1_G->adsc_workarea_1 + 1);
       ADSL_AUX_GET_WORKAREA->imc_len_work_area = inl_size;
       return TRUE;                         /* all done                */
	 }
	 case DEF_AUX_MARK_WORKAREA_INC:
	 {
		 struct dsd_managed_workarea* adsl_workarea_1_w1 = ((struct dsd_managed_workarea*)ap_param)-1;
		 adsl_workarea_1_w1->inc_usage_count++;
		 return TRUE;
	 }
	 case DEF_AUX_MARK_WORKAREA_DEC:
	 {
		 struct dsd_managed_workarea* adsl_workarea_1_w1 = ((struct dsd_managed_workarea*)ap_param)-1;
		 return m_wa_chain_free_wa(ADSL_CONN_1_G, adsl_workarea_1_w1);
	 }
   }
   return adsl_aux->amc_aux(adsl_aux->vpc_userfld, imp_func, ap_param, imp_length);
}

HL_LOCAL_SCOPE BOOL m_subaux_wa_allocator_extern( void * vpp_userfld, int imp_func, void * ap_param, int imp_length ) {
   struct dsd_workarea_chain* ADSL_CONN_1_G = ((struct dsd_workarea_chain *) vpp_userfld);
   struct dsd_aux_helper* adsl_aux = ADSL_CONN_1_G->adsc_aux; 
   switch (imp_func) {                      /* depend on function      */
     case DEF_AUX_GET_WORKAREA:             /* get additional work area */
	 {
       dsd_aux_get_workarea* ADSL_AUX_GET_WORKAREA = ((struct dsd_aux_get_workarea *) ap_param);
	   int inl_min_size = ADSL_AUX_GET_WORKAREA->imc_len_work_area;
	   if(!adsl_aux->amc_aux(adsl_aux->vpc_userfld, imp_func, ap_param, imp_length))
		   return FALSE;
#if SM_MINIFY_WORKAREAS
	   if(ADSL_AUX_GET_WORKAREA->imc_len_work_area > inl_min_size)
		   ADSL_AUX_GET_WORKAREA->imc_len_work_area = inl_min_size;
#endif
	   return TRUE;
	 }
	 case DEF_AUX_MARK_WORKAREA_INC:
		 return TRUE;
	 case DEF_AUX_MARK_WORKAREA_DEC:
		 return TRUE;
   }
   return adsl_aux->amc_aux(adsl_aux->vpc_userfld, imp_func, ap_param, imp_length);
}

HL_LOCAL_SCOPE struct dsd_gather_i_1_pos m_make_gather_pos(dsd_gather_i_1* adsp_cur) {
	if(adsp_cur != NULL) {
		dsd_gather_i_1_pos dsl_in_cl1 = { adsp_cur, adsp_cur->achc_ginp_cur };
		return dsl_in_cl1;
	}
	dsd_gather_i_1_pos dsl_in_cl1 = { NULL, NULL };
	return dsl_in_cl1;
}

HL_LOCAL_SCOPE bool m_cmp_gather_pos(const dsd_gather_i_1_pos* adsp_p1, const dsd_gather_i_1_pos* adsp_p2) {
	return adsp_p1->adsc_gather == adsp_p2->adsc_gather && adsp_p1->achc_pos == adsp_p2->achc_pos;
}

HL_LOCAL_SCOPE void m_write_uint32_le(char* achp_dst, uint32_t ump_value) {
	achp_dst[0] = (char)ump_value;
	achp_dst[1] = (char)(ump_value>>8);
	achp_dst[2] = (char)(ump_value>>16);
	achp_dst[3] = (char)(ump_value>>24);
}

struct dsd_gather_writer {
	struct dsd_gather_i_3_list dsc_fifo;
	struct dsd_workarea_allocator* adsc_wa_alloc;
	struct dsd_workarea_allocator dsc_wa_front;
	struct dsd_workarea_allocator dsc_wa_back;
	struct dsd_workarea_allocator* adsc_wa_cur;
	struct dsd_gather_i_3* adsc_gather_cur;
	char* achc_lower;
	char* achc_cur;
	char* achc_upper;
	int inc_lower_abs_pos;
};

struct dsd_gather_writer_pos {
	struct dsd_gather_i_3* adsc_gather_cur;
	char* achc_cur;
	char* achc_lower;
	int inc_abs_pos;
};

HL_LOCAL_SCOPE void m_gw_list_free_gather_i_3(struct dsd_gather_i_3_list* adsp_list, struct dsd_gather_i_3* adsp_g) {
	if(adsp_g->adsc_owner == NULL)
		return;
	struct dsd_gather_writer* adsl_gw = HL_UPCAST(struct dsd_gather_writer, dsc_fifo, adsp_list);
	struct dsd_aux_helper* adsl_aux_helper = adsl_gw->adsc_wa_alloc->adsc_aux;
	m_free_gather_i_2((struct dsd_gather_i_2*)adsp_g, adsl_aux_helper);
}

HL_LOCAL_SCOPE void m_gw_init(struct dsd_gather_writer* adsp_gw, struct dsd_workarea_allocator* adsp_wa_alloc) {
	m_gather3_list_init(&adsp_gw->dsc_fifo);
	adsp_gw->dsc_fifo.amc_free_cb = m_gw_list_free_gather_i_3;
	adsp_gw->adsc_wa_alloc = adsp_wa_alloc;
	m_wa_allocator_init(&adsp_gw->dsc_wa_front);
	m_wa_allocator_init(&adsp_gw->dsc_wa_back);
	adsp_gw->adsc_wa_cur = NULL;
	adsp_gw->adsc_gather_cur = &adsp_gw->dsc_fifo.dsc_head;
	adsp_gw->achc_lower = NULL;
	adsp_gw->achc_cur = NULL;
	adsp_gw->achc_upper = NULL;
	adsp_gw->inc_lower_abs_pos = 0;
}

HL_LOCAL_SCOPE BOOL m_gw_flush_gather_start(struct dsd_gather_writer* adsp_gw, struct dsd_workarea_allocator* adsp_context) {
	struct dsd_gather_i_3* adsl_gather_cur = adsp_gw->adsc_gather_cur;
	if(adsl_gather_cur == NULL)
		return FALSE;
	if(adsp_context == NULL)
		return FALSE;
	if(adsp_context != &adsp_gw->dsc_wa_front) {
		return FALSE;
	}
	//if(adsp_gw->adsc_gather_cur->adsc_owner != adsp_gw->adsc_wa_alloc->adsc_wa_cur)
	//	return FALSE;
	char* achl_cur = adsp_gw->achc_cur;
	char* achl_lower = adsp_gw->achc_lower;
	char* achl_upper = adsp_gw->achc_upper;
	adsp_gw->inc_lower_abs_pos -= (adsl_gather_cur->dsc_base.achc_ginp_cur-achl_cur);
	adsl_gather_cur->dsc_base.achc_ginp_cur = achl_cur;
	m_wa_allocator_commit_upper(adsp_context, achl_cur);
	adsp_gw->achc_lower = achl_cur;
	if(adsl_gather_cur->adsc_owner == NULL)
		adsl_gather_cur->adsc_owner = m_wa_allocator_share_inc(adsp_context);
	m_wa_allocator_swap(adsp_gw->adsc_wa_alloc, adsp_context);
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gw_flush_gather_end(struct dsd_gather_writer* adsp_gw, struct dsd_workarea_allocator* adsp_context) {
	struct dsd_gather_i_3* adsl_gather_cur = adsp_gw->adsc_gather_cur;
	if(adsl_gather_cur == NULL)
		return FALSE;
	if(adsp_context == NULL)
		return FALSE;
	if(adsp_context != &adsp_gw->dsc_wa_back) {
		return FALSE;
	}
	//if(adsp_gw->adsc_gather_cur->adsc_owner != adsp_gw->adsc_wa_alloc->adsc_wa_cur)
	//	return FALSE;
	char* achl_cur = adsp_gw->achc_cur;
	char* achl_lower = adsp_gw->achc_lower;
	char* achl_upper = adsp_gw->achc_upper;
	adsl_gather_cur->dsc_base.achc_ginp_end = achl_cur;
	m_wa_allocator_commit_lower(adsp_context, achl_cur);
	adsp_gw->achc_upper = achl_cur;
	if(adsl_gather_cur->adsc_owner == NULL)
		adsl_gather_cur->adsc_owner = m_wa_allocator_share_inc(adsp_context);
	m_wa_allocator_swap(adsp_gw->adsc_wa_alloc, adsp_context);
	return TRUE;
}

HL_LOCAL_SCOPE void m_gw_destroy(struct dsd_gather_writer* adsp_gw) {
	m_gather3_list_destroy(&adsp_gw->dsc_fifo);
	if(m_wa_allocator_available(&adsp_gw->dsc_wa_front) > m_wa_allocator_available(adsp_gw->adsc_wa_alloc))
		m_wa_allocator_swap(adsp_gw->adsc_wa_alloc, &adsp_gw->dsc_wa_front);
	m_wa_allocator_destroy(&adsp_gw->dsc_wa_front);
	if(m_wa_allocator_available(&adsp_gw->dsc_wa_back) > m_wa_allocator_available(adsp_gw->adsc_wa_alloc))
		m_wa_allocator_swap(adsp_gw->adsc_wa_alloc, &adsp_gw->dsc_wa_back);
	m_wa_allocator_destroy(&adsp_gw->dsc_wa_back);
}

HL_LOCAL_SCOPE BOOL m_gw_mark_start(struct dsd_gather_writer* adsp_gw) {
	if(adsp_gw->adsc_wa_alloc == NULL)
		return FALSE;
	if(m_gw_flush_gather_start(adsp_gw, adsp_gw->adsc_wa_cur))
		return TRUE;
	struct dsd_gather_i_3_itr dsl_itr;
	if(!m_gather3_list_get_itr(&adsp_gw->dsc_fifo, adsp_gw->adsc_gather_cur, &dsl_itr))
		return FALSE;
	dsl_itr.adsc_cur->dsc_base.achc_ginp_cur = adsp_gw->achc_cur;
	if(!m_gather3_itr_prev(&dsl_itr))
		return TRUE;
	BOOL bol_next;
	do {
		struct dsd_gather_i_3* adsl_cur = dsl_itr.adsc_cur;
		bol_next = m_gather3_itr_prev(&dsl_itr);
		m_gather3_list_remove(&adsp_gw->dsc_fifo, adsl_cur);
		adsp_gw->dsc_fifo.amc_free_cb(&adsp_gw->dsc_fifo, adsl_cur);
	} while(bol_next);
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gw_mark_end(struct dsd_gather_writer* adsp_gw) {
	if(adsp_gw->adsc_wa_alloc == NULL)
		return FALSE;
	if(m_gw_flush_gather_end(adsp_gw, adsp_gw->adsc_wa_cur))
		return TRUE;
	struct dsd_gather_i_3_itr dsl_itr;
	if(!m_gather3_list_get_itr(&adsp_gw->dsc_fifo, adsp_gw->adsc_gather_cur, &dsl_itr))
		return FALSE;
	dsl_itr.adsc_cur->dsc_base.achc_ginp_end = adsp_gw->achc_cur;
	if(!m_gather3_itr_next(&dsl_itr)) {
		return TRUE;
	}
	BOOL bol_next;
	do {
		struct dsd_gather_i_3* adsl_cur = dsl_itr.adsc_cur;
		bol_next = m_gather3_itr_next(&dsl_itr);
		m_gather3_list_remove(&adsp_gw->dsc_fifo, adsl_cur);
		adsp_gw->dsc_fifo.amc_free_cb(&adsp_gw->dsc_fifo, adsl_cur);
	} while(bol_next);
	return TRUE;
}

#if 0
HL_LOCAL_SCOPE BOOL m_gw_end(struct dsd_gather_writer* adsp_gw) {
	if(adsp_gw->adsc_wa_alloc == NULL)
		return FALSE;
	//m_gw_flush_gather(adsp_gw);
	adsp_gw->adsc_wa_alloc = NULL;
	return TRUE;
}
#endif

HL_LOCAL_SCOPE BOOL m_gw_alloc_gather(struct dsd_gather_writer* adsp_gw, struct dsd_workarea_allocator* adsp_context) {
LBL_AGAIN:
	struct dsd_gather_i_3* adsl_gather_cur = (struct dsd_gather_i_3*)m_wa_allocator_alloc_lower(
		adsp_context, sizeof(struct dsd_gather_i_3), HL_ALIGNOF(struct dsd_gather_i_3));
	if(adsl_gather_cur == NULL) {
		if(!m_wa_allocator_reserve_lower(adsp_gw->adsc_wa_alloc, sizeof(struct dsd_gather_i_3)+1, HL_ALIGNOF(struct dsd_gather_i_3)))
			return FALSE;
		m_wa_allocator_release(adsp_gw->adsc_wa_alloc, adsp_context);
		goto LBL_AGAIN;
	}
	adsp_gw->inc_lower_abs_pos += adsp_gw->adsc_gather_cur->dsc_base.achc_ginp_end-adsp_gw->adsc_gather_cur->dsc_base.achc_ginp_cur;
	adsp_gw->adsc_gather_cur = adsl_gather_cur;
	adsp_gw->achc_lower = adsp_context->achc_lower;
	adsp_gw->achc_cur = adsp_context->achc_lower;
	adsp_gw->achc_upper = adsp_context->achc_upper;
	adsl_gather_cur->dsc_base.achc_ginp_cur = adsp_context->achc_lower;
	adsl_gather_cur->dsc_base.achc_ginp_end = adsp_context->achc_lower;
	adsl_gather_cur->dsc_base.adsc_next = NULL;
	adsl_gather_cur->adsc_owner = NULL;
	adsl_gather_cur->adsc_prev = NULL;
	adsp_gw->adsc_wa_cur = adsp_context;
	m_gather3_list_append(&adsp_gw->dsc_fifo, adsl_gather_cur);
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gw_alloc_gather2(struct dsd_gather_writer* adsp_gw, struct dsd_workarea_allocator* adsp_context) {
LBL_AGAIN:
	struct dsd_gather_i_3* adsl_gather_cur = (struct dsd_gather_i_3*)m_wa_allocator_alloc_upper(
		adsp_context, sizeof(struct dsd_gather_i_3), HL_ALIGNOF(struct dsd_gather_i_3));
	if(adsl_gather_cur == NULL) {
		if(!m_wa_allocator_reserve_upper(adsp_gw->adsc_wa_alloc, sizeof(struct dsd_gather_i_3)+1, HL_ALIGNOF(struct dsd_gather_i_3)))
			return FALSE;
		m_wa_allocator_release(adsp_gw->adsc_wa_alloc, adsp_context);
		goto LBL_AGAIN;
	}
	adsp_gw->inc_lower_abs_pos -= adsp_gw->adsc_gather_cur->dsc_base.achc_ginp_end-adsp_gw->adsc_gather_cur->dsc_base.achc_ginp_cur;
	adsp_gw->adsc_gather_cur = adsl_gather_cur;
	adsp_gw->achc_lower = adsp_context->achc_lower;
	adsp_gw->achc_cur = adsp_context->achc_upper;
	adsp_gw->achc_upper = adsp_context->achc_upper;
	adsl_gather_cur->dsc_base.achc_ginp_cur = adsp_context->achc_upper;
	adsl_gather_cur->dsc_base.achc_ginp_end = adsp_context->achc_upper;
	adsl_gather_cur->dsc_base.adsc_next = NULL;
	adsl_gather_cur->adsc_owner = NULL;
	adsl_gather_cur->adsc_prev = NULL;
	adsp_gw->adsc_wa_cur = adsp_context;
	m_gather3_list_prepend(&adsp_gw->dsc_fifo, adsl_gather_cur);
	return TRUE;
}

#if 0
HL_LOCAL_SCOPE BOOL m_gw_start(struct dsd_gather_writer* adsp_gw, struct dsd_workarea_allocator* adsp_wa_alloc) {
	if(adsp_gw->adsc_wa_alloc != NULL)
		return FALSE;
	adsp_gw->adsc_wa_alloc = adsp_wa_alloc;
	//return m_gw_alloc_gather(adsp_gw, &adsp_gw->dsc_wa_back);
	return TRUE;
}
#endif

HL_LOCAL_SCOPE int m_gw_get_abs_pos(const struct dsd_gather_writer* adsp_gw) {
	return adsp_gw->inc_lower_abs_pos + (adsp_gw->achc_cur-adsp_gw->adsc_gather_cur->dsc_base.achc_ginp_cur);
}

HL_LOCAL_SCOPE void m_gw_get_position(const struct dsd_gather_writer* adsp_gw, struct dsd_gather_writer_pos* adsp_pos) {
	adsp_pos->adsc_gather_cur = adsp_gw->adsc_gather_cur;
	adsp_pos->achc_cur = adsp_gw->achc_cur;
	adsp_pos->achc_lower = adsp_gw->adsc_gather_cur->dsc_base.achc_ginp_cur;
	adsp_pos->inc_abs_pos = adsp_gw->inc_lower_abs_pos + (adsp_pos->achc_cur-adsp_pos->achc_lower);
}

HL_LOCAL_SCOPE void m_gw_set_position(struct dsd_gather_writer* adsp_gw, const struct dsd_gather_writer_pos* adsp_pos) {
	adsp_gw->adsc_gather_cur = adsp_pos->adsc_gather_cur;
	adsp_gw->achc_cur = adsp_pos->achc_cur;
#if 0
	if(adsp_gw->adsc_gather_cur == NULL) {
		adsp_gw->achc_lower = NULL;
		adsp_gw->achc_upper = NULL;
		adsp_gw->adsc_wa_cur = NULL;
		return;
	}
#endif
	adsp_gw->achc_lower = adsp_pos->adsc_gather_cur->dsc_base.achc_ginp_cur;
	adsp_gw->achc_upper = adsp_pos->adsc_gather_cur->dsc_base.achc_ginp_end;
	adsp_gw->inc_lower_abs_pos = adsp_pos->inc_abs_pos - (adsp_pos->achc_cur-adsp_pos->achc_lower);
	adsp_gw->adsc_wa_cur = NULL;

	if(adsp_gw->achc_upper == adsp_gw->dsc_wa_back.achc_lower) {
		adsp_gw->adsc_wa_cur = &adsp_gw->dsc_wa_back;
		adsp_gw->achc_upper = adsp_gw->dsc_wa_back.achc_upper;
		return;
	}
	if(adsp_gw->achc_lower == adsp_gw->dsc_wa_back.achc_lower) {
		assert(adsp_gw->achc_upper == adsp_gw->dsc_wa_back.achc_upper);
		adsp_gw->adsc_wa_cur = &adsp_gw->dsc_wa_back;
		return;
	}
	if(adsp_gw->achc_lower == adsp_gw->dsc_wa_front.achc_upper) {
		adsp_gw->adsc_wa_cur = &adsp_gw->dsc_wa_front;
		adsp_gw->achc_lower = adsp_gw->dsc_wa_back.achc_lower;
		return;
	}
	if(adsp_gw->achc_upper == adsp_gw->dsc_wa_front.achc_upper) {
		assert(adsp_gw->achc_upper == adsp_gw->dsc_wa_front.achc_upper);
		adsp_gw->adsc_wa_cur = &adsp_gw->dsc_wa_front;
		return;
	}
#if 0
	struct dsd_gather_i_3_itr dsl_itr;
	if(!m_gather3_list_get_first(&adsp_gw->dsc_fifo, &dsl_itr))
		return;
	struct dsd_gather_i_3_itr dsl_itr2;
	if(!m_gather3_list_get_last(&adsp_gw->dsc_fifo, &dsl_itr2))
		return;
	assert(dsl_itr.adsc_cur != adsp_gw->adsc_gather_cur);
	assert(dsl_itr2.adsc_cur != adsp_gw->adsc_gather_cur);
#endif
}

HL_LOCAL_SCOPE BOOL m_gw_next_gather(struct dsd_gather_writer* adsp_gw) {
	struct dsd_gather_i_3_itr dsl_itr;
	if(m_gather3_list_get_itr(&adsp_gw->dsc_fifo, adsp_gw->adsc_gather_cur, &dsl_itr)) {
		if(m_gather3_itr_next(&dsl_itr)) {
			struct dsd_gather_writer_pos dsl_pos;
			dsl_pos.adsc_gather_cur = dsl_itr.adsc_cur;
			dsl_pos.achc_cur = dsl_itr.adsc_cur->dsc_base.achc_ginp_cur;
			dsl_pos.inc_abs_pos = adsp_gw->inc_lower_abs_pos + (adsp_gw->adsc_gather_cur->dsc_base.achc_ginp_end-adsp_gw->adsc_gather_cur->dsc_base.achc_ginp_cur);
			dsl_pos.achc_lower = dsl_pos.achc_cur;
			m_gw_set_position(adsp_gw, &dsl_pos);
			return TRUE;
		}
		m_gw_flush_gather_end(adsp_gw, adsp_gw->adsc_wa_cur);
	}
	return m_gw_alloc_gather(adsp_gw, &adsp_gw->dsc_wa_back);
}

HL_LOCAL_SCOPE BOOL m_gw_prev_gather(struct dsd_gather_writer* adsp_gw) {
	struct dsd_gather_i_3_itr dsl_itr;
	if(m_gather3_list_get_itr(&adsp_gw->dsc_fifo, adsp_gw->adsc_gather_cur, &dsl_itr)) {
		if(m_gather3_itr_prev(&dsl_itr)) {
			struct dsd_gather_writer_pos dsl_pos;
			dsl_pos.adsc_gather_cur = dsl_itr.adsc_cur;
			dsl_pos.achc_cur = dsl_itr.adsc_cur->dsc_base.achc_ginp_end;
			dsl_pos.inc_abs_pos = adsp_gw->inc_lower_abs_pos - (adsp_gw->adsc_gather_cur->dsc_base.achc_ginp_end-adsp_gw->adsc_gather_cur->dsc_base.achc_ginp_cur);
			dsl_pos.achc_lower = dsl_pos.achc_cur;
			m_gw_set_position(adsp_gw, &dsl_pos);
			return TRUE;
		}
		m_gw_flush_gather_start(adsp_gw, adsp_gw->adsc_wa_cur);
	}
	return m_gw_alloc_gather2(adsp_gw, &adsp_gw->dsc_wa_front);
}

HL_LOCAL_SCOPE BOOL m_gw_write_bytes(struct dsd_gather_writer* adsp_gw, const void* achp_src, size_t szp_len) {
	const char* achl_src = (const char*)achp_src;
	//const char* achl_srcend = achp_src + szp_len;
	while(szp_len > 0) {
		size_t inl_rest = adsp_gw->achc_upper - adsp_gw->achc_cur;
		if(inl_rest <= 0) {
			if(!m_gw_next_gather(adsp_gw))
				return FALSE;
			continue;
		}
		if(szp_len <= inl_rest) {
			memcpy(adsp_gw->achc_cur, achp_src, szp_len);
			adsp_gw->achc_cur += szp_len;
			return TRUE;
		}
		memcpy(adsp_gw->achc_cur, achp_src, inl_rest);
		adsp_gw->achc_cur += inl_rest;
		achl_src += inl_rest;
		szp_len -= inl_rest;
	}
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gw_prepend_bytes(struct dsd_gather_writer* adsp_gw, const void* achp_src, size_t szp_len) {
	const char* achl_src = (const char*)achp_src;
	const char* achl_srcend = achl_src + szp_len;
	while(szp_len > 0) {
		size_t inl_rest = adsp_gw->achc_cur - adsp_gw->achc_lower;
		if(inl_rest <= 0) {
			if(!m_gw_prev_gather(adsp_gw))
				return FALSE;
			continue;
		}
		if(szp_len <= inl_rest) {
			adsp_gw->achc_cur -= szp_len;
			achl_srcend -= szp_len;
			memcpy(adsp_gw->achc_cur, achl_srcend, szp_len);
			return TRUE;
		}
		adsp_gw->achc_cur -= inl_rest;
		achl_srcend -= inl_rest;
		memcpy(adsp_gw->achc_cur, achl_srcend, inl_rest);
		szp_len -= inl_rest;
	}
	return TRUE;
}

HL_LOCAL_SCOPE struct dsd_gather_i_1* m_gather_i_1_reverse(struct dsd_gather_i_1* adsp_data) {
	struct dsd_gather_i_1* adsl_reversed = NULL;
	struct dsd_gather_i_1* adsl_cur = adsp_data;
	while(adsl_cur != NULL) {
		struct dsd_gather_i_1* adsl_next = adsl_cur->adsc_next;
		adsl_cur->adsc_next = adsl_reversed;
		adsl_reversed = adsl_cur;
		adsl_cur = adsl_next;
	}
	return adsl_reversed;
}

HL_LOCAL_SCOPE BOOL m_gw_prepend_gather_list(struct dsd_gather_writer* adsp_gw, struct dsd_gather_i_1* adsp_data) {
	// Reverse the list to iterate from back to front
	struct dsd_gather_i_1* adsl_reversed = m_gather_i_1_reverse(adsp_data);
	struct dsd_gather_i_1* adsl_cur = adsl_reversed;
	adsl_reversed = NULL;
	// Iterate from back to front and reverse the source to the orginal order
	while(adsl_cur != NULL) {
		struct dsd_gather_i_1* adsl_next = adsl_cur->adsc_next;
		adsl_cur->adsc_next = adsl_reversed;
		adsl_reversed = adsl_cur;
		if(!m_gw_prepend_bytes(adsp_gw, adsl_cur->achc_ginp_cur, adsl_cur->achc_ginp_end-adsl_cur->achc_ginp_cur)) {
			if(adsl_next == NULL)
				return FALSE;
			// Reconstruct the rest of the list (reverse rest of the list)
			struct dsd_gather_i_1* adsl_reversed2 = m_gather_i_1_reverse(adsl_next);
			adsl_next->adsc_next = adsl_reversed;
			return FALSE;
		}
		adsl_cur = adsl_next;
	}
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gw_write_gather_list(struct dsd_gather_writer* adsp_gw, const struct dsd_gather_i_1* adsp_data, size_t szp_len) {
	if(szp_len <= 0)
		return TRUE;
	const struct dsd_gather_i_1* adsl_cur = adsp_data;
	while(adsl_cur != NULL) {
		size_t szl_length = adsl_cur->achc_ginp_end-adsl_cur->achc_ginp_cur;
		if(szl_length > szp_len)
			szl_length = szp_len;
		if(!m_gw_write_bytes(adsp_gw, adsl_cur->achc_ginp_cur, szl_length)) {
			return FALSE;
		}
		szp_len -= szl_length;
		if(szp_len <= 0)
			return TRUE;
		adsl_cur = adsl_cur->adsc_next;
	}
	return FALSE;
}

HL_LOCAL_SCOPE char* m_gw_provide(struct dsd_gather_writer* adsp_gw, char* achp_temp, size_t szp_len) {
	if(adsp_gw->achc_cur + szp_len <= adsp_gw->achc_upper)
		return adsp_gw->achc_cur;
	return achp_temp;
}

HL_LOCAL_SCOPE char* m_gw_provide2(struct dsd_gather_writer* adsp_gw, char* achp_temp, size_t szp_len) {
	char* achl_cur2 = adsp_gw->achc_cur - szp_len;
	if((achl_cur2-adsp_gw->achc_lower) >= 0)
		return achl_cur2;
	return achp_temp;
}

HL_LOCAL_SCOPE BOOL m_gw_commit(struct dsd_gather_writer* adsp_gw, const char* achp_dst, size_t szp_len) {
	if(adsp_gw->achc_cur == achp_dst) {
		adsp_gw->achc_cur += szp_len;
		return TRUE;
	}
	return m_gw_write_bytes(adsp_gw, achp_dst, szp_len);
}

HL_LOCAL_SCOPE BOOL m_gw_commit2(struct dsd_gather_writer* adsp_gw, const char* achp_dst, size_t szp_len) {
	char* achl_cur2 = adsp_gw->achc_cur - szp_len;
	if(achl_cur2 == achp_dst) {
		adsp_gw->achc_cur = achl_cur2;
		return TRUE;
	}
	return m_gw_prepend_bytes(adsp_gw, achp_dst, szp_len);
}

HL_LOCAL_SCOPE BOOL m_gw_write_uint8(struct dsd_gather_writer* adsp_gw, uint8_t ucp_value) {
	return m_gw_write_bytes(adsp_gw, &ucp_value, 1);
}

HL_LOCAL_SCOPE BOOL m_gw_write_uint16_le(struct dsd_gather_writer* adsp_gw, uint16_t ump_value) {
	char chrl_temp[2];
	char* achl_dst = m_gw_provide(adsp_gw, chrl_temp, sizeof(chrl_temp));
	if(achl_dst == NULL)
		return FALSE;
	achl_dst[0] = (char)ump_value;
	achl_dst[1] = (char)(ump_value >> 8);
	return m_gw_commit(adsp_gw, achl_dst, sizeof(chrl_temp));
}

HL_LOCAL_SCOPE BOOL m_gw_write_uint32_le(struct dsd_gather_writer* adsp_gw, uint32_t ump_value) {
	char chrl_temp[4];
	char* achl_dst = m_gw_provide(adsp_gw, chrl_temp, sizeof(chrl_temp));
	if(achl_dst == NULL)
		return FALSE;
	achl_dst[0] = (char)ump_value;
	achl_dst[1] = (char)(ump_value >> 8);
	achl_dst[2] = (char)(ump_value >> 16);
	achl_dst[3] = (char)(ump_value >> 24);
	return m_gw_commit(adsp_gw, achl_dst, sizeof(chrl_temp));
}

HL_LOCAL_SCOPE BOOL m_gw_write_sint32_le(struct dsd_gather_writer* adsp_gw, int32_t imp_value) {
	return m_gw_write_uint32_le(adsp_gw, (uint32_t)imp_value);
}

HL_LOCAL_SCOPE BOOL m_gw_prepend_uint16_le(struct dsd_gather_writer* adsp_gw, uint16_t ump_value) {
	char chrl_temp[2];
	char* achl_dst = m_gw_provide2(adsp_gw, chrl_temp, sizeof(chrl_temp));
	if(achl_dst == NULL)
		return FALSE;
	achl_dst[0] = (char)ump_value;
	achl_dst[1] = (char)(ump_value >> 8);
	return m_gw_commit2(adsp_gw, achl_dst, sizeof(chrl_temp));
}

HL_LOCAL_SCOPE BOOL m_gw_prepend_uint32_le(struct dsd_gather_writer* adsp_gw, uint32_t ump_value) {
	char chrl_temp[4];
	char* achl_dst = m_gw_provide2(adsp_gw, chrl_temp, sizeof(chrl_temp));
	if(achl_dst == NULL)
		return FALSE;
	achl_dst[0] = (char)ump_value;
	achl_dst[1] = (char)(ump_value >> 8);
	achl_dst[2] = (char)(ump_value >> 16);
	achl_dst[3] = (char)(ump_value >> 24);
	return m_gw_commit2(adsp_gw, achl_dst, sizeof(chrl_temp));
}

HL_LOCAL_SCOPE BOOL m_gw_write_hasn1_uint32_be(struct dsd_gather_writer* adsp_gw, uint32_t ump_value) {
	char chrl_temp[5];
	size_t iml_count;
	if((ump_value >> 7) == 0) {
		chrl_temp[0] = (char) ump_value;
		iml_count = 1;
	}
	else if((ump_value >> 14) == 0) {
		chrl_temp[0] = (char) ((ump_value >> 7) | 0x80);
		chrl_temp[1] = (char) (ump_value & 0x7f);
		iml_count = 2;
	}
	else if((ump_value >> 21) == 0) {
		chrl_temp[0] = (char) ((ump_value >> 14) | 0x80);
		chrl_temp[1] = (char) ((ump_value >> 7) | 0x80);
		chrl_temp[2] = (char) (ump_value & 0x7f);
		iml_count = 3;
	}
	else if((ump_value >> 28) == 0) {
		chrl_temp[0] = (char) ((ump_value >> 21) | 0x80);
		chrl_temp[1] = (char) ((ump_value >> 14) | 0x80);
		chrl_temp[2] = (char) ((ump_value >> 7) | 0x80);
		chrl_temp[3] = (char) (ump_value & 0x7f);
		iml_count = 4;
	}
	else {
		chrl_temp[0] = (char) ((ump_value >> 28) | 0x80);
		chrl_temp[1] = (char) ((ump_value >> 21) | 0x80);
		chrl_temp[2] = (char) ((ump_value >> 14) | 0x80);
		chrl_temp[3] = (char) ((ump_value >> 7) | 0x80);
		chrl_temp[4] = (char) (ump_value & 0x7f);
		iml_count = 5;
	}
	return m_gw_write_bytes(adsp_gw, chrl_temp, iml_count);
}

/**
 * Converts a possibly signed value to an HASN1 expression. <br>
 * <br>
 * Positive values are converted to: <br>
 * u = 2s <br>
 * Negative values are converted to: <br>
 * u = (-2s)-1 <br>
 */
HL_LOCAL_SCOPE uint32_t m_hasn1_signed_to_unsigned(int32_t im_sval) {
	if(im_sval < 0) {
		return (uint32_t)(((~im_sval) << 1) | 0x1);
	}
	return (uint32_t)(im_sval << 1);
}

/**
	* Converts a possibly signed value from an HASN1 expression. <br>
	* <br>
	* Positive values are converted to: <br>
	* s = u/2 <br>
	* Negative values are converted to: <br>
	* s = (u+1)/-2 <br>
	*/
HL_LOCAL_SCOPE int32_t m_hasn1_unsigned_to_signed(uint32_t um_uval) {
	/* Is positive? */
	if((um_uval & 0x1) == 0) {
		return um_uval >> 1;
	}
	return ~(um_uval >> 1);
}

HL_LOCAL_SCOPE BOOL m_gw_write_hasn1_sint32_be(struct dsd_gather_writer* adsp_gw, int32_t imp_value) {
	return m_gw_write_hasn1_uint32_be(adsp_gw, m_hasn1_signed_to_unsigned(imp_value));
}

/**
 * Prepends a single byte.
 *
 * @param by_val The value.
 */
HL_LOCAL_SCOPE BOOL m_gw_prepend_byte(struct dsd_gather_writer* adsp_gw, char by_val) {
	return m_gw_prepend_bytes(adsp_gw, &by_val, 1);
}

HL_LOCAL_SCOPE int m_cpy_uc_vx_vx2(struct dsd_unicode_string* adsp_dst, unsigned int unp_dst_unit_size_shift, struct dsd_unicode_string* adsp_val) {
	char* achl_out = (char*)adsp_dst->ac_str;
	char* achl_out_cur = achl_out;
	char* achl_out_end = achl_out_cur + (adsp_dst->imc_len_str<<unp_dst_unit_size_shift);
	const char* achl_in = (const char*)adsp_val->ac_str;
	const char* achl_in_end = achl_in + adsp_val->imc_len_str;
	while(achl_in < achl_in_end) {
		unsigned int uml_ucs_char = 0;
		int iml_res = m_get_vc_ch_ex(&uml_ucs_char, achl_in, achl_in_end, adsp_val->iec_chs_str);
		if(iml_res < 0) {
			// Not enough input?
			if(iml_res == -1) {
				break;
			}
			//this->inc_input_rest = 0;
			//uml_ucs_char = 0xFFFD;
			achl_in += unp_dst_unit_size_shift;
			break;
		}
		// Not enough input?
		if(iml_res > (achl_in_end-achl_in)) {
			break;
		}
		int inl_len_units = (achl_out_end-achl_out_cur)>>unp_dst_unit_size_shift;
		int inl_res2 = m_cpy_vx_vx(achl_out_cur, inl_len_units, adsp_dst->iec_chs_str,
			&uml_ucs_char, 1, ied_chs_utf_32);
		//int inl_res = m_u8l_from_u32l(achl_out_cur, achp_out_end-achl_out_cur,
        //                    (int*)&uml_ucs_char, 1);
        if(inl_res2 == 0)
            break;
        if(inl_res2 < 0)
            return -1;
		achl_in += iml_res;
        achl_out_cur += inl_res2<<unp_dst_unit_size_shift;
	}
	adsp_val->ac_str = (void*)achl_in;
	adsp_val->imc_len_str = (achl_in_end-achl_in)>>unp_dst_unit_size_shift;
	return achl_out_cur-achl_out;
}

/**
 * Writes an UTF-16 encoded string (little endian).
 */
HL_LOCAL_SCOPE BOOL m_gw_write_utf16_string(struct dsd_gather_writer* adsp_gw, const struct dsd_unicode_string* adsp_val) {
	uint16_t ucrl_max[1024];
	struct dsd_unicode_string dsl_dst;
	dsl_dst.ac_str = ucrl_max;
	dsl_dst.imc_len_str = 8;
	dsl_dst.iec_chs_str = ied_chs_utf_16;
	struct dsd_unicode_string dsl_src;
	dsl_src.ac_str = adsp_val->ac_str;
	dsl_src.imc_len_str = m_len_bytes_ucs(adsp_val);
	dsl_src.iec_chs_str = adsp_val->iec_chs_str;
	while(dsl_src.imc_len_str > 0) {
		int inl_num_bytes = m_cpy_uc_vx_vx2(&dsl_dst, 1, &dsl_src);
		if(inl_num_bytes < 0)
			return FALSE;
		const uint16_t* achl_cur = (uint16_t*)dsl_dst.ac_str;
		const uint16_t* achl_end = (const uint16_t*)(((const char*)achl_cur) + inl_num_bytes);
		while(achl_cur < achl_end) {
			if(!m_gw_write_uint16_le(adsp_gw, *achl_cur))
				return FALSE;
			achl_cur++;
		}
	}
	return TRUE;
}

HL_LOCAL_SCOPE int m_get_chs_unit_size(enum ied_charset iec_chs_str) {
	// TODO:
	switch(iec_chs_str) {
	case ied_chs_utf_8:
		return 1;
	case ied_chs_utf_16:
	case ied_chs_be_utf_16:
	case ied_chs_le_utf_16:
		return 2;
	default:
		return -1;
	}
}

/**
 * Prepends an UTF-16 encoded string (little endian).
 *
 * @param str_val The string to write.
 */
HL_LOCAL_SCOPE BOOL m_gw_prepend_utf16_string(struct dsd_gather_writer* adsp_gw, const struct dsd_unicode_string* adsp_val) {
	const int IN_SRC_MAX = 512;
	const char* achl_src_start = (const char*)adsp_val->ac_str;
	const char* achl_src_end = achl_src_start + m_len_bytes_ucs(adsp_val);
	const char* achl_src_cur = achl_src_end;
	switch(adsp_val->iec_chs_str) {
	case ied_chs_le_utf_16:
#if defined(HL_LITTLE_ENDIAN) || !defined(HL_BIG_ENDIAN)
	case ied_chs_utf_16:
#endif
		return m_gw_prepend_bytes(adsp_gw, achl_src_start, achl_src_end-achl_src_start);
	default:
		break;
	}
	int inl_src_unit_size = m_get_chs_unit_size(adsp_val->iec_chs_str);
	if(inl_src_unit_size < 0)
		return FALSE;
	uint16_t ucrl_max[IN_SRC_MAX+1];
	struct dsd_unicode_string dsl_dst;
	dsl_dst.ac_str = ucrl_max;
	dsl_dst.imc_len_str = sizeof(ucrl_max)/sizeof(ucrl_max[0]);
	dsl_dst.iec_chs_str = ied_chs_utf_16;
	while(achl_src_cur > achl_src_start) {
		int inl_src_rest = achl_src_cur - achl_src_start;
		if(inl_src_rest > IN_SRC_MAX)
			inl_src_rest = IN_SRC_MAX;
		achl_src_cur -= inl_src_rest;
		struct dsd_unicode_string dsl_src;
		dsl_src.ac_str = (char*)achl_src_cur;
		dsl_src.imc_len_str = inl_src_rest;
		dsl_src.iec_chs_str = adsp_val->iec_chs_str;
		do {
			int inl_num_bytes = m_cpy_uc_vx_vx2(&dsl_dst, 1, &dsl_src);
			if(inl_num_bytes < 0)
				return FALSE;
			if(inl_num_bytes == 0 && dsl_src.ac_str == achl_src_cur+inl_src_unit_size) {
				achl_src_cur -= inl_src_unit_size;
				inl_src_rest += inl_src_unit_size;
				dsl_src.ac_str = (char*)achl_src_cur;
				dsl_src.imc_len_str = inl_src_rest;
				if(achl_src_cur < achl_src_start)
					return FALSE;
				continue;
			}
			if(dsl_src.imc_len_str > 0)
				return FALSE;
			const uint16_t* achl_start = (uint16_t*)dsl_dst.ac_str;
			const uint16_t* achl_end = (const uint16_t*)(((const char*)achl_start) + inl_num_bytes);
			while(achl_end > achl_start) {
				achl_end--;
				if(!m_gw_prepend_uint16_le(adsp_gw, *achl_end))
					return FALSE;
			}
			break;
		} while(TRUE);
	}
	return TRUE;
}

/**
 * Prepend a ASN1 encoded INTEGER field.
 *
 * @param im_val The value.
 */
HL_LOCAL_SCOPE BOOL m_gw_prepend_asn1_int(struct dsd_gather_writer* adsp_gw, unsigned int im_val) {
	char chrl_temp[6];
	char* achl_dst = m_gw_provide2(adsp_gw, chrl_temp, sizeof(chrl_temp));
	if(achl_dst == NULL)
		return FALSE;
	char* achl_dst2 = achl_dst + sizeof(chrl_temp);
	char* achl_dst3 = achl_dst2;
	if(im_val <= 0xff) {
		*(--achl_dst2) = (char) im_val;
		*(--achl_dst2) = (char) 0x1;
	}
	else if(im_val <= 0xffff) {
		*(--achl_dst2) = (char) im_val;
		*(--achl_dst2) = (char) (im_val >> 8);
		*(--achl_dst2) = (char) 0x2;
	}
	else if(im_val <= 0xffffff) {
		*(--achl_dst2) = (char) im_val;
		*(--achl_dst2) = (char) (im_val >> 8);
		*(--achl_dst2) = (char) (im_val >> 16);
		*(--achl_dst2) = (char) 0x3;
	}
	else {
		*(--achl_dst2) = (char) im_val;
		*(--achl_dst2) = (char) (im_val >> 8);
		*(--achl_dst2) = (char) (im_val >> 16);
		*(--achl_dst2) = (char) (im_val >> 24);
		*(--achl_dst2) = (char) 0x4;
	}
	*(--achl_dst2) = (char) 0x2;
	return m_gw_commit2(adsp_gw, achl_dst2, achl_dst3-achl_dst2);
}

/**
 * Prepend a ASN1 encoded length field.
 *
 * @param im_val The value.
 */
HL_LOCAL_SCOPE BOOL m_gw_prepend_asn1_length(struct dsd_gather_writer* adsp_gw, unsigned int im_val) {
	char chrl_temp[5];
	char* achl_dst = m_gw_provide2(adsp_gw, chrl_temp, sizeof(chrl_temp));
	if(achl_dst == NULL)
		return FALSE;
	char* achl_dst2 = achl_dst + sizeof(chrl_temp);
	char* achl_dst3 = achl_dst2;
	if(im_val <= 0x7f) {
		*(--achl_dst2) = (char) im_val;
	}
	else if(im_val <= 0xff) {
		*(--achl_dst2) = (char) im_val;
		*(--achl_dst2) = (char) 0x81;
	}
	else if(im_val <= 0xffff) {
		*(--achl_dst2) = (char) im_val;
		*(--achl_dst2) = (char) (im_val >> 8);
		*(--achl_dst2) = (char) 0x82;
	}
	else if(im_val <= 0xffffff) {
		*(--achl_dst2) = (char) im_val;
		*(--achl_dst2) = (char) (im_val >> 8);
		*(--achl_dst2) = (char) (im_val >> 16);
		*(--achl_dst2) = (char) 0x83;
	}
	else {
		*(--achl_dst2) = (char) im_val;
		*(--achl_dst2) = (char) (im_val >> 8);
		*(--achl_dst2) = (char) (im_val >> 16);
		*(--achl_dst2) = (char) (im_val >> 24);
		*(--achl_dst2) = (char) 0x84;
	}
	return m_gw_commit2(adsp_gw, achl_dst2, achl_dst3-achl_dst2);
}

struct dsd_gather_reader {
	struct dsd_gather_i_1_fifo* adsc_list;
	struct dsd_gather_i_1* adsc_cur;
	const char* achc_cur;
	const char* achc_end;
	BOOL boc_peek;
	int inc_position;
};

HL_LOCAL_SCOPE void m_gr_init(struct dsd_gather_reader* adsp_gr, struct dsd_gather_i_1_fifo* adsp_list) {
	adsp_gr->adsc_list = adsp_list;
	adsp_gr->adsc_cur = NULL;
	adsp_gr->achc_cur = NULL;
	adsp_gr->achc_end = NULL;
	adsp_gr->boc_peek = FALSE;
	adsp_gr->inc_position = 0;
}

HL_LOCAL_SCOPE BOOL m_gr_next_gather2(struct dsd_gather_reader* adsp_gr) {
	struct dsd_gather_i_1* adsl_cur = adsp_gr->adsc_cur;
	struct dsd_gather_i_1* adsl_next;
	if(adsl_cur != NULL) {
		adsl_next = adsl_cur->adsc_next;
	}
	else {
		adsl_next = adsp_gr->adsc_list->adsc_first;
	}
	adsp_gr->adsc_cur = adsl_next;
	if(adsl_next == NULL) {
		adsp_gr->achc_cur = NULL;
		adsp_gr->achc_end = NULL;
		return FALSE;
	}
	adsp_gr->achc_cur = adsl_next->achc_ginp_cur;
	adsp_gr->achc_end = adsl_next->achc_ginp_end;
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gr_next_gather(struct dsd_gather_reader* adsp_gr) {
	struct dsd_gather_i_1* adsl_cur = adsp_gr->adsc_cur;
	struct dsd_gather_i_1* adsl_next;
	if(adsl_cur != NULL) {
		adsl_next = adsl_cur->adsc_next;
		adsp_gr->inc_position += adsp_gr->achc_cur - adsl_cur->achc_ginp_cur;
		if(!adsp_gr->boc_peek) {
			adsl_cur->achc_ginp_cur = (char*)adsp_gr->achc_cur;
			m_gather_fifo_free_processed(adsp_gr->adsc_list);
		}
	}
	else {
		adsl_next = adsp_gr->adsc_list->adsc_first;
	}
	adsp_gr->adsc_cur = adsl_next;
	if(adsl_next == NULL) {
		adsp_gr->achc_cur = NULL;
		adsp_gr->achc_end = NULL;
		return FALSE;
	}
	adsp_gr->achc_cur = adsl_next->achc_ginp_cur;
	adsp_gr->achc_end = adsl_next->achc_ginp_end;
	return TRUE;
}

HL_LOCAL_SCOPE dsd_gather_i_1* m_gr_commit(struct dsd_gather_reader* adsp_gr) {
	adsp_gr->inc_position += adsp_gr->achc_cur - adsp_gr->adsc_cur->achc_ginp_cur;
	adsp_gr->adsc_cur->achc_ginp_cur = (char*)adsp_gr->achc_cur;
	return adsp_gr->adsc_cur;
}

HL_LOCAL_SCOPE void m_gr_get_position(struct dsd_gather_reader* adsp_gr, struct dsd_gather_i_1_pos* adsp_pos) {
	adsp_pos->adsc_gather = adsp_gr->adsc_cur;
	adsp_pos->achc_pos = (char*)adsp_gr->achc_cur;
}

HL_LOCAL_SCOPE void m_gr_commit(struct dsd_gather_reader* adsp_gr, struct dsd_gather_i_1_pos* adsp_pos) {
	adsp_pos->adsc_gather = adsp_gr->adsc_cur;
	adsp_pos->achc_pos = (char*)adsp_gr->achc_cur;
	if(adsp_gr->adsc_cur == NULL)
		return;
	if(adsp_gr->boc_peek)
		return;
	adsp_gr->inc_position += adsp_gr->achc_cur - adsp_gr->adsc_cur->achc_ginp_cur;
	adsp_gr->adsc_cur->achc_ginp_cur = (char*)adsp_gr->achc_cur;
}

HL_LOCAL_SCOPE BOOL m_gr_has_more(struct dsd_gather_reader* adsp_gr) {
LBL_AGAIN:
	if(adsp_gr->achc_cur + 1 <= adsp_gr->achc_end) {
		return TRUE;
	}
	if(!m_gr_next_gather(adsp_gr))
		return FALSE;
	goto LBL_AGAIN;
}

HL_LOCAL_SCOPE int m_gr_get_abs_position(struct dsd_gather_reader* adsp_gr) {
	struct dsd_gather_i_1* adsl_cur = adsp_gr->adsc_cur;
	if(adsl_cur == NULL)
		return adsp_gr->inc_position;
	return adsp_gr->inc_position + (adsp_gr->achc_cur - adsl_cur->achc_ginp_cur);
}

HL_LOCAL_SCOPE BOOL m_gr_read_char(struct dsd_gather_reader* adsp_gr, char* achp_out) {
LBL_AGAIN:
	if(adsp_gr->achc_cur < adsp_gr->achc_end) {
		*achp_out = *adsp_gr->achc_cur++;
		return TRUE;
	}
	if(!m_gr_next_gather(adsp_gr))
		return FALSE;
	goto LBL_AGAIN;
}

HL_LOCAL_SCOPE const void* m_gr_provide(struct dsd_gather_reader* adsp_gr, void* achp_tmp, size_t szp_len) {
	const char* achl_cur2 = adsp_gr->achc_cur + szp_len;
	if(achl_cur2 <= adsp_gr->achc_end) {
		const char* achl_cur = adsp_gr->achc_cur;
		adsp_gr->achc_cur = achl_cur2;
		return achl_cur;
	}
	char* achl_tmp = (char*)achp_tmp;
	char* achl_tmp2 = (char*)achp_tmp + szp_len;
	while(achl_tmp < achl_tmp2) {
		if(!m_gr_read_char(adsp_gr, achl_tmp))
			return NULL;
		achl_tmp++;
	}
	return achp_tmp;
}

HL_LOCAL_SCOPE BOOL m_gr_read_bytes(struct dsd_gather_reader* adsp_gr, char* achp_out, int inp_nbytes) {
	while(inp_nbytes > 0) {
		int inl_len = adsp_gr->achc_end - adsp_gr->achc_cur;
		if(inl_len <= 0) {
			if(!m_gr_next_gather(adsp_gr))
				return FALSE;
			continue;
		}
		if(inl_len > inp_nbytes)
			inl_len = inp_nbytes;
		memcpy(achp_out, adsp_gr->achc_cur, inl_len);
		achp_out += inl_len;
		adsp_gr->achc_cur += inl_len;
		inp_nbytes -= inl_len;
	}
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gr_read_gather(struct dsd_gather_reader* adsp_gr, size_t szp_limit, struct dsd_gather_i_1* adsp_out) {
	while(TRUE) {
		int inl_len = adsp_gr->achc_end - adsp_gr->achc_cur;
		if(inl_len <= 0) {
			if(!m_gr_next_gather(adsp_gr))
				return FALSE;
			continue;
		}
		adsp_out->achc_ginp_cur = (char*)adsp_gr->achc_cur;
		if(inl_len > szp_limit)
			inl_len = szp_limit;
		adsp_gr->achc_cur += inl_len;
		adsp_out->achc_ginp_end = (char*)adsp_gr->achc_cur;
		adsp_out->adsc_next = NULL;
		return TRUE;
	}
}

HL_LOCAL_SCOPE BOOL m_gr_skip(struct dsd_gather_reader* adsp_gr, int inp_nbytes) {
	while(inp_nbytes > 0) {
		int inl_len = adsp_gr->achc_end - adsp_gr->achc_cur;
		if(inl_len <= 0) {
			if(!m_gr_next_gather(adsp_gr))
				return FALSE;
			continue;
		}
		if(inl_len > inp_nbytes)
			inl_len = inp_nbytes;
		adsp_gr->achc_cur += inl_len;
		inp_nbytes -= inl_len;
	}
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gr_seek(struct dsd_gather_reader* adsp_gr, int inp_pos) {
	int inl_cur_pos = m_gr_get_abs_position(adsp_gr);
	if(inp_pos < inl_cur_pos)
		return FALSE;
	return m_gr_skip(adsp_gr, inp_pos-inl_cur_pos);
}

HL_LOCAL_SCOPE BOOL m_gr_begin_lookahead(struct dsd_gather_reader* adsp_gr, struct dsd_gather_i_1_pos* adsp_pos) {
	if(adsp_gr->boc_peek)
		return FALSE;
	m_gr_has_more(adsp_gr);
	adsp_pos->adsc_gather = adsp_gr->adsc_cur;
	adsp_pos->achc_pos = (char*)adsp_gr->achc_cur;
	adsp_gr->boc_peek = TRUE;
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gr_end_lookahead(struct dsd_gather_reader* adsp_gr, const struct dsd_gather_i_1_pos* adsp_pos) {
	if(!adsp_gr->boc_peek)
		return FALSE;
	struct dsd_gather_i_1* adsl_cur = adsp_pos->adsc_gather;
	do {
		if(adsl_cur == adsp_gr->adsc_cur) {
			adsp_gr->boc_peek = FALSE;
			return TRUE;
		}
		if(adsl_cur == NULL)
			break;
		adsl_cur->achc_ginp_cur = adsl_cur->achc_ginp_end;
		adsl_cur = adsl_cur->adsc_next;
	} while(TRUE);
	return FALSE;
}

HL_LOCAL_SCOPE BOOL m_gr_read_uint8(struct dsd_gather_reader* adsp_gr, uint8_t* ainp_out) {
	unsigned char ucl_tmp;
	if(!m_gr_read_char(adsp_gr, (char*)&ucl_tmp))
		return FALSE;
	*ainp_out = ucl_tmp;
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gr_read_asn1_length(struct dsd_gather_reader* adsp_gr, unsigned int* aunp_out) {
	char chl_tmp;
	if(!m_gr_read_char(adsp_gr, &chl_tmp))
		return FALSE;
	/* Bit 0x80 not set? */
	if(chl_tmp >= 0) {
		/* The 7 bit rest is the length. */
		*aunp_out = chl_tmp;
		return TRUE;
	}
	/* The 7 bit indicate the number of bytes the BE stored integer uses. */
	chl_tmp &= 0x7f;
	if(chl_tmp > 4) {
		// TODO: Format error
		return FALSE;
	}
	unsigned char chrl_tmp[4];
	const unsigned char* achl_cur = (const unsigned char*)m_gr_provide(adsp_gr, chrl_tmp, chl_tmp);
	if(achl_cur == NULL)
		return FALSE;
	switch(chl_tmp) {
	case 1:
		*aunp_out = (achl_cur[0]);
		return TRUE;
	case 2:
		*aunp_out = (achl_cur[0]<<8) | achl_cur[1];
		return TRUE;
	case 3:
		*aunp_out = (achl_cur[0]<<16) | (achl_cur[1]<<8) | achl_cur[2];
		return TRUE;
	case 4:
		*aunp_out = (achl_cur[0]<<24) | (achl_cur[1]<<16) | (achl_cur[2]<<8) | achl_cur[3];
		return TRUE;
	default:
		// TODO: Format error
		return FALSE;
	}
}

HL_LOCAL_SCOPE BOOL m_gr_read_asn1_integer(struct dsd_gather_reader* adsp_gr, unsigned int* aunp_out) {
	unsigned char chl_tmp;
	if(!m_gr_read_char(adsp_gr, (char*)&chl_tmp))
		return FALSE;
	/* Not an integer? */
	if(chl_tmp != 0x02) {
		// TODO: Format error
		// throw new dsd_hob_error("Invalid ASN1 type");
		return FALSE;
	}
	/* Read the number of bytes used. */
	if(!m_gr_read_char(adsp_gr, (char*)&chl_tmp))
		return FALSE;
	if(chl_tmp > 4) {
		// TODO: Format error
		return FALSE;
	}
	unsigned char chrl_tmp[4];
	const unsigned char* achl_cur = (const unsigned char*)m_gr_provide(adsp_gr, chrl_tmp, chl_tmp);
	if(achl_cur == NULL)
		return FALSE;
	switch(chl_tmp) {
	case 1:
		*aunp_out = (achl_cur[0]);
		return TRUE;
	case 2:
		*aunp_out = (achl_cur[0]<<8) | achl_cur[1];
		return TRUE;
	case 3:
		*aunp_out = (achl_cur[0]<<16) | (achl_cur[1]<<8) | achl_cur[2];
		return TRUE;
	case 4:
		*aunp_out = (achl_cur[0]<<24) | (achl_cur[1]<<16) | (achl_cur[2]<<8) | achl_cur[3];
		return TRUE;
	default:
		// TODO: Format error
		//throw new dsd_hob_error("Unsupported ASN.1 integer size " + im_val);
		return FALSE;
	}
}

HL_LOCAL_SCOPE BOOL m_gr_read_uint16_le(struct dsd_gather_reader* adsp_gr, uint16_t* ump_out) {
	unsigned char chrl_tmp[2];
	const unsigned char* achl_cur = (const unsigned char*)m_gr_provide(adsp_gr, chrl_tmp, sizeof(chrl_tmp));
	if(achl_cur == NULL)
		return FALSE;
	*ump_out = achl_cur[0] | (achl_cur[1]<<8);
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gr_read_uint32_le(struct dsd_gather_reader* adsp_gr, uint32_t* ump_out) {
	unsigned char chrl_tmp[4];
	const unsigned char* achl_cur = (const unsigned char*)m_gr_provide(adsp_gr, chrl_tmp, sizeof(chrl_tmp));
	if(achl_cur == NULL)
		return FALSE;
	*ump_out = achl_cur[0] | (achl_cur[1]<<8) | (achl_cur[2]<<16) | (achl_cur[3]<<24);
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gr_read_uint64_le(struct dsd_gather_reader* adsp_gr, uint64_t* ump_out) {
	unsigned char chrl_tmp[8];
	const unsigned char* achl_cur = (const unsigned char*)m_gr_provide(adsp_gr, chrl_tmp, sizeof(chrl_tmp));
	if(achl_cur == NULL)
		return FALSE;
	*ump_out = (uint64_t)(achl_cur[0] | (achl_cur[1]<<8) | (achl_cur[2]<<16) | (achl_cur[3]<<24))
		| ((uint64_t)(achl_cur[4] | (achl_cur[5]<<8) | (achl_cur[6]<<16) | (achl_cur[7]<<24))<<32);
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gr_read_string(struct dsd_gather_reader* adsp_gr, char* achp_dst, size_t unp_bufsize) {
	if (achp_dst == NULL) {
		return FALSE;
	}
	for (uint32_t uml_i=0; uml_i<unp_bufsize; uml_i++) {
		char chl_current = 0;
		if (!m_gr_read_char(adsp_gr, &chl_current)) {
			return FALSE;
		}
		achp_dst[uml_i] = chl_current;
		if (chl_current == '\0' ) {
			return TRUE;
		}
	}
	return FALSE;
}

/**
	* Reads an HASN1 encoded unsigned integer (big endian)
	*
	* @return The read value.
	*/
HL_LOCAL_SCOPE BOOL m_gr_read_hasn1_uint32_be(struct dsd_gather_reader* adsp_gr, uint32_t* aump_out) {
	uint32_t uml_val = 0;
	do {
		char chl_tmp;
		if(!m_gr_read_char(adsp_gr, (char*)&chl_tmp))
			return FALSE;
		if(chl_tmp >= 0) {
			*aump_out = ((uml_val << 7) | chl_tmp);
			return TRUE;
		}
		uml_val <<= 7;
		uml_val |= (chl_tmp & 0x7f);
	} while(true);
}

/**
 * Reads an HASN1 encoded signed integer (big endian)
 *
 * @return The read value.
 */
HL_LOCAL_SCOPE BOOL m_gr_read_hasn1_sint32_be(struct dsd_gather_reader* adsp_gr, int32_t* aump_out) {
	uint32_t uml_value;
	if(!m_gr_read_hasn1_uint32_be(adsp_gr, &uml_value))
		return FALSE;
	*aump_out = m_hasn1_unsigned_to_signed(uml_value);
	return TRUE;
}

typedef BOOL (*amd_gr_write_to_proc_t)(struct dsd_gather_i_1* adsp_data, void* avop_user);

HL_LOCAL_SCOPE BOOL m_gr_write_to(struct dsd_gather_reader* adsp_gr, size_t szp_length, amd_gr_write_to_proc_t amp_proc, void* avop_user) {
	while(szp_length >= 0) {
		struct dsd_gather_i_1 dsl_tmp;
		if(!m_gr_read_gather(adsp_gr, szp_length, &dsl_tmp))
			return FALSE;
		size_t szl_len = dsl_tmp.achc_ginp_end-dsl_tmp.achc_ginp_cur;
		if(!amp_proc(&dsl_tmp, avop_user))
			return FALSE;
		if(szl_len >= szp_length)
			break;
		szp_length -= szl_len;
	}
	return TRUE;
}

#if 0
HL_LOCAL_SCOPE BOOL m_gr_read_zero_terminated_utf16_le_string(struct dsd_gather_reader* adsp_gr, int im_chars, struct dsd_unicode_string* adsp_out) {
	if(im_chars <= 0) {
		adsp_out->ac_str = NULL;
		adsp_out->imc_len_str = 0;
		adsp_out->iec_chs_str = ied_chs_le_utf_16;
		return TRUE;
	}
	String str_val = this.read_utf16_string(im_chars - 1);
	this.skip_uint16_le();
	return TRUE;
}
#endif

HL_LOCAL_SCOPE BOOL m_gr_provide_gathers(struct dsd_gather_reader* adsp_gr, int inp_nbytes, struct dsd_gather_i_1* adsp_out, struct dsd_gather_i_1** aadsp_last) {
	adsp_out->achc_ginp_cur = (char*)adsp_gr->achc_cur;
	int inl_len = adsp_gr->achc_end - adsp_gr->achc_cur;
	if(inl_len >= inp_nbytes) {
		adsp_gr->achc_cur += inp_nbytes;
		adsp_out->achc_ginp_end = (char*)(adsp_gr->achc_cur);
		adsp_out->adsc_next = NULL;
		*aadsp_last = adsp_out;
		return TRUE;
	}
	adsp_out->achc_ginp_end = (char*)adsp_gr->achc_end;
	adsp_out->adsc_next = adsp_gr->adsc_cur->adsc_next;
	struct dsd_gather_i_1* adsl_last = adsp_out;
	inp_nbytes -= inl_len;
	while(inp_nbytes > 0) {
		inl_len = adsp_gr->achc_end - adsp_gr->achc_cur;
		if(inl_len <= 0) {
			adsl_last = adsp_gr->adsc_cur;
			if(!m_gr_next_gather2(adsp_gr))
				return FALSE;
			continue;
		}
		if(inl_len > inp_nbytes)
			inl_len = inp_nbytes;
		adsp_gr->achc_cur += inl_len;
		inp_nbytes -= inl_len;
	}
	*aadsp_last = adsl_last;
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gr_extract_gathers(struct dsd_gather_reader* adsp_gr, int inp_nbytes, struct dsd_gather_i_1* adsp_tuple) {
	// Not allowed in peek mode!
	if(adsp_gr->boc_peek)
		return FALSE;
	struct dsd_gather_i_1* adsl_last;
	if(!m_gr_provide_gathers(adsp_gr, inp_nbytes, &adsp_tuple[0], &adsl_last))
		return FALSE;
	if(adsl_last == &adsp_tuple[0]) {
		return TRUE;
	}
	adsp_tuple[1].achc_ginp_cur = adsl_last->achc_ginp_cur;
	adsp_tuple[1].achc_ginp_end = (char*)adsp_gr->achc_cur;
	adsp_tuple[1].adsc_next = NULL;
	adsl_last->adsc_next = &adsp_tuple[1];
	return TRUE;
}

HL_LOCAL_SCOPE BOOL m_gather2_copy(struct dsd_workarea_allocator* adsp_wa_alloc1, const char* achp_src, int inp_srclen, struct dsd_gather_i_1_fifo* adsp_list) {
	while(inp_srclen > 0) {
		struct dsd_gather_i_2* adsl_out_cl = (struct dsd_gather_i_2*)m_wa_allocator_reserve_lower(
			adsp_wa_alloc1, sizeof(dsd_gather_i_2)+1, HL_ALIGNOF(dsd_gather_i_2));
		if(adsl_out_cl == NULL)
			return FALSE;
		adsl_out_cl->adsc_owner = m_wa_allocator_share_inc(adsp_wa_alloc1);
		char* achl_out_cl_start = (char*)(adsl_out_cl+1);
		adsl_out_cl->dsc_base.achc_ginp_cur = achl_out_cl_start;
		size_t szl_copy = adsp_wa_alloc1->achc_upper - achl_out_cl_start;
		if(szl_copy > (size_t)inp_srclen)
			szl_copy = (size_t)inp_srclen;
		memcpy(achl_out_cl_start, achp_src, szl_copy);
		adsl_out_cl->dsc_base.achc_ginp_end = achl_out_cl_start + szl_copy;
		adsl_out_cl->dsc_base.adsc_next = NULL;
		m_wa_allocator_commit_lower(adsp_wa_alloc1, adsl_out_cl->dsc_base.achc_ginp_end);
		m_gather_fifo_append(adsp_list, &adsl_out_cl->dsc_base);
		achp_src += szl_copy;
		inp_srclen -= szl_copy;
	}
	return TRUE;
}

HL_LOCAL_SCOPE int m_gather1_copy(struct dsd_gather_i_1** aadsp_src, char* achp_dst, char* achp_dstend) {
	struct dsd_gather_i_1* adsp_src = *aadsp_src;
	char* achl_dstcur = achp_dst;
	while(adsp_src != NULL && achl_dstcur < achp_dstend) {
		size_t szl_copy = adsp_src->achc_ginp_end - adsp_src->achc_ginp_cur;
		size_t szl_dstlen = achp_dstend - achl_dstcur;
		if(szl_copy > szl_dstlen)
			szl_copy = szl_dstlen;
		memcpy(achl_dstcur, adsp_src->achc_ginp_cur, szl_copy);
		adsp_src->achc_ginp_cur += szl_copy;
		achl_dstcur += szl_copy;
		if(adsp_src->achc_ginp_cur < adsp_src->achc_ginp_end)
			break;
		adsp_src = adsp_src->adsc_next;
	}
	*aadsp_src = adsp_src;
	return achl_dstcur-achp_dst;
}

HL_LOCAL_SCOPE int m_gather1_copy_const(const struct dsd_gather_i_1** aadsp_src, char* achp_dst, char* achp_dstend) {
	const struct dsd_gather_i_1* adsp_src = *aadsp_src;
	char* achl_dstcur = achp_dst;
	while(adsp_src != NULL && achl_dstcur < achp_dstend) {
		size_t szl_copy = adsp_src->achc_ginp_end - adsp_src->achc_ginp_cur;
		size_t szl_dstlen = achp_dstend - achl_dstcur;
		if(szl_copy > szl_dstlen)
			szl_copy = szl_dstlen;
		char* achl_ginp_cur = adsp_src->achc_ginp_cur;
		memcpy(achl_dstcur, achl_ginp_cur, szl_copy);
		achl_ginp_cur += szl_copy;
		achl_dstcur += szl_copy;
		if(achl_ginp_cur < adsp_src->achc_ginp_end)
			break;
		adsp_src = adsp_src->adsc_next;
	}
	*aadsp_src = adsp_src;
	return achl_dstcur-achp_dst;
}

#endif //_XS_TK_GATHER_TOOLS_CPP_
