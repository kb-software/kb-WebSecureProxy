//*set TRACE_STOR=0;
/**
   Universal Routine to Sub-Allocate Storage
   Copyright (C) HOB Germany 2006
   Copyright (C) HOB Germany 2007
   Copyright (C) HOB Germany 2008
   Copyright (C) HOB Germany 2009
   Copyright (C) HOB Germany 2010
   Copyright (C) HOB Germany 2012
   21.04.06 KB
   documentation in HOBTEXT SOFTWARE.COSTAND.XSLSTOR1
*/
/**
  to-do 18.06.08 KB
  SDH and D_BIG_STOR:
  additional field in struct dsd_stor_sdh_1
*/
//#define D_CHECK_GAP
#define AG_PSEUDO_STOR ((void *) &m_aux_stor_start)

#ifndef HL_UNIX
#include <windows.h>
#endif
#ifdef HL_UNIX
#ifndef HL_FREEBSD
#include <malloc.h>
#else
#include <stdlib.h>
#endif
#include <string.h>
#include "hob-unix01.h"
#endif
#include <stdio.h>
#include "hob-stor-sdh.h"

struct dsd_aux_stor_header {                /* Auxiliary Header        */
   struct dsd_aux_stor_header *adsc_next;   /* address next in chain   */
   unsigned int umc_length;                 /* length including header */
   unsigned int umc_no_ele;                 /* number of elements      */
   unsigned int umc_len_gap;                /* maximum length gap      */
};

struct dsd_aux_stor_element {               /* Auxiliary Entry         */
   unsigned int umc_start;                  /* displacement start      */
   unsigned int umc_end;                    /* displacement end        */
};

static void m_aux_stor_increase( struct dsd_stor_sdh_1 * );
#ifdef D_CHECK_GAP
extern "C" BOOL m_aux_stor_check_gap( struct dsd_stor_sdh_1 *adsp_contr );
#endif

#define D_AUX_STOR_SIZE (adsp_contr->imc_stor_size)

/* start get storage from system                                       */
extern "C" void m_aux_stor_start( struct dsd_stor_sdh_1 *adsp_contr ) {
   void       *ap_w1;                       /* working-variable        */
   BOOL       bol1;                         /* working-variable        */

   bol1 = adsp_contr->amc_aux( adsp_contr->vpc_userfld,
                               DEF_AUX_MEMGET,
                               &ap_w1,
                               adsp_contr->imc_stor_size );  /* size of storage element */
   if (bol1 == FALSE) {
     printf( "xslstor1-l%05d-W m_aux_stor_start aux DEF_AUX_MEMGET failed\n",
             __LINE__ );
     return;
   }
   memset( ap_w1, 0, sizeof(struct dsd_aux_stor_header) );
   ((struct dsd_aux_stor_header *) ap_w1)->umc_length = adsp_contr->imc_stor_size;
   ((struct dsd_aux_stor_header *) ap_w1)->umc_len_gap
      = adsp_contr->imc_stor_size - sizeof(struct dsd_aux_stor_header) - sizeof(struct dsd_aux_stor_element);
   adsp_contr->ac_stor_anchor = ap_w1;      /* set new element         */
   *(&adsp_contr->ac_big_stor_anchor) = NULL;
} /* end m_aux_stor_start()                                            */

extern "C" void * m_aux_stor_alloc( struct dsd_stor_sdh_1 *adsp_contr, int implen ) {
   BOOL       bol1;                         /* working-variable        */
   int        iml_len;                      /* length entry            */
   unsigned int uml1, uml2, uml3;           /* working-variables       */
   unsigned int uml_gap;                    /* size of gap             */
   unsigned int uml_no_ele;                 /* number of elements      */
   unsigned int uml_end;                    /* end of area             */
   char       *achl1, *achl2;               /* working-variables       */

   if (implen >= (D_AUX_STOR_SIZE / 2)) {
     bol1 = adsp_contr->amc_aux( adsp_contr->vpc_userfld,
                                 DEF_AUX_MEMGET,
                                 &achl1,
                                 implen + 2 * sizeof(void *) );  /* size of memory */
     if (bol1 == FALSE) {
       printf( "xslstor1-l%05d-W m_aux_stor_alloc aux DEF_AUX_MEMGET failed\n",
               __LINE__ );
       return NULL;
     }
     *((void **) achl1) = *(&adsp_contr->ac_big_stor_anchor);
     *(&adsp_contr->ac_big_stor_anchor) = achl1;
     *((void **) achl1 + 1) = (void *) implen;  /* save length of storage */
     return achl1 + 2 * sizeof(void *);
   }
   iml_len = (implen + sizeof(void *) - 1) & (0 - sizeof(void *));

   pgetaux08:                               /* get first auxiliary ar  */
   achl1 = (char *) adsp_contr->ac_stor_anchor;  /* get first element  */

   pgetaux20:                               /* next auxiliary area     */
   if (iml_len > ((struct dsd_aux_stor_header *) achl1)->umc_len_gap) {
     goto pgetaux36;
   }
   uml_no_ele = ((struct dsd_aux_stor_header *) achl1)->umc_no_ele;
   uml_end = ((struct dsd_aux_stor_header *) achl1)->umc_length;
   uml3 = sizeof(struct dsd_aux_stor_header)
          + (((struct dsd_aux_stor_header *) achl1)->umc_no_ele + 2)
            * sizeof(struct dsd_aux_stor_element);
   achl2 = (char *) achl1 + sizeof(struct dsd_aux_stor_header);
   uml_gap = 0;                             /* no gap till now         */
   while (uml_no_ele) {                     /* next element aux area   */
     uml_end -= ((struct dsd_aux_stor_element *) achl2)->umc_end;
     if (iml_len <= uml_end) {              /* space found             */
       uml_end += ((struct dsd_aux_stor_element *) achl2)->umc_end;
       break;
     }
     if (uml_gap < uml_end) uml_gap = uml_end;  /* set new gap         */
     uml_end = ((struct dsd_aux_stor_element *) achl2)->umc_start;
     achl2 += sizeof(struct dsd_aux_stor_element);
     uml_no_ele--;                          /* decrement counter ele   */
   }
   ((struct dsd_aux_stor_header *) achl1)->umc_no_ele++;
   if (uml_no_ele == 0) goto pgetaux32;     /* make only last element  */
   uml2 = uml_end - iml_len - ((struct dsd_aux_stor_element *) achl2)->umc_end;  /* compute gap after this */
   if (uml_gap < uml2) uml_gap = uml2;      /* set new gap             */
   do {                                     /* next element aux area   */
     uml_no_ele--;                          /* decrement counter ele   */
     ((struct dsd_aux_stor_element *) achl2 + uml_no_ele + 1)->umc_start
       = ((struct dsd_aux_stor_element *) achl2 + uml_no_ele)->umc_start;
     ((struct dsd_aux_stor_element *) achl2 + uml_no_ele + 1)->umc_end
       = ((struct dsd_aux_stor_element *) achl2 + uml_no_ele)->umc_end;
     uml1 = ((struct dsd_aux_stor_element *) achl2 + uml_no_ele)->umc_start - uml3;  /* compute new gap */
     if (uml_gap < uml1) uml_gap = uml1;    /* set new gap             */
     uml3 = ((struct dsd_aux_stor_element *) achl2 + uml_no_ele)->umc_end;  /* get last end */
   } while (uml_no_ele);

   pgetaux32:                               /* process remaining part  */
   /* make the new element                                             */
   ((struct dsd_aux_stor_element *) achl2)->umc_end = uml_end;
   uml_end -= iml_len;
   ((struct dsd_aux_stor_element *) achl2)->umc_start = uml_end;
   uml2 = ((struct dsd_aux_stor_element *) ((char *) achl1 + sizeof(struct dsd_aux_stor_header))
             + ((struct dsd_aux_stor_header *) achl1)->umc_no_ele - 1)->umc_start;
   uml3 = sizeof(struct dsd_aux_stor_header)
          + (((struct dsd_aux_stor_header *) achl1)->umc_no_ele + 1)
            * sizeof(struct dsd_aux_stor_element);
   if (uml3 > uml2) uml_gap = 0;            /* no space in directory   */
   else {
     uml2 -= uml3;                          /* gap at border           */
     if (uml_gap < uml2) uml_gap = uml2;    /* set new gap             */
   }
   ((struct dsd_aux_stor_header *) achl1)->umc_len_gap = uml_gap;
#ifdef D_CHECK_GAP
   m_aux_stor_check_gap( adsp_contr );
#endif
   return achl1 + uml_end;                  /* return address entry    */

   pgetaux36:                               /* end of auxiliary area   */
   achl1 = (char *) ((struct dsd_aux_stor_header *) achl1)->adsc_next;
   if (achl1) goto pgetaux20;
   /* increase memory as no space available                            */
   m_aux_stor_increase( adsp_contr );
   goto pgetaux08;                          /* start from new          */
} /* end m_aux_stor_alloc()                                            */

extern "C" void m_aux_stor_free( struct dsd_stor_sdh_1 *adsp_contr, void *ap_free ) {
   unsigned int uml_no_ele;                 /* number of elements      */
   unsigned int uml_end;                    /* end of area             */
   char       *achl1, *achl2;               /* working variables       */
   BOOL       bol1;                         /* working-variable        */
   int        iml1;                         /* working variable        */

   if (ap_free == NULL) return;             /* value for unallocated storage */
   achl1 = (char *) adsp_contr->ac_stor_anchor;  /* get first element  */

   while (TRUE) {                           /* next auxiliary area     */
     if (   (((char *) ap_free) > achl1)
         && (((char *) ap_free) < (achl1 + ((struct dsd_aux_stor_header *) achl1)->umc_length))) {
       break;                               /* auxiliary area found    */
     }
     achl1 = (char *) ((struct dsd_aux_stor_header *) achl1)->adsc_next;
     if (achl1 == NULL) {                   /* no more area            */
       /* check if in chain of big storage                             */
       achl1 = (char *) (&adsp_contr->ac_big_stor_anchor);   /* here is anchor          */
       while (TRUE) {                       /* loop over all entries big storage */
         achl2 = achl1;                     /* save previous entry     */
         achl1 = (char *) *((void **) achl1);
         if (achl1 == NULL) break;          /* end of chain reached    */
         if (((void *) (achl1 + 2 * sizeof(void *))) == ap_free) {
           *((void **) achl2) = *((void **) achl1);  /* remove from chain */
           bol1 = adsp_contr->amc_aux( adsp_contr->vpc_userfld,
                                       DEF_AUX_MEMFREE,
                                       &achl1,
                                       sizeof(void *) );  /* size of address */
           if (bol1 == FALSE) {
             printf( "xslstor1-l%05d-W m_aux_stor_free aux DEF_AUX_MEMFREE failed\n",
                     __LINE__ );
             return;
           }
           return;                          /* all done                */
         }
       }
       printf( "xslstor1-l%05d-W m_aux_stor_free invalid address to free = %p / 1\n",
               __LINE__, ap_free );
       return;
     }
   }
   /* auxiliary area found                                             */
   uml_end = ((struct dsd_aux_stor_header *) achl1)->umc_length;
   achl2 = (char *) achl1 + sizeof(struct dsd_aux_stor_header);
   uml_no_ele = ((struct dsd_aux_stor_header *) achl1)->umc_no_ele;
   while (TRUE) {
     if (uml_no_ele == 0) {
       printf( "xslstor1-l%05d-W m_aux_stor_free invalid address to free = %p / 2\n",
               __LINE__, ap_free );
       return;
     }
     uml_no_ele--;                          /* decrement counter ele   */
     if (ap_free == (achl1 + ((struct dsd_aux_stor_element *) achl2)->umc_start)) break;
     uml_end = ((struct dsd_aux_stor_element *) achl2)->umc_start;
     achl2 += sizeof(struct dsd_aux_stor_element);
   }
   if (uml_no_ele > 0) {
     if (((struct dsd_aux_stor_header *) achl1)->umc_len_gap != 0) {
       uml_end -= ((struct dsd_aux_stor_element *) (achl2 + sizeof(struct dsd_aux_stor_element)))->umc_end;
       if (((struct dsd_aux_stor_header *) achl1)->umc_len_gap < uml_end) {
         ((struct dsd_aux_stor_header *) achl1)->umc_len_gap = uml_end;
       }
     }
     iml1 = uml_no_ele;                     /* get number of elements  */
     do {
       ((struct dsd_aux_stor_element *) achl2)->umc_start
         = ((struct dsd_aux_stor_element *) achl2 + 1)->umc_start;
       ((struct dsd_aux_stor_element *) achl2)->umc_end
         = ((struct dsd_aux_stor_element *) achl2 + 1)->umc_end;
       achl2 += sizeof(struct dsd_aux_stor_element),
       iml1--;                              /* element was moved       */
     } while (iml1 > 0);                    /* over remaining elements */
   }
   ((struct dsd_aux_stor_header *) achl1)->umc_no_ele--;
   if (((struct dsd_aux_stor_header *) achl1)->umc_no_ele) {
     /* if gap was zero before, walk thru the array                    */
     if (((struct dsd_aux_stor_header *) achl1)->umc_len_gap == 0) {
       uml_no_ele = ((struct dsd_aux_stor_header *) achl1)->umc_no_ele;
       uml_end = ((struct dsd_aux_stor_header *) achl1)->umc_length;
       achl2 = (char *) achl1 + sizeof(struct dsd_aux_stor_header);
       do {
         uml_end -= ((struct dsd_aux_stor_element *) achl2)->umc_end;
         if (((struct dsd_aux_stor_header *) achl1)->umc_len_gap < uml_end) {
           ((struct dsd_aux_stor_header *) achl1)->umc_len_gap = uml_end;
         }
         uml_end = ((struct dsd_aux_stor_element *) achl2)->umc_start;
         achl2 += sizeof(struct dsd_aux_stor_element);
         uml_no_ele--;                      /* decrement counter ele   */
       } while (uml_no_ele);
     }
     uml_end = ((struct dsd_aux_stor_element *) (achl1
                 + sizeof(struct dsd_aux_stor_header)
                 + (((struct dsd_aux_stor_header *) achl1)->umc_no_ele - 1)
                   * sizeof(struct dsd_aux_stor_element)))->umc_start
               - (sizeof(struct dsd_aux_stor_header)
                 + (((struct dsd_aux_stor_header *) achl1)->umc_no_ele + 1)
                   * sizeof(struct dsd_aux_stor_element));
     if (((struct dsd_aux_stor_header *) achl1)->umc_len_gap < uml_end) {
       ((struct dsd_aux_stor_header *) achl1)->umc_len_gap = uml_end;
     }
   } else {                                 /* area is empty           */
     ((struct dsd_aux_stor_header *) achl1)->umc_len_gap
       = ((struct dsd_aux_stor_header *) achl1)->umc_length
         - sizeof(struct dsd_aux_stor_header)
         - sizeof(struct dsd_aux_stor_element);
   }
} /* end m_aux_stor_free()                                             */

extern "C" void * m_aux_stor_realloc( struct dsd_stor_sdh_1 *adsp_contr, void *ap_old, int implen ) {
   BOOL       bol1;                         /* working-variable        */
   int        iml1;                         /* working variable        */
   unsigned int uml1, uml2, uml3;           /* working-variables       */
   int        iml_len;                      /* length entry            */
   int        iml_old_len;                  /* length old entry        */
   BOOL       bol_gap_new;                  /* calculate new gap       */
   unsigned int uml_gap_o;                  /* size of gap old         */
   unsigned int uml_gap_n;                  /* size of gap new         */
   unsigned int uml_no_ele_o;               /* number of elements old  */
   unsigned int uml_no_ele_n;               /* number of elements new  */
   unsigned int uml_end_o;                  /* end of area old         */
   unsigned int uml_end_n;                  /* end of area new         */
   char       *achl1, *achl2, *achl3;       /* working variables       */
   char       *achl_bs_1, *achl_bs_2;       /* where to find in storage for big elements */
   char       *achl_a_sp;                   /* area with space         */
   char       *achl_new;                    /* new area                */

   if (ap_old == NULL) {                    /* is like alloc()         */
     return m_aux_stor_alloc( adsp_contr, implen );
   }
   if (implen == 0) {                       /* is like free()          */
     m_aux_stor_free( adsp_contr, ap_old );
     return NULL;
   }
   achl_bs_1 = NULL;                        /* where to find in storage for big elements */
   iml_len = (implen + sizeof(void *) - 1) & (0 - sizeof(void *));
   achl1 = (char *) adsp_contr->ac_stor_anchor;  /* get first element  */
   achl_a_sp = NULL;                        /* area with space         */

   while (TRUE) {                           /* next auxiliary area     */
     if (   (achl_a_sp == NULL)             /* no area with space yet  */
         && (implen < (D_AUX_STOR_SIZE / 2))
         && (iml_len <= ((struct dsd_aux_stor_header *) achl1)->umc_len_gap)) {
       achl_a_sp = achl1;                   /* area with space         */
     }
     if (   (((char *) ap_old) > achl1)
         && (((char *) ap_old) < (achl1 + ((struct dsd_aux_stor_header *) achl1)->umc_length))) {
       break;                               /* auxiliary area found    */
     }
     achl1 = (char *) ((struct dsd_aux_stor_header *) achl1)->adsc_next;
     if (achl1 == NULL) {                   /* no more area            */
       /* check if in chain of big storage                             */
       achl_bs_1 = (char *) (&adsp_contr->ac_big_stor_anchor);  /* here is anchor       */
       while (TRUE) {                       /* loop over all entries big storage */
         achl_bs_2 = achl_bs_1;             /* save previous entry     */
         achl_bs_1 = (char *) *((void **) achl_bs_1);
         if (achl_bs_1 == NULL) break;      /* end of chain reached    */
         if (((void *) (achl_bs_1 + 2 * sizeof(void *))) == ap_old) {
           if (implen < (D_AUX_STOR_SIZE / 2)) {
             if (achl_a_sp) goto p_new_ele;  /* auxiliary area with space already found */
             /* increase memory as no space available                  */
             m_aux_stor_increase( adsp_contr );
             achl_a_sp = (char *) ((struct dsd_aux_stor_header *) adsp_contr->ac_stor_anchor)->adsc_next;
             goto p_new_ele;                /* search space for new element */
           }
           bol1 = adsp_contr->amc_aux( adsp_contr->vpc_userfld,
                                       DEF_AUX_MEMGET,
                                       &achl1,
                                       implen + 2 * sizeof(void *) );  /* size of memory */
           if (bol1 == FALSE) {
             printf( "xslstor1-l%05d-W m_aux_stor_realloc aux DEF_AUX_MEMGET failed\n",
                     __LINE__ );
             return NULL;
           }
           *((void **) achl1) = *((void **) achl_bs_1);  /* get old chain */
           *((void **) achl1 + 1) = (void *) implen;  /* set new length */
#ifndef HL_UNIX
           iml1 = (int) *((void **) achl_bs_1 + 1);  /* get old length */
#else
           iml1 = (int) ((long long int) *((void **) achl_bs_1 + 1));  /* get old length */
#endif
           if (iml1 > implen) iml1 = implen;  /* compute how much to copy */
           memcpy( achl1 + 2 * sizeof(void *), achl_bs_1 + 2 * sizeof(void *), iml1 );  /* copy area */
           *((void **) achl_bs_2) = achl1;  /* remove old element from chain */
           bol1 = adsp_contr->amc_aux( adsp_contr->vpc_userfld,
                                       DEF_AUX_MEMFREE,
                                       &achl_bs_1,
                                       sizeof(void *) );  /* size of address */
           if (bol1 == FALSE) {
             printf( "xslstor1-l%05d-W m_aux_stor_realloc aux DEF_AUX_MEMFREE failed\n",
                     __LINE__ );
             return NULL;
           }
           return (void *) (achl1 + 2 * sizeof(void *));  /* all done  */
         }
       }
       printf( "xslstor1-l%05d-W m_aux_stor_realloc invalid address to free = %p / 1\n",
               __LINE__, ap_old );
       return NULL;
     }
   }
   /* auxiliary area with old entry found                              */
   uml_end_o = ((struct dsd_aux_stor_header *) achl1)->umc_length;
   achl2 = (char *) achl1 + sizeof(struct dsd_aux_stor_header);
   uml_no_ele_o = ((struct dsd_aux_stor_header *) achl1)->umc_no_ele;
   uml_gap_o = 0;                           /* no gap till now         */
   while (TRUE) {
     if (uml_no_ele_o == 0) {
       printf( "xslstor1-l%05d-W m_aux_stor_realloc invalid address to free = %p / 2\n",
               __LINE__, ap_old );
       return NULL;
     }
     uml_no_ele_o--;                        /* decrement counter elements */
     if (ap_old == (achl1 + ((struct dsd_aux_stor_element *) achl2)->umc_start)) break;
     uml_end_o -= ((struct dsd_aux_stor_element *) achl2)->umc_end;
     if (uml_gap_o < uml_end_o) uml_gap_o = uml_end_o;  /* set new gap */
     uml_end_o = ((struct dsd_aux_stor_element *) achl2)->umc_start;
     achl2 += sizeof(struct dsd_aux_stor_element);
   }
   /* element found in table                                           */
   bol_gap_new = FALSE;                     /* do not calculate new gap */
   iml_old_len                              /* length old entry        */
     = ((struct dsd_aux_stor_element *) achl2)->umc_end
         - ((struct dsd_aux_stor_element *) achl2)->umc_start;
   if (implen >= (D_AUX_STOR_SIZE / 2)) {   /* acquire big element     */
     bol1 = adsp_contr->amc_aux( adsp_contr->vpc_userfld,
                                 DEF_AUX_MEMGET,
                                 &achl3,
                                 implen + 2 * sizeof(void *) );  /* size of memory */
     if (bol1 == FALSE) {
       printf( "xslstor1-l%05d-W m_aux_stor_realloc aux DEF_AUX_MEMGET failed\n",
               __LINE__ );
       return NULL;
     }
     *((void **) achl3) = *(&adsp_contr->ac_big_stor_anchor);
     *(&adsp_contr->ac_big_stor_anchor) = achl3;
     *((void **) achl3 + 1) = (void *) implen;  /* save length of storage */
     achl_new = achl3 + 2 * sizeof(void *);  /* address of new element */
     memcpy( achl_new, ap_old, iml_old_len );
     goto p_del_ele;                        /* delete old element      */
   }
   uml1 = ((struct dsd_aux_stor_element *) achl2)->umc_start + iml_len;
   if (uml1 <= uml_end_o) {                 /* possible to increase element */
     if (uml1 == ((struct dsd_aux_stor_element *) achl2)->umc_end) {
       return ap_old;                       /* nothing changed         */
     }
     ((struct dsd_aux_stor_element *) achl2)->umc_end = uml1;  /* set new end */
     /* has to set gap, maybe size of gap has changed                  */
     uml_end_o -= uml1;
     if (uml_gap_o < uml_end_o) uml_gap_o = uml_end_o;  /* set new gap */
     while (uml_no_ele_o) {                 /* loop over remaining elements */
       uml_end_o = ((struct dsd_aux_stor_element *) achl2)->umc_start;
       achl2 += sizeof(struct dsd_aux_stor_element);
       uml_end_o -= ((struct dsd_aux_stor_element *) achl2)->umc_end;
       if (uml_gap_o < uml_end_o) uml_gap_o = uml_end_o;  /* set new gap */
       uml_no_ele_o--;                      /* decrement counter elements */
     }
     iml1 = ((struct dsd_aux_stor_element *) (achl1
              + sizeof(struct dsd_aux_stor_header)
              + (((struct dsd_aux_stor_header *) achl1)->umc_no_ele - 1)
                * sizeof(struct dsd_aux_stor_element)))->umc_start
            - (sizeof(struct dsd_aux_stor_header)
              + (((struct dsd_aux_stor_header *) achl1)->umc_no_ele + 1)
                * sizeof(struct dsd_aux_stor_element));
     if (iml1 >= 0) {                       /* possible to add new elements */
       if (uml_gap_o < uml_end_o) uml_gap_o = uml_end_o;
       if (uml_gap_o < iml1) uml_gap_o = iml1;
       ((struct dsd_aux_stor_header *) achl1)->umc_len_gap = uml_gap_o;
     } else {                               /* not possible to add new elements */
       ((struct dsd_aux_stor_header *) achl1)->umc_len_gap = 0;
     }
     return ap_old;                         /* changed in place        */
   }
   /* necessary to copy element                                        */
   while (achl_a_sp == NULL) {              /* search auxiliary area   */
     achl_a_sp = (char *) ((struct dsd_aux_stor_header *) achl1)->adsc_next;
     while (achl_a_sp) {                    /* check this auxiliary area */
       if (iml_len <= ((struct dsd_aux_stor_header *) achl_a_sp)->umc_len_gap) {
         break;                             /* space in this auxiliary area */
       }
       achl_a_sp = (char *) ((struct dsd_aux_stor_header *) achl_a_sp)->adsc_next;
     }
     if (achl_a_sp) break;                  /* auxiliary area found    */
     /* increase memory as no space available                          */
     m_aux_stor_increase( adsp_contr );
     achl_a_sp = (char *) ((struct dsd_aux_stor_header *) adsp_contr->ac_stor_anchor)->adsc_next;
     break;
   }

   p_new_ele:                               /* search space for new element */
   uml_no_ele_n = ((struct dsd_aux_stor_header *) achl_a_sp)->umc_no_ele;
   uml_end_n = ((struct dsd_aux_stor_header *) achl_a_sp)->umc_length;
   uml3 = sizeof(struct dsd_aux_stor_header)
          + (((struct dsd_aux_stor_header *) achl_a_sp)->umc_no_ele + 2)
            * sizeof(struct dsd_aux_stor_element);
   achl3 = (char *) achl_a_sp + sizeof(struct dsd_aux_stor_header);
   uml_gap_n = 0;                           /* no gap till now         */
   while (uml_no_ele_n) {                   /* next element aux area   */
     uml_end_n -= ((struct dsd_aux_stor_element *) achl3)->umc_end;
     if (iml_len <= uml_end_n) {            /* space found             */
       uml_end_n += ((struct dsd_aux_stor_element *) achl3)->umc_end;
       break;
     }
     if (uml_gap_n < uml_end_n) uml_gap_n = uml_end_n;  /* set new gap */
     uml_end_n = ((struct dsd_aux_stor_element *) achl3)->umc_start;
     achl3 += sizeof(struct dsd_aux_stor_element);
     uml_no_ele_n--;                        /* decrement counter elements */
   }
   ((struct dsd_aux_stor_header *) achl_a_sp)->umc_no_ele++;
   if (achl_a_sp == achl1) {                /* in same area as old element */
     if (achl2 > achl3) achl2 += sizeof(struct dsd_aux_stor_element);
     bol_gap_new = TRUE;                    /* calculate new gap       */
   }
   if (uml_no_ele_n) {                      /* not only make only last element */
     uml2 = uml_end_n - iml_len - ((struct dsd_aux_stor_element *) achl3)->umc_end;  /* compute gap after this */
     if (uml_gap_n < uml2) uml_gap_n = uml2;  /* set new gap           */
     do {                                   /* next element aux area   */
       uml_no_ele_n--;                      /* decrement counter ele   */
       ((struct dsd_aux_stor_element *) achl3 + uml_no_ele_n + 1)->umc_start
         = ((struct dsd_aux_stor_element *) achl3 + uml_no_ele_n)->umc_start;
       ((struct dsd_aux_stor_element *) achl3 + uml_no_ele_n + 1)->umc_end
         = ((struct dsd_aux_stor_element *) achl3 + uml_no_ele_n)->umc_end;
       uml1 = ((struct dsd_aux_stor_element *) achl3 + uml_no_ele_n)->umc_start - uml3;  /* compute new gap */
       if (uml_gap_n < uml1) uml_gap_n = uml1;  /* set new gap         */
       uml3 = ((struct dsd_aux_stor_element *) achl3 + uml_no_ele_n)->umc_end;  /* get last end */
     } while (uml_no_ele_n);
   }
   /* make the new element                                             */
   ((struct dsd_aux_stor_element *) achl3)->umc_end = uml_end_n;
   uml_end_n -= iml_len;
   ((struct dsd_aux_stor_element *) achl3)->umc_start = uml_end_n;
   uml2 = ((struct dsd_aux_stor_element *) ((char *) achl_a_sp + sizeof(struct dsd_aux_stor_header))
             + ((struct dsd_aux_stor_header *) achl_a_sp)->umc_no_ele - 1)->umc_start;
   uml3 = sizeof(struct dsd_aux_stor_header)
          + (((struct dsd_aux_stor_header *) achl_a_sp)->umc_no_ele + 1)
            * sizeof(struct dsd_aux_stor_element);
   if (uml3 > uml2) uml_gap_n = 0;          /* no space in directory   */
   else {
     uml2 -= uml3;                          /* gap at border           */
     if (uml_gap_n < uml2) uml_gap_n = uml2;  /* set new gap           */
   }
   ((struct dsd_aux_stor_header *) achl_a_sp)->umc_len_gap = uml_gap_n;
   achl_new = achl_a_sp + uml_end_n;        /* this is new address entry */
   if (achl_bs_1) {                         /* old element is big storage */
     memcpy( achl_new,
             achl_bs_1 + 2 * sizeof(void *),
             ((struct dsd_aux_stor_element *) achl3)->umc_end
               - ((struct dsd_aux_stor_element *) achl3)->umc_start );
     *((void **) achl_bs_2) = *((void **) achl_bs_1);  /* remove old element from chain */
     bol1 = adsp_contr->amc_aux( adsp_contr->vpc_userfld,
                                 DEF_AUX_MEMFREE,
                                 &achl_bs_1,
                                 sizeof(void *) );  /* size of address */
     if (bol1 == FALSE) {
       printf( "xslstor1-l%05d-W m_aux_stor_realloc aux DEF_AUX_MEMFREE failed\n",
               __LINE__ );
       return NULL;
     }
#ifdef D_CHECK_GAP
     m_aux_stor_check_gap( adsp_contr );
#endif
     return achl_new;                       /* all done                */
   }
   memcpy( achl_new, ap_old, iml_old_len );
   /* delete the old element                                           */
   if (achl1 == achl_a_sp) uml_no_ele_o++;  /* one element added       */

   p_del_ele:                               /* delete old element      */
   if (uml_no_ele_o > 0) {
     if (((struct dsd_aux_stor_header *) achl1)->umc_len_gap != 0) {
       uml_end_o -= ((struct dsd_aux_stor_element *) (achl2 + sizeof(struct dsd_aux_stor_element)))->umc_end;
       if (((struct dsd_aux_stor_header *) achl1)->umc_len_gap < uml_end_o) {
         ((struct dsd_aux_stor_header *) achl1)->umc_len_gap = uml_end_o;
       }
     }
     iml1 = uml_no_ele_o;                   /* get number of elements  */
     do {
       ((struct dsd_aux_stor_element *) achl2)->umc_start
         = ((struct dsd_aux_stor_element *) achl2 + 1)->umc_start;
       ((struct dsd_aux_stor_element *) achl2)->umc_end
         = ((struct dsd_aux_stor_element *) achl2 + 1)->umc_end;
       achl2 += sizeof(struct dsd_aux_stor_element),
       iml1--;                              /* element was moved       */
     } while (iml1 > 0);                    /* over remaining elements */
   }
   ((struct dsd_aux_stor_header *) achl1)->umc_no_ele--;
   if (((struct dsd_aux_stor_header *) achl1)->umc_no_ele) {
//*if def B090204;
     /* if gap was zero before, walk thru the array                    */
     if (((struct dsd_aux_stor_header *) achl1)->umc_len_gap == 0) {
//*cend;
       bol_gap_new = TRUE;                  /* calculate new gap       */
//*if def B090204;
     } else {
       uml_gap_o = ((struct dsd_aux_stor_element *) (achl1
                     + sizeof(struct dsd_aux_stor_header)
                     + (((struct dsd_aux_stor_header *) achl1)->umc_no_ele - 1)
                       * sizeof(struct dsd_aux_stor_element)))->umc_start
                   - (sizeof(struct dsd_aux_stor_header)
                     + (((struct dsd_aux_stor_header *) achl1)->umc_no_ele + 1)
                       * sizeof(struct dsd_aux_stor_element));
       if (((struct dsd_aux_stor_header *) achl1)->umc_len_gap < uml_gap_o) {
         ((struct dsd_aux_stor_header *) achl1)->umc_len_gap = uml_gap_o;
       }
     }
//*cend;
   } else {                                 /* area is empty           */
     ((struct dsd_aux_stor_header *) achl1)->umc_len_gap
       = ((struct dsd_aux_stor_header *) achl1)->umc_length
         - sizeof(struct dsd_aux_stor_header)
         - sizeof(struct dsd_aux_stor_element);
   }
   if (bol_gap_new) {                       /* calculate new gap       */
     ((struct dsd_aux_stor_header *) achl1)->umc_len_gap = 0;
     /* walk thru the array                                            */
     uml_no_ele_o = ((struct dsd_aux_stor_header *) achl1)->umc_no_ele;
     uml_end_o = ((struct dsd_aux_stor_header *) achl1)->umc_length;
     achl2 = (char *) achl1 + sizeof(struct dsd_aux_stor_header);
     do {
       uml_end_o -= ((struct dsd_aux_stor_element *) achl2)->umc_end;
       if (((struct dsd_aux_stor_header *) achl1)->umc_len_gap < uml_end_o) {
         ((struct dsd_aux_stor_header *) achl1)->umc_len_gap = uml_end_o;
       }
       uml_end_o = ((struct dsd_aux_stor_element *) achl2)->umc_start;
       achl2 += sizeof(struct dsd_aux_stor_element);
       uml_no_ele_o--;                      /* decrement counter elements */
     } while (uml_no_ele_o);
     uml_end_o = ((struct dsd_aux_stor_element *) (achl1
                   + sizeof(struct dsd_aux_stor_header)
                   + (((struct dsd_aux_stor_header *) achl1)->umc_no_ele - 1)
                     * sizeof(struct dsd_aux_stor_element)))->umc_start
                 - (sizeof(struct dsd_aux_stor_header)
                   + (((struct dsd_aux_stor_header *) achl1)->umc_no_ele + 1)
                     * sizeof(struct dsd_aux_stor_element));
     if (((struct dsd_aux_stor_header *) achl1)->umc_len_gap < uml_end_o) {
       ((struct dsd_aux_stor_header *) achl1)->umc_len_gap = uml_end_o;
     }
   }
#ifdef D_CHECK_GAP
   m_aux_stor_check_gap( adsp_contr );
#endif
   return achl_new;                         /* return address entry    */
} /* end m_aux_stor_realloc()                                          */

/* get more storage from system                                        */
static void m_aux_stor_increase( struct dsd_stor_sdh_1 *adsp_contr ) {
   void       *ap_w1;                       /* working-variable        */
   BOOL       bol1;                         /* working-variable        */

   bol1 = adsp_contr->amc_aux( adsp_contr->vpc_userfld,
                               DEF_AUX_MEMGET,
                               &ap_w1,
                               adsp_contr->imc_stor_size );  /* size of storage element */
   if (bol1 == FALSE) {
     printf( "xslstor1-l%05d-W m_aux_stor_increase aux DEF_AUX_MEMGET failed\n",
             __LINE__ );
     return;
   }
   memset( ap_w1, 0, sizeof(struct dsd_aux_stor_header) );
   ((struct dsd_aux_stor_header *) ap_w1)->umc_length = adsp_contr->imc_stor_size;
   ((struct dsd_aux_stor_header *) ap_w1)->umc_len_gap
      = adsp_contr->imc_stor_size - sizeof(struct dsd_aux_stor_header) - sizeof(struct dsd_aux_stor_element);
   /* insert the new container as second one in chain                  */
   ((struct dsd_aux_stor_header *) ap_w1)->adsc_next
     = ((struct dsd_aux_stor_header *) adsp_contr->ac_stor_anchor)->adsc_next;
   ((struct dsd_aux_stor_header *) adsp_contr->ac_stor_anchor)->adsc_next = (struct dsd_aux_stor_header *) ap_w1;  /* insert new element */
} /* end m_aux_stor_increase()                                         */

/* free all storage from system                                        */
extern "C" void m_aux_stor_end( struct dsd_stor_sdh_1 *adsp_contr ) {
   void       *ap_w1;                       /* working-variable        */
   BOOL       bol1;                         /* working-variable        */

   /* free all in chain of big storage                                 */
   while (*(&adsp_contr->ac_big_stor_anchor)) {
     ap_w1 = *(&adsp_contr->ac_big_stor_anchor);
     *(&adsp_contr->ac_big_stor_anchor) = *((void **) ap_w1);
     bol1 = adsp_contr->amc_aux( adsp_contr->vpc_userfld,
                                 DEF_AUX_MEMFREE,
                                 &ap_w1,
                                 sizeof(void *) );  /* size of address */
     if (bol1 == FALSE) {
       printf( "xslstor1-l%05d-W m_aux_stor_end aux DEF_AUX_MEMFREE failed\n",
               __LINE__ );
       return;
     }
   }
   while (adsp_contr->ac_stor_anchor) {     /* loop over all areas     */
     ap_w1 = adsp_contr->ac_stor_anchor;    /* get this area           */
     adsp_contr->ac_stor_anchor = ((struct dsd_aux_stor_header *) ap_w1)->adsc_next;
     bol1 = adsp_contr->amc_aux( adsp_contr->vpc_userfld,
                                 DEF_AUX_MEMFREE,
                                 &ap_w1,
                                 sizeof(void *) );  /* size of address */
     if (bol1 == FALSE) {
       printf( "xslstor1-l%05d-W m_aux_stor_end aux DEF_AUX_MEMFREE failed\n",
               __LINE__ );
       return;
     }
   }
} /* end m_aux_stor_end()                                              */

#ifdef D_CHECK_GAP
/* check if the gap is correct                                         */
extern "C" BOOL m_aux_stor_check_gap( struct dsd_stor_sdh_1 *adsp_contr ) {
   unsigned int uml_no_ele;                 /* number of elements      */
   unsigned int uml_gap;                    /* size of gap             */
   int        iml_end;                      /* end of area             */
   char       *achl1, *achl2;               /* working variables       */

   achl1 = (char *) adsp_contr->ac_stor_anchor;  /* get first element  */
   do {                                     /* loop over all auxiliary areas */
     uml_gap = 0;                           /* clear size of gap       */
     iml_end = ((struct dsd_aux_stor_header *) achl1)->umc_length;
     achl2 = (char *) achl1 + sizeof(struct dsd_aux_stor_header);
     uml_no_ele = ((struct dsd_aux_stor_header *) achl1)->umc_no_ele;
     while (uml_no_ele) {                   /* loop over all elements  */
       iml_end -= ((struct dsd_aux_stor_element *) achl2)->umc_end;
       if (iml_end < 0) {                   /* element too long        */
         printf( "xslstor1-l%05d-E m_aux_stor_check_gap gap less than zero position %p.\n",
                 __LINE__, achl2 );
         return FALSE;
       }
       if (((struct dsd_aux_stor_element *) achl2)->umc_end
             <= ((struct dsd_aux_stor_element *) achl2)->umc_start) {
         printf( "xslstor1-l%05d-E m_aux_stor_check_gap element end less than start position %p.\n",
                 __LINE__, achl2 );
         return FALSE;
       }
       if (uml_gap < iml_end) uml_gap = iml_end;  /* set new gap       */
       uml_no_ele--;                        /* decrement counter elements */
       iml_end = ((struct dsd_aux_stor_element *) achl2)->umc_start;
       achl2 += sizeof(struct dsd_aux_stor_element);
     }
     iml_end -= achl2 - achl1;              /* gap after header        */
     if (iml_end < 0) {                     /* element too long        */
       printf( "xslstor1-l%05d-E m_aux_stor_check_gap gap after header invalid position %p\n",
               __LINE__, achl1 );
       return FALSE;
     }
     iml_end -= sizeof(struct dsd_aux_stor_element);  /* space for one entry */
     if (iml_end >= 0) {                    /* can add new entry       */
       if (uml_gap < iml_end) uml_gap = iml_end;  /* set new gap       */
     } else {
       uml_gap = 0;                         /* cannot add new entry    */
     }
     if (((struct dsd_aux_stor_header *) achl1)->umc_len_gap != uml_gap) {
       printf( "xslstor1-l%05d-E m_aux_stor_check_gap gap calculated wrong - position %p gap-s %08X gap-r %08X\n",
               __LINE__, achl1,
               ((struct dsd_aux_stor_header *) achl1)->umc_len_gap,
               uml_gap );
       return FALSE;
     }
     achl1 = (char *) ((struct dsd_aux_stor_header *) achl1)->adsc_next;
   } while (achl1);
   return TRUE;                             /* all valid               */
} /* end m_aux_stor_check_gap()                                        */
#endif
