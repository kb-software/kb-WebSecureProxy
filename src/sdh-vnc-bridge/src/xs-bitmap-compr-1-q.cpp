/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xs-bitmap-compr-1-04                                |*/
/*| -------------                                                     |*/
/*|  RDP bitmap compression                                           |*/
/*|  derived from xs-bitmap-compr-1-02                                |*/
/*|    with instructions from Mr. Martin                              |*/
/*|  KB 15.02.11                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|                                                                   |*/
/*| First Version for Production                                      |*/
/*| uses only Code Color and Fill 9                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/




/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#include <stddef.h>
#ifdef WIN32
#include <windows.h>
#include <stdio.h>
#else                                       /* is Unix                 */
#ifndef HL_UNIX
#define HL_UNIX
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "hob-hunix01.h"
#endif
#include "hob-bitmap-compr-1.h"

struct dsd_wa_contr {                       /* work area control       */
   struct dsd_gather_i_1 *adsc_gai1_last;   /* last output data        */
};

/*+-------------------------------------------------------------------+*/
/*| Internal function calls.                                          |*/
/*+-------------------------------------------------------------------+*/

static BOOL m_bmc_s( struct dsd_bitmap_compr_1 * );
static BOOL m_bmc_24( struct dsd_bitmap_compr_1 * );
static BOOL m_bmc_i( struct dsd_bitmap_compr_1 * );
static BOOL m_wa_extend( struct dsd_bitmap_compr_1 *, struct dsd_wa_contr * );

#define BITMAP_COMPR_EOD(adsp_bmc1)			((int)(adsp_bmc1->achc_wa_free_end - adsp_bmc1->achc_wa_free_start) <= (int)sizeof(struct dsd_gather_i_1))

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Main control procedure.                                           |*/
/*+-------------------------------------------------------------------+*/

extern "C" BOOL m_bitmap_compr_1( struct dsd_bitmap_compr_1 *adsp_bmc1 ) {
   switch (adsp_bmc1->imc_bpp) {            /* bytes per pixel         */
     case 2:
       return m_bmc_s( adsp_bmc1 );
     case 3:
       return m_bmc_24( adsp_bmc1 );
     case 4:
       return m_bmc_i( adsp_bmc1 );
   }
   return FALSE;
} /* end m_bitmap_compr_1()                                            */

static BOOL m_bmc_s( struct dsd_bitmap_compr_1 *adsp_bmc1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   int        iml_cur_line;                 /* current line            */
   int        iml_disp_nl;                  /* displacement next line  */
   int        iml_save_fill;                /* save number of fill     */
   unsigned short int xxl_pixel_white;         /* pixel white             */
   unsigned short int *axxl_cur;               /* current position        */
   unsigned short int *axxl_eol_1;             /* end of line             */
   unsigned short int *axxl_eol_2;             /* end of valid pixels     */
   unsigned short int *axxl_w1;                /* working variable        */
   struct dsd_wa_contr dsl_wac;             /* work area control       */

   if (BITMAP_COMPR_EOD(adsp_bmc1)) {
     if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
     bol1 = adsp_bmc1->amc_get_workarea( adsp_bmc1 );
     if (bol1 == FALSE) return FALSE;       /* error occured           */
     if (BITMAP_COMPR_EOD(adsp_bmc1)) {
       return FALSE;
     }
   }
// to-do 13.03.10 KB storage alignment
   adsp_bmc1->achc_wa_free_end -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) adsp_bmc1->achc_wa_free_end)
   ADSL_GAI1_OUT_G->achc_ginp_cur = adsp_bmc1->achc_wa_free_start;
   adsp_bmc1->adsc_gai1_out = ADSL_GAI1_OUT_G;  /* output data         */
   dsl_wac.adsc_gai1_last = ADSL_GAI1_OUT_G;  /* last output data      */
#undef ADSL_GAI1_OUT_G
   xxl_pixel_white = 0XFFFF;                /* pixel white             */
   if (adsp_bmc1->imc_coldep == 15) {
     xxl_pixel_white = 0X7FFF;              /* pixel white             */
   }
   iml_disp_nl = adsp_bmc1->imc_dim_x;      /* displacement next line  */
   iml_save_fill = 0;                       /* save number of fill     */
   iml_cur_line = adsp_bmc1->imc_dest_bottom;  /* current line         */

   p_bmc_20:                                /* next line               */
   axxl_cur = (unsigned short int *) adsp_bmc1->ac_screen_buffer
                + iml_cur_line * iml_disp_nl
                + adsp_bmc1->imc_dest_left;
   axxl_eol_1 = axxl_cur + adsp_bmc1->imc_bitmap_width;
   axxl_eol_2 = (unsigned short int *) adsp_bmc1->ac_screen_buffer
                + iml_cur_line * iml_disp_nl
                + adsp_bmc1->imc_dest_right + 1;

   p_bmc_32:                                /* examine pixels          */
   if (iml_cur_line == adsp_bmc1->imc_dest_bottom) {  /* is first line */
     goto p_bmc_40;                         /* examine run length      */
   }
   axxl_w1 = axxl_cur;                      /* get current position    */
   while (TRUE) {
     if (*axxl_cur != *(axxl_cur + iml_disp_nl)) break;  /* not same as line before */
     axxl_cur++;                            /* next pixel              */
     if (axxl_cur >= axxl_eol_2) {          /* at end of valid pixels  */
       axxl_cur = axxl_eol_1;               /* set end total line      */
       break;
     }
   }
   iml_save_fill += axxl_cur - axxl_w1;     /* number of pixels        */
   if (axxl_cur >= axxl_eol_1) {            /* at end of line          */
     goto p_bmc_80;                         /* end of this line        */
   }
   while (iml_save_fill > 0) {              /* save number of fill     */
     if (iml_save_fill < 32) {
       if ((adsp_bmc1->achc_wa_free_start + 1)
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) iml_save_fill;  /* control byte */
       break;
     }
     if (iml_save_fill < (32 + 256)) {
       if ((adsp_bmc1->achc_wa_free_start + 2)
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0;  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml_save_fill - 32);  /* byte with length */
       break;
     }
     if ((adsp_bmc1->achc_wa_free_start + 3)
           > adsp_bmc1->achc_wa_free_end) {
       if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
       bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
       if (bol1 == FALSE) return FALSE;     /* error occured           */
     }
     iml1 = iml_save_fill;
     if (iml1 > 0XFFFF) iml1 = 0XFFFF;
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0XF0;  /* control byte */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) iml1;  /* first byte with length */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml1 >> 8);  /* second byte with length */
     iml_save_fill -= iml1;
     if (iml_save_fill <= 0) break;         /* nothing more            */
     /* output of a single pixel is needed                             */

     axxl_w1 = (unsigned short int *) adsp_bmc1->ac_screen_buffer
                 + iml_cur_line * iml_disp_nl
                 + adsp_bmc1->imc_dest_left;
     iml1 = axxl_cur - axxl_w1;
     iml2 = iml1 - iml_save_fill;
     if (iml2 < 0) {
       iml3 = adsp_bmc1->imc_bitmap_width;
       iml4 = (iml2 * -1 + iml3 - 1) / iml3;
       iml2 += iml4 * iml3;
       axxl_w1 += iml4 * iml_disp_nl;
     }
     axxl_w1 += iml2;
     if ((adsp_bmc1->achc_wa_free_start + 1 + sizeof(unsigned short int))
           > adsp_bmc1->achc_wa_free_end) {
       if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
       bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
       if (bol1 == FALSE) return FALSE;     /* error occured           */
     }
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (0X60 | 1);  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 0);  /* first byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 1);  /* second byte colour */
     iml_save_fill--;                       /* one pixel less          */
   }
   iml_save_fill = 0;                       /* save number of fill     */

   p_bmc_40:                                /* examine run length      */
   axxl_w1 = axxl_cur;                      /* get current position    */
   while (TRUE) {
     axxl_cur++;                            /* next pixel              */
     if (axxl_cur >= axxl_eol_2) {          /* at end of valid pixels  */
       axxl_cur = axxl_eol_1;               /* set end total line      */
       break;
     }
     if (*axxl_cur != *axxl_w1) break;      /* not same colour         */
   }
   iml1 = axxl_cur - axxl_w1;               /* number of pixels        */
   do {
     if (iml1 < 32) {
       if (iml1 == 1) {
         if ((adsp_bmc1->achc_wa_free_start + 1) > adsp_bmc1->achc_wa_free_end) {
           if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
           bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
           if (bol1 == FALSE) return FALSE;  /* error occured          */
         }
         if (*axxl_w1 == 0) {
           *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0XFE;  /* black */
           break;
         }
         if (*axxl_w1 == xxl_pixel_white) {
           *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0XFD;  /* white */
           break;
         }
       }
       if ((adsp_bmc1->achc_wa_free_start + 1 + sizeof(unsigned short int))
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (0X60 | iml1);  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 0);  /* first byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 1);  /* second byte colour */
       break;
     }
     if (iml1 < (32 + 256)) {
       if ((adsp_bmc1->achc_wa_free_start + 2 + sizeof(unsigned short int))
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0X60;  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml1 - 32);  /* byte with length */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 0);  /* first byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 1);  /* second byte colour */
       break;
     }
     if ((adsp_bmc1->achc_wa_free_start + 3 + sizeof(unsigned short int))
           > adsp_bmc1->achc_wa_free_end) {
       if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
       bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
       if (bol1 == FALSE) return FALSE;     /* error occured           */
     }
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0XF3;  /* control byte */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) iml1;  /* first byte with length */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml1 >> 8);  /* second byte with length */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 0);  /* first byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 1);  /* second byte colour */
   } while (FALSE);
   if (axxl_cur < axxl_eol_1) {             /* not yet end of line     */
     goto p_bmc_32;                         /* examine pixels          */
   }

   p_bmc_80:                                /* end of this line        */
   if (iml_cur_line > adsp_bmc1->imc_dest_top) {  /* still lines to do */
     iml_cur_line--;                        /* current line            */
     goto p_bmc_20;                         /* next line               */
   }
   while (iml_save_fill > 0) {              /* save number of fill     */
     if (iml_save_fill < 32) {
       if ((adsp_bmc1->achc_wa_free_start + 1)
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) iml_save_fill;  /* control byte */
       break;
     }
     if (iml_save_fill < (32 + 256)) {
       if ((adsp_bmc1->achc_wa_free_start + 2)
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0;  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml_save_fill - 32);  /* byte with length */
       break;
     }
     if ((adsp_bmc1->achc_wa_free_start + 3)
           > adsp_bmc1->achc_wa_free_end) {
       if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
       bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
       if (bol1 == FALSE) return FALSE;     /* error occured           */
     }
     iml1 = iml_save_fill;
     if (iml1 > 0XFFFF) iml1 = 0XFFFF;
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0XF0;  /* control byte */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) iml1;  /* first byte with length */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml1 >> 8);  /* second byte with length */
     iml_save_fill -= iml1;
     if (iml_save_fill <= 0) break;         /* nothing more            */
     /* output of a single pixel is needed                             */

     axxl_w1 = (unsigned short int *) adsp_bmc1->ac_screen_buffer
                 + iml_cur_line * iml_disp_nl
                 + adsp_bmc1->imc_dest_left;
     iml1 = axxl_cur - axxl_w1;
     iml2 = iml1 - iml_save_fill;
     if (iml2 < 0) {
       iml3 = adsp_bmc1->imc_bitmap_width;
       iml4 = (iml2 * -1 + iml3 - 1) / iml3;
       iml2 += iml4 * iml3;
       axxl_w1 += iml4 * iml_disp_nl;
     }
     axxl_w1 += iml2;
     if ((adsp_bmc1->achc_wa_free_start + 1 + sizeof(unsigned short int))
           > adsp_bmc1->achc_wa_free_end) {
       if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
       bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
       if (bol1 == FALSE) return FALSE;     /* error occured           */
     }
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (0X60 | 1);  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 0);  /* first byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 1);  /* second byte colour */
     iml_save_fill--;                       /* one pixel less          */
   }
   dsl_wac.adsc_gai1_last->achc_ginp_end = adsp_bmc1->achc_wa_free_start;
   dsl_wac.adsc_gai1_last->adsc_next = NULL;  /* is last in chain      */
   return TRUE;
} /* end m_bmc_s()                                                     */

static BOOL m_bmc_24( struct dsd_bitmap_compr_1 *adsp_bmc1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   int        iml_cur_line;                 /* current line            */
   int        iml_disp_nl;                  /* displacement next line  */
   int        iml_save_fill;                /* save number of fill     */
   unsigned char *axxl_cur;               /* current position        */
   unsigned char *axxl_eol_1;             /* end of line             */
   unsigned char *axxl_eol_2;             /* end of valid pixels     */
   unsigned char *axxl_w1;                /* working variable        */
   struct dsd_wa_contr dsl_wac;             /* work area control       */

   if (BITMAP_COMPR_EOD(adsp_bmc1)) {
     if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
     bol1 = adsp_bmc1->amc_get_workarea( adsp_bmc1 );
     if (bol1 == FALSE) return FALSE;       /* error occured           */
     if (BITMAP_COMPR_EOD(adsp_bmc1)) {
       return FALSE;
     }
   }
// to-do 13.03.10 KB storage alignment
   adsp_bmc1->achc_wa_free_end -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) adsp_bmc1->achc_wa_free_end)
   ADSL_GAI1_OUT_G->achc_ginp_cur = adsp_bmc1->achc_wa_free_start;
   adsp_bmc1->adsc_gai1_out = ADSL_GAI1_OUT_G;  /* output data         */
   dsl_wac.adsc_gai1_last = ADSL_GAI1_OUT_G;  /* last output data      */
#undef ADSL_GAI1_OUT_G
   iml_disp_nl = adsp_bmc1->imc_dim_x * 3;  /* displacement next line  */
   iml_save_fill = 0;                       /* save number of fill     */
   iml_cur_line = adsp_bmc1->imc_dest_bottom;  /* current line         */

   p_bmc_20:                                /* next line               */
   axxl_cur = (unsigned char *) adsp_bmc1->ac_screen_buffer
                + iml_cur_line * iml_disp_nl
                + adsp_bmc1->imc_dest_left * 3;
   axxl_eol_1 = axxl_cur + adsp_bmc1->imc_bitmap_width * 3;
   axxl_eol_2 = (unsigned char *) adsp_bmc1->ac_screen_buffer
                + iml_cur_line * iml_disp_nl
                + (adsp_bmc1->imc_dest_right + 1) * 3;

   p_bmc_32:                                /* examine pixels          */
   if (iml_cur_line == adsp_bmc1->imc_dest_bottom) {  /* is first line */
     goto p_bmc_40;                         /* examine run length      */
   }
   axxl_w1 = axxl_cur;                      /* get current position    */
   while (TRUE) {
     if (*axxl_cur != *(axxl_cur + iml_disp_nl)) break;  /* not same as line before */
     axxl_cur++;                            /* next pixel              */
     if (axxl_cur >= axxl_eol_2) {          /* at end of valid pixels  */
       axxl_cur = axxl_eol_1;               /* set end total line      */
       break;
     }
   }
   iml1 = (axxl_cur - axxl_w1) / 3;         /* number of pixels        */
   iml_save_fill += iml1;                   /* save number of pixels   */
   axxl_cur = axxl_w1 + iml1 * 3;           /* here next pixel         */
   if (axxl_cur >= axxl_eol_1) {            /* at end of line          */
     goto p_bmc_80;                         /* end of this line        */
   }
   while (iml_save_fill > 0) {              /* save number of fill     */
     if (iml_save_fill < 32) {
       if ((adsp_bmc1->achc_wa_free_start + 1)
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) iml_save_fill;  /* control byte */
       break;
     }
     if (iml_save_fill < (32 + 256)) {
       if ((adsp_bmc1->achc_wa_free_start + 2)
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0;  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml_save_fill - 32);  /* byte with length */
       break;
     }
     if ((adsp_bmc1->achc_wa_free_start + 3)
           > adsp_bmc1->achc_wa_free_end) {
       if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
       bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
       if (bol1 == FALSE) return FALSE;     /* error occured           */
     }
     iml1 = iml_save_fill;
     if (iml1 > 0XFFFF) iml1 = 0XFFFF;
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0XF0;  /* control byte */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) iml1;  /* first byte with length */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml1 >> 8);  /* second byte with length */
     iml_save_fill -= iml1;
     if (iml_save_fill <= 0) break;         /* nothing more            */
     /* output of a single pixel is needed                             */

     axxl_w1 = (unsigned char *) adsp_bmc1->ac_screen_buffer
                 + iml_cur_line * iml_disp_nl
                 + adsp_bmc1->imc_dest_left * 3;
     iml1 = (axxl_cur - axxl_w1) / 3;
     iml2 = iml1 - iml_save_fill;
     if (iml2 < 0) {
       iml3 = adsp_bmc1->imc_bitmap_width * 3;
       iml4 = (iml2 * -1 + iml3 - 1) / iml3;
       iml2 += iml4 * iml3;
       axxl_w1 += iml4 * iml_disp_nl;
     }
     axxl_w1 += iml2 * 3;
     if ((adsp_bmc1->achc_wa_free_start + 1 + 3)
           > adsp_bmc1->achc_wa_free_end) {
       if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
       bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
       if (bol1 == FALSE) return FALSE;     /* error occured           */
     }
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (0X60 | 1);  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 0);  /* first byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 1);  /* second byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 2);  /* third byte colour */
     iml_save_fill--;                       /* one pixel less          */
   }
   iml_save_fill = 0;                       /* save number of fill     */

   p_bmc_40:                                /* examine run length      */
   axxl_w1 = axxl_cur;                      /* get current position    */
   while (TRUE) {
     axxl_cur += 3;                         /* next pixel              */
     if (axxl_cur >= axxl_eol_2) {          /* at end of valid pixels  */
       axxl_cur = axxl_eol_1;               /* set end total line      */
       break;
     }
     if (*(axxl_cur + 0) != *(axxl_w1 + 0)) break;  /* not same colour */
     if (*(axxl_cur + 1) != *(axxl_w1 + 1)) break;  /* not same colour */
     if (*(axxl_cur + 2) != *(axxl_w1 + 2)) break;  /* not same colour */
   }
   iml1 = (axxl_cur - axxl_w1) / 3;         /* number of pixels        */
   axxl_cur = axxl_w1 + iml1 * 3;           /* here next pixel         */
   do {
     if (iml1 < 32) {
       if (iml1 == 1) {
         if ((adsp_bmc1->achc_wa_free_start + 1) > adsp_bmc1->achc_wa_free_end) {
           if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
           bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
           if (bol1 == FALSE) return FALSE;  /* error occured          */
         }
         if (   (*(axxl_w1 + 0) == 0)
             && (*(axxl_w1 + 1) == 0)
             && (*(axxl_w1 + 2) == 0)) {
           *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0XFE;  /* black */
           break;
         }
         if (   (*(axxl_w1 + 0) == 0XFF)
             && (*(axxl_w1 + 1) == 0XFF)
             && (*(axxl_w1 + 2) == 0XFF)) {
           *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0XFD;  /* white */
           break;
         }
       }
       if ((adsp_bmc1->achc_wa_free_start + 1 + 3)
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (0X60 | iml1);  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 0);  /* first byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 1);  /* second byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 2);  /* third byte colour */
       break;
     }
     if (iml1 < (32 + 256)) {
       if ((adsp_bmc1->achc_wa_free_start + 2 + 3)
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0X60;  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml1 - 32);  /* byte with length */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 0);  /* first byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 1);  /* second byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 2);  /* third byte colour */
       break;
     }
     if ((adsp_bmc1->achc_wa_free_start + 3 + 3)
           > adsp_bmc1->achc_wa_free_end) {
       if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
       bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
       if (bol1 == FALSE) return FALSE;     /* error occured           */
     }
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0XF3;  /* control byte */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) iml1;  /* first byte with length */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml1 >> 8);  /* second byte with length */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 0);  /* first byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 1);  /* second byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 2);  /* third byte colour */
   } while (FALSE);
   if (axxl_cur < axxl_eol_1) {             /* not yet end of line     */
     goto p_bmc_32;                         /* examine pixels          */
   }

   p_bmc_80:                                /* end of this line        */
   if (iml_cur_line > adsp_bmc1->imc_dest_top) {  /* still lines to do */
     iml_cur_line--;                        /* current line            */
     goto p_bmc_20;                         /* next line               */
   }
   while (iml_save_fill > 0) {              /* save number of fill     */
     if (iml_save_fill < 32) {
       if ((adsp_bmc1->achc_wa_free_start + 1)
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) iml_save_fill;  /* control byte */
       break;
     }
     if (iml_save_fill < (32 + 256)) {
       if ((adsp_bmc1->achc_wa_free_start + 2)
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0;  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml_save_fill - 32);  /* byte with length */
       break;
     }
     if ((adsp_bmc1->achc_wa_free_start + 3)
           > adsp_bmc1->achc_wa_free_end) {
       if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
       bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
       if (bol1 == FALSE) return FALSE;     /* error occured           */
     }
     iml1 = iml_save_fill;
     if (iml1 > 0XFFFF) iml1 = 0XFFFF;
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0XF0;  /* control byte */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) iml1;  /* first byte with length */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml1 >> 8);  /* second byte with length */
     iml_save_fill -= iml1;
     if (iml_save_fill <= 0) break;         /* nothing more            */
     /* output of a single pixel is needed                             */

     axxl_w1 = (unsigned char *) adsp_bmc1->ac_screen_buffer
                 + iml_cur_line * iml_disp_nl
                 + adsp_bmc1->imc_dest_left * 3;
     iml1 = (axxl_cur - axxl_w1) / 3;
     iml2 = iml1 - iml_save_fill;
     if (iml2 < 0) {
       iml3 = adsp_bmc1->imc_bitmap_width * 3;
       iml4 = (iml2 * -1 + iml3 - 1) / iml3;
       iml2 += iml4 * iml3;
       axxl_w1 += iml4 * iml_disp_nl;
     }
     axxl_w1 += iml2 * 3;
     if ((adsp_bmc1->achc_wa_free_start + 1 + 3)
           > adsp_bmc1->achc_wa_free_end) {
       if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
       bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
       if (bol1 == FALSE) return FALSE;     /* error occured           */
     }
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (0X60 | 1);  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 0);  /* first byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 1);  /* second byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 2);  /* third byte colour */
     iml_save_fill--;                       /* one pixel less          */
   }
   dsl_wac.adsc_gai1_last->achc_ginp_end = adsp_bmc1->achc_wa_free_start;
   dsl_wac.adsc_gai1_last->adsc_next = NULL;  /* is last in chain      */
   return TRUE;
} /* end m_bmc_24()                                                    */

static BOOL m_bmc_i( struct dsd_bitmap_compr_1 *adsp_bmc1 ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2, iml3, iml4;       /* working variables       */
   int        iml_cur_line;                 /* current line            */
   int        iml_disp_nl;                  /* displacement next line  */
   int        iml_save_fill;                /* save number of fill     */
   unsigned int *axxl_cur;               /* current position        */
   unsigned int *axxl_eol_1;             /* end of line             */
   unsigned int *axxl_eol_2;             /* end of valid pixels     */
   unsigned int *axxl_w1;                /* working variable        */
   struct dsd_wa_contr dsl_wac;             /* work area control       */

   if (BITMAP_COMPR_EOD(adsp_bmc1)) {
     if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
     bol1 = adsp_bmc1->amc_get_workarea( adsp_bmc1 );
     if (bol1 == FALSE) return FALSE;       /* error occured           */
     if (BITMAP_COMPR_EOD(adsp_bmc1)) {
       return FALSE;
     }
   }
// to-do 13.03.10 KB storage alignment
   adsp_bmc1->achc_wa_free_end -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) adsp_bmc1->achc_wa_free_end)
   ADSL_GAI1_OUT_G->achc_ginp_cur = adsp_bmc1->achc_wa_free_start;
   adsp_bmc1->adsc_gai1_out = ADSL_GAI1_OUT_G;  /* output data         */
   dsl_wac.adsc_gai1_last = ADSL_GAI1_OUT_G;  /* last output data      */
#undef ADSL_GAI1_OUT_G
   iml_disp_nl = adsp_bmc1->imc_dim_x;      /* displacement next line  */
   iml_save_fill = 0;                       /* save number of fill     */
   iml_cur_line = adsp_bmc1->imc_dest_bottom;  /* current line         */

   p_bmc_20:                                /* next line               */
   axxl_cur = (unsigned int *) adsp_bmc1->ac_screen_buffer
                + iml_cur_line * iml_disp_nl
                + adsp_bmc1->imc_dest_left;
   axxl_eol_1 = axxl_cur + adsp_bmc1->imc_bitmap_width;
   axxl_eol_2 = (unsigned int *) adsp_bmc1->ac_screen_buffer
                + iml_cur_line * iml_disp_nl
                + adsp_bmc1->imc_dest_right + 1;

   p_bmc_32:                                /* examine pixels          */
   if (iml_cur_line == adsp_bmc1->imc_dest_bottom) {  /* is first line */
     goto p_bmc_40;                         /* examine run length      */
   }
   axxl_w1 = axxl_cur;                      /* get current position    */
   while (TRUE) {
     if (*axxl_cur != *(axxl_cur + iml_disp_nl)) break;  /* not same as line before */
     axxl_cur++;                            /* next pixel              */
     if (axxl_cur >= axxl_eol_2) {          /* at end of valid pixels  */
       axxl_cur = axxl_eol_1;               /* set end total line      */
       break;
     }
   }
   iml_save_fill += axxl_cur - axxl_w1;     /* number of pixels        */
   if (axxl_cur >= axxl_eol_1) {            /* at end of line          */
     goto p_bmc_80;                         /* end of this line        */
   }
   while (iml_save_fill > 0) {              /* save number of fill     */
     if (iml_save_fill < 32) {
       if ((adsp_bmc1->achc_wa_free_start + 1)
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) iml_save_fill;  /* control byte */
       break;
     }
     if (iml_save_fill < (32 + 256)) {
       if ((adsp_bmc1->achc_wa_free_start + 2)
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0;  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml_save_fill - 32);  /* byte with length */
       break;
     }
     if ((adsp_bmc1->achc_wa_free_start + 3)
           > adsp_bmc1->achc_wa_free_end) {
       if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
       bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
       if (bol1 == FALSE) return FALSE;     /* error occured           */
     }
     iml1 = iml_save_fill;
     if (iml1 > 0XFFFF) iml1 = 0XFFFF;
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0XF0;  /* control byte */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) iml1;  /* first byte with length */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml1 >> 8);  /* second byte with length */
     iml_save_fill -= iml1;
     if (iml_save_fill <= 0) break;         /* nothing more            */
     /* output of a single pixel is needed                             */

     axxl_w1 = (unsigned int *) adsp_bmc1->ac_screen_buffer
                 + iml_cur_line * iml_disp_nl
                 + adsp_bmc1->imc_dest_left;
     iml1 = axxl_cur - axxl_w1;
     iml2 = iml1 - iml_save_fill;
     if (iml2 < 0) {
       iml3 = adsp_bmc1->imc_bitmap_width;
       iml4 = (iml2 * -1 + iml3 - 1) / iml3;
       iml2 += iml4 * iml3;
       axxl_w1 += iml4 * iml_disp_nl;
     }
     axxl_w1 += iml2;
     if ((adsp_bmc1->achc_wa_free_start + 1 + sizeof(unsigned int))
           > adsp_bmc1->achc_wa_free_end) {
       if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
       bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
       if (bol1 == FALSE) return FALSE;     /* error occured           */
     }
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (0X60 | 1);  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 0);  /* first byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 1);  /* second byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 2);  /* third byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 3);  /* fourth byte colour */
     iml_save_fill--;                       /* one pixel less          */
   }
   iml_save_fill = 0;                       /* save number of fill     */

   p_bmc_40:                                /* examine run length      */
   axxl_w1 = axxl_cur;                      /* get current position    */
   while (TRUE) {
     axxl_cur++;                            /* next pixel              */
     if (axxl_cur >= axxl_eol_2) {          /* at end of valid pixels  */
       axxl_cur = axxl_eol_1;               /* set end total line      */
       break;
     }
     if (*axxl_cur != *axxl_w1) break;      /* not same colour         */
   }
   iml1 = axxl_cur - axxl_w1;               /* number of pixels        */
   do {
     if (iml1 < 32) {
       if (iml1 == 1) {
         if ((adsp_bmc1->achc_wa_free_start + 1) > adsp_bmc1->achc_wa_free_end) {
           if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
           bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
           if (bol1 == FALSE) return FALSE;  /* error occured          */
         }
         if (*axxl_w1 == 0) {
           *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0XFE;  /* black */
           break;
         }
         if (*axxl_w1 == (unsigned int) 0XFFFFFFFF) {
           *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0XFD;  /* white */
           break;
         }
       }
       if ((adsp_bmc1->achc_wa_free_start + 1 + sizeof(unsigned int))
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (0X60 | iml1);  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 0);  /* first byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 1);  /* second byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 2);  /* third byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 3);  /* fourth byte colour */
       break;
     }
     if (iml1 < (32 + 256)) {
       if ((adsp_bmc1->achc_wa_free_start + 2 + sizeof(unsigned int))
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0X60;  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml1 - 32);  /* byte with length */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 0);  /* first byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 1);  /* second byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 2);  /* third byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 3);  /* fourth byte colour */
       break;
     }
     if ((adsp_bmc1->achc_wa_free_start + 3 + sizeof(unsigned int))
           > adsp_bmc1->achc_wa_free_end) {
       if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
       bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
       if (bol1 == FALSE) return FALSE;     /* error occured           */
     }
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0XF3;  /* control byte */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) iml1;  /* first byte with length */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml1 >> 8);  /* second byte with length */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 0);  /* first byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 1);  /* second byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 2);  /* third byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 3);  /* fourth byte colour */
   } while (FALSE);
   if (axxl_cur < axxl_eol_1) {             /* not yet end of line     */
     goto p_bmc_32;                         /* examine pixels          */
   }

   p_bmc_80:                                /* end of this line        */
   if (iml_cur_line > adsp_bmc1->imc_dest_top) {  /* still lines to do */
     iml_cur_line--;                        /* current line            */
     goto p_bmc_20;                         /* next line               */
   }
   while (iml_save_fill > 0) {              /* save number of fill     */
     if (iml_save_fill < 32) {
       if ((adsp_bmc1->achc_wa_free_start + 1)
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) iml_save_fill;  /* control byte */
       break;
     }
     if (iml_save_fill < (32 + 256)) {
       if ((adsp_bmc1->achc_wa_free_start + 2)
             > adsp_bmc1->achc_wa_free_end) {
         if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
         bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
         if (bol1 == FALSE) return FALSE;   /* error occured           */
       }
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0;  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml_save_fill - 32);  /* byte with length */
       break;
     }
     if ((adsp_bmc1->achc_wa_free_start + 3)
           > adsp_bmc1->achc_wa_free_end) {
       if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
       bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
       if (bol1 == FALSE) return FALSE;     /* error occured           */
     }
     iml1 = iml_save_fill;
     if (iml1 > 0XFFFF) iml1 = 0XFFFF;
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) 0XF0;  /* control byte */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) iml1;  /* first byte with length */
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (iml1 >> 8);  /* second byte with length */
     iml_save_fill -= iml1;
     if (iml_save_fill <= 0) break;         /* nothing more            */
     /* output of a single pixel is needed                             */

     axxl_w1 = (unsigned int *) adsp_bmc1->ac_screen_buffer
                 + iml_cur_line * iml_disp_nl
                 + adsp_bmc1->imc_dest_left;
     iml1 = axxl_cur - axxl_w1;
     iml2 = iml1 - iml_save_fill;
     if (iml2 < 0) {
       iml3 = adsp_bmc1->imc_bitmap_width;
       iml4 = (iml2 * -1 + iml3 - 1) / iml3;
       iml2 += iml4 * iml3;
       axxl_w1 += iml4 * iml_disp_nl;
     }
     axxl_w1 += iml2;
     if ((adsp_bmc1->achc_wa_free_start + 1 + sizeof(unsigned int))
           > adsp_bmc1->achc_wa_free_end) {
       if (adsp_bmc1->amc_get_workarea == NULL) return FALSE;
       bol1 = m_wa_extend( adsp_bmc1, &dsl_wac );
       if (bol1 == FALSE) return FALSE;     /* error occured           */
     }
     *adsp_bmc1->achc_wa_free_start++ = (unsigned char) (0X60 | 1);  /* control byte */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 0);  /* first byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 1);  /* second byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 2);  /* third byte colour */
       *adsp_bmc1->achc_wa_free_start++ = *((unsigned char *) axxl_w1 + 3);  /* fourth byte colour */
     iml_save_fill--;                       /* one pixel less          */
   }
   dsl_wac.adsc_gai1_last->achc_ginp_end = adsp_bmc1->achc_wa_free_start;
   dsl_wac.adsc_gai1_last->adsc_next = NULL;  /* is last in chain      */
   return TRUE;
} /* end m_bmc_i()                                                     */

static BOOL m_wa_extend( struct dsd_bitmap_compr_1 *adsp_bmc1,
                         struct dsd_wa_contr *adsp_wac ) {
   BOOL       bol1;                         /* working variable        */

   adsp_wac->adsc_gai1_last->achc_ginp_end = adsp_bmc1->achc_wa_free_start;
   bol1 = adsp_bmc1->amc_get_workarea( adsp_bmc1 );
   if (bol1 == FALSE) return FALSE;         /* error occured           */
   if ((adsp_bmc1->achc_wa_free_end - adsp_bmc1->achc_wa_free_start)
         < 32) {
     return FALSE;
   }
// to-do 13.03.10 KB storage alignment
   adsp_bmc1->achc_wa_free_end -= sizeof(struct dsd_gather_i_1);
#define ADSL_GAI1_OUT_G ((struct dsd_gather_i_1 *) adsp_bmc1->achc_wa_free_end)
   ADSL_GAI1_OUT_G->achc_ginp_cur = adsp_bmc1->achc_wa_free_start;
   adsp_wac->adsc_gai1_last->adsc_next = ADSL_GAI1_OUT_G;  /* append to chain of gather */
   adsp_wac->adsc_gai1_last = ADSL_GAI1_OUT_G;  /* last output data    */
#undef ADSL_GAI1_OUT_G
   return TRUE;                             /* all done                */
} /* m_wa_extend()                                                     */

