/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: hob-bitmap-compr-1.h                                |*/
/*| -------------                                                     |*/
/*|  HOB Header file for RDP Bitmap Compression                       |*/
/*|  KB 27.02.10                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2010                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|  GCC all platforms                                                |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#ifndef DEF_HL_HOB_BITMAP_COMPR_1_H__
#define DEF_HL_HOB_BITMAP_COMPR_1_H__

#ifndef DEF_HL_STR_G_I_1
#define DEF_HL_STR_G_I_1
struct dsd_gather_i_1 {                     /* gather input data       */
   struct dsd_gather_i_1 *adsc_next;        /* next in chain           */
   char *     achc_ginp_cur;                /* current position        */
   char *     achc_ginp_end;                /* end of input data       */
};
#endif

struct dsd_bitmap_compr_1 {                 /* Bitmap Compression      */
   void *     ac_screen_buffer;             /* screen buffer           */
   int        imc_coldep;                   /* current colour depth    */
   int        imc_bpp;                      /* bytes per pixel         */
   int        imc_dim_x;                    /* dimension x pixels      */
   int        imc_dim_y;                    /* dimension y pixels      */
   int        imc_dest_left;                /* destLeft                */
   int        imc_dest_top;                 /* destTop                 */
   int        imc_dest_right;               /* destRight               */
   int        imc_dest_bottom;              /* destBottom              */
   int        imc_bitmap_width;             /* width of bitmap         */
   int        imc_bitmap_height;            /* height of bitmap        */
   struct dsd_gather_i_1 *adsc_gai1_out;    /* output data             */
   char       *achc_wa_free_start;          /* start of free part of work area */
   char       *achc_wa_free_end;            /* end of free part of work area */
   BOOL       (* amc_get_workarea) ( struct dsd_bitmap_compr_1 * );  /* get new work area */
};

extern "C" BOOL m_bitmap_compr_1( struct dsd_bitmap_compr_1 * );

#endif /*!DEF_HL_HOB_BITMAP_COMPR_1_H__*/
