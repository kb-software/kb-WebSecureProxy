/**
  hob-cdrdef1.h HOBLink Compression Record
  06.10.97 KB / 04.04.99 KB / 30.08.06 KB
*/

struct dsd_cdr_field {
   int        imc_func;                     /* called function         */
#ifndef DEF_IFUNC_START
#define DEF_IFUNC_START        0            /* start of processing, initialize */
#endif
#ifndef DEF_IFUNC_CONT
#define DEF_IFUNC_CONT         1            /* process data as specified */
                                            /* by buffer pointers      */
#endif
#ifndef DEF_IFUNC_RESET
#define DEF_IFUNC_RESET        2
#endif
#ifndef DEF_IFUNC_END
#define DEF_IFUNC_END          3
#endif
   int        imc_return;                   /* return code             */
#ifndef DEF_IRET_NORMAL
#define DEF_IRET_NORMAL        0            /* continue processing     */
#endif
#ifndef DEF_IRET_END
#define DEF_IRET_END           1            /* subroutine has ended processing */
#endif
#ifndef DEF_IRET_ERRAU
#define DEF_IRET_ERRAU         2            /* error in auxiliary prog */
#endif
#ifndef DEF_IRET_INVDA
#define DEF_IRET_INVDA         5            /* invalid data found      */
#endif
   BOOL       boc_mp_flush;                 /* end-of-record input     */
                                            /* set by main-program     */
   BOOL       boc_sr_flush;                 /* end-of-record output    */
                                            /* set by subroutine       */
   BOOL       boc_maybe_uncompressed;       /* subroutine may req unco */
                                            /* set by subroutine       */
   BOOL       boc_compressed;               /* use compressed output   */
                                            /* set by subroutine       */
   char       *achc_inpa;                   /* address act input-data  */
   char       *achc_inpe;                   /* address end input-data  */
   char       *achc_outa;                   /* address act output-data */
   char       *achc_oute;                   /* address end output-data */
   BOOL (* amc_aux) ( void *, int, void *, int );  /*auxiliary helper routine pointer */
                                            /* callback                */
#ifndef DEF_AUX_MEMGET
#define DEF_AUX_MEMGET             0        /* get / acquire a block of memory */
#endif
#ifndef DEF_AUX_MEMFREE
#define DEF_AUX_MEMFREE            1        /* free / release a block of memory */
#endif
   void *     ac_ext;                       /* attached buffer pointer */
   void *     vpc_userfld;                  /* User Field Subroutine   */
   int        imc_save_mp_needed;           /* length save-area needed */
                                            /* set by subroutine       */
   char       *achc_save_mp;                /* save-area from main pr  */
                                            /* set by main-program     */
   int        imc_save_mp_given;            /* length save-area given  */
                                            /* set by main-program     */
   int        imc_param_1;                  /* parameter value 1       */
   int        imc_param_2;                  /* parameter value 2       */
   int        imc_param_3;                  /* parameter value 3       */
   int        imc_param_4;                  /* parameter value 4       */
};

#ifndef UCDRPROG

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

extern PTYPE void m_cdr_enc( struct dsd_cdr_field * );  /* encode = compression */
extern PTYPE void m_cdr_dec( struct dsd_cdr_field * );  /* decode = decompression */
#endif
