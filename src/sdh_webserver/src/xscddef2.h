#include <types_defines.h>

/*! \brief Compression interface structure
 *
 * @ingroup webserver
 *
 * xscddef2.h HOBLink Compression Interface 05.12.04 KB
 * file-oriented compression
*/
struct dsd_hl_cd_2 {
   unsigned char chrc_eye_catcher[8];       /*!< eye-catcher             */
   int        inc_func;                     /*!< called function         */
#ifndef DEF_IFUNC_START
#define DEF_IFUNC_START        0            //!< socket has been connected
#endif
#ifndef DEF_IFUNC_CONT
#define DEF_IFUNC_CONT         1            //!< process data as specified
                                            //!< by buffer pointers
#endif
   int        inc_return;                   /*!< return code             */
#ifndef DEF_IRET_NORMAL
#define DEF_IRET_NORMAL        0
#endif
#define DEF_IRET_END           1
#ifndef DEF_IRET_END
#endif
#ifndef DEF_IRET_ERRAU
#define DEF_IRET_ERRAU         2            /*!< error in auxiliary prog */
#endif
#ifndef DEF_IRET_ERREY
#define DEF_IRET_ERREY         3            /*!< eyecather invalid       */
#endif
#ifndef DEF_IRET_ERRNE
#define DEF_IRET_ERRNE         4            /*!< no end-of-file found    */
#endif
   BOOL       boc_eof;                      /*!< end of file input       */
                                            /*!< set by subroutine       */
   char       *achc_inpa;                   /*!< address act input-data  */
   char       *achc_inpe;                   /*!< address end input-data  */
   char       *achc_outa;                   /*!< address act output-data */
   char       *achc_oute;                   /*!< address end output-data */
   BOOL (* amc_aux) ( void *, int, void *, int );  //!< Helper routine pointer
#ifndef DEF_AUX_MEMGET
#define DEF_AUX_MEMGET             0        //!< get a block of memory
#endif
#ifndef DEF_AUX_MEMFREE
#define DEF_AUX_MEMFREE            1        //!< release a block of memory
#endif
   void *     ac_ext;                       //!< attached buffer pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
};

#ifndef UCDPROG

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

extern PTYPE void m_cd_enc( struct dsd_hl_cd_2 * );
extern PTYPE void m_cd_dec( struct dsd_hl_cd_2 * );

#endif
