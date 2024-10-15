/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xsltime1                                            |*/
/*| -------------                                                     |*/
/*|  Header File of HOB Time Library                                  |*/
/*|    with date and time functions                                   |*/
/*|  KB 01.11.04                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB 2004                                           |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

// MJ 16.06.08:
#define FOR_WEBSERVER_GATE

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
#ifndef DEF_HL_CHARSET
#define DEF_HL_CHARSET

enum ied_charset {                          /* define character set    */
   ied_chs_invalid = 0,                     /* parameter is invalid    */
   ied_chs_ascii_850,                       /* ASCII 850               */
   ied_chs_ansi_819,                        /* ANSI 819                */
   ied_chs_utf_8,                           /* Unicode UTF-8           */
   ied_chs_utf_16,                          /* Unicode UTF-16 = WCHAR  */
   ied_chs_be_utf_16,                       /* Unicode UTF-16 big endian */
   ied_chs_le_utf_16,                       /* Unicode UTF-16 little endian */
   ied_chs_utf_32,                          /* Unicode UTF-32          */
   ied_chs_be_utf_32,                       /* Unicode UTF-32 big endian */
   ied_chs_le_utf_32,                       /* Unicode UTF-32 little endian */
   ied_chs_html_1                           /* HTML character set      */
};
#endif

#ifndef DEF_HL_AUX_EPOCH_1
#define DEF_HL_AUX_EPOCH_1

struct dsd_hl_aux_epoch_1 {                 /* request compute epoch   */
   void *     ac_epoch_str;                 /* epoch                   */
   ied_charset iec_chs_epoch;               /* character set           */
   int        inc_len_epoch;                /* length epoch in elements */
   int        imc_epoch_val;                /* epoch value             */
};
#endif

#ifndef PTYPE
#ifdef __cplusplus
#define PTYPE "C"
#else
#define PTYPE
#endif
#endif

#ifndef FOR_WEBSERVER_GATE
    extern PTYPE BOOL m_string_from_epoch( struct dsd_hl_aux_epoch_1 * );
    extern PTYPE BOOL m_epoch_from_string( struct dsd_hl_aux_epoch_1 * );
    #ifdef HL_WINALL1
    extern PTYPE int m_win_epoch_from_filetime( struct _FILETIME * );
    #endif
#else // wsg definitions:
    bool m_string_from_epoch( struct dsd_hl_aux_epoch_1 * );
    bool m_epoch_from_string( struct dsd_hl_aux_epoch_1 * );
    #ifdef HL_WINALL1
    int m_win_epoch_from_filetime( struct _FILETIME * );
    #endif
#endif // FOR_WEBSERVER_GATE
