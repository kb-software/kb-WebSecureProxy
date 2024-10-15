/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: XSBSTR01                                            |*/
/*| -------------                                                     |*/
/*|  HOBLink Secure / Blade Server Trimming / VDI cluster             |*/
/*|  KB 15.08.03                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB electronic 2003                                |*/
/*|  Copyright (C) HOB Germany 2008                                   |*/
/*|  Copyright (C) HOB Germany 2011                                   |*/
/*|  Copyright (C) HOB Germany 2012                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual C++ 6.0                                                |*/
/*|  MS Linker                                                        |*/
/*|  MS Visual Studio 2005 / VC8                                      |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#ifdef OLD_1112
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
#ifdef MAKEDEF1
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#ifdef HL_WINALL1
#include <windows.h>
#else
#include "solaris.h"
#endif
#define __XHSERVIF__
#include "XSHLSE01.H"

#define CHAR_CR        0X0D                 /* carriage-return         */
#define CHAR_LF        0X0A                 /* line-feed               */

#define GHFW(str) ((ULONG) ((str & 0X000000FF) << 24) \
        | ((str & 0X0000FF00) << 8) | ((str & 0X00FF0000) >> 8) \
        | ((str & 0XFF000000) >> 24))

#define GHHW(str) ((USHORT) ((str & 0X00FF) << 8) \
        | ((str & 0XFF00) >> 8))

#define TID    DWORD
#define HEV    void *
#define HQUEUE void *
#define APIRET int
#endif
#ifndef UNSIG_MED
#define UNSIG_MED unsigned int
#endif
#endif

/*+-------------------------------------------------------------------+*/
/*| Function Calls definitions.                                       |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Constant data.                                                    |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Internal used classes.                                            |*/
/*+-------------------------------------------------------------------+*/

#define DEF_NO_F_BSTR1         32           /* number in one frame     */

class dcl_blasetr_1 {                       /* class blade server trim */
   private:
     static class dcl_blasetr_1 *adss_blasetr_1_anchor;  /* anchor     */
     static class dcl_blasetr_1 *adss_blasetr_1_free;  /* anchor free  */
     class dcl_blasetr_1 *adsc_next;        /* chain of entries        */
     char     chrc_ineta_port[ 2 + 16 + 2];  /* INETA and port         */
     int      imc_end_time;                 /* time to end             */
     char     chc_usage;                    /* usage 1 = intern 2 = ex */
   public:
     enum en_call { en_ca_check, en_ca_stage1, en_ca_stage2 };
     static BOOL m_check_ineta( char *achp_ineta_port, en_call ienp_ca );
     static void m_set_twin_ineta( char *achp_ineta_port );
};

struct d_frame_bstr1_1 {                    /* frame for class blade s */
   class dcl_blasetr_1 dcltab1[ DEF_NO_F_BSTR1 ];
};

BOOL dcl_blasetr_1::m_check_ineta( char *achp_ineta_port, en_call ienp_ca ) {
   class dcl_blasetr_1 *adsl_blasetr_1_w1;
   class dcl_blasetr_1 *adsl_blasetr_1_w2;
   class dcl_blasetr_1 *adsl_blasetr_1_w3;
   struct d_frame_bstr1_1 *adlframe1;       /* frame for class blade s */
   int        iml1;                         /* working variable        */
   int        iml_old_end_time;             /* old end-time            */

#ifdef TRACEHLB
   printf( "dcl_blasetr_1::m_check_ineta() INETA=%d.%d.%d.%d\n",
           umpineta & 0XFF,
           (umpineta >> 8) & 0XFF,
           (umpineta >> 16) & 0XFF,
           (umpineta >> 24) & 0XFF );
#endif
   iml_old_end_time = m_get_time();         /* retrieve time in sec    */
   iml1 = *((unsigned char *) achp_ineta_port + 0);  /* get length     */
   m_lock_blade_control();                  /* lock resource           */
   adsl_blasetr_1_w1 = adss_blasetr_1_anchor;  /* get anchor           */
   adsl_blasetr_1_w2 = NULL;                /* is first in chain       */
   while (adsl_blasetr_1_w1) {              /* loop over chain         */
     adsl_blasetr_1_w3 = adsl_blasetr_1_w1;  /* save this entry        */
     adsl_blasetr_1_w1 = adsl_blasetr_1_w1->adsc_next;  /* get next in chain */
     if (adsl_blasetr_1_w3->imc_end_time < iml_old_end_time) {
       if (adsl_blasetr_1_w2 == NULL) {
         adss_blasetr_1_anchor = adsl_blasetr_1_w1;
       } else {
         adsl_blasetr_1_w2->adsc_next = adsl_blasetr_1_w1;
       }
       adsl_blasetr_1_w3->adsc_next = adss_blasetr_1_free;
       adss_blasetr_1_free = adsl_blasetr_1_w3;
     } else {
       adsl_blasetr_1_w2 = adsl_blasetr_1_w3;   /* save chain              */
       if (   (iml1 == *((unsigned char *) adsl_blasetr_1_w3->chrc_ineta_port + 0))
           && !memcmp( achp_ineta_port + 2,adsl_blasetr_1_w3->chrc_ineta_port + 2, iml1 - 2) ) {
         if (   (ienp_ca != en_ca_stage2)
             || (adsl_blasetr_1_w3->chc_usage == '2')) {
           m_unlock_blade_control();        /* unlock resource         */
           return FALSE;                    /* do not use this blade   */
         }
       }
     }
   }
   if (ienp_ca != en_ca_stage1) {
     m_unlock_blade_control();              /* unlock resource         */
     return TRUE;                           /* can use this blade      */
   }
   if (adss_blasetr_1_free == NULL) {       /* chain of free entries   */
     adlframe1 = (struct d_frame_bstr1_1 *) malloc( sizeof(struct d_frame_bstr1_1) );
     adsl_blasetr_1_w1 = &adlframe1->dcltab1[0];
     adss_blasetr_1_free = adsl_blasetr_1_w1;  /* get first entry      */
     iml1 = DEF_NO_F_BSTR1 - 1;
     do {
       adsl_blasetr_1_w1->adsc_next = adsl_blasetr_1_w1 + 1;
       adsl_blasetr_1_w1++;
       iml1--;
     } while (iml1 > 0);
     adsl_blasetr_1_w1->adsc_next = NULL;
   }
   adsl_blasetr_1_w1 = adss_blasetr_1_free;  /* get free entry         */
   adss_blasetr_1_free = adsl_blasetr_1_w1->adsc_next;  /* here is next free */
   memcpy( adsl_blasetr_1_w1->chrc_ineta_port, achp_ineta_port, sizeof(adsl_blasetr_1_w1->chrc_ineta_port) );  /* set INETA and port */
   adsl_blasetr_1_w1->chc_usage = '1';      /* set usage               */
#ifndef B080324
   adsl_blasetr_1_w1->imc_end_time = iml_old_end_time
                                   + adsg_loconf_1_inuse->imc_vdi_sign_on_time;  /* VDI sign on time */
#else
   adsl_blasetr_1_w1->imc_end_time = iml_old_end_time
                                   + ds_blade_control.imc_sign_on_time;
#endif
   adsl_blasetr_1_w1->adsc_next = adss_blasetr_1_anchor;  /* get old anchor */
   adss_blasetr_1_anchor = adsl_blasetr_1_w1;  /* set new anchor       */
   m_unlock_blade_control();                /* unlock resource         */
#ifndef B080324
   if (adsg_loconf_1_inuse->adsc_cluster == NULL) {  /* pointer to main cluster structure */
#ifdef FORKEDIT
   }
#endif
#else
   if (ds_blade_control.boc_twin_active == FALSE) {
#endif
     return TRUE;                           /* this blade is valid     */
   }
   iml1 = *((unsigned char *) achp_ineta_port + 0);
   m_cluster_vdi_send( (char *) achp_ineta_port + 2, iml1 - 2 );  /* send to others in cluster */
   return TRUE;                             /* this blade still valid  */
} /* end dcl_blasetr_1::m_check_ineta()                                */

void dcl_blasetr_1::m_set_twin_ineta( char *achp_ineta_port ) {
   class dcl_blasetr_1 *adsl_blasetr_1_w1;
   struct d_frame_bstr1_1 *adlframe1;       /* frame for class blade s */
   int iml1;                                /* working variable        */

#ifdef TRACEHLB
   printf( "dcl_blasetr_1::m_set_twin_ineta() INETA=%d.%d.%d.%d\n",
           umpineta & 0XFF,
           (umpineta >> 8) & 0XFF,
           (umpineta >> 16) & 0XFF,
           (umpineta >> 24) & 0XFF );
#endif
   m_lock_blade_control();                  /* lock resource           */
   if (adss_blasetr_1_free == NULL) {       /* chain of free entries   */
     adlframe1 = (struct d_frame_bstr1_1 *) malloc( sizeof(struct d_frame_bstr1_1) );
     adsl_blasetr_1_w1 = &adlframe1->dcltab1[0];
     adss_blasetr_1_free = adsl_blasetr_1_w1;  /* get first entry      */
     iml1 = DEF_NO_F_BSTR1 - 1;
     do {
       adsl_blasetr_1_w1->adsc_next = adsl_blasetr_1_w1 + 1;
       adsl_blasetr_1_w1++;
       iml1--;
     } while (iml1 > 0);
     adsl_blasetr_1_w1->adsc_next = NULL;
   }
   adsl_blasetr_1_w1 = adss_blasetr_1_free;  /* get free entry         */
   adss_blasetr_1_free = adsl_blasetr_1_w1->adsc_next;  /* here is next free */
   memcpy( adsl_blasetr_1_w1->chrc_ineta_port, achp_ineta_port, sizeof(adsl_blasetr_1_w1->chrc_ineta_port) );  /* set INETA and port */
   adsl_blasetr_1_w1->chc_usage = '2';      /* set usage               */
#ifndef B080324
   adsl_blasetr_1_w1->imc_end_time = m_get_time()
                                   + adsg_loconf_1_inuse->imc_vdi_sign_on_time;  /* VDI sign on time */
#else
   adsl_blasetr_1_w1->imc_end_time = m_get_time()
                                   + ds_blade_control.imc_sign_on_time;
#endif
   adsl_blasetr_1_w1->adsc_next = adss_blasetr_1_anchor;  /* get old anchor */
   adss_blasetr_1_anchor = adsl_blasetr_1_w1;  /* set new anchor       */
   m_unlock_blade_control();                /* unlock resource         */
} /* end dcl_blasetr_1::m_set_twin_ineta()                             */

