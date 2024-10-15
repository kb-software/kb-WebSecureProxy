//#define TRACEHL1
#define AECHANGE1
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: iswtspo1.cpp                                        |*/
/*| -------------                                                     |*/
/*|  get WTS (Windows Terminal Server) ports                          |*/
/*|  retrieve ports from Windows registry                             |*/
/*|  KB 12.01.07                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#include <windows.h>
#include <hob-wtspo1.h>

/**
  when iswtspo1 is called from IBIPGW08, the Windows WebSecureProxy,
  it cannot call WinSock functions direct,
  since there is no WinSock linked to IBIPGW08
*/

#ifndef IBIPGW08
#define IP_inet_addr inet_addr
#else
extern "C" {
typedef long (WINAPI* fnIP_inet_addr) (const char   FAR *cp );
}
//typedef long (WINAPI* fnIP_inet_addr) (const char   FAR *cp );
extern fnIP_inet_addr lpfninet_addr;
#define IP_inet_addr lpfninet_addr
#endif

/*+-------------------------------------------------------------------+*/
/*| Function Calls definitions.                                       |*/
/*+-------------------------------------------------------------------+*/

/* printf in main program                                              */
extern PTYPE int m_hl1_printf( char *achptext, ... );

/*+-------------------------------------------------------------------+*/
/*| Internal used structures.                                         |*/
/*+-------------------------------------------------------------------+*/

struct dsd_wts_reg_1 {                      /* WTS registry            */
   struct dsd_wts_reg_1 *adsc_next;         /* for chaining            */
   int        imc_len;                      /* length of name          */
   int        imc_port;                     /* port found              */
   int        imc_function;                 /* function found          */
#ifdef AECHANGE1
   int		  imc_wsenabled;				/* Winstation enabled	   */
#endif
   DWORD      dwc_lan_adapter;              /* LanAdapter found        */
   BOOL       boc_la;                       /* status LanAdapter       */
};

struct dsd_wts_reg_2 {                      /* WTS registry            */
  struct dsd_wts_reg_2 *adsc_next;          /* for chaining            */
  int   imc_len;                            /* length of name          */
  BOOL  boc_valid;                          /* entry is valid          */
  DWORD dwc_lan_adapter;                    /* LanAdapter found        */
  BOOL  boc_la;                             /* status LanAdapter       */
  unsigned int umc_ineta;                   /* IP-addr of adapter      */
};

/*+-------------------------------------------------------------------+*/
/*| Procedure division.                                               |*/
/*+-------------------------------------------------------------------+*/

/* get ports                                                           */
extern PTYPE void m_get_wtspo1_ineta( struct dsd_wtspo_1 *adsp_wtspo_1,
                                      struct dsd_ineta_1 *adsp_ineta_1,
                                      int imp_flags ) {
   int        iml1, iml2;                   /* working variables       */
   int        iml_port;                     /* port found              */
   int        iml_function;                 /* function processed      */
#ifdef AECHANGE1
   int		  iml_wsenabled;				/* Winstation enabled	   */
#endif
   DWORD      dwl1;                         /* working variable        */
   char       *achl1, *achl2;               /* working variables       */
   DWORD      dwl_error;                    /* return errors           */
   BOOL       bol1;                         /* working variable        */
   HKEY       dsl_key_1;                    /* registry key            */
   struct _FILETIME dsl_ft_1;               /* file time               */
   int        iml_len_reg_1;                /* length registry key     */
   int        iml_len_reg_2;                /* length registry key     */
   DWORD      dwl_len;
   DWORD      dwl_type;
   struct dsd_wts_reg_1 *adsl_wts_reg_11;   /* WTS registry            */
   struct dsd_wts_reg_1 *adsl_wts_reg_12;   /* WTS registry            */
   struct dsd_wts_reg_2 *adsl_wts_reg_21;   /* WTS registry            */
   struct dsd_wts_reg_2 *adsl_wts_reg_22;   /* WTS registry            */
   struct dsd_wts_reg_2 *adsl_wts_reg_23;   /* WTS registry            */
   char       chrl_work_1[512];             /* working variable        */
   char       chrl_work_2[ MAX_PATH ];      /* working variable        */
   char       chrl_work_3[ MAX_PATH ];      /* working variable        */

#ifdef TRACEHL1
   m_hl1_printf( "m_get_wtspo1_ineta() l%05d called " __DATE__, __LINE__ );
#endif
   memset( adsp_wtspo_1, 0, sizeof(struct dsd_wtspo_1) );
   if ((imp_flags & (DEF_WTSPO1_RDP | DEF_WTSPO1_ICA)) == 0) {
     goto pmtinf20;                         /* get SSL ports           */
   }

   adsl_wts_reg_11 = NULL;                  /* WTS registry chain      */
   adsl_wts_reg_21 = NULL;                  /* WTS registry chain      */
   achl1 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\Winstations",
   iml1 = RegOpenKeyExA( HKEY_LOCAL_MACHINE, achl1,
                         0, KEY_ALL_ACCESS, &dsl_key_1 );
   if (iml1 != ERROR_SUCCESS) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegOpenKeyEx Error %d - ignored",
                   __LINE__, achl1, iml1 );
     if (imp_flags & DEF_WTSPO1_RDP) {      /* RDP port requested      */
       adsp_wtspo_1->imc_port_rdp = -1;     /* make port invalid       */
     }
     if (imp_flags & DEF_WTSPO1_ICA) {      /* RDP port requested      */
       adsp_wtspo_1->imc_port_ica = -1;     /* make port invalid       */
     }
     goto pwtsreg64;                        /* continue                */
   }
   iml2 = 0;                                /* set index               */

   pwtsreg04:
   dwl1 = sizeof(chrl_work_1);
   iml1 = RegEnumKeyExA( dsl_key_1, iml2, chrl_work_1, &dwl1, NULL,
                         NULL, NULL, &dsl_ft_1 );
   if (iml1 != ERROR_SUCCESS) goto pwtsreg08;
   adsl_wts_reg_12 = (struct dsd_wts_reg_1 *) malloc( sizeof(struct dsd_wts_reg_1) + dwl1 + 1 );
#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T pwtsreg04 - adsl_wts_reg_12=%p adsl_wts_reg_11=%p name=%s",
                 __LINE__, adsl_wts_reg_12, adsl_wts_reg_11, chrl_work_1 );
#endif
   adsl_wts_reg_12->imc_len = dwl1;         /* set length              */
   memcpy( adsl_wts_reg_12 + 1, chrl_work_1, dwl1 );  /* copy key name */
   *((char *) (adsl_wts_reg_12 + 1) + dwl1) = 0;  /* make zero-terminated */
   adsl_wts_reg_12->adsc_next = adsl_wts_reg_11;  /* get old chain     */
   adsl_wts_reg_11 = adsl_wts_reg_12;       /* set new anchor          */
   iml2++;
   goto pwtsreg04;

   pwtsreg08:
   iml1 = RegCloseKey( dsl_key_1 );
   if (iml1 != ERROR_SUCCESS) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegCloseKey Error %d - ignored",
                   __LINE__, achl1, iml1 );
   }
   if (adsl_wts_reg_11 == NULL) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port nothing found - ignored",
                   __LINE__, achl1 );
     if (imp_flags & DEF_WTSPO1_RDP) {      /* RDP port requested      */
       adsp_wtspo_1->imc_port_rdp = -1;     /* make port invalid       */
     }
     if (imp_flags & DEF_WTSPO1_ICA) {      /* RDP port requested      */
       adsp_wtspo_1->imc_port_ica = -1;     /* make port invalid       */
     }
     goto pwtsreg64;                        /* continue                */
   }
   iml_len_reg_1 = strlen( achl1 );
   memcpy( chrl_work_2, achl1, iml_len_reg_1 );
   adsl_wts_reg_12 = adsl_wts_reg_11;       /* get first in chain      */

   pwtsreg12:                               /* read entry registry     */
#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T pwtsreg12 - adsl_wts_reg_12=%p adsl_wts_reg_12->adsc_next=%p",
                 __LINE__, adsl_wts_reg_12, adsl_wts_reg_12->adsc_next );
#endif
   if ((iml_len_reg_1 + 1 + adsl_wts_reg_12->imc_len + 1) > sizeof(chrl_work_2)) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port entry %s too long - ignored",
                   __LINE__, achl1, adsl_wts_reg_12 + 1 );
     goto pwtsreg16;                        /* continue                */
   }
   chrl_work_2[iml_len_reg_1] = '\\';
   memcpy( &chrl_work_2[ iml_len_reg_1 + 1 ], adsl_wts_reg_12 + 1, adsl_wts_reg_12->imc_len );
   chrl_work_2[ iml_len_reg_1 + 1 + adsl_wts_reg_12->imc_len ] = 0;  /* zero-terminated */
   iml1 = RegOpenKeyExA( HKEY_LOCAL_MACHINE, chrl_work_2,
                         0, KEY_ALL_ACCESS, &dsl_key_1 );
   if (iml1 != ERROR_SUCCESS) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegOpenKeyEx Error %d - ignored",
                   __LINE__, chrl_work_2, iml1 );
     goto pwtsreg16;                        /* continue                */
   }
   iml_port = -1;                           /* set port invalid        */
   dwl_len = sizeof(iml_port);
   iml1 = RegQueryValueExA( dsl_key_1, "PortNumber",
                            0, &dwl_type,
                            (unsigned char *) &iml_port, &dwl_len );
   if (iml1 != ERROR_SUCCESS) {
     if (iml1 != ERROR_FILE_NOT_FOUND) {
       m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegQueryValueEx PortNumber Error %d - ignored",
                     __LINE__, chrl_work_2, iml1 );
     }
     iml_port = -1;                         /* set port invalid        */
   }
#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T found registry RDP/ICA %s serverport %d",
                 __LINE__, chrl_work_2, iml_port );
#endif

#ifdef AECHANGE1
   dwl_len = sizeof(iml_wsenabled);
		/* search entry that enables RDP-Ports */
   iml1 = RegQueryValueExA( dsl_key_1, "fEnableWinStation",	
                            0, &dwl_type,
							(unsigned char *) &iml_wsenabled, &dwl_len );
   if (iml1 != ERROR_SUCCESS) {
     if (iml1 != ERROR_FILE_NOT_FOUND) {
       m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegQueryValueEx fEnableWinStation Error %d - ignored",
                     __LINE__, chrl_work_2, iml1 );
     }
     iml_wsenabled = -1;                    /* set variable invalid    */
	}

#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T found registry RDP/ICA %s fEnableWinStation %d",
                 __LINE__, chrl_work_2, iml_wsenabled );
#endif

#endif

   dwl_len = sizeof(chrl_work_3);
   iml1 = RegQueryValueExA( dsl_key_1, "WdPrefix",
                            0, &dwl_type,
                            (unsigned char *) chrl_work_3, &dwl_len );
   if (iml1 != ERROR_SUCCESS) {
     if (iml1 != ERROR_FILE_NOT_FOUND) {
       m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegQueryValueEx WdPrefix Error %d - ignored",
                     __LINE__, chrl_work_2, iml1 );
     }
     chrl_work_3[0] = 0;                    /* set variable invalid    */
   }
   iml2 = 0;
   if (!_stricoll( chrl_work_3, "RDP" )) {
     iml2 = 1;
   } else if (!_stricoll( chrl_work_3, "ICA" )) {
     iml2 = 2;
   }
#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T found registry RDP/ICA %s function %d",
                 __LINE__, chrl_work_2, iml2 );
#endif
   dwl_len = sizeof(chrl_work_3);
   iml1 = RegQueryValueExA( dsl_key_1, "PdName",
                            0, &dwl_type,
                            (unsigned char *) chrl_work_3, &dwl_len );
   if (iml1 != ERROR_SUCCESS) {
     if (iml1 != ERROR_FILE_NOT_FOUND) {
       m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegQueryValueEx PdName Error %d - ignored",
                     __LINE__, chrl_work_2, iml1 );
     }
     chrl_work_3[0] = 0;                    /* set variable invalid    */
   }
   if (_stricoll( chrl_work_3, "TCP" )) {   /* if protocol not TCP     */
     iml2 = 0;                              /* set function invalid    */
   }
#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T found registry RDP/ICA %s / %s overwritten-function %d",
                 __LINE__, chrl_work_2, chrl_work_3, iml2 );
#endif
   bol1 = TRUE;
   dwl_len = sizeof(dwl1);
   iml1 = RegQueryValueExA( dsl_key_1, "LanAdapter",
                            0, &dwl_type,
                            (unsigned char *) &dwl1, &dwl_len );
   if (iml1 != ERROR_SUCCESS) {
     if (iml1 != ERROR_FILE_NOT_FOUND) {
       m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegQueryValueEx LanAdapter Error %d - ignored",
                     __LINE__, chrl_work_2, iml1 );
     }
     bol1 = FALSE;                          /* set LanAdapter invalid  */
   }
#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T found registry RDP/ICA %s LanAdapter %08X",
                 __LINE__, chrl_work_2, dwl1 );
#endif
   iml1 = RegCloseKey( dsl_key_1 );
   if (iml1 != ERROR_SUCCESS) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegCloseKey Error %d - ignored",
                   __LINE__, chrl_work_2, iml1 );
   }
   adsl_wts_reg_12->imc_port = iml_port;    /* port found              */
   adsl_wts_reg_12->imc_function = iml2;    /* function found          */
   adsl_wts_reg_12->dwc_lan_adapter = dwl1;  /* LanAdapter found       */
   adsl_wts_reg_12->boc_la = bol1;          /* status LanAdapter       */
#ifdef AECHANGE1
   adsl_wts_reg_12->imc_wsenabled = iml_wsenabled;	/* Winstation enabled */
#endif

   pwtsreg16:                               /* check next entry        */
#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T pwtsreg16 - adsl_wts_reg_12=%p adsl_wts_reg_12->adsc_next=%p",
                 __LINE__, adsl_wts_reg_12, adsl_wts_reg_12->adsc_next );
#endif
   adsl_wts_reg_12 = adsl_wts_reg_12->adsc_next;  /* get next in chain */
   if (adsl_wts_reg_12) goto pwtsreg12;     /* continue                */
   /* check if for every adapter                                       */
   iml_function = 1;                        /* start with RDP          */
   if ((imp_flags & DEF_WTSPO1_RDP) == 0) {  /* RDP port not requested */
     iml_function = 2;                      /* process only ICA        */
   }

   pwtsreg20:                               /* process next function   */
   bol1 = TRUE;                             /* do not check INETA      */
   iml_port = -1;                           /* set port invalid        */
   adsl_wts_reg_12 = adsl_wts_reg_11;       /* get first in chain      */
   while (adsl_wts_reg_12) {                /* loop over all elements  */
     if (adsl_wts_reg_12->imc_function == iml_function) {  /* function found */
		 if (   (iml_port >= 0
#ifdef AECHANGE1
			 /* if server-port is already set and Winstation is enabled in more
				than one registry entry ==> too many ports found */
			 && adsl_wts_reg_12->imc_wsenabled
#endif			
			 )  /* server-port already set */
           && (bol1)) {                     /* for all adapters        */
         m_hl1_printf( "iswtspo1-%05d-W registry search RDP/ICA port - more than one port found",
                       __LINE__ );
		 iml_port = -1;                     /* make port invalid       */
         goto pwtsreg60;                    /* continue                */
       }
       if (adsl_wts_reg_12->boc_la == FALSE) {  /* status LanAdapter   */
         m_hl1_printf( "iswtspo1-%05d-W registry search RDP/ICA port - invalid LanAdapter",
                       __LINE__ );
         iml_port = -1;                     /* make port invalid       */
         goto pwtsreg60;                    /* continue                */
       }
       if (adsl_wts_reg_12->imc_port <= 0) {  /* invalid port          */
         m_hl1_printf( "iswtspo1-%05d-W registry search RDP/ICA port - invalid port", __LINE__ );
         iml_port = -1;                     /* make port invalid       */
         goto pwtsreg60;                    /* continue                */
       }
	
#ifdef AECHANGE1
			/* set port invalid if Winstation is disabled */
		if (adsl_wts_reg_12->imc_wsenabled == 0)
		{
			adsl_wts_reg_12->imc_port = -1;
		}	
		else
		{
#endif
			iml_port = adsl_wts_reg_12->imc_port;  /* get port              */
#ifdef AECHANGE1
		}
#endif
	
	if (adsl_wts_reg_12->dwc_lan_adapter) {  /* LanAdapter found    */
         bol1 = FALSE;                      /* has to search LanAdapt  */
       }
     }
     adsl_wts_reg_12 = adsl_wts_reg_12->adsc_next;  /* get next in chain */
   }
   if (iml_port < 0) {                      /* server-port not found */
     achl1 = "RDP";
     if (iml_function == 2) achl1 = "ICA";
     m_hl1_printf( "iswtspo1-%05d-W registry search %s port - no port found",
                   __LINE__, achl1 );
     goto pwtsreg60;                        /* continue                */
   }
   if (bol1) goto pwtsreg60;                /* all set                 */
   if (adsp_ineta_1->iec_ineta == ied_ineta_any) {  /* no LanAdapter necessary */
     iml_port = -1;                         /* make port invalid       */
     achl1 = "RDP";
     if (iml_function == 2) achl1 = "ICA";
     m_hl1_printf( "iswtspo1-%05d-W registry search %s port - more than one Lan Adapter and no IN_INETA set",
                   __LINE__, achl1 );
     goto pwtsreg60;                        /* continue                */
   }
   achl1 = "SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\lanatable",
   iml1 = RegOpenKeyExA( HKEY_LOCAL_MACHINE, achl1,
                         0, KEY_ALL_ACCESS, &dsl_key_1 );
   if (iml1 != ERROR_SUCCESS) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegOpenKeyEx Error %d - ignored",
                   __LINE__, achl1, iml1 );
     iml_port = -1;                         /* make port invalid       */
     goto pwtsreg60;                        /* continue                */
   }
   iml2 = 0;                                /* set index               */

   pwtsreg24:                               /* get next section        */
   dwl1 = sizeof(chrl_work_1);
   iml1 = RegEnumKeyExA( dsl_key_1, iml2, chrl_work_1, &dwl1, NULL,
                         NULL, NULL, &dsl_ft_1 );
   if (iml1 != ERROR_SUCCESS) goto pwtsreg28;
   adsl_wts_reg_22 = (struct dsd_wts_reg_2 *) malloc( sizeof(struct dsd_wts_reg_2) + dwl1 + 1 );
#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T pwtsreg04 - adsl_wts_reg_22=%p adsl_wts_reg_21=%p name=%s",
                 __LINE__, adsl_wts_reg_22, adsl_wts_reg_21, chrl_work_1 );
#endif
   adsl_wts_reg_22->imc_len = dwl1;         /* set length              */
   adsl_wts_reg_22->boc_valid = FALSE;      /* not yet valid           */
   memcpy( adsl_wts_reg_22 + 1, chrl_work_1, dwl1 );  /* copy key name */
   *((char *) (adsl_wts_reg_22 + 1) + dwl1) = 0;  /* make zero-terminated */
   adsl_wts_reg_22->adsc_next = adsl_wts_reg_21;  /* get old chain     */
   adsl_wts_reg_21 = adsl_wts_reg_22;       /* set new anchor          */
   iml2++;
   goto pwtsreg24;

   pwtsreg28:
   iml1 = RegCloseKey( dsl_key_1 );
   if (iml1 != ERROR_SUCCESS) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegCloseKey Error %d - ignored",
                   __LINE__, achl1, iml1 );
     iml_port = -1;                         /* make port invalid       */
     goto pwtsreg60;                        /* continue                */
   }
   iml_len_reg_1 = strlen( achl1 );
   memcpy( chrl_work_2, achl1, iml_len_reg_1 );
   adsl_wts_reg_22 = adsl_wts_reg_21;       /* get first in chain      */

   pwtsreg32:                               /* read entry registry     */
#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T pwtsreg22 - adsl_wts_reg_22=%p adsl_wts_reg_22->adsc_next=%p",
                 __LINE__, adsl_wts_reg_22, adsl_wts_reg_22->adsc_next );
#endif
   if ((iml_len_reg_1 + 1 + adsl_wts_reg_22->imc_len + 1) > sizeof(chrl_work_2)) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port entry %s too long - ignored",
                   __LINE__, achl1, adsl_wts_reg_22 + 1 );
     goto pwtsreg36;                        /* continue                */
   }
   chrl_work_2[iml_len_reg_1] = '\\';
   memcpy( &chrl_work_2[ iml_len_reg_1 + 1 ], adsl_wts_reg_22 + 1, adsl_wts_reg_22->imc_len );
   chrl_work_2[ iml_len_reg_1 + 1 + adsl_wts_reg_22->imc_len ] = 0;  /* zero-terminated */
   iml1 = RegOpenKeyExA( HKEY_LOCAL_MACHINE, chrl_work_2,
                         0, KEY_ALL_ACCESS, &dsl_key_1 );
   if (iml1 != ERROR_SUCCESS) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegOpenKeyEx Error %d - ignored",
                   __LINE__, chrl_work_2, iml1 );
     goto pwtsreg36;                        /* continue                */
   }
   bol1 = TRUE;
   dwl_len = sizeof(dwl1);
   iml1 = RegQueryValueExA( dsl_key_1, "LanaID",
                          0, &dwl_type,
                          (unsigned char *) &dwl1, &dwl_len );
   if (iml1 != ERROR_SUCCESS) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegQueryValueEx LanaID Error %d - ignored",
                   __LINE__, chrl_work_2, iml1 );
     bol1 = FALSE;                          /* set LanAdapter invalid  */
   }
#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T found registry RDP/ICA %s LanAdapter %08X",
                 __LINE__, chrl_work_2, dwl1 );
#endif
   iml1 = RegCloseKey( dsl_key_1 );
   if (iml1 != ERROR_SUCCESS) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegCloseKey Error %d - ignored",
                   __LINE__, chrl_work_2, iml1 );
   }
   adsl_wts_reg_22->dwc_lan_adapter = dwl1;  /* LanAdapter found       */
   adsl_wts_reg_22->boc_la = bol1;          /* status LanAdapter       */

   pwtsreg36:                               /* check adsc_next entry   */
#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T pwtsreg36 - adsl_wts_reg_22=%p adsl_wts_reg_22->adsc_next=%p",
                 __LINE__, adsl_wts_reg_22, adsl_wts_reg_22->adsc_next );
#endif
   adsl_wts_reg_22 = adsl_wts_reg_22->adsc_next;  /* get next in chain */
   if (adsl_wts_reg_22) goto pwtsreg32;     /* continue                */

   achl1 = "SYSTEM\\CurrentControlSet\\Services\\",
   iml_len_reg_1 = strlen( achl1 );
   achl2 = "\\Parameters\\Tcpip",
   iml_len_reg_2 = strlen( achl2 );
   memcpy( chrl_work_2, achl1, iml_len_reg_1 );
   adsl_wts_reg_22 = adsl_wts_reg_21;       /* get first in chain      */

   pwtsreg40:                               /* read entry registry     */
#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T pwtsreg40 - adsl_wts_reg_22=%p adsl_wts_reg_22->adsc_next=%p",
                 __LINE__, adsl_wts_reg_22, adsl_wts_reg_22->adsc_next );
#endif
   if ((iml_len_reg_1 + adsl_wts_reg_22->imc_len + iml_len_reg_2 + 1)
        > sizeof(chrl_work_2)) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port entry %s too long - ignored",
                   __LINE__, achl1, adsl_wts_reg_22 + 1 );
     goto pwtsreg48;                        /* continue                */
   }
   memcpy( &chrl_work_2[iml_len_reg_1], adsl_wts_reg_22 + 1, adsl_wts_reg_22->imc_len );
   memcpy( &chrl_work_2[ iml_len_reg_1 + adsl_wts_reg_22->imc_len ], achl2, iml_len_reg_2 + 1 );
   iml1 = RegOpenKeyExA( HKEY_LOCAL_MACHINE, chrl_work_2,
                         0, KEY_ALL_ACCESS, &dsl_key_1 );
   if (iml1 != ERROR_SUCCESS) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegOpenKeyEx Error %d - ignored",
                   __LINE__, chrl_work_2, iml1 );
     goto pwtsreg48;                        /* continue                */
   }
   dwl_len = sizeof(chrl_work_3);
   iml1 = RegQueryValueExA( dsl_key_1, "IPAddress",
                           0, &dwl_type,
                           (unsigned char *) chrl_work_3, &dwl_len );
   if (iml1 != ERROR_SUCCESS) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegQueryValueEx IPAddress Error %d - ignored",
                   __LINE__, chrl_work_2, iml1 );
     goto pwtsreg44;                        /* do not set values       */
   }
   /* attention IPV6                                                   */
   adsl_wts_reg_22->umc_ineta = IP_inet_addr( (char *) chrl_work_3 );
   if (adsl_wts_reg_22->umc_ineta != 0XFFFFFFFF) {  /* valid IP-address */
     adsl_wts_reg_22->boc_valid = TRUE;     /* is valid now            */
   }
#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T found registry RDP/ICA %s IPAddress %s / %08X",
                 __LINE__, chrl_work_2, chrl_work_3, adsl_wts_reg_22->umc_ineta );
#endif
   if (adsl_wts_reg_22->boc_valid == FALSE) {  /* is not valid         */
     goto pwtsreg44;                        /* do not set values       */
   }
   if (adsl_wts_reg_22->umc_ineta) {        /* is not dhcp             */
     goto pwtsreg44;                        /* do not set values       */
   }
   adsl_wts_reg_22->boc_valid = FALSE;      /* is not valid            */
   dwl_len = sizeof(chrl_work_3);
   iml1 = RegQueryValueExA( dsl_key_1, "DhcpIPAddress",
                            0, &dwl_type,
                            (unsigned char *) chrl_work_3, &dwl_len );
   if (iml1 != ERROR_SUCCESS) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegQueryValueEx DhcpIPAddress Error %d - ignored",
                   __LINE__, chrl_work_2, iml1 );
     goto pwtsreg44;                        /* do not set values       */
   }
   /* attention IPV6                                                   */
   adsl_wts_reg_22->umc_ineta = IP_inet_addr( (char *) chrl_work_3 );
   if (adsl_wts_reg_22->umc_ineta != 0XFFFFFFFF) {  /* valid IP-address */
     adsl_wts_reg_22->boc_valid = TRUE;     /* is valid now            */
   }
#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T found registry RDP/ICA %s DhcpIPAddress %s / %08X",
                 __LINE__, chrl_work_2, chrl_work_3, adsl_wts_reg_22->umc_ineta );
#endif

   pwtsreg44:                               /* close key again         */
   iml1 = RegCloseKey( dsl_key_1 );
   if (iml1 != ERROR_SUCCESS) {
     m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port RegCloseKey Error %d - ignored",
                   __LINE__, chrl_work_2, iml1 );
   }

   pwtsreg48:                               /* check next entry        */
#ifdef TRACEHL1
   m_hl1_printf( "iswtspo1-%05d-T pwtsreg48 - adsl_wts_reg_22=%p adsl_wts_reg_22->adsc_next=%p",
                 __LINE__, adsl_wts_reg_22, adsl_wts_reg_22->adsc_next );
#endif
   adsl_wts_reg_22 = adsl_wts_reg_22->adsc_next;  /* get next in chain */
   if (adsl_wts_reg_22) goto pwtsreg40;     /* continue                */
   adsl_wts_reg_23 = NULL;                  /* nothing found yet       */
   adsl_wts_reg_22 = adsl_wts_reg_21;       /* get first in chain      */
   while (adsl_wts_reg_22) {                /* loop over all elements  */
     /* attention IPV6                                                 */
     if (   (adsl_wts_reg_22->umc_ineta == adsp_ineta_1->dsc_un_ineta_1.umc_ineta_v4)  /* INETA found */
         && (adsl_wts_reg_22->boc_valid)
         && (adsl_wts_reg_22->boc_la)) {
       if (adsl_wts_reg_23) {
         m_hl1_printf( "iswtspo1-%05d-W registry %s search RDP/ICA port IN_INETA found multiple times",
                       __LINE__ );
         iml_port = -1;                     /* make port invalid       */
         goto pwtsreg60;                    /* continue                */
       }
       adsl_wts_reg_23 = adsl_wts_reg_22;   /* save entry              */
     }
     adsl_wts_reg_22 = adsl_wts_reg_22->adsc_next;  /* get next in chain */
   }
   if (adsl_wts_reg_23 == NULL) {           /* nothing found           */
     m_hl1_printf( "iswtspo1-%05d-T registry search RDP/ICA port IN_INETA not found in registry",
                   __LINE__ );
     iml_port = -1;                         /* make port invalid       */
     goto pwtsreg60;                        /* continue                */
   }
   iml_port = -1;                           /* set default port        */
   adsl_wts_reg_12 = adsl_wts_reg_11;       /* get first in chain      */
   while (adsl_wts_reg_12) {                /* loop over all elements  */
     if (   (adsl_wts_reg_12->imc_function == iml_function)  /* function found */
         && (adsl_wts_reg_12->dwc_lan_adapter == adsl_wts_reg_23->dwc_lan_adapter)
         && (adsl_wts_reg_12->boc_la)) {
       if (iml_port >= 0) {                 /* server-port already set */
         m_hl1_printf( "iswtspo1-%05d-W registry search RDP/ICA port - more than one port found", __LINE__ );
         iml_port = -1;                     /* make port invalid       */
         goto pwtsreg60;                    /* continue                */
       }
       if (adsl_wts_reg_12->imc_port <= 0) {  /* invalid port          */
         m_hl1_printf( "iswtspo1-%05d-W registry search RDP/ICA port - invalid port", __LINE__ );
         iml_port = -1;                     /* make port invalid       */
         goto pwtsreg60;                    /* continue                */
       }
       iml_port = adsl_wts_reg_12->imc_port;  /* get port              */
     }
     adsl_wts_reg_12 = adsl_wts_reg_12->adsc_next;  /* get next in chain */
   }
   if (iml_port < 0) {                      /* server-port not found   */
     achl1 = "RDP";
     if (iml_function == 2) achl1 = "ICA";
     m_hl1_printf( "iswtspo1-%05d-W registry search %s port - no port found",
                   __LINE__, achl1 );
   }

   pwtsreg60:                               /* end of search with this function */
   switch (iml_function) {
     case 1:
       adsp_wtspo_1->imc_port_rdp = iml_port;  /* set port             */
       break;
     case 2:
       adsp_wtspo_1->imc_port_ica = iml_port;  /* set port             */
       break;
   }
   iml_function++;                          /* next function           */
   if (    (iml_function == 2)              /* process ICA now         */
        && (imp_flags & DEF_WTSPO1_RDP)) {  /* ICA port requested      */
     goto pwtsreg20;                        /* process next function   */
   }
   while (adsl_wts_reg_11) {                /* chain still elements    */
     adsl_wts_reg_12 = adsl_wts_reg_11;     /* get old entry           */
     adsl_wts_reg_11 = adsl_wts_reg_11->adsc_next;  /* get next in chain */
     free( adsl_wts_reg_12 );               /* free old entry          */
   }
   while (adsl_wts_reg_21) {                /* chain still elements    */
     adsl_wts_reg_22 = adsl_wts_reg_21;     /* get old entry           */
     adsl_wts_reg_21 = adsl_wts_reg_21->adsc_next;  /* get next in chain */
     free( adsl_wts_reg_22 );               /* free old entry          */
   }

   pwtsreg64:                               /* non-ssl ports done      */
   if ((imp_flags & (DEF_WTSPO1_SSL_RDP | DEF_WTSPO1_SSL_ICA)) == 0) return;

   pmtinf20:                                /* get SSL ports           */
   if (imp_flags & DEF_WTSPO1_SSL_RDP) {    /* get SSL RDP             */
     adsp_wtspo_1->imc_port_ssl_rdp = -1;   /* set default value       */
   }
   if (imp_flags & DEF_WTSPO1_SSL_ICA) {    /* get SSL ICA             */
     adsp_wtspo_1->imc_port_ssl_ica = -1;   /* set default value       */
   }
   iml1 = RegOpenKeyExA( HKEY_LOCAL_MACHINE,
                         "Software\\HOBSoftware\\Secure",
                         0, KEY_ALL_ACCESS, &dsl_key_1 );
   if (iml1 != ERROR_SUCCESS) {
     m_hl1_printf( "iswtspo1-%05d-W Error get SSL ports RegOpenKeyEx Error %d - ignored",
                   __LINE__, iml1 );
     return;                                /* not successfull         */
   }
   if (imp_flags & DEF_WTSPO1_SSL_RDP) {    /* get SSL RDP             */
     dwl_len = sizeof(adsp_wtspo_1->imc_port_ssl_rdp);
     iml1 = RegQueryValueExA( dsl_key_1, "RDP_Port",
                              0, &dwl_type,
                              (unsigned char *) &adsp_wtspo_1->imc_port_ssl_rdp, &dwl_len );
     if (iml1 != ERROR_SUCCESS) {           /* error occured           */
       m_hl1_printf( "iswtspo1-%05d-W Error get SSL RDP port RegQueryValueEx Error %d - ignored",
                     __LINE__, iml1 );
     }
#ifdef TRACEHL1
     if (iml1 == ERROR_SUCCESS) {
       m_hl1_printf( "iswtspo1-%05d-T found SSL RDP Port %d",
                     __LINE__, adsp_wtspo_1->imc_port_ssl_rdp );
     }
#endif
   }
   if (imp_flags & DEF_WTSPO1_SSL_ICA) {    /* get SSL ICA             */
     dwl_len = sizeof(adsp_wtspo_1->imc_port_ssl_ica);
     iml1 = RegQueryValueExA( dsl_key_1, "ICA_Port",
                              0, &dwl_type,
                              (unsigned char *) &adsp_wtspo_1->imc_port_ssl_ica, &dwl_len );
     if (iml1 != ERROR_SUCCESS) {           /* error occured           */
       m_hl1_printf( "iswtspo1-%05d-W Error get SSL ICA port RegQueryValueEx Error %d - ignored",
                     __LINE__, iml1 );
     }
#ifdef TRACEHL1
     if (iml1 == ERROR_SUCCESS) {
       m_hl1_printf( "iswtspo1-%05d-T found SSL ICA Port %d",
                     __LINE__, adsp_wtspo_1->imc_port_ssl_ica );
     }
#endif
   }
   iml1 = RegCloseKey( dsl_key_1 );
   if (iml1 != ERROR_SUCCESS) {
     m_hl1_printf( "iswtspo1-%05d-W Error get SSL ports RegCloseKey Error %d - ignored",
                   __LINE__, iml2 );
   }
   return;                                  /* all done                */
} /* end m_get_wtspo1_ineta()                                          */
