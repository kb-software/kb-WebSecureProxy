#include "cPrecomp.h"

/*+--------------------------------------------------------------------------+*/
/*|                                                                          |*/
/*| PROGRAM NAME:                                                            |*/
/*| -------------                                                            |*/
/*|  original PRECOMP by KB was converted to a SDH                           |*/
/*|  JF 04.01.06                                                             |*/
/*|  lots of type casts were needed                                          |*/
/*|  initialization of arrays, variables, etc has to be done in constructor  |*/
/*|                                                                          |*/
/*|  For the time being only a WIN32-version is available !!!                |*/
/*|                                                                          |*/
/*| COPYRIGHT:                                                               |*/
/*| ----------                                                               |*/
/*|  Copyright (C) HOB Germany 2006                                          |*/
/*|                                                                          |*/
/*+--------------------------------------------------------------------------+*/

// JF and MJ 18.03.11 New SDH-API implemented.
// JF and MJ 30.07.10 crash on Sun Solaris (SPARC) Ticket[20382]. 
// J.Frank  05.08.09  Problems with ach_ppp_unix_parameter fixed.
//                    Ticket[18243]: ach_ppp_system_parameter added.
// J.Frank  27.11.08  Ticket[16598]: ach_ppp_unix_parameter added
// J.Frank  07.10.08  warnings removed concerning ach_ppp_ineta/ach_ppp_l2tp_arg/ach_ppp_localhost/ach_ppp_socks_mode
// M.Jakobs 12.09.08  lots of casts "(char*)" added
// J.Frank  18.02.08  Ticket[14388]: new 'SystemVariables' (better: 'predefined variables') were added with the define PRECOMP_NEW_PREDEFINED_VARS
// J.Frank  06.02.08  m_sdh_printf replaces printf


cPrecomp::cPrecomp(int in_flags_inp)
{
    ach_empty_string = (char*)""; // JF 07.10.08

icopyc = 0;
ilinenr = 0;
ins_linenr_out = 1;
#ifndef WORK_AS_SDH
memset(szfni, 0, MAX_PATH);
memcpy(szfni, "TEST.INP", MAX_PATH);
memset(szfno, 0, MAX_PATH);
memcpy(szfno, "out.html", MAX_PATH);
#endif // #ifndef WORK_AS_SDH
ainf1 = 0;

/* table of operators */
tabop[0].chop   = '+';
tabop[0].class1 = '2';
tabop[0].ityp   = 0;
tabop[1].chop   = '-';
tabop[1].class1 = '2';
tabop[1].ityp   = 0;
tabop[2].chop   = '*';
tabop[2].class1 = '4';
tabop[2].ityp   = 0;
tabop[3].chop   = '/';
tabop[3].class1 = '4';
tabop[3].ityp   = 0;
tabop[4].chop   = '(';
tabop[4].class1 = '8';
tabop[4].ityp   = 1;
tabop[5].chop   = ')';
tabop[5].class1 = '1';
tabop[5].ityp   = 2;
tabop[6].chop   = ',';
tabop[6].class1 = '0';
tabop[6].ityp   = 3;
tabop[7].chop   = ';';
tabop[7].class1 = '0';
tabop[7].ityp   = 3;

/* table of conditions */
memcpy(tabcond[0].cname, "DEF ", 4);
memcpy(tabcond[1].cname, "NDF ", 4);
memcpy(tabcond[2].cname, "EQ  ", 4);
memcpy(tabcond[3].cname, "NE  ", 4);
memcpy(tabcond[4].cname, "GT  ", 4);
memcpy(tabcond[5].cname, "LT  ", 4);
memcpy(tabcond[6].cname, "GE  ", 4);
memcpy(tabcond[7].cname, "LE  ", 4);

/* table of macro arguments */
memcpy(tabmarg[0].aname, "MINT    ", 8);
memcpy(tabmarg[1].aname, "MTEXT   ", 8);
memcpy(tabmarg[2].aname, "MQUOTE  ", 8);

int i=0;
for (i=0; i<=0xFF; i++) {
    chartab[i] = 0;
}
chartab[0x24] = '$';
for (i=0x30; i<=0x39; i++) {
    chartab[i] = i;
}
for (int i=65; i<=90; i++) {
    chartab[i] = i;
}
chartab[0x5F] = 0x5F;
for (int i=0x61; i<=0x7A; i++) {
    chartab[i] = i-32;
}
chartab[0x81] = 0x9A;
chartab[0x84] = 0x8E;
chartab[0x8E] = 0x8E;
chartab[0x94] = 0x99;
chartab[0x99] = 0x99;
chartab[0x9A] = 0x9A;

// initialize tabbef
// initialization must be done explicitly, because compiler error that array tname is too short (16 chars will be filled with 16 chars -> missing NULL-terminbation)
memcpy(tabbef[0].tname, "INT             ", LENSYM);
tabbef[0].tb1 = '0';
tabbef[0].tb2 = '0';
memcpy(tabbef[1].tname, "TEXT            ", LENSYM);
tabbef[1].tb1 = '0';
tabbef[1].tb2 = '0';
memcpy(tabbef[2].tname, "HEXA            ", LENSYM);
tabbef[2].tb1 = '0';
tabbef[2].tb2 = '0';
memcpy(tabbef[3].tname, "TAB             ", LENSYM);
tabbef[3].tb1 = '0';
tabbef[3].tb2 = '0';
memcpy(tabbef[4].tname, "CONT            ", LENSYM);
tabbef[4].tb1 = '0';
tabbef[4].tb2 = '0';
memcpy(tabbef[5].tname, "SET             ", LENSYM);
tabbef[5].tb1 = '1';
tabbef[5].tb2 = '0';
memcpy(tabbef[6].tname, "DEFT            ", LENSYM);
tabbef[6].tb1 = '1';
tabbef[6].tb2 = '0';
memcpy(tabbef[7].tname, "INCLUDE         ", LENSYM);
tabbef[7].tb1 = '1';
tabbef[7].tb2 = '0';
memcpy(tabbef[8].tname, "CANCEL          ", LENSYM);
tabbef[8].tb1 = '1';
tabbef[8].tb2 = '0';
memcpy(tabbef[9].tname, "DISP            ", LENSYM);
tabbef[9].tb1 = '1';
tabbef[9].tb2 = '0';
memcpy(tabbef[10].tname, "ACC             ", LENSYM);
tabbef[10].tb1 = '1';
tabbef[10].tb2 = '0';
memcpy(tabbef[11].tname, "IIF             ", LENSYM);
tabbef[11].tb1 = '2';
tabbef[11].tb2 = '0';
memcpy(tabbef[12].tname, "IF              ", LENSYM);
tabbef[12].tb1 = '2';
tabbef[12].tb2 = '1';
memcpy(tabbef[13].tname, "IFT             ", LENSYM);
tabbef[13].tb1 = '2';
tabbef[13].tb2 = '1';
memcpy(tabbef[14].tname, "IFF             ", LENSYM);
tabbef[14].tb1 = '2';
tabbef[14].tb2 = '1';
memcpy(tabbef[15].tname, "IFTF            ", LENSYM);
tabbef[15].tb1 = '2';
tabbef[15].tb2 = '1';
memcpy(tabbef[16].tname, "CEND            ", LENSYM);
tabbef[16].tb1 = '2';
tabbef[16].tb2 = '1';
memcpy(tabbef[17].tname, "MACRO           ", LENSYM);
tabbef[17].tb1 = '2';
tabbef[17].tb2 = '1';
memcpy(tabbef[18].tname, "MEND            ", LENSYM);
tabbef[18].tb1 = '2';
tabbef[18].tb2 = '1';
memcpy(tabbef[19].tname, "MEXIT            ", LENSYM);
tabbef[19].tb1 = '1';
tabbef[19].tb2 = '0';
memcpy(tabbef[20].tname, "MSET            ", LENSYM);
tabbef[20].tb1 = '1';
tabbef[20].tb2 = '0';
memcpy(tabbef[21].tname, "MDEFT           ", LENSYM);
tabbef[21].tb1 = '1';
tabbef[21].tb2 = '0';
memcpy(tabbef[22].tname, "RPT             ", LENSYM);
tabbef[22].tb1 = '2';
tabbef[22].tb2 = '1';
memcpy(tabbef[23].tname, "RPTN            ", LENSYM);
tabbef[23].tb1 = '2';
tabbef[23].tb2 = '1';
memcpy(tabbef[24].tname, "REND            ", LENSYM);
tabbef[24].tb1 = '2';
tabbef[24].tb2 = '1';
memcpy(tabbef[25].tname, "REXIT           ", LENSYM);
tabbef[25].tb1 = '1';
tabbef[25].tb2 = '0';

// JF 
in_bytes_occupied_wa = 0;
this->in_flags = in_flags_inp;
in_len_ainf1 = 0;
memset(&ch_msg[0], 0, MSG_LEN);

#ifdef __OLD_HEADERS__
    printf( "Precomp __OLD_HEADERS__\n"); // here ads_trans is not set !!!
#endif

    ach_ppp_ineta = NULL;
    ach_ppp_l2tp_arg = NULL;
    ach_ppp_socks_mode = NULL;
    ach_ppp_localhost = NULL;
    ach_ppp_unix_parameter = NULL;
    ach_ppp_system_parameter = NULL;
}

int cPrecomp::m_hlclib01(struct dsd_hl_clib_1* ads_trans_inp) {
   BOOL bou1;

   if (ads_trans_inp == NULL) { // JF
       return -1;
   }

   this->ads_trans = ads_trans_inp;

   // JF 06.02.08 for testing
   // m_sdh_printf( "hallo %d\n",123 );

   // setup the gather-out-structure (memory is reserved at the beginning of the workarea)
   struct dsd_gather_i_1* ads_gath = (struct dsd_gather_i_1 *)ads_trans->achc_work_area;
   if ( ads_trans->inc_func == DEF_IFUNC_TOSERVER ) {
       ads_trans->adsc_gai1_out_to_server = ads_gath;
   } else {
       ads_trans->adsc_gai1_out_to_client = ads_gath;
   }
   ads_gath ->adsc_next = NULL;
   ads_gath->achc_ginp_cur = (char*)(ads_trans->achc_work_area+sizeof(dsd_gather_i_1));
   ads_gath->achc_ginp_end = ads_gath->achc_ginp_cur;  // this signals: up to now there are no data to be returned; the pointer will be updated, when work is done
   in_bytes_occupied_wa += sizeof(dsd_gather_i_1); // update the pointer of used memory


#ifdef WORK_AS_SDH
   memset(strlineout, 0, LINELEN+1); // initialize this variable !!
   uinfile();
#else
   strcpy( (char*)strlineout, szfni );
   uinfile();                               /* Eroeffnen File          */
   if (rc) {
     m_sdh_printf( "Input Open Error: return code = %ld", rc );
     return 0;
   }
#endif // #ifdef WORK_AS_SDH

#if defined WIN32 || WIN64
#ifndef WORK_AS_SDH
   hfo = CreateFile( szfno, GENERIC_WRITE, 0, 0,
                     CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0 );
   if (hfo == INVALID_HANDLE_VALUE) {
     m_sdh_printf( "Output CreateFile Error: %ld\n", GetLastError() );
     CloseHandle( ainf1->hfi );
     free( ainf1 );
     return 1;
   }
#endif // #ifndef WORK_AS_SDH
#endif

   // JF: ATTENTION: THERE MUST BE AN ALPHABETICAL ORDER
   // JF: ATTENTION: THERE MUST BE AN ALPHABETICAL ORDER
   aanfsym = (ULONG) &chstack[0] + sizeof(chstack) - DEF_SEC_NO * sizeof(DSYMBOL) - sizeof(void*); //MJ 4
   memset( &wss, 0, sizeof(DSYMBOL) );
   memcpy( wss.symbol, "$COPYC          ", LENSYM );
   wss.modebsec = 1;
   wss.u.value = DEF_SEC_COPYC;
   memcpy( (PVOID) (aanfsym + sizeof(void*)), &wss, sizeof(DSYMBOL) );
   memset( &wss, 0, sizeof(DSYMBOL) );
   memcpy( wss.symbol, "$DATE           ", LENSYM );
   wss.modebsec = 1;
   wss.u.value = DEF_SEC_DATE;
   memcpy( (PVOID) (aanfsym + sizeof(void*) + sizeof(DSYMBOL)), &wss, sizeof(DSYMBOL) );
   memset( &wss, 0, sizeof(DSYMBOL) );
   memcpy( wss.symbol, "$INPFCOU        ", LENSYM );
   wss.modebsec = 1;
   wss.u.value = DEF_SEC_INPFCOU;
   memcpy( (PVOID) (aanfsym + sizeof(void*) + 2 * sizeof(DSYMBOL)), &wss, sizeof(DSYMBOL) );
   memset( &wss, 0, sizeof(DSYMBOL) );
   memcpy( wss.symbol, "$INPFILN        ", LENSYM );
   wss.modebsec = 1;
   wss.modebtex = 1;
   wss.u.value = DEF_SEC_INPFILN;
   memcpy( (PVOID) (aanfsym + sizeof(void*) + 3 * sizeof(DSYMBOL)), &wss, sizeof(DSYMBOL) );
   /* make entry $LINE_A                                               */
   memset( &wss, 0, sizeof(DSYMBOL) );
   memcpy( wss.symbol, "$LINE_A         ", LENSYM );
   wss.modebsec = 1;
   wss.u.value = DEF_SEC_LINE_A;
   memcpy( (PVOID) (aanfsym + sizeof(void*) + 4 * sizeof(DSYMBOL)), &wss, sizeof(DSYMBOL) );
   /* make entry $LINE_FI                                              */
   memset( &wss, 0, sizeof(DSYMBOL) );
   memcpy( wss.symbol, "$LINE_FI        ", LENSYM );
   wss.modebsec = 1;
   wss.u.value = DEF_SEC_LINE_FI;
   memcpy( (PVOID) (aanfsym + sizeof(void*) + 5 * sizeof(DSYMBOL)), &wss, sizeof(DSYMBOL) );
   /* make entry $LINE_O                                               */
   memset( &wss, 0, sizeof(DSYMBOL) );
   memcpy( wss.symbol, "$LINE_O         ", LENSYM );
   wss.modebsec = 1;
   wss.u.value = DEF_SEC_LINE_O;
   memcpy( (PVOID) (aanfsym + sizeof(void*) + 6 * sizeof(DSYMBOL)), &wss, sizeof(DSYMBOL) );

   // ATTENTION: THERE MUST BE AN ALPHABETICAL ORDER !!!
   // HOB-PPP-Tunnel: applet-parameter WSP_INETA
   memset( &wss, 0, sizeof(DSYMBOL) );
   memcpy( wss.symbol, "$PPP_INETA      ", LENSYM );
   wss.modebsec = 1;
   wss.modebtex = 1;
   wss.u.value = DEF_SEC_PPP_INETA;
   memcpy( (PVOID) (aanfsym + sizeof(void*) + DEF_SEC_PPP_INETA * sizeof(DSYMBOL)), &wss, sizeof(DSYMBOL) );
   // HOB-PPP-Tunnel: applet-parameter WSP_L2TP_ARG
   memset( &wss, 0, sizeof(DSYMBOL) );
   memcpy( wss.symbol, "$PPP_L2TP_ARG   ", LENSYM );
   wss.modebsec = 1;
   wss.modebtex = 1;
   wss.u.value = DEF_SEC_PPP_L2TP_ARG;
   memcpy( (PVOID) (aanfsym + sizeof(void*) + DEF_SEC_PPP_L2TP_ARG * sizeof(DSYMBOL)), &wss, sizeof(DSYMBOL) );
   // HOB-PPP-Tunnel: applet-parameter WSP_L2TP_LOCAL_HOST
   memset( &wss, 0, sizeof(DSYMBOL) );
   memcpy( wss.symbol, "$PPP_LOCAL_HOST ", LENSYM );
   wss.modebsec = 1;
   wss.modebtex = 1;
   wss.u.value = DEF_SEC_PPP_LOCALHOST;
   memcpy( (PVOID) (aanfsym + sizeof(void*) + DEF_SEC_PPP_LOCALHOST * sizeof(DSYMBOL)), &wss, sizeof(DSYMBOL) );
   // HOB-PPP-Tunnel: applet-parameter WSP_SOCKS_MODE
   memset( &wss, 0, sizeof(DSYMBOL) );
   memcpy( wss.symbol, "$PPP_SOCKS_MODE ", LENSYM );
   wss.modebsec = 1;
   wss.modebtex = 1;
   wss.u.value = DEF_SEC_PPP_SOCKS_MODE;
   memcpy( (PVOID) (aanfsym + sizeof(void*) + DEF_SEC_PPP_SOCKS_MODE * sizeof(DSYMBOL)), &wss, sizeof(DSYMBOL) );

   *((ULONG *) aanfsym) = DEF_SEC_NO;       /* number of symbols in table */

   astack = aanfsym;
   aglobsym = aanfsym;                      /* address global symbols  */
   atextende = (ULONG) &chstack[0];

   ulSout = 0;
   kzout = 'F';
   kzbef1 = ' ';
   countif1 = countif2 = 0;
   icountmac1 = 0;
   icountrpt1 = 0;
   kzifakt2 = '1';

   /* 15.08.97 - ignore character EOF                                  */
   ainf1->ifia = 0;
   /* end of new                                                       */

   pread10:                                 /* read next line          */
   ul_Sout_save = ulSout;                   /* save position output    */

   pread12:                                 /* read next part          */
   if (ainf1->astorinps) {                  /* read from storage       */
     if (ainf1->astorinpc < ainf1->astorinpe) {  /* not yet at end     */
       i1 = *((unsigned short *) ainf1->astorinpc);
       ainf1->astorinpc += 2;
       ainf1->ifil = i1;
       if (ainf1->ifil > LINELEN) ainf1->ifil = LINELEN;
       if (i1) {
         memcpy( ainf1->strlineinp, ainf1->astorinpc, ainf1->ifil );
         ainf1->astorinpc += i1;
       }
       if (ainf1->ifil < LINELEN) ainf1->strlineinp[ainf1->ifil++] = CHAR_CR;
       if (ainf1->ifil < LINELEN) ainf1->strlineinp[ainf1->ifil++] = CHAR_LF;
       goto pread14;                        /* process data            */
     }

     if (ainf1->irepcount > 0) ainf1->irepcount--;
     if (ainf1->irepcount == 0) {           /* end of data             */
       i1 = countif1 + countif2;            /* get number of if        */
       if (i1) {
         m_sdh_printf((char*)"%s: %ld/x CEND missing at MEND/REND (%dx)\n", "HPREE001E", ilinenr, i1);
       }
       incstack( sizeof(DIFAKT), countif1 ); //astack += countif1 * sizeof(DIFAKT);
       countif2 = 0;
       countif1 = *((int *) astack);        /* get ifs before          */
       kzifakt1 = *((unsigned char *) (astack + 4));
       kzifakt2 = *((unsigned char *) (astack + 5));
       incstack( 6, 1 ); //astack += 6;
       /* inserted 30.12.98 KB - start                                 */
       kzbef1 = ' ';                        /* no more command         */
       /* inserted 30.12.98 KB - end                                   */
       if (   (ainf1->ch_flag_macro_rpt == 'R')  /* is from repeat     */
           && (atextende == (ULONG)ainf1->astorinpe))    // JF ULONG
         atextende = (ULONG)ainf1->astorinps;  // JF ULONG    /* storage no longer need. */
       bou1 = FALSE;
       /* remove table for macro variables                             */
       if (ainf1->ch_flag_macro_rpt == 'M') {  /* is from macro        */
         i1 = 4 + *((ULONG *) aanfsym) * sizeof(DSYMBOL);  /* to remov */
         if (astack < aanfsym) {
           memmove( (PVOID) (astack + i1), (PVOID) astack,
                    aanfsym - astack );
         }
         aanfsym += i1;
         incstack( i1, 1 ); //astack += i1;
         bou1 = TRUE;                       /* was from macro          */
       }
       ainf2 = (INFILE*)ainf1->next;  // JF INFILE*
       free( ainf1 );
       ainf1 = ainf2;
       if (bou1) goto pread12;
       ulSout = ul_Sout_save;               /* no output till now      */
       bcont = TRUE;                        /* do not store first line */
       goto pzeilign;                       /* ignore remainder of lin */
     }
     ainf1->astorinpc = ainf1->astorinps;
     ainf1->ilnr = 0;                       /* reset line-number       */
     goto pread12;
   }
#ifndef WORK_AS_SDH
   if (ainf1->hfi) {
#else 
    {   // set this bracket; otherwise UNIX-compiler complains about not initializing ulRead in case goto pread14; is called      
#endif // #ifndef WORK_AS_SDH

       ULONG ulRead = 0;

#ifdef WORK_AS_SDH   // JF read from input gather
     int in_len_to_read = LINELEN - ainf1->ifil;
     struct dsd_gather_i_1* current_gather = ads_trans->adsc_gather_i_1_in;
     int in_rest_of_data = current_gather->achc_ginp_end - current_gather->achc_ginp_cur;
     if (in_rest_of_data == 0) { // data of the current gather are already read in -> are there other gathers
         struct dsd_gather_i_1* myTestGather = current_gather->adsc_next;
        while(myTestGather != NULL){
            if (myTestGather->achc_ginp_end == myTestGather->achc_ginp_cur) { // data of this gather are also read in -> goto next
                myTestGather=myTestGather->adsc_next;
            }
            else {
                in_rest_of_data = myTestGather->achc_ginp_end - myTestGather->achc_ginp_cur;
                current_gather = myTestGather;
                break;
            }
        }
     }

     if (in_rest_of_data > 0) {
         if (in_rest_of_data < in_len_to_read) { // avoid reading behind pointers !!!
             in_len_to_read = in_rest_of_data;
         }
         memcpy(&ainf1->strlineinp[ainf1->ifil], current_gather->achc_ginp_cur, in_len_to_read);
         m_dump_data((unsigned char*)current_gather->achc_ginp_cur, in_len_to_read, NULL);

         current_gather->achc_ginp_cur += in_len_to_read;
         ulRead = in_len_to_read;
     }
     else { // when we get here all data were read in, but not all data are yet processed
         ;
     }
#else
     ReadFile( ainf1->hfi, (PSZ) &ainf1->strlineinp[ainf1->ifil], (ULONG) LINELEN-ainf1->ifil, &ulRead, 0 );
     m_dump_data((unsigned char*)&ainf1->strlineinp[ainf1->ifil], ulRead, NULL);
#endif // WORK_AS_SDH

     ainf1->ifil += ulRead;
#ifndef WORK_AS_SDH
}
#else 
    }   // close the prior set bracket; otherwise UNIX-compiler complains about not initializing ulRead in case goto pread14; is called
#endif // #ifndef WORK_AS_SDH


   /* 15.08.97 - ignore character EOF                                  */
   while (   (ainf1->ifia < ainf1->ifil)
          && (ainf1->strlineinp[ainf1->ifia] == CHAR_EOF)) {
     ainf1->ifia++;
   }
   /* end of new                                                       */
   if (!ainf1->ifil) goto pread50;  // JF we are ready

   pread14:                                 /* line to process         */
   ilinenr++;
   ainf1->ilnr++;
   bcont = FALSE;
/* ainf1->ifia = 0; */

   pread2:
   i2 = 0;
   while (ainf1->ifia < ainf1->ifil) {
     ch1 = strlineout[ulSout++] = ainf1->strlineinp[ainf1->ifia++];
     if (ulSout > LINELEN) ulSout = LINELEN;
     switch( ch1 ) {
       case '%':
         if (i2 == 1) {
           /* output must be done, in RPT and MACRO still two %        */
           if ((kzout == 'M') || (kzout == 'R')) {
             strlineout[ulSout++] = '%';
             if (ulSout > LINELEN) ulSout = LINELEN;
           }
           i2 = 0;
         } else {
           ulSout--;
           i2 = 1;
         }
         break;
       case CHAR_CR:
         if (i2 == 1) goto pbef01;
         i2 = 2;
         break;
       case CHAR_LF:
         if (i2 == 1) goto pbef01;
         if (i2 == 2) goto pread4;
         i2 = 0;
         break;
       default:
         if (i2 == 1) goto pbef01;
         i2 = 0;
     }
   }
   if (ainf1->astorinps) goto pread4;       /* read from storage       */

   pread3:
   m_sdh_printf((char*)"%s: %ld/%ld input line too long\n", "HPREE002E", ilinenr, ainf1->ilnr);

   pread4:
   /* 15.08.97 - ignore character EOF                                  */
   while (   (ainf1->ifia < ainf1->ifil)
          && (ainf1->strlineinp[ainf1->ifia] == CHAR_EOF)) {
     ainf1->ifia++;
   }
   i2 = 0;
   while (ainf1->ifia < ainf1->ifil)
     ainf1->strlineinp[i2++] = ainf1->strlineinp[ainf1->ifia++];
   ainf1->ifil = i2;                        /* set new end             */
   ainf1->ifia = 0;                         /* next this character     */

   if (!bcont) {
     bou1 = FALSE;                          /* no previous output      */
     switch (kzout) {
       case 'F':
         if (ulSout == 0) break;            /* 21.05.05 KB             */
#ifdef WORK_AS_SDH
         memcpy(ads_trans->achc_work_area+in_bytes_occupied_wa, strlineout, ulSout);
         in_bytes_occupied_wa += ulSout;
        m_dump_data((unsigned char*)strlineout, ulSout, NULL);
#else
         WriteFile( hfo, strlineout, ulSout, &ulWrite, 0 );
#endif // WORK_AS_SDH
         ins_linenr_out++;                  /* increment line-number output */
         break;
       case 'D':                            /* display found           */
         if (ulSout)
           if (strlineout[--ulSout] != CHAR_LF) ulSout++;
         if (ulSout)
           if (strlineout[--ulSout] != CHAR_CR) ulSout++;
         strlineout[ulSout] = 0;
         bou1 = TRUE;                       /* get previous output     */
         break;
       case 'I':                            /* include found           */
         if (ulSout)
           if (strlineout[--ulSout] != CHAR_LF) ulSout++;
         if (ulSout)
           if (strlineout[--ulSout] != CHAR_CR) ulSout++;
         if (!ulSout) {
           m_sdh_printf((char*)"%s: %ld/%ld Include command is empty\n", "HPREE003E", ilinenr, ainf1->ilnr);
           break;
         }
         strlineout[ulSout] = 0;
         uinfile();
#ifndef WORK_AS_SDH         
         if (rc) {
           m_sdh_printf( "Include:%s DosOpen Error: return code = %ld\n", strlineout, rc );
           break;
         }
#endif
         icopyc++;                          /* one more copy           */
         bou1 = TRUE;                       /* get previous output     */
         break;
       case 'T':                            /* store text-variable     */
#ifdef JF_CORRECT_ALIGNMENT
        asymtab = (ULONG)(*((ULONG*) astack));
#else
         asymtab = (ULONG)(*((void **) astack));  // JF (ULONG)
#endif
         incstack( sizeof(asymtab), 1 );// astack += sizeof(asymtab);
         if (ulSout)
           if (strlineout[--ulSout] != CHAR_LF) ulSout++;
         if (ulSout)
           if (strlineout[--ulSout] != CHAR_CR) ulSout++;
         if (asymtab) {
           if (ulSout > astack - atextende) {
             m_sdh_printf((char*)"%s: %ld/%ld Text memory too small - terminated\n", "HPREE005E", ilinenr, ainf1->ilnr);
             goto pcancel;
           }
           if (ulSout)
             memcpy( (PVOID) atextende, strlineout, ulSout );
           ((DSYMBOL *)asymtab)->modet2 = ulSout;
           atextende += ulSout;
         }
         bou1 = TRUE;                       /* get previous output     */
         break;
       case 'M':                            /* store macro             */
       case 'R':                            /* store rpt               */
         if (ulSout)
           if (strlineout[--ulSout] != CHAR_LF) ulSout++;
         if (ulSout)
           if (strlineout[--ulSout] != CHAR_CR) ulSout++;
         if ((2 + ulSout) > (astack - atextende)) {
           m_sdh_printf((char*)"%s: %ld/%ld Macro-storage not big enough - abend\n", "HPREE006E", ilinenr, ainf1->ilnr);
           goto pcancel;
         }
         *((unsigned short *) atextende) = ulSout;
         atextende += 2;
         if (ulSout) {
           memcpy( (PVOID) atextende, strlineout, ulSout );
           atextende += ulSout;
         }
         break;
       case 'A':                            /* macro arguments         */
         if (ulSout)
           if (strlineout[--ulSout] != CHAR_LF) ulSout++;
         if (ulSout)
           if (strlineout[--ulSout] != CHAR_CR) ulSout++;
         if (!umargs()) goto pcancel;       /* process arguments       */
         bou1 = TRUE;                       /* get previous output     */
         break;
     }
     ulSout = 0;                            /* no more output          */
     if (bou1) {                            /* get previous output     */
       ul_Sout_save = *((ULONG *) astack);
       incstack( sizeof(ULONG), 1 );//astack += sizeof(ULONG);
       if (ul_Sout_save) {
         memcpy( strlineout, (const void*)astack, ul_Sout_save );  // JF (const void*)
         incstack( ul_Sout_save, 1 );//astack += ul_Sout_save;
       }
       ulSout = ul_Sout_save;               /* get previous output     */
     }
     if (kzout == '0') ulSout = ul_Sout_save;  /* save output          */
     if ((kzout < 'M') || (kzout > 'S')) {  /* not store macro / rpt   */
       kzout = 'F';
       if (kzifakt2 != '1') kzout = '0';
     }
     kzbef1 = ' ';
   }

   goto pread10;

   pread50:   // JF we are ready                              /* end-of-file reached     */
#ifndef WORK_AS_SDH
   if (ainf1->hfi) {
#if defined WIN32 || WIN64
     CloseHandle( ainf1->hfi );
#endif
     icopyc--;                              /* decrement copy-counter  */
   }
#endif // #ifndef WORK_AS_SDH
   ainf2 = (INFILE*)ainf1->next;  // JF (INFILE*)

#ifndef WORK_AS_SDH
    free( ainf1 );
#else
   // JF: give free memory by calling application
////__int64 cycles0 = GetMachineCycleCount();
   ads_trans->amc_aux(ads_trans->vpc_userfld, DEF_AUX_MEMFREE, &ainf1, in_len_ainf1);
////__int64 cycles1 = GetMachineCycleCount();
////printf("lib DEF_AUX_MEMFREE: cycles0      %15d\n", cycles0);
////printf("lib DEF_AUX_MEMFREE: cycles1      %15d\n", cycles1);
////printf("lib DEF_AUX_MEMFREE: total    %15d\n", (cycles1-cycles0));
////printf("lib DEF_AUX_MEMFREE: total(M) %15d\n", (cycles1-cycles0)/1000000);
#endif // WORK_AS_SDH
   
   ainf1 = ainf2;
   if (ainf1) goto pread10;

   /* Anzahl CEND Rest */
   countif2 += countif1;
   if (countif2) {
     m_sdh_printf((char*)"%s: *End* CEND - End condition - missing (%ldX)", "HPREE007E", countif2);
   }
   if ((kzout >= 'M') && (kzout <= 'S')) {  /* store macro / rpt       */     
       m_sdh_printf((char*)"%s: *End* still in RPT/RPTN/MACRO\n", "HPREE008E");
   }

   pread60:
#if defined WIN32 || WIN64
#ifndef WORK_AS_SDH
   CloseHandle( hfo );
#endif // #ifndef WORK_AS_SDH
#endif

   // setup the gather-out-structure (memory is reserved at the beginning of the workarea)
   ads_gath->achc_ginp_end = (char*)(ads_trans->achc_work_area+in_bytes_occupied_wa);

   return 0; // JF normal end of function m_hlclib01

   pbef01:                                  /* command found           */
   ulSout--;                                /* no output of control-ch */
   isavecommand = ainf1->ifia - 2;          /* save address command    */
   usymbol();
   if (strsymbol[0] == ' ') {     
       m_sdh_printf((char*)"%s: %ld/%ld empty command\n", "HPREE009E", ilinenr, ainf1->ilnr);
     ainf1->ifia--;
     goto pread2;
   }

   itabbef = 0;

   pbef02:                                  /* check if macro          */
   ch_symbol_scope = 'M';                   /* M = macro, not global   */
   usymbtab();                              /* search symbol in table  */
   if (kzsym2 != '1') goto pbef04;          /* symbol not in table     */
   if ((kzout >= 'M') && (kzout <= 'S')) {  /* store macro / rpt       */
     if ((kzout == 'M') || (kzout == 'R'))  /* output must be done     */
       goto pstmacrpt00;                    /* store macro or repeat   */
     goto pzeilign;
   }
   if (((DSYMBOL *) asymtab)->modebmac != 1) {  /* is not macro        */
       m_sdh_printf((char*)"%s: %ld/%ld found variable as command / macro: %s\n", "HPREE010E", ilinenr, ainf1->ilnr, strsymbol);
     ainf1->ifia--;
     goto pread2;
   }
   ulSout = ul_Sout_save;                   /* no output till now      */
   if (kzifakt2 != '1') goto pzeilign;      /* do not process macro    */
   if (!decstack( sizeof(DSYMBOL), 1 )) goto pcancel;
   memcpy( (PVOID) astack, (PVOID) asymtab, sizeof(DSYMBOL) );
   if (!usaveSout()) goto pcancel;          /* save previous output    */
   ulSout = 0;                              /* no output till now      */
   kzout = 'A';                             /* process arguments       */
   goto pread2;                             /* read arguments          */

   pbef04:                                  /* search command in table */
   if (itabbef == sizeof(tabbef) / sizeof(tabbef[0])) {
       m_sdh_printf((char*)"%s: %ld/%ld command not defined: %s\n", "HPREE011E", ilinenr, ainf1->ilnr, strsymbol);
     ainf1->ifia--;
     goto pread2;
   }
   if ( memcmp( strsymbol, tabbef[itabbef].tname, LENSYM ) ) {
     itabbef++;
     goto pbef04;
   }
   if ((kzout >= 'M') && (kzout <= 'S')) {  /* store macro / rpt       */
     if ((kzout == 'M') || (kzout == 'N')) {  /* store current macro   */
       if (itabbef == DEF_C_MACRO) {        /* nested macro comes      */
         icountmac1++;                      /* count levels            */
       } else if (itabbef == DEF_C_MEND) {  /* end of macro            */
         if (!icountmac1) {                 /* not in nested macro     */
           upruefend();                       /* check if syntax correct */
           if (kzout != 'M') {              /* do not store macro      */
             kzout = 'F';
           }
           memcpy( &wss, (PVOID) astack, sizeof(DSYMBOL) );
           incstack( sizeof(DSYMBOL), 1 );//astack += sizeof(DSYMBOL);
           wss.modet2 = atextende - wss.u.addr;  /* set length         */
           ch_symbol_scope = 'G';           /* G = global, not macro   */
           if (!usymbein()) goto pcancel;
           kzout = 'F';
           goto pzeilign;
         }
         icountmac1--;                      /* one level below         */
       }
     }
     if ((kzout == 'R') || (kzout == 'S')) {  /* store repeat          */
       if (   (itabbef == DEF_C_RPT)        /* nested rpt comes        */
           || (itabbef == DEF_C_RPTN)) {    /* nested rptn comes       */
         icountrpt1++;                      /* count levels            */
       } else if (itabbef == DEF_C_REND) {  /* end of repeat           */
         if (!icountrpt1) {                 /* not in nested repeat    */
           upruefend();                       /* check if syntax correct */
           if (kzout != 'R') goto pzeilign;  /* do not repeat stmts    */
           ainf2 = ainf1;                   /* save chain              */

           ainf1 = (INFILE*)malloc( sizeof(INFILE) );  // JF (INFILE*)
           // JF: allocate memory by calling application
            // there will arise a problem at freeing the memory, because we must provide the length of memory to free, when WSP is requested to free memory
            // because we don't get here in case precomp-sdh is called by WebServerDll, the code is not changed here and at the according free()-statement
            //if (! ads_trans->amc_aux(ads_trans->vpc_userfld, DEF_AUX_MEMGET, &ainf1, sizeof(INFILE))) {
                //return -100; // if this happens, it's an desaster...
            //}

           memset( ainf1, 0, sizeof(INFILE) );  /* clear all values    */
           ainf1->next = ainf2;
           ainf1->ilnr = 0;
           ainf1->ifil = 0;                 /* noch nichts eingelesen  */
           ainf1->ifia = 0;
           ainf1->astorinps = ainf1->astorinpc = (unsigned char*)(*((PVOID *) astack));  // JF (unsigned char*)
           ainf1->astorinpe = (unsigned char*)atextende; // JF (unsigned char*)   /* end-address repeat      */
           ainf1->irepcount = *((int *) (astack + 4));  /* count       */
           ainf1->ch_flag_macro_rpt = 'R';  /* read from repeat        */
           incstack( 2 , 1 );//astack += 8 - 6;                 /* adjust variables        */
           *((int *) (astack + 0)) = countif1;  /* save if             */
           *((unsigned char *) (astack + 4)) = kzifakt1;  /* save if   */
           *((unsigned char *) (astack + 5)) = kzifakt2;  /* save if   */
           countif1 = 0;
           ulSout = ul_Sout_save;           /* no output till now      */
           kzout = 'F';                     /* normal output           */
           goto pread10;                    /* process first line      */
         }
         icountrpt1--;                      /* one level below         */
       }
     }
     if ((kzout == 'M') || (kzout == 'R'))  /* output must be done     */
       goto pstmacrpt00;                    /* store macro or repeat   */
     goto pzeilign;
   }
   if (kzbef1 > '0') {
     if (kzbef1 <= tabbef[itabbef].tb1) {
       m_sdh_printf((char*)"%s: %ld/%ld invalid command interlacing\n", "HPREE012E", ilinenr, ainf1->ilnr);
       ainf1->ifia--;
       goto pread2;
     }
   }
   if (tabbef[itabbef].tb2 != '1') {        /* Befehl nicht immer      */
     if (kzifakt2 != '1') {                 /* im Moment Ausgabe?      */
       ainf1->ifia--;
       goto pread2;
     }
   }
   if (kzbef1 < tabbef[itabbef].tb1)
     kzbef1 = tabbef[itabbef].tb1;          /* Befehl kennzeichnen     */

   switch (itabbef) {
     case 0:                                /* INT                     */
       if (!uint()) goto pcancel;
       goto pread2;
     case 1:                                /* TEXT                    */
       if (!utext()) goto pcancel;
       goto pread2;
     case 2:                                /* HEXA                    */
       uhexa();
       goto pread2;
     case 3:                                /* TAB                     */
       if (!utab()) goto pcancel;
       goto pread2;
     case 4:                                /* CONT                    */
       upruefend();
       bcont = TRUE;
       goto pzeilign;
     case 5:                                /* SET                     */
       if (!uset()) goto pcancel;
       kzout = '0';
       goto pzeilign;
     case DEF_C_MSET:                       /* MSET                    */
       if (aanfsym == aglobsym) {
           m_sdh_printf((char*)"%s: %ld/%ld mset not in macro\n", "HPREE013E", ilinenr, ainf1->ilnr);
         goto pzeilign;
       }
       if (!umset()) goto pcancel;
       kzout = '0';
       goto pzeilign;
     case 6:                                /* DEFT                    */
       if (!udeft()) goto pcancel;
       if (kzout == 'F') {
         if (!usaveSout()) goto pcancel;    /* save previous output    */
         if (!decstack( sizeof(asymtab), 1 )) goto pcancel;
//printf("....vor  &astack   %p  %p\n", &astack, astack);
//if ((astack % 8) != 0) {
//    printf(".... nicht modulo 8...\n");
//}

#ifdef JF_CORRECT_ALIGNMENT
        *((ULONG*) astack) = asymtab;
#else
         *((void **) astack) = (void*)asymtab;  // JF (void*)   /* save address variable   */
#endif
//printf("....nach &astack   %p  %p\n", &astack, astack);
         kzout = 'T';
       }
       ulSout = ul_Sout_save;               /* no output till now      */
       goto pread2;
     case DEF_C_MDEFT:                      /* MDEFT                   */
       if (aanfsym == aglobsym) {
           m_sdh_printf((char*)"%s: %ld/%ld mdeft not in macro\n", "HPREE014E", ilinenr, ainf1->ilnr);
         goto pzeilign;
       }
       if (!umdeft()) goto pcancel;
       if (kzout == 'F') {
         if (!usaveSout()) goto pcancel;    /* save previous output    */
         if (!decstack( sizeof(asymtab), 1 )) goto pcancel;
#ifdef JF_CORRECT_ALIGNMENT
        *((ULONG*) astack) = asymtab;
#else
         *((void **) astack) = (void*)asymtab;  // JF (void*)   /* save address variable   */
#endif
         kzout = 'T';
       }
       ulSout = ul_Sout_save;               /* no output till now      */
       goto pread2;
     case 7:                                /* INCLUDE                 */
       if (ch1 == ':') ch1 = ' ';
       if (ch1 != ' ') {
           m_sdh_printf((char*)"%s: %ld/%ld Include seperator is wrong\n", "HPREE015E", ilinenr, ainf1->ilnr);
         goto pzeilign;
       }
       while (ch1 == ' ') {
         if (ainf1->ifia < ainf1->ifil) {
           ch1 = ainf1->strlineinp[ainf1->ifia++];
         }
         else {
           ainf1->ifia = ainf1->ifil+1;
           ch1 = 0;
         }
       }
       ainf1->ifia--;
       if (kzout == 'F') {
         kzout = 'I';
         if (!usaveSout()) goto pcancel;    /* save previous output    */
       }
       ulSout = 0;
       goto pread2;
     case 8:                                /* CANCEL                  */
       upruefend();
       goto pcancel;
     case 9:                                /* DISP                    */
       if (ch1 != ':') {
           m_sdh_printf((char*)"%s: %ld/%ld control sign missing behind DISP:\n", "HPREE016E", ilinenr, ainf1->ilnr);
         goto pzeilign;
       }
       if (kzout == 'F') {
         kzout = 'D';                       /* output to display       */
         if (!usaveSout()) goto pcancel;    /* save previous output    */
       }
       ulSout = 0;
       goto pread2;
     case 10:                               /* ACC                     */
       if (!uacc()) goto pcancel;
       kzout = '0';
       goto pzeilign;
     case 11:                               /* IIF                     */
       if (!uholif()) goto pcancel;
       if (kzifaktu == '1') goto pread2;
       kzout = '0';
       goto pzeilign;
     case 12:                               /* IF                      */
       if (kzifakt2 != '1') {
         countif2++;
         goto pzeilign;
       }
       countif1++;
       if (!decstack( sizeof(DIFAKT), 1 )) goto pcancel;
       ((DIFAKT *)astack)->tifakt1 = kzifakt1;
       if (!uholif()) goto pcancel;
       kzifakt1 = kzifakt2 = kzifaktu;
       kzout = '0';
       goto pzeilign;
     case 13:                               /* IFT                     */
       upruefend();
       kzout = '0';
       if (countif2) goto pzeilign;
       if (!countif1) goto piffehl1;
       if (kzifakt1 == '1') goto pifxtr;
       goto pifxfa;
     case 14:                               /* IFF                     */
       upruefend();
       kzout = '0';
       if (countif2) goto pzeilign;
       if (!countif1) goto piffehl1;
       if (kzifakt1 == '1') goto pifxfa;
       goto pifxtr;
     case 15:                               /* IFTF                    */
       upruefend();
       kzout = '0';
       if (countif2) goto pzeilign;
       if (!countif1) goto piffehl1;
       goto pifxtr;
     case 16:                               /* CEND                    */
       upruefend();
       kzout = '0';
       if (countif2) {
         countif2--;
         goto pzeilign;
       }
       if (!countif1) {
           m_sdh_printf((char*)"%s: %ld/%ld CEND without IF\n", "HPREE017E", ilinenr, ainf1->ilnr);
         goto pzeilign;
       }
       countif1--;
       kzifakt1 = ((DIFAKT *)astack)->tifakt1;
       incstack( sizeof(DIFAKT), 1 );//astack += sizeof(DIFAKT);
       kzifakt2 = '1';
       goto pzeilign;
     case DEF_C_MACRO:
       if (!ucmacro()) goto pcancel;
       ulSout = 0;
       if (kzout != 'M') goto pzeilign;     /* no more commands        */
       goto pread2;                         /* get macro arguments     */
     case DEF_C_MEND:
       upruefend();                           /* check if syntax correct */
       m_sdh_printf((char*)"%s: %ld/%ld MEND without starting MACRO\n", "HPREE018E", ilinenr, ainf1->ilnr);
       goto pzeilign;
     case DEF_C_MEXIT:
       upruefend();                           /* check if syntax correct */
       if (ainf1->ch_flag_macro_rpt != 'M') {  /* not from repeat      */
           m_sdh_printf((char*)"%s: %ld/%ld MEXIT not within macro\n", "HPREE019E", ilinenr, ainf1->ilnr);
         goto pzeilign;
       }
       ainf2 = (INFILE*)ainf1->next;  // JF (INFILE*)
       free( ainf1 );
       ainf1 = ainf2;
       incstack( sizeof(DIFAKT), countif1 );//astack += countif1 * sizeof(DIFAKT);
       countif2 = 0;
       countif1 = *((int *) astack);        /* get ifs before          */
       kzifakt1 = *((unsigned char *) (astack + 4));
       kzifakt2 = *((unsigned char *) (astack + 5));
       incstack( 6 , 1 );//astack += 6;
       /* remove table for macro symbols                               */
       i1 = 4 + *((ULONG *) aanfsym) * sizeof(DSYMBOL);  /* to remove  */
       if (astack < aanfsym) {
         memmove( (PVOID) (astack + i1), (PVOID) astack,
                  aanfsym - astack );
       }
       aanfsym += i1;
       incstack( i1, 1 );//astack += i1;
       ulSout = ul_Sout_save;               /* no output till now      */
       bcont = TRUE;                        /* do not store first line */
       goto pzeilign;                       /* ignore remainder of lin */
     case DEF_C_RPT:
       upruefend();                           /* check if syntax correct */
       ulSout = 0;                          /* no output till now      */
       if (kzifakt2 != '1') {               /* do not repeat stmts     */
         kzout = 'S';                       /* ignore all              */
         goto pzeilign;                     /* no more commands        */
       }
       if (!decstack( 8, 1 )) goto pcancel;
       *((PVOID *) astack) = (void*)atextende;  // ?JF (void*)   /* save start of stmts     */
       *((int *) (astack + 4)) = -1;        /* count indefinite        */
       kzout = 'R';                         /* store repeat now        */
       bcont = TRUE;                        /* do not store first line */
       goto pzeilign;                       /* no more commands        */
     case DEF_C_RPTN:
       ulSout = 0;                          /* no output till now      */
       if (kzifakt2 != '1') {               /* do not repeat stmts     */
         kzout = 'S';                       /* ignore all              */
         goto pzeilign;                     /* no more commands        */
       }
       ch_expr_end_search = ';';            /* expression end searched */
       if (!uausdr()) goto pcancel;
       if (wss.u.value > 0) {               /* do repeat               */
         if (!decstack( 8, 1 )) goto pcancel;
         *((PVOID *) astack) = (void*)atextende; // ?JF (void*)  /* save start of stmts     */
         *((int *) (astack + 4)) = wss.u.value;  /* set count          */
         kzout = 'R';                       /* store repeat now        */
         bcont = TRUE;                      /* do not store first line */
         goto pzeilign;                     /* no more commands        */
       }
       if (wss.u.value < 0) {               /* do repeat               */
           m_sdh_printf((char*)"%s: %ld/%ld RPTN with negative count %d\n", "HPREE020E", ilinenr, ainf1->ilnr, wss.u.value);
       }
       kzout = 'S';                         /* ignore all              */
       goto pzeilign;                       /* no more commands        */
     case DEF_C_REND:
       upruefend();                           /* check if syntax correct */
       m_sdh_printf((char*)"%s: %ld/%ld REND without starting RPT/RPTN\n", "HPREE021E", ilinenr, ainf1->ilnr);
       goto pzeilign;
     case DEF_C_REXIT:
       upruefend();                           /* check if syntax correct */
       if (ainf1->ch_flag_macro_rpt != 'R') {  /* not from repeat      */
           m_sdh_printf((char*)"%s: %ld/%ld REXIT without starting RPT/RPTN\n", "HPREE022E", ilinenr, ainf1->ilnr);
         goto pzeilign;
       }
       if (atextende == (ULONG)ainf1->astorinpe)   // JF (ULONG)
         atextende = (ULONG)ainf1->astorinps;  // JF (ULONG)    /* storage no longer need. */
       ainf2 = (INFILE*)ainf1->next;  // JF (INFILE*)
       free( ainf1 );
       ainf1 = ainf2;
       incstack( sizeof(DIFAKT), countif1 );//astack += countif1 * sizeof(DIFAKT);
       countif2 = 0;
       countif1 = *((int *) astack);        /* get ifs before          */
       kzifakt1 = *((unsigned char *) (astack + 4));
       kzifakt2 = *((unsigned char *) (astack + 5));
       incstack( 6, 1 );//astack += 6;
       ulSout = ul_Sout_save;               /* no output till now      */
       bcont = TRUE;                        /* do not store first line */
       goto pzeilign;                       /* ignore remainder of lin */
   }

   pifxfa:
   kzifakt2 = '0';
   goto pzeilign;

   pifxtr:
   kzifakt2 = '1';
   goto pzeilign;

   piffehl1:
   m_sdh_printf((char*)"%s: %ld/%ld Request condition (IFT/IFF/IFTF) without IF\n", "HPREE023E", ilinenr, ainf1->ilnr);

   pstmacrpt00:                             /* store macro or repeat   */
   while (isavecommand < ainf1->ifia) {     /* all characters          */
     strlineout[ulSout++] = ainf1->strlineinp[isavecommand++];
     if (ulSout > LINELEN) ulSout = LINELEN;
   }
   i2 = 0;
   while (ainf1->ifia < ainf1->ifil) {
     ch1 = strlineout[ulSout++] = ainf1->strlineinp[ainf1->ifia++];
     if (ulSout > LINELEN) ulSout = LINELEN;
     switch( ch1 ) {
       case CHAR_CR:
         i2 = 2;
         break;
       case CHAR_LF:
         if (i2 == 2) goto pread4;
         i2 = 0;
         break;
     }
   }
   goto pread4;                             /* store output            */

   pzeilign:                                /* Rest der Zeile ueberles */
   i2 = 0;
   while (ainf1->ifia < ainf1->ifil) {
     switch( ainf1->strlineinp[ainf1->ifia++] ) {
       case CHAR_CR:
         i2 = 2;
         break;
       case CHAR_LF:
         if (i2 == 2) goto pread4;
         i2 = 0;
         break;
     }
   }
   goto pread3;

   pcancel:
   while(ainf1) {
#ifndef WORK_AS_SDH
     if (ainf1->hfi) {
#if defined WIN32 || WIN64
       CloseHandle( ainf1->hfi );
#endif
     }
#endif // #ifndef WORK_AS_SDH
     ainf2 = (INFILE*)ainf1->next; // JF (INFILE*)
     free( ainf1 );
     ainf1 = ainf2;
   }
   goto pread60;
}

void cPrecomp::ugetdate( void )
{
   struct tm *newtime;
   time_t ltime;

   time(&ltime);
   newtime = localtime(&ltime);

   wss.u.value = newtime->tm_year % 100;      /* nur zwei Ziffern Jahr   */
   wss.u.value += (newtime->tm_mon + 1) * 100;
   wss.u.value += newtime->tm_mday * 10000;
}

//__int64 cPrecomp::GetMachineCycleCount()
//{      
//   __int64 cycles;
//   _asm rdtsc; // won't work on 486 or below - only pentium or above
//   _asm lea ebx,cycles;
//   _asm mov [ebx],eax;
//   _asm mov [ebx+4],edx;
//   return cycles;
//}

void cPrecomp::uinfile( void )
{
   int  iu1;

   iu1 = strlen( (const char*)strlineout ) + 1;  // JF (const char*)
   ainf2 = ainf1;                           /* save chain              */
#ifndef WORK_AS_SDH
    ainf1 = (INFILE*)malloc( sizeof(INFILE) + iu1 );   // JF (INFILE*)
#else
   // JF: allocate memory by calling application
   in_len_ainf1 = sizeof(INFILE) + iu1;
////__int64 cycles0 = GetMachineCycleCount();
   if (! ads_trans->amc_aux(ads_trans->vpc_userfld, DEF_AUX_MEMGET, &ainf1, in_len_ainf1)) {
       return; // if this happens, it's an desaster...
   }
////__int64 cycles1 = GetMachineCycleCount();
////printf("lib DEF_AUX_MEMGET: cycles0      %15d\n", cycles0);
////printf("lib DEF_AUX_MEMGET: cycles1      %15d\n", cycles1);
////printf("lib DEF_AUX_MEMGET: total    %15d\n", (cycles1-cycles0));
////printf("lib DEF_AUX_MEMGET: total(M) %15d\n", (cycles1-cycles0)/1000000);
#endif // WORK_AS_SDH

   memset( ainf1, 0, sizeof(INFILE) );      /* clear all values        */
   memcpy( ainf1 + 1, strlineout, iu1 );    /* set file-name           */
   ainf1->next = ainf2;
   ainf1->ilnr = 0;
   ainf1->ifil = 0;                         /* noch nichts eingelesen  */
   /* 15.08.97 - ignore character EOF                                  */
   ainf1->ifia = 0;
   /* end of new */
#ifndef WORK_AS_SDH
#if defined WIN32 || WIN64
   ainf1->hfi = CreateFile( (LPCTSTR)strlineout, GENERIC_READ, FILE_SHARE_READ, 0,   // JF (LPCSTR)
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );
   rc = 0;
   if (ainf1->hfi == INVALID_HANDLE_VALUE) {
     rc = GetLastError();
     free( ainf1 );
     ainf1 = ainf2;
   }
#endif
#endif // #ifndef WORK_AS_SDH
}

void cPrecomp::upruefend( void )
{
////__int64 cycles0 = GetMachineCycleCount();
    if (ch1 != ';') {
       m_sdh_printf((char*)"%s: %ld/%ld Endsign (;) missing behind command\n", "HPREE024E", ilinenr, ainf1->ilnr);
////__int64 cycles1 = GetMachineCycleCount();
////printf("lib DEF_AUX_CONSOLE_OUT:\n");
////printf("lib DEF_AUX_CONSOLE_OUT: cycles0      %15d\n", cycles0);
////printf("lib DEF_AUX_CONSOLE_OUT: cycles1      %15d\n", cycles1);
////printf("lib DEF_AUX_CONSOLE_OUT: total    %15d\n", (cycles1-cycles0));
////printf("lib DEF_AUX_CONSOLE_OUT: total(M) %15d\n", (cycles1-cycles0)/1000000);
    }
}

void cPrecomp::usymbol( void )                 /* suchen Symbol           */
{
   while (ch1 == ' ') {                     /* Blanks am Anfang weg    */
     if (ainf1->ifia < ainf1->ifil) {
       ch1 = ainf1->strlineinp[ainf1->ifia++];
     } else {
       ainf1->ifia = ainf1->ifil+1;
       ch1 = 0;
     }
   }
   usymbos();
}

void cPrecomp::usymbos( void )                 /* Space nicht ueberlesen  */
{
    // JF read in the symbol (name or value)
   memset( strsymbol, ' ', LENSYM );
   strsymbol[LENSYM] = 0;
   if (ch1 >= '0' && ch1 <= '9') {          /* nicht Ziffer am Anfang  */
     goto psymb4;
   }

   i2 = 0;

   psymb2:
   if (!chartab[ch1]) {
     goto psymb4;
   }
   if (i2 < LENSYM)
       strsymbol[i2++] = chartab[ch1];
   if (ainf1->ifia < ainf1->ifil) {
     ch1 = ainf1->strlineinp[ainf1->ifia++];
     goto psymb2;
   }
   ainf1->ifia = ainf1->ifil+1;
   ch1 = 0;

   psymb4:
   memcpy( wss.symbol, strsymbol, LENSYM );
}

void cPrecomp::usymbsun( void )
{
   wss.u.value = 0;
   usymbtab();
   if (kzsym2 == ' ') {
       m_sdh_printf((char*)"%s: %ld/%ld numeric variable not defined\n", "HPREE025E", ilinenr, ainf1->ilnr);
     return;
   }
   if (((DSYMBOL *)asymtab)->modebtex) {
       m_sdh_printf((char*)"%s: %ld/%ld numeric variable searched - text found\n", "HPREE026E", ilinenr, ainf1->ilnr);
     return;
   }
   wss.u.value = ((DSYMBOL *)asymtab)->u.value;
   if (((DSYMBOL *)asymtab)->modebsec) usecvalue();
}

void cPrecomp::usymbsut( void )
{
   wss.u.value = 0;
   usymbtab();
   if (kzsym2 == ' ') {
       m_sdh_printf((char*)"%s: %ld/%ld Text variable not defined\n", "HPREE027E", ilinenr, ainf1->ilnr);
     wss.modebdef = 0;                      /* value not defined       */
     return;
   }
   if (!((DSYMBOL *)asymtab)->modebtex) {
       m_sdh_printf((char*)"%s: %ld/%ld Text variable searched - number found\n", "HPREE028E", ilinenr, ainf1->ilnr);
     return;
   }
   memcpy( &wss, (PVOID) asymtab, sizeof(DSYMBOL) );
   if (((DSYMBOL *)asymtab)->modebsec) usecvalue();
}

BOOL cPrecomp::usymbein( void )
{
   usymbtab();                              /* search symbol in table  */
   if (kzsym2 == '1') {
     if (((DSYMBOL *)asymtab)->modebsec) {
         m_sdh_printf((char*)"%s: %ld/%ld System variable shall be changed\n", "HPREE029E", ilinenr, ainf1->ilnr);
       asymtab = 0;                         /* nichts einfuegen        */
       return TRUE;
     }
     if (((DSYMBOL *)asymtab)->modebtex != wss.modebtex) {
       if (((DSYMBOL *)asymtab)->modebtex) {
           m_sdh_printf((char*)"%s: %ld/%ld Text shall be replaced with variable\n", "HPREE030E", ilinenr, ainf1->ilnr);
       } else {
           m_sdh_printf((char*)"%s: %ld/%ld Variable shall be replaced with text\n", "HPREE031E", ilinenr, ainf1->ilnr);
       }
       asymtab = 0;                         /* nichts einfuegen        */
       return TRUE;
     }
   } else {
     if (!decstack( sizeof(DSYMBOL), 1 )) return FALSE;
     asymtab -= sizeof(DSYMBOL);
     aanfsym -= sizeof(DSYMBOL);
     if (asymtab - astack)
       memmove( (PVOID) astack, (PVOID) (astack + sizeof(DSYMBOL)),
                asymtab - astack );
     if (ch_symbol_scope == 'G') {          /* G = global, not macro   */
       aglobsym -= sizeof(DSYMBOL);         /* one more symbol         */
       (*((ULONG *) aglobsym))++;
     } else {
       (*((ULONG *) aanfsym))++;
     }
   }
   wss.modebdef = 1;                        /* value defined           */
   memcpy( (PVOID) asymtab, &wss, sizeof(DSYMBOL) );
   return TRUE;
}

void cPrecomp::usymbtab( void )                /* search symbol in table  */
{
   int   ianzsym;
   ULONG aaktsym;
   int   isymw1;
   ULONG ausymts;                           /* start symbol table      */
   ULONG ausymte;                           /* end symbol table        */

   kzsym2 = ' ';                            /* noch nichts gefunden    */
   ausymts = aanfsym;                       /* check also macro        */
   if (ch_symbol_scope == 'G') {            /* G = global, not macro   */
     ausymts = aglobsym;                    /* check only global       */
   }

   psymbt00:                                /* search in this table    */
   aaktsym = ausymts + sizeof(void*);                   /* set start               */
   ianzsym = *((ULONG *) ausymts);          /* get number of elements  */
   ausymte = ausymts + sizeof(void*) + ianzsym * sizeof(DSYMBOL);  /* set end      */
   asymtab = aaktsym;                       /* if nothing found        */

   // JF search the symbol from the table-store
   psymbt02:
   if (ianzsym == 0) goto psymbt04;
   ianzsym = (ianzsym - 1) / 2;
   asymtab = ianzsym * sizeof(DSYMBOL) + aaktsym;
   if (asymtab >= ausymte)
     goto psymbt02;
   isymw1 = memcmp( ((DSYMBOL *)asymtab)->symbol, wss.symbol, LENSYM );
   if (isymw1 > 0)
       goto psymbt02;
   if (isymw1 == 0) 
       goto psymbt03;
   aaktsym = asymtab + sizeof(DSYMBOL);
   ianzsym++;
   goto psymbt02;

   psymbt03:
   kzsym2 = '1';                            /* return symbol found     */
   return;                                  /* all done                */

   psymbt04:
   if (ausymts == aglobsym)                 /* last is global table    */
     return;
   if (ch_symbol_scope == 'S')              /* S = set macro           */
     return;
   ausymts = ausymte;                       /* check next table        */
   goto psymbt00;                           /* search in this table    */
}

void cPrecomp::usecvalue( void )
{
   switch (wss.u.value) {
     case DEF_SEC_COPYC:
       wss.u.value = icopyc;                /* set value               */
       break;
     case DEF_SEC_DATE:
       ugetdate();                          /* set date                */
       break;
     case DEF_SEC_INPFCOU:
       ainf2 = ainf1;                       /* get chain input-files   */
       while (ainf2->astorinps) ainf2 = (INFILE*)ainf2->next; // JF (INFILE*) /* ignore stor   */
       wss.u.value = ainf2->ilnr;           /* set line-number input-f */
       break;
     case DEF_SEC_INPFILN:
       ainf2 = ainf1;                       /* get chain input-files   */
       while (ainf2->astorinps) ainf2 = (INFILE*)ainf2->next; // JF (INFILE*) /* ignore stor   */
       wss.u.addr = (ULONG) (ainf2 + 1);    /* set address of file-na  */
       wss.modet2 = strlen( (const char*)/*(PVOID)*/ (ainf2 + 1) );  // JF (PVOID) -> (const char*)
                                            /* set length of file-name */
       break;
     case DEF_SEC_LINE_A:                   /* $LINE_A line over all   */
       wss.u.value = ilinenr;               /* set value               */
       break;
     case DEF_SEC_LINE_FI:                  /* $LINE_FI line of this file */
       wss.u.value = ainf1->ilnr;           /* set value               */
       break;
     case DEF_SEC_LINE_O:                   /* $LINE_O line output     */
       wss.u.value = ins_linenr_out;        /* set value               */
       break;

       // HOB-PPP-Tunnel: applet-parameter WSP_INETA
     case DEF_SEC_PPP_INETA: {
         ach_ppp_ineta = m_get_ppp_ineta(); // JF 07.10.08
         wss.u.addr = (ULONG) (ach_ppp_ineta);
         wss.modet2 = strlen((const char*)ach_ppp_ineta);
         wss.modebdef = 1; // without this flag nothing will be replaced; I don't know, when and how this flag gets set -> so I do it here
         break;
     }
       // HOB-PPP-Tunnel: applet-parameter WSP_L2TP_ARG
     case DEF_SEC_PPP_L2TP_ARG: {
         ach_ppp_l2tp_arg = m_get_ppp_l2tp_arg(); // JF 07.10.08
         wss.u.addr = (ULONG) (ach_ppp_l2tp_arg);
         wss.modet2 = strlen((const char*)ach_ppp_l2tp_arg);
         wss.modebdef = 1; // without this flag nothing will be replaced; I don't know, when and how this flag gets set -> so I do it here
       break;
     }
       // HOB-PPP-Tunnel: applet-parameter WSP_L2TP_LOCAL_HOST
     case DEF_SEC_PPP_LOCALHOST: {
         ach_ppp_localhost = m_get_ppp_localhost(); // JF 07.10.08
         wss.u.addr = (ULONG) (ach_ppp_localhost);
         wss.modet2 = strlen((const char*)ach_ppp_localhost);
         wss.modebdef = 1; // without this flag nothing will be replaced; I don't know, when and how this flag gets set -> so I do it here
       break;
     }
       // HOB-PPP-Tunnel: applet-parameter WSP_SOCKS_MODE
     case DEF_SEC_PPP_SOCKS_MODE: {
         ach_ppp_socks_mode = m_get_ppp_socks_mode(); // JF 07.10.08
         wss.u.addr = (ULONG) (ach_ppp_socks_mode);
         wss.modet2 = strlen((const char*)ach_ppp_socks_mode);
         wss.modebdef = 1; // without this flag nothing will be replaced; I don't know, when and how this flag gets set -> so I do it here
       break;
     }
       // JF Ticket[16598] HOB-PPP-Tunnel: applet-parameter WSP_L2TP_LOCAL_HOST
     case DEF_SEC_PPP_UNIX_PARAMETER: {
         ach_ppp_unix_parameter = m_get_ppp_unix_parameter();
         wss.u.addr = (ULONG) (ach_ppp_unix_parameter);
         wss.modet2 = strlen((const char*)ach_ppp_unix_parameter);
         wss.modebdef = 1; // without this flag nothing will be replaced; I don't know, when and how this flag gets set -> so I do it here
       break;
     }
     // JF Ticket[16598] HOB-PPP-Tunnel: applet-parameter WSP_PPP_SYSTEM_PARAMS
     case DEF_SEC_PPP_SYSTEM_PARAMS: {
         ach_ppp_system_parameter = m_get_ppp_system_parameter();
         wss.u.addr = (ULONG) (ach_ppp_system_parameter);
         wss.modet2 = strlen((const char*)ach_ppp_system_parameter);
         wss.modebdef = 1; // without this flag nothing will be replaced; I don't know, when and how this flag gets set -> so I do it here
       break;
     }
   }
}

void cPrecomp::uzahl( void )
{
   wss.u.value = 0;
   while (ch1 >= '0' && ch1 <= '9') {
     wss.u.value = wss.u.value * 10 + ch1 - '0';
     if (ainf1->ifia < ainf1->ifil) {
       ch1 = ainf1->strlineinp[ainf1->ifia++];
     }
     else {
       ainf1->ifia = ainf1->ifil+1;
       ch1 = 0;
     }
   }
}

BOOL cPrecomp::uausdr( void )
{
   unsigned char kzausd1;                   /* Merker kzausd1          */
     /* 1 = es muss reine Nummer folgen                                */
     /* 2 = es muss Nummer, eventuell Minus, folgen                    */
     /* 3 = es muss Operator folgen                                    */
   int icont;
   int iunobracket;                         /* count brackets          */

   iunobracket = 0;                         /* count brackets          */
   if (!decstack(4, 1)) return FALSE;
   (((DLONG *)astack)->i) = 0;              /* setzen Stopper          */
   ch_symbol_scope = 'M';                   /* M = macro, not global   */
   kzausd1 = '2';
   usymbol();
   goto pausd02;

   pausd01:
   usymbos();                               /* hole naechstes Zeichen  */

   pausd02:
   wss.u.value = 0;
   if (ch1 == CHAR_QUOTE) {
     if ((wss.symbol[0] != 'L') || (wss.symbol[1] != ' ')) {
         m_sdh_printf((char*)"%s: %ld/%ld invalid command with quote / %s\n", "HPREE032E", ilinenr, ainf1->ilnr, strsymbol);
       goto pausd90;
     }
     if (ainf1->ifia < ainf1->ifil) {
       ch1 = ainf1->strlineinp[ainf1->ifia++];
     } else {
       ainf1->ifia = ainf1->ifil+1;
       ch1 = 0;
     }
     usymbos();                             /* get variable            */
     if (wss.symbol[0] == ' ') {
         m_sdh_printf((char*)"%s: %ld/%ld invalid character in function length / %c\n", "HPREE033E", ilinenr, ainf1->ilnr, ch1);
       goto pausd90;
     }
     wss.u.value = 0;
     usymbtab();
     if (kzsym2 == ' ') {
         m_sdh_printf((char*)"%s: %ld/%ld variable (function length) not defined / %s\n", "HPREE034E", ilinenr, ainf1->ilnr, strsymbol);
       goto pausd90;
     }
     if (((DSYMBOL *)asymtab)->modebtex) {  /* text-variable found     */
       wss.u.value = ((DSYMBOL *)asymtab)->modet2;
     } else {                               /* numeric variable        */
       wss.u.value = ((DSYMBOL *)asymtab)->u.value;
       if (((DSYMBOL *)asymtab)->modebsec) usecvalue();
       i1 = wss.u.value;
       wss.u.value = 0;
       do {
         wss.u.value++;
         i1 /= 10;
       } while (i1 != 0);
     }
   } else if (wss.symbol[0] != ' ') usymbsun();
   else {
     if (ch1 >= '0' && ch1 <= '9') uzahl();
     else goto pausd14;
   }
   kzausd1 = '3';                           /* dann Operator gesucht   */

   pausd10:                                 /* suchen Operator         */
   usymbos();                               /* hole naechstes Zeichen  */
   if (wss.symbol[0] != ' ') goto pausd84;
   if (ch1 >= '0' && ch1 <= '9') goto pausd84;

   pausd14:                                 /* suchen Operator         */
   ch_expr_end_found = ch1;
   if (ch1 == ' ') {
     if (ch_expr_end_search == ';') {       /* expression end searched */
         m_sdh_printf((char*)"%s: %ld/%ld Space in expression - expression not terminated\n", "HPREE035E", ilinenr, ainf1->ilnr);
       goto pausd90;
     }
     goto pausd80;
   }
   itabop = 0;

   pausd16:
   if (itabop == sizeof(tabop) / sizeof(tabop[0])) {
       m_sdh_printf((char*)"%s: %ld/%ld wrong character in expression / %c\n", "HPREE036E", ilinenr, ainf1->ilnr, ch1);
     goto pausd90;
   }
   if (ch1 != tabop[itabop].chop) {
     itabop++;
     goto pausd16;
   }
   if (tabop[itabop].ityp == 1) goto pausd30;
   if (tabop[itabop].ityp == 2) goto pausd40;
   if (tabop[itabop].ityp == 3) goto pausd80;

   if (kzausd1 < '2') goto pausd82;
   if (kzausd1 == '2') {
     if (ch1 != '-') goto pausd82;
   }
   /* changed 15.03.00 KB - Start                                      */
   kzausd1 = '2';
   /* changed 15.03.00 KB - End                                        */
   icont = 0;

   pausd22:
   if (!decstack(sizeof(DSTOP), 1)) return FALSE;
   ((DSTOP *)astack)->par = 0;              /* Anzahl Klammern         */
   ((DSTOP *)astack)->op = ch1;             /* Operator                */
   ((DSTOP *)astack)->class1 = tabop[itabop].class1;
   ((DSTOP *)astack)->value = wss.u.value;

   pausd24:
   if (((DSTOP *)(astack+sizeof(DSTOP)))->par == 0) {
     if (((DSTOP *)astack)->class1 <=
        ((DSTOP *)(astack+sizeof(DSTOP)))->class1) {
       if (((DSTOP *)(astack+sizeof(DSTOP)))->op == '+')
         ((DSTOP *)astack)->value +=
           ((DSTOP *)(astack+sizeof(DSTOP)))->value;
       if (((DSTOP *)(astack+sizeof(DSTOP)))->op == '-')
         ((DSTOP *)astack)->value =
           ((DSTOP *)(astack+sizeof(DSTOP)))->value -
           ((DSTOP *)astack)->value;
       if (((DSTOP *)(astack+sizeof(DSTOP)))->op == '*')
         ((DSTOP *)astack)->value *=
           ((DSTOP *)(astack+sizeof(DSTOP)))->value;
       if (((DSTOP *)(astack+sizeof(DSTOP)))->op == '/')
         ((DSTOP *)astack)->value =
           ((DSTOP *)(astack+sizeof(DSTOP)))->value /
           ((DSTOP *)astack)->value;
       memcpy( ((DSTOP *)(astack+sizeof(DSTOP))),
               ((DSTOP *)astack), sizeof(DSTOP) );
       incstack( sizeof(DSTOP), 1 );//astack += sizeof(DSTOP);
       goto pausd24;
     }
   }
   if (!icont) goto pausd32;
   if (icont == 1) goto pausd41;
   goto pausd81;

   pausd30:                                 /* Klammer auf gefunden    */
   if (kzausd1 == '3') goto pausd84;
   kzausd1 = '2';                           /* danach Minus erlaubt    */
   (((DSTOP *)astack)->par)++;              /* Anzahl Klammern         */
   iunobracket++;

   pausd32:                                 /* Setze noch Zeichen      */
   if (ainf1->ifia < ainf1->ifil) {
     ch1 = ainf1->strlineinp[ainf1->ifia++];
   }
   else {
     ainf1->ifia = ainf1->ifil+1;
     ch1 = 0;
   }
   goto pausd01;

   pausd40:                                 /* Klammer zu gefunden     */
   if (kzausd1 != '3') goto pausd84;
   icont = 1;                               /* Fortsetzung             */
   if (   (ch_expr_end_search != ';')       /* expression end searched */
       && (iunobracket == 0)) {             /* no brackets open        */
     goto pausd80;
   }
   iunobracket--;
   goto pausd22;

   pausd41:
   if (!((DSTOP *)(astack+sizeof(DSTOP)))->par) {
       m_sdh_printf((char*)"%s: %ld/%ld closing bracket without openeing bracket\n", "HPREE037E", ilinenr, ainf1->ilnr);
   }
   else (((DSTOP *)(astack+sizeof(DSTOP)))->par)--;
   wss.u.value = ((DSTOP *)astack)->value;
   incstack( sizeof(DSTOP), 1 );//astack += sizeof(DSTOP);
   if (ainf1->ifia < ainf1->ifil) {
     ch1 = ainf1->strlineinp[ainf1->ifia++];
   }
   else {
     ainf1->ifia = ainf1->ifil+1;
     ch1 = 0;
   }
   goto pausd10;                            /* suche Operator          */

   pausd80:                                 /* Ende des Ausdrucks      */
   if (kzausd1 != '3') goto pausd84;
   icont = 2;                               /* Fortsetzung             */
   ch1 = ';';                               /* set operator end        */
   goto pausd22;

   pausd81:
   wss.u.value = ((DSTOP *)astack)->value;
   incstack( sizeof(DSTOP), 1 );//astack += sizeof(DSTOP);
   if (!((DSTOP *)astack)->op) goto pausd96;
   m_sdh_printf((char*)"%s: %ld/%ld closing bracket missing\n", "HPREE038E", ilinenr, ainf1->ilnr);
   goto pausd90;

   pausd82:
   m_sdh_printf((char*)"%s: %ld/%ld no symbol or number found in expression\n", "HPREE039E", ilinenr, ainf1->ilnr);
   goto pausd90;

   pausd84:
   m_sdh_printf((char*)"%s: %ld/%ld no operator found in expression\n", "HPREE040E", ilinenr, ainf1->ilnr);

   pausd90:                                 /* Fehler-Ausgang          */
   while (((DSTOP *)astack)->op)
     incstack( sizeof(DSTOP), 1 );//astack += sizeof(DSTOP);
   wss.u.value = 0;

   pausd96:                                 /* fertig                  */
   incstack( 4, 1 );//astack += 4;
   return TRUE;
}

BOOL cPrecomp::uholif( void )                  /* Abarbeiten IIF und IF   */
{
   int iifakt;

   kzifaktu = '0';
   usymbol();
   iifakt = 0;
   ch_symbol_scope = 'M';                   /* M = macro, not global   */

   pif04:
   if (iifakt == sizeof(tabcond) / sizeof(tabcond[0])) {
       m_sdh_printf((char*)"%s: %ld/%ld condition not defined - %s\n", "HPREE041E", ilinenr, ainf1->ilnr, strsymbol);
     return TRUE;
   }
   if (memcmp( wss.symbol, &tabcond[iifakt].cname,
               sizeof(tabcond[0].cname) )) {
     iifakt++;
     goto pif04;
   }
   if (iifakt >= 2) goto pif41;
   usymbol();
   if (strsymbol[0] == ' ') {
       m_sdh_printf((char*)"%s: %ld/%ld no symbol behind DEF/NDF\n", "HPREE042E", ilinenr, ainf1->ilnr);
     return TRUE;
   }
   upruefend();
   usymbtab();
   if (iifakt == 0 && kzsym2 == '1') kzifaktu = '1';
   if (iifakt == 1 && kzsym2 != '1') kzifaktu = '1';
   return TRUE;

   pif41:
   ch_expr_end_search = ';';                /* expression end searched */
   if (!uausdr()) return FALSE;
   switch (iifakt) {
     case 2:                                /* EQ                      */
       if (wss.u.value == 0) kzifaktu = '1';
       break;
     case 3:                                /* NE                      */
       if (wss.u.value != 0) kzifaktu = '1';
       break;
     case 4:                                /* GT                      */
       if (wss.u.value > 0) kzifaktu = '1';
       break;
     case 5:                                /* LT                      */
       if (wss.u.value < 0) kzifaktu = '1';
       break;
     case 6:                                /* GE                      */
       if (wss.u.value >= 0) kzifaktu = '1';
       break;
     case 7:                                /* LE                      */
       if (wss.u.value <= 0) kzifaktu = '1';
       break;
   }
   return TRUE;
}

BOOL cPrecomp::uint( void )                    /* Befehl INT              */
{
   int ianzo1;
   int ianzo2;
   int icont;

   ch_symbol_scope = 'M';                   /* M = macro, not global   */
   memset( &wss, 0, sizeof(DSYMBOL) );
   usymbol();
   if (strsymbol[0] != ' ') goto pint06;
   if (ch1 != '(') goto pint05;
   ch1 = ' ';                               /* Zeichen Åberlesen       */
   usymbol();
   if (strsymbol[0] != ' ') usymbsun();
   else uzahl();
   if (ch1 != ')') goto pint06;
   if (wss.u.value <= 0 || wss.u.value > 16) {
       m_sdh_printf((char*)"%s: %ld/%ld INT - invalid length (1 to 16)\n", "HPREE043E", ilinenr, ainf1->ilnr);
     return TRUE;
   }
   if (ainf1->ifia < ainf1->ifil) {
     ch1 = ainf1->strlineinp[ainf1->ifia++];
   }
   else {
     ainf1->ifia = ainf1->ifil+1;
     ch1 = 0;
   }

   pint05:
   if (ch1 == ':') goto pint10;

   pint06:
   m_sdh_printf((char*)"%s: %ld/%ld no : or (nnn) behind INT\n", "HPREE044E", ilinenr, ainf1->ilnr);
   return TRUE;

   pint10:
   if (ainf1->ifia < ainf1->ifil) {
     ch1 = ainf1->strlineinp[ainf1->ifia++];
   }
   else {
     ainf1->ifia = ainf1->ifil+1;
     ch1 = 0;
   }
   if (!decstack(8, 1)) return FALSE;
   (((DLONG *)astack)->i) = wss.u.value;
   ch_expr_end_search = ';';                /* expression end searched */
   if (!uausdr()) return FALSE;
   ianzo1 = 0;
   if (ulSout == LINELEN) goto pint22;
   (((DLONG *)(astack+4))->i) = wss.u.value;
   if (wss.u.value < 0) wss.u.value *= -1;
   icont = 1;                               /* Fortsetzung             */

   pint12:                                  /* gib Ziffer aus          */
   strlineout[ulSout] = wss.u.value % 10 + '0';
   wss.u.value /= 10;
   ianzo1++;
   (((DLONG *)astack)->i)--;
   if (!((DLONG *)astack)->i) goto pint22;
   if (wss.u.value) goto pint16;

   pint14:                                  /* Pruefe was kommt noch   */
   icont = 2;                               /* gib Nullen aus          */
   if (((DLONG *)(astack+4))->i < 0) {
     /* Aenderung 25.01.97 KB */
     if (((DLONG *)astack)->i <= 1) icont = 3;
     goto pint16;
   }
   if (((DLONG *)astack)->i <= 0) goto pint22;

   pint16:                                  /* noch Verschieben        */
   if (ianzo1 == LINELEN - ulSout) goto pint22;
   ianzo2 = ianzo1;
   while (ianzo2) {
     ianzo2--;
     strlineout[ulSout+ianzo2+1] = strlineout[ulSout+ianzo2];
   }
   if (icont == 1) goto pint12;
   if (icont == 3) goto pint20;

   strlineout[ulSout] = '0';
   ianzo1++;
   (((DLONG *)astack)->i)--;
   goto pint14;

   pint20:                                  /* noch Minus ausgeben     */
   strlineout[ulSout] = '-';
   ianzo1++;

   pint22:                                  /* soweit fertig           */
   ulSout += ianzo1;                        /* setze Ausgabe richtig   */
   incstack( 8, 1 );//astack += 8;                             /* Stack wieder richtig    */
   return TRUE;
}

BOOL cPrecomp::utext( void )                   /* Befehl TEXT             */
{
   ch_symbol_scope = 'M';                   /* M = macro, not global   */
   if (!decstack( sizeof(long), 2 )) return FALSE;
   memset( (PVOID) astack, 0, 2*sizeof(long) );          /* bis jetzt kein Format   */
   usymbol();
   if (strsymbol[0] != ' ') goto ptext21;
   if (ch1 != '(') goto ptext11;
   ch1 = ' ';                               /* Zeichen Åberlesen       */
   usymbol();
   if (strsymbol[0] != ' ') usymbsun();
   else uzahl();
   if (wss.u.value < 1 || wss.u.value > LINELEN) {
       m_sdh_printf((char*)"%s: %ld/%ld TEXT - invalid position info\n", "HPREE045E", ilinenr, ainf1->ilnr);
     goto ptext22;
   }
   ((DLONG *)astack)->i = wss.u.value - 1;  /* Position minus 1        */
   if (ch1 == ')') goto ptext10;
   if (ch1 != ',') goto ptext21;
   ch1 = ' ';                               /* Zeichen Åberlesen       */
   usymbol();
   if (strsymbol[0] != ' ') usymbsun();
   else uzahl();
   if (wss.u.value < 1 || wss.u.value > LINELEN) {
       m_sdh_printf((char*)"%s: %ld/%ld TEXT - invalid length info\n", "HPREE046E", ilinenr, ainf1->ilnr);
     goto ptext22;
   }
   ((DLONG *)(astack+ 1*sizeof(long)))->i = wss.u.value;  /* Laenge ausgeben         */
   if (ch1 != ')') goto ptext21;

   ptext10:
   if (ainf1->ifia < ainf1->ifil) {
     ch1 = ainf1->strlineinp[ainf1->ifia++];
   }
   else {
     ainf1->ifia = ainf1->ifil+1;
     ch1 = 0;
   }

   ptext11:
   if (ch1 != ':') goto ptext21;
   ch1 = ' ';                               /* Zeichen Åberlesen       */
   usymbol();
   if (strsymbol[0] == ' ') goto ptext21;
   upruefend();
   usymbsut();
   wss.u.addr += ((DLONG *)astack)->i;
   wss.modet2 -= ((DLONG *)astack)->i;
   if (((DLONG *)(astack+1*sizeof(long)))->i) {
     if (((DLONG *)(astack+1*sizeof(long)))->i < wss.modet2) {
       wss.modet2 = ((DLONG *)(astack+1*sizeof(long)))->i;
     }
   }
   if (wss.modet2 > LINELEN - ulSout)
     wss.modet2 = LINELEN - ulSout;
   if (wss.modebdef != 1) wss.modet2 = 0;
   if (wss.modet2 > 0) {
     memcpy( &strlineout[ulSout], (PVOID) wss.u.addr, wss.modet2 );
     ulSout += wss.modet2;
   }
   incstack( sizeof(long), 2 );//astack += 8;                             /* Stack wieder richtig    */
   return TRUE;

   ptext21:
   m_sdh_printf((char*)"%s: %ld/%ld wrong syntax behind TEXT\n", "HPREE047E", ilinenr, ainf1->ilnr);

   ptext22:
   incstack( sizeof(long), 2 );//astack += 8;                             /* Stack wieder richtig    */
   kzout = '0';                             /* keine Ausgabe           */
   return TRUE;
}

void cPrecomp::uhexa( void )                   /* Befehl HEXA             */
{
   int ihexa;

   if (ch1 != ':') {
       m_sdh_printf((char*)"%s: %ld/%ld HEXA - no : behind instruction\n", "HPREE048E", ilinenr, ainf1->ilnr);
     kzout = '0';                           /* keine Ausgabe           */
     return;
   }

   phexa02:
   if (ainf1->ifia < ainf1->ifil) {
     ch1 = ainf1->strlineinp[ainf1->ifia++];
   }
   else {
     ainf1->ifia = ainf1->ifil+1;
     ch1 = 0;
   }
   if (ch1 == ';') return;
   if (ch1 >= '0' && ch1 <= '9') {
     ihexa = ch1 - '0';
     goto phexa04;
   }
   if (ch1 >= 'A' && ch1 <= 'F') {
     ihexa = ch1 - 'A' + 10;
     goto phexa04;
   }
   goto phexa12;

   phexa04:
   ihexa *= 16;
   if (ainf1->ifia < ainf1->ifil) {
     ch1 = ainf1->strlineinp[ainf1->ifia++];
   }
   else {
     ainf1->ifia = ainf1->ifil+1;
     ch1 = 0;
   }
   if (ch1 >= '0' && ch1 <= '9') {
     ihexa += ch1 - '0';
     goto phexa06;
   }
   if (ch1 >= 'A' && ch1 <= 'F') {
     ihexa += ch1 - 'A' + 10;
     goto phexa06;
   }
   goto phexa12;

   phexa06:
   strlineout[ulSout++] = ihexa;
   if (ulSout > LINELEN) ulSout = LINELEN;
   goto phexa02;

   phexa12:
   m_sdh_printf((char*)"%s: %ld/%ld HEXA - HEXA character is not 0-9 and A-F\n", "HPREE049E", ilinenr, ainf1->ilnr);
   kzout = '0';                             /* keine Ausgabe           */
   return;
}

BOOL cPrecomp::utab( void )                    /* Befehl TAB              */
{
   usymbol();
   if (strsymbol[0] != ' ') goto ptab12;
   if (ch1 != ':') goto ptab12;
   ch1 = ' ';                               /* Zeichen Åberlesen       */
   ch_expr_end_search = ';';                /* expression end searched */
   if (!uausdr()) return FALSE;
   if (wss.u.value > LINELEN) goto ptab06;
   if (wss.u.value < ulSout+1) goto ptab06;
   wss.u.value -= ulSout + 1;
   if (wss.u.value) {
     memset( &strlineout[ulSout], ' ', wss.u.value );
     ulSout += wss.u.value;
   }
   return TRUE;

   ptab06:
   m_sdh_printf((char*)"%s: %ld/%ld TAB value not possible\n", "HPREE050E", ilinenr, ainf1->ilnr);
   return TRUE;

   ptab12:
   m_sdh_printf((char*)"%s: %ld/%ld missing control character : behind TAB\n", "HPREE051E", ilinenr, ainf1->ilnr);
   return TRUE;
}

BOOL cPrecomp::uset( void )                    /* Befehl SET              */
{
   if (ch1 == ':') ch1 = ' ';               /* wegen Befehls-Zeile     */
   usymbol();
   if (strsymbol[0] == ' ') goto pset12;
   if (!decstack( sizeof(wss.symbol), 1 )) return FALSE;
   memcpy( (PVOID) astack, wss.symbol, sizeof(wss.symbol) );
   usymbol();
   if (strsymbol[0] != ' ') goto pset11;
   if (ch1 != '=') goto pset11;
   memset( &wss, 0, sizeof(DSYMBOL) );
   ch1 = ' ';
   ch_expr_end_search = ';';                /* expression end searched */
   if (!uausdr()) return FALSE;
   memcpy( wss.symbol, (PVOID) astack, sizeof(wss.symbol) );
   incstack( sizeof(wss.symbol), 1 );//astack += sizeof(wss.symbol);
   wss.modebsec = 0;
   wss.modebtex = 0;
   ch_symbol_scope = 'G';                   /* G = global, not macro   */
   if (!usymbein()) return FALSE;
   return TRUE;

   pset11:
   incstack( sizeof(wss.symbol), 1 );//astack += sizeof(wss.symbol);

   pset12:
   m_sdh_printf((char*)"%s: %ld/%ld no variable or no = behind SET\n", "HPREE052E", ilinenr, ainf1->ilnr);
   return TRUE;
}

BOOL cPrecomp::umset( void )                   /* command MSET            */
{
   if (ch1 == ':') ch1 = ' ';               /* wegen Befehls-Zeile     */
   usymbol();
   if (strsymbol[0] == ' ') goto pmset12;
   if (!decstack( sizeof(wss.symbol), 1 )) return FALSE;
   memcpy( (PVOID) astack, wss.symbol, sizeof(wss.symbol) );
   usymbol();
   if (strsymbol[0] != ' ') goto pmset11;
   if (ch1 != '=') goto pmset11;
   memset( &wss, 0, sizeof(DSYMBOL) );
   ch1 = ' ';
   ch_expr_end_search = ';';                /* expression end searched */
   if (!uausdr()) return FALSE;
   memcpy( wss.symbol, (PVOID) astack, sizeof(wss.symbol) );
   incstack( sizeof(wss.symbol), 1 );//astack += sizeof(wss.symbol);
   wss.modebsec = 0;
   wss.modebtex = 0;
   ch_symbol_scope = 'S';                   /* S = set macro           */
   if (!usymbein()) return FALSE;
   return TRUE;

   pmset11:
   incstack( sizeof(wss.symbol), 1 );//astack += sizeof(wss.symbol);

   pmset12:
   m_sdh_printf((char*)"%s: %ld/%ld no variable or no = behind MSET\n", "HPREE053E", ilinenr, ainf1->ilnr);
   return TRUE;
}

BOOL cPrecomp::udeft( void )                   /* Befehl DEFT             */
{
   usymbol();
   if (strsymbol[0] == ' ')
       goto pdeft12;
   if (!decstack(sizeof(wss.symbol), 1))
       return FALSE;
   memcpy( (PVOID) astack, wss.symbol, sizeof(wss.symbol) );
   usymbol();
   if (strsymbol[0] != ' ')
       goto pdeft11;
   if (ch1 != ':') 
       goto pdeft11;
   memset( &wss, 0, sizeof(DSYMBOL) );
   memcpy( wss.symbol, (PVOID) astack, sizeof(wss.symbol) );
   incstack( sizeof(wss.symbol), 1 );//astack += sizeof(wss.symbol);
   wss.u.addr = atextende;
   wss.modebtex = 1;
   ch_symbol_scope = 'G';                   /* G = global, not macro   */
   if (!usymbein())
       return FALSE;
   return TRUE;

   pdeft11:
   incstack( sizeof(wss.symbol), 1 );//astack += sizeof(wss.symbol);

   pdeft12:
   m_sdh_printf((char*)"%s: %ld/%ld no variable or no : behind DEFT\n", "HPREE054E", ilinenr, ainf1->ilnr);
   return TRUE;
}

BOOL cPrecomp::umdeft( void )                  /* command MDEFT           */
{
   usymbol();
   if (strsymbol[0] == ' ') goto pdeft12;
   if (!decstack(sizeof(wss.symbol), 1)) return FALSE;
   memcpy( (PVOID) astack, wss.symbol, sizeof(wss.symbol) );
   usymbol();
   if (strsymbol[0] != ' ') goto pdeft11;
   if (ch1 != ':') goto pdeft11;
   memset( &wss, 0, sizeof(DSYMBOL) );
   memcpy( wss.symbol, (PVOID) astack, sizeof(wss.symbol) );
   incstack( sizeof(wss.symbol), 1 );//astack += sizeof(wss.symbol);
   wss.u.addr = atextende;
   wss.modebtex = 1;
   ch_symbol_scope = 'S';                   /* S = set macro           */
   if (!usymbein()) return FALSE;
   return TRUE;

   pdeft11:
   incstack( sizeof(wss.symbol), 1 );//astack += sizeof(wss.symbol);

   pdeft12:
   m_sdh_printf((char*)"%s: %ld/%ld no variable or no : behind DEFT keine Variable bzw. :\n", "HPREE055E", ilinenr, ainf1->ilnr);
   return TRUE;
}

BOOL cPrecomp::uacc( void )                    /* Befehl ACC              */
{
   int iacclen;
   int iaccind;
   int iaccanf;
   unsigned char stracc[80+1];
   unsigned char chacc;

   usymbol();
   if (strsymbol[0] != ' ' || ch1 != ':') {
       m_sdh_printf((char*)"%s: %ld/%ld no : behind  ACC\n", "HPREE056E", ilinenr, ainf1->ilnr);
     return TRUE;
   }
   ch1 = ' ';
   memset( &wss, 0, sizeof(DSYMBOL) );
   usymbol();
   if (strsymbol[0] == ' ') {
       m_sdh_printf((char*)"%s: %ld/%ld ACC - no symbol found\n", "HPREE057E", ilinenr, ainf1->ilnr);
     return TRUE;
   }
   while (ch1 == ' ') {                     /* Blanks ueberlesen       */
     if (ainf1->ifia < ainf1->ifil) {
       ch1 = ainf1->strlineinp[ainf1->ifia++];
     }
     else {
       ainf1->ifia = ainf1->ifil+1;
       ch1 = 0;
     }
   }
   chacc = ch1;
   if (chacc >= 'a' && chacc <= 'z') chacc -= 32;
   if (!((chacc == 'A') || (chacc == 'N') || (chacc == 'I'))) {  // JF (chacc = 'I')
       m_sdh_printf((char*)"%s: %ld/%ld ACC - no format behind symbol\n", "HPREE058E", ilinenr, ainf1->ilnr);
     return TRUE;
   }
   if (ainf1->ifia < ainf1->ifil) {
     ch1 = ainf1->strlineinp[ainf1->ifia++];
   }
   else {
     ainf1->ifia = ainf1->ifil+1;
     ch1 = 0;
   }
   uzahl();
   if (wss.u.value <= 0 || wss.u.value > 80) {
       m_sdh_printf((char*)"%s: %ld/%ld ACC - incorrect length format\n", "HPREE059E", ilinenr, ainf1->ilnr);
     return TRUE;
   }
   if (ch1 != ';') {
       m_sdh_printf((char*)"%s: %ld/%ld no end sign (;)\n", "HPREE060E", ilinenr, ainf1->ilnr);
     return TRUE;
   }
   iacclen = wss.u.value;

   pacc18:
   scanf( "%80s", stracc );
   wss.modet2 = strlen( (const char*)stracc );  // JF (const char*)
   if (wss.modet2 > iacclen) {
       m_sdh_printf((char*)"%s: ACC - Console input too long\n", "HPREE061E");
     goto pacc18;
   }
   if (chacc == 'A') {
     if (wss.modet2 > astack - atextende) {
         m_sdh_printf((char*)"%s: %ld/%ld ACC memory is not large enough - terminated\n", "HPREE062E", ilinenr, ainf1->ilnr);
       return FALSE;
     }
     wss.u.addr = atextende;
     wss.modebtex = 1;
     if (wss.modet2)
       memcpy( (PVOID) atextende, stracc, wss.modet2 );
     atextende += wss.modet2;
     ch_symbol_scope = 'G';                 /* G = global, not macro   */
     if (!usymbein()) return FALSE;
     return TRUE;
   }
   wss.u.value = 0;
   if (!wss.modet2) goto pacc34;
   iaccind = 0;

   pacc30:
   if (iaccind == wss.modet2) goto pacc34;
   if (stracc[iaccind] == ' ') {
     iaccind++;
     goto pacc30;
   }
   iaccanf = iaccind;
   if ((chacc == 'I') &&
       ((stracc[iaccind] == '-') || (stracc[iaccind] == '+'))) {
     iaccind++;
     if (iaccind == wss.modet2) goto pacc36;
   }

   pacc32:
   if (!((stracc[iaccind] >= '0') && (stracc[iaccind] <= '9')))
     goto pacc36;
   wss.u.value = wss.u.value * 10 + stracc[iaccind] - '0';
   iaccind++;
   if (iaccind < wss.modet2) goto pacc32;
   if (stracc[iaccanf] == '-') wss.u.value *= -1;

   pacc34:
   wss.modet2 = 0;
   ch_symbol_scope = 'G';                   /* G = global, not macro   */
   if (!usymbein()) return FALSE;
   return TRUE;

   pacc36:                                  /* Eingabe war falsch      */
   m_sdh_printf((char*)"%s: ACC - Input not numeric\n", "HPREE063E");
   goto pacc18;
}

BOOL cPrecomp::ucmacro( void )                 /* command MACRO           */
{
   if (ch1 != ':') {
       m_sdh_printf((char*)"%s: %ld/%ld MACRO - after Command no : / %c\n", "HPREE064E", ilinenr, ainf1->ilnr, ch1);
     return TRUE;
   }
   if (kzifakt2 != '1') {                   /* do not define macro     */
     kzout = 'N';                           /* ignore macro            */
     return TRUE;
   }
   ch1 = ' ';
   memset( &wss, 0, sizeof(DSYMBOL) );
   usymbol();
   if (strsymbol[0] == ' ') {
       m_sdh_printf((char*)"%s: %ld/%ld after MACRO no macro-name\n", "HPREE065E", ilinenr, ainf1->ilnr);
     return TRUE;
   }
   ch_symbol_scope = 'M';                   /* M = macro, not global   */
   usymbtab();                              /* search symbol in table  */
   if (kzsym2 == '1') {
     if (((DSYMBOL *)asymtab)->modebmac != 1) {
         m_sdh_printf((char*)"%s: %ld/%ld MACRO found / variable already defined\n", "HPREE066E", ilinenr, ainf1->ilnr);
       asymtab = 0;                         /* nichts einfuegen        */
       return TRUE;
     }
   }
   wss.u.addr = atextende;
   wss.modebmac = 1;
   if (!decstack( sizeof(DSYMBOL), 1 )) return FALSE;
   memcpy( (PVOID) astack, &wss, sizeof(DSYMBOL) );
   kzout = 'M';                             /* store macro now         */

#if defined HL_UNIX
   // JF 01.02.07 AIX-compiler complains, that no return value is returned; I set return-value to FALSE
   return FALSE;
#endif
}

BOOL cPrecomp::umargs( void )                  /* macro arguments         */
{
   unsigned char *auinpc, *auinpe;          /* input line              */
   int iuindma;
   int iu1;
   int iu_len_save_out;                     /* length in stack         */
   unsigned char chu1;
   BOOL bo_quote;

   iu_len_save_out = sizeof(ULONG) + *((ULONG *) astack);
   memcpy( &wss, (PVOID) (astack + iu_len_save_out), sizeof(DSYMBOL) );
   if (!decstack( 6 + 4, 1 )) return FALSE;
   memmove( (PVOID) astack, (PVOID) (astack + 6 + 4),
            iu_len_save_out + sizeof(DSYMBOL) );
   aanfsym -= 4;                            /* space for new table     */
   if (aanfsym - (astack + iu_len_save_out + sizeof(DSYMBOL) + 6))
     memmove( (PVOID) (astack + iu_len_save_out + sizeof(DSYMBOL) + 6),
              (PVOID) (astack + iu_len_save_out + sizeof(DSYMBOL) + 6 + 4),
              aanfsym - (astack + iu_len_save_out + sizeof(DSYMBOL) + 6));
   /* save if                                                          */
   *((int *) (astack + iu_len_save_out + sizeof(DSYMBOL))) = countif1;
   *((unsigned char *) (astack + iu_len_save_out + sizeof(DSYMBOL) + 4)) = kzifakt1;
   *((unsigned char *) (astack + iu_len_save_out + sizeof(DSYMBOL) + 5)) = kzifakt2;
   countif1 = 0;
   *((ULONG *) aanfsym) = 0;                /* no elements till now    */
   ainf2 = ainf1;                           /* save chain              */
   ainf1 = (INFILE*)malloc( sizeof(INFILE) );  // JF (INFILE*)
   // JF: allocate memory by calling application;
   // there will arise a problem at freeing the memory, because we must provide the length of memory to free, when WSP is requested to free memory
   // because we don't get here in case precomp-sdh is called by WebServerDll, the code is not changed here and at the according free()-statement
   //if (! ads_trans->amc_aux(ads_trans->vpc_userfld, DEF_AUX_MEMGET, &ainf1, sizeof(INFILE))) {
       //return FALSE; // if this happens, it's an desaster...
   //}
   memset( ainf1, 0, sizeof(INFILE) );      /* clear all values        */
   ainf1->next = ainf2;
   /* process arguments                                                */
   auinpc = (unsigned char*)(wss.u.addr + 2);   // JF wss.u.addr + 2 -> (unsigned char*)(wss.u.addr + 2)   /* here starts line        */
   auinpe = auinpc + *((unsigned short *) wss.u.addr);
   if (ulSout) {
     ainf1->ifil = ulSout;
     if (ainf1->ifil > sizeof(ainf1->strlineinp))
       ainf1->ifil = sizeof(ainf1->strlineinp);
     memcpy( ainf1->strlineinp, strlineout, ainf1->ifil );
   }

   pmarg10:
   chu1 = ' ';
   while (chu1 == ' ') {                    /* Blanks am Anfang weg    */
     if (auinpc < auinpe) {                 /* not at end of arguments */
       chu1 = *auinpc++;                    /* get next character      */
     } else {
       chu1 = 0;
     }
   }
   memset( strsymbol, ' ', LENSYM );
   strsymbol[LENSYM] = 0;
   if (chu1 >= '0' && chu1 <= '9') {        /* nicht Ziffer am Anfang  */
       m_sdh_printf((char*)"%s: %ld/x macro argument number found - %c\n", "HPREE067E", ilinenr, chu1);
     goto pmarg40;
   }

   iu1 = 0;

   pmarg12:
   if (!chartab[chu1]) {
     goto pmarg14;
   }
   if (iu1 < LENSYM) strsymbol[iu1++] = chartab[chu1];
   if (auinpc < auinpe) {                   /* not at end of arguments */
     chu1 = *auinpc++;                      /* get next character      */
     goto pmarg12;
   }
   chu1 = 0;

   pmarg14:                                 /* argument found          */
   memcpy( wss.symbol, strsymbol, LENSYM );
   iuindma = 0;

   pmarg20:
   if (iuindma == sizeof(tabmarg) / sizeof(tabmarg[0])) {
       m_sdh_printf((char*)"%s: %ld/x macro argument type invalid - %s\n", "HPREE068E", ilinenr, strsymbol);
     goto pmarg40;
   }
   if (memcmp( wss.symbol, &tabmarg[iuindma].aname,
               sizeof(tabmarg[0].aname) )) {
     iuindma++;
     goto pmarg20;
   }
   if (chu1 != ':') {
       m_sdh_printf((char*)"%s: %ld/x after macro argument separator invalid / : / %c\n", "HPREE069E", ilinenr, chu1);
     goto pmarg40;
   }
   if (auinpc < auinpe) {                   /* not at end of arguments */
     chu1 = *auinpc++;                      /* get next character      */
   } else {                                 /* argument invalid        */
       m_sdh_printf((char*)"%s: %ld/x macro arguments too short\n", "HPREE070E", ilinenr);
     goto pmarg40;
   }
   if (chu1 >= '0' && chu1 <= '9') {        /* nicht Ziffer am Anfang  */
       m_sdh_printf((char*)"%s: %ld/x macro argument number found - %c\n", "HPREE071E", ilinenr, chu1);
     goto pmarg40;
   }

   memset( strsymbol, ' ', LENSYM );
   strsymbol[LENSYM] = 0;
   iu1 = 0;

   pmarg22:
   if (chu1 == ' ') {                       /* ignore blanks           */
     if (auinpc < auinpe) {                 /* not at end of arguments */
       chu1 = *auinpc++;                    /* get next character      */
       goto pmarg22;
     }
     chu1 = 0;
   }
   if (!chartab[chu1]) {
     goto pmarg24;
   }
   if (iu1 < LENSYM) strsymbol[iu1++] = chartab[chu1];
   if (auinpc < auinpe) {                   /* not at end of arguments */
     chu1 = *auinpc++;                      /* get next character      */
     goto pmarg22;
   }
   chu1 = 0;

   pmarg24:
   if ((chu1 != ',') && (chu1 != ')')) {
       m_sdh_printf((char*)"%s: %ld/x after macro variable separator invalid / , / ) / %c\n", "HPREE072E", ilinenr, chu1);
     goto pmarg40;
   }
   memcpy( wss.symbol, strsymbol, LENSYM );
   switch (iuindma) {
     case 0:                                /* MINT                    */
       if (!decstack( sizeof(wss.symbol), 1 )) return FALSE;
       memcpy( (PVOID) astack, &wss.symbol, sizeof(wss.symbol) );
       memset( &wss, 0, sizeof(DSYMBOL) );
       ch1 = ' ';
       ch_expr_end_search = ',';            /* expression end searched */
       if (!uausdr()) return FALSE;
       memcpy( wss.symbol, (PVOID) astack, sizeof(wss.symbol) );
       incstack( sizeof(wss.symbol), 1 );//astack += sizeof(wss.symbol);
       wss.modebsec = 0;
       wss.modebtex = 0;
       break;
     case 1:                                /* MTEXT                   */
       wss.u.addr = atextende;              /* store text variable     */
       while (TRUE) {                       /* remove blanks at begin  */
         if (ainf1->ifia >= ainf1->ifil) break;
         if (ainf1->strlineinp[ainf1->ifia] != ' ') break;
         ainf1->ifia++;
       }
       while(   (ainf1->ifia < ainf1->ifil)
             && (ainf1->strlineinp[ainf1->ifia] != ' ')
             && (ainf1->strlineinp[ainf1->ifia] != ',')
             && (ainf1->strlineinp[ainf1->ifia] != ')')) {
         if ((atextende + 1) >= astack) {
             m_sdh_printf((char*)"%s: %ld/x stack overflow - MTEXT - abend\n", "HPREE073E", ilinenr);
           return FALSE;
         }
         *((unsigned char *) atextende) = ainf1->strlineinp[ainf1->ifia];
         atextende++;
         ainf1->ifia++;
       }
       if (ainf1->ifia >= ainf1->ifil) {
           m_sdh_printf((char*)"%s: %ld/x macro arguments MTEXT invalid\n", "HPREE074E", ilinenr);
         goto pmarg40;
       }
       wss.modet2 = atextende - wss.u.addr;  /* set length             */
       wss.modebsec = 0;
       wss.modebtex = 1;
       break;
     case 2:                                /* MQUOTE                  */
       wss.u.addr = atextende;              /* store text variable     */
       while (TRUE) {                       /* remove blanks at begin  */
         if (ainf1->ifia >= ainf1->ifil) break;
         if (ainf1->strlineinp[ainf1->ifia] != ' ') break;
         ainf1->ifia++;
       }
       if (ainf1->ifia >= ainf1->ifil) {
           m_sdh_printf((char*)"%s: %ld/x macro arguments MQUOTE invalid\n", "HPREE075E", ilinenr);
         goto pmarg40;
       }
       if (ainf1->strlineinp[ainf1->ifia] != CHAR_QUOTE) {
           m_sdh_printf((char*)"%s: %ld/x macro arguments MQUOTE does not start correct %c\n", "HPREE076E", ilinenr, ainf1->strlineinp[ainf1->ifia]);
         goto pmarg40;
       }
       ainf1->ifia++;
       if (ainf1->ifia >= ainf1->ifil) {
           m_sdh_printf((char*)"%s: %ld/x macro arguments MQUOTE invalid\n", "HPREE077E", ilinenr);
         goto pmarg40;
       }
       bo_quote = FALSE;                    /* no quote found          */
       while (TRUE) {                       /* remove blanks at begin  */
         if (ainf1->ifia >= ainf1->ifil) break;
         if (ainf1->strlineinp[ainf1->ifia] == CHAR_QUOTE) {
           if (bo_quote) {
             if ((atextende + 1) > astack) {
             m_sdh_printf((char*)"%s: %ld/x stack overflow - MQUOTE - abend\n", "HPREE078E", ilinenr);
               return FALSE;
             }
             *((unsigned char *) atextende) = CHAR_QUOTE;
             atextende++;
             bo_quote = FALSE;
           } else {
             bo_quote = TRUE;
           }
         } else {
           if (bo_quote) break;
           if ((atextende + 1) > astack) {
               m_sdh_printf((char*)"%s: %ld/x stack overflow - MQUOTE - abend\n", "HPREE079E", ilinenr);
             return FALSE;
           }
           *((unsigned char *) atextende) = ainf1->strlineinp[ainf1->ifia];
           atextende++;
         }
         ainf1->ifia++;
       }
       if (ainf1->ifia >= ainf1->ifil) goto pmarg40;
       wss.modet2 = atextende - wss.u.addr;  /* set length             */
       wss.modebsec = 0;
       wss.modebtex = 1;
       break;
   }
   ch_symbol_scope = 'S';                   /* S = set macro           */
   if (!usymbein()) return FALSE;
   while (   (ainf1->ifia < ainf1->ifil)
          && (ainf1->strlineinp[ainf1->ifia] == ' '))
     ainf1->ifia++;
   if (iuindma != 0) {
     if (ainf1->ifia < ainf1->ifil) {
       ch_expr_end_found = ainf1->strlineinp[ainf1->ifia];
       ainf1->ifia++;
     } else {
       ch_expr_end_found = ' ';
     }
   } else {
     if (   (ch_expr_end_found == ' ')
         && (ainf1->ifia < ainf1->ifil))
     ch_expr_end_found = ainf1->strlineinp[ainf1->ifia];
   }
   if (chu1 == ',') {
     if (ainf1->ifia >= ainf1->ifil) {
         m_sdh_printf((char*)"%s: %ld/x macro arguments too short\n", "HPREE080E", ilinenr);
       goto pmarg40;
     }
     if (ch_expr_end_found != ',') {        /* expression end found    */
         m_sdh_printf((char*)"%s: %ld/x separator after macro arguments invalid %c\n", "HPREE081E", ilinenr, ch_expr_end_found);
       goto pmarg40;
     }
     goto pmarg10;
   }
   if (ch_expr_end_found != ')') {          /* expression end found    */
       m_sdh_printf((char*)"%s: %ld/x invalid end of macro arguments %c\n", "HPREE082E", ilinenr, ch_expr_end_found);
   }
   /* end of arguments                                                 */
   memcpy( &wss, (PVOID) (astack + iu_len_save_out), sizeof(DSYMBOL) );
   memmove( (PVOID) (astack + sizeof(DSYMBOL)), (PVOID) astack,
            iu_len_save_out );
   incstack( sizeof(DSYMBOL), 1 );//astack += sizeof(DSYMBOL);
   ainf1->ilnr = 0;                         /* is in first line        */
   ainf1->ifil = 0;                         /* noch nichts eingelesen  */
   ainf1->ifia = 0;
   ainf1->astorinps = (unsigned char*)wss.u.addr;  // JF (unsigned char*)         /* get address storage sta */
   ainf1->astorinpe = (unsigned char*)(wss.u.addr + wss.modet2);  // JF wss.u.addr + wss.modet2 -> (unsigned char*)(wss.u.addr + wss.modet2)  /* end-address         */
   ainf1->ch_flag_macro_rpt = 'M';          /* read from macro         */
   ainf1->astorinpc = auinpe;               /* get address storage sta */
   return TRUE;

   pmarg40:                                 /* invalid macro argument  */
   countif2 = 0;
   /* get ifs before                                                   */
   countif1 = *((int *) (astack + iu_len_save_out + sizeof(DSYMBOL)));
   kzifakt1 = *((unsigned char *) (astack + iu_len_save_out + sizeof(DSYMBOL) + 4));
   kzifakt2 = *((unsigned char *) (astack + iu_len_save_out + sizeof(DSYMBOL) + 5));
   memmove( (PVOID) (astack + sizeof(DSYMBOL) + 6), (PVOID) astack,
            iu_len_save_out );
   incstack( sizeof(DSYMBOL) + 6, 1 );//astack += sizeof(DSYMBOL) + 6;
   /* remove table for macro variables                                 */
   i1 = 4 + *((ULONG *) aanfsym) * sizeof(DSYMBOL);  /* to remove      */
   if (astack < aanfsym) {
     memmove( (PVOID) (astack + i1), (PVOID) astack,
              aanfsym - astack );
   }
   aanfsym += i1;
   memmove( (PVOID) (astack + i1), (PVOID) astack,
            iu_len_save_out );
   incstack( i1, 1 );//astack += i1;
   ainf2 = (INFILE*)ainf1->next; // JF (INFILE*)
   free( ainf1 );
   ainf1 = ainf2;
   return TRUE;
}

BOOL cPrecomp::usaveSout( void ) {             /* save previous output    */
   if (ul_Sout_save) {
     if (!decstack( ul_Sout_save, 1 )) return FALSE;
     memcpy( (void*)astack, strlineout, ul_Sout_save );   // JF (void*)
   }
   if (!decstack( sizeof(ULONG), 1 )) return FALSE;
   *((ULONG *) astack) = ul_Sout_save;      /* save length             */
   return TRUE;                             /* all done                */
}

// JF
//////BOOL cPrecomp::decstack( istsize )
//////   int istsize;
BOOL cPrecomp::decstack( int istsize, int inp_count )
{
   istsize = (istsize + (sizeof(void*)-1)) & (~(sizeof(void*)-1));
   istsize *= inp_count;

   astack -= istsize;
   if (astack >= atextende) return TRUE;
   m_sdh_printf((char*)"%s: %ld/%ld Variables memory not large enough - terminated\n", "HPREE083E", ilinenr, ainf1->ilnr);
   return FALSE;
}

BOOL cPrecomp::incstack( int inp_size, int inp_count )
{
   inp_size = (inp_size + (sizeof(void*)-1)) & (~(sizeof(void*)-1));
   inp_size *= inp_count;
   astack += inp_size;

   if ( astack < (ULONG)&chstack[0] ) {
       m_sdh_printf((char*)"%s: %ld/%ld incstack failed (line %d)\n", "HPREE883E", ilinenr, ainf1->ilnr, __LINE__ );
       return FALSE;
   }
   return TRUE;
}


void cPrecomp::m_dump_data(unsigned char* lpData, int nLen, FILE* fTrace) {

    if (in_flags == 0) {
        return;
    }

    char ch_line[100];
    int nCount = 0;
    ch_line[0] = 0;
    char temp[10];
    char ch_ascii[20];

    // JF 05.01.07 we support only 6-digit-counts; therefore limit the length
    if (nLen > 0xFFFFFF-1) {
        nLen = 0xFFFFFF-1;
        if (fTrace != NULL) {
            fprintf(fTrace, "DumpData was limited to 0xFFFFFF\n");
        }
        else {
            printf("DumpData was limited to 0xFFFFFF\n");
        }
    }

   for (int i=0; i < nLen; i++) {
       if (nCount == 0) {
           sprintf(ch_line, "%06X ", i);
           sprintf(ch_ascii, " -                 ");
       }

      // hex-output of data
      // decimal: sprintf(temp,"%03d ",lpData[i]);
#if defined HL_UNIX  // e.g. FF gets displayed as FFFFFFFF
      sprintf(temp,"%02X ",(lpData[i] & 0xFF));
#else      
      sprintf(temp,"%02X ",lpData[i]);
#endif

      ch_ascii[nCount+ 3]= lpData[i];
      if ( ((unsigned int)ch_ascii[nCount+3] < 0x20) || ((unsigned int)ch_ascii[nCount+3] > 0x7E) )
         ch_ascii[nCount+ 3]= '.';

      strcat(ch_line,temp);

       nCount++;

       if (nCount == 16) {
         strcat(ch_line, ch_ascii);
            if (fTrace != NULL) {
                fprintf(fTrace, "%s\n", ch_line);
            }
            else {
                m_sdh_printf((char*)"%s\n", ch_line);
            }
           nCount = 0;
           ch_line[0] = 0;
       }
   } // for

    // fill up a line which is not yet complete
   if(ch_line[0]) {
      for(;nCount < 16; nCount++)
         strcat(ch_line,"   "); // hex-output of data
         // decimal: strcat(szDump,"    ");
      strcat(ch_line, ch_ascii);
        if (fTrace != NULL) {
            fprintf(fTrace, "%s\n", ch_line);
        }
        else {            
            m_sdh_printf((char*)"%s\n", ch_line);
        }
   } // if(ch_line[0])

    // create space to next block of data
    if (fTrace != NULL) {
        fprintf(fTrace, "%s\n", " ");
    }
    else {
        m_sdh_printf((char*)"%s\n", " ");
    }
}

// subroutine for output to console
int cPrecomp::m_sdh_printf( char *achptext, ... ) {
    va_list dsl_argptr;
    char chrl_out1[512];
    va_start(dsl_argptr, achptext);
    int in_ret = vsnprintf(chrl_out1, sizeof(chrl_out1), achptext, dsl_argptr);
    va_end(dsl_argptr);

#ifndef WORK_AS_SDH
    printf(chrl_out1);
#else
    (*ads_trans->amc_aux) (ads_trans->vpc_userfld, DEF_AUX_CONSOLE_OUT, chrl_out1, in_ret);
#endif
   return in_ret;
} // end m_sdh_printf()



void cPrecomp::m_set_ppp_ineta(char* achl_ppp_ineta) {
    ach_ppp_ineta = achl_ppp_ineta;
}
char* cPrecomp::m_get_ppp_ineta() {
    if (ach_ppp_ineta == NULL) { // JF 07.10.08
        m_set_ppp_ineta(ach_empty_string);
    }
    return ach_ppp_ineta;
}

void cPrecomp::m_set_ppp_l2tp_arg(char* achl_ppp_l2tp_arg) {
    ach_ppp_l2tp_arg = achl_ppp_l2tp_arg;
}
char* cPrecomp::m_get_ppp_l2tp_arg() {
    if (ach_ppp_l2tp_arg == NULL) { // JF 07.10.08
        m_set_ppp_l2tp_arg(ach_empty_string);
    }
    return ach_ppp_l2tp_arg;
}

void cPrecomp::m_set_ppp_socks_mode(char* achl_ppp_socks_mode) {
    ach_ppp_socks_mode = achl_ppp_socks_mode;
}
char* cPrecomp::m_get_ppp_socks_mode() {
    if (ach_ppp_socks_mode == NULL) { // JF 07.10.08
        m_set_ppp_socks_mode(ach_empty_string);
    }
    return ach_ppp_socks_mode;
}

void cPrecomp::m_set_ppp_localhost(char* achl_ppp_localhost) {
    ach_ppp_localhost = achl_ppp_localhost;
}
char* cPrecomp::m_get_ppp_localhost() {
     if (ach_ppp_localhost == NULL) { // JF 07.10.08
         m_set_ppp_localhost(ach_empty_string);
     }
    return ach_ppp_localhost;
}

// JF 27.11.08 Ticket[16598]
void cPrecomp::m_set_ppp_unix_parameter(char* achl_ppp_unix_parameter) {
    ach_ppp_unix_parameter = achl_ppp_unix_parameter;
}
char* cPrecomp::m_get_ppp_unix_parameter() {
     if (ach_ppp_unix_parameter == NULL) {
         m_set_ppp_unix_parameter(ach_empty_string);
     }
    return ach_ppp_unix_parameter;
}


void cPrecomp::m_set_ppp_system_parameter(char* achl_ppp_system_parameter) {
	ach_ppp_system_parameter = achl_ppp_system_parameter;
}
char* cPrecomp::m_get_ppp_system_parameter() {
	 if (ach_ppp_system_parameter == NULL) {
		 m_set_ppp_system_parameter(ach_empty_string);
	 }
	return ach_ppp_system_parameter;
}

