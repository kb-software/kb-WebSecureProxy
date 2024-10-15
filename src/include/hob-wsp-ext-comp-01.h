/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| FILE NAME: hob-wsp-ext-comp-01.h                                  |*/
/*| ----------                                                        |*/
/*|  Header-File for Usage of External Components of the HOB WSP      |*/
/*|    WebSecureProxy                                                 |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|  Copyright (C) HOB Germany 2017                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/**
   The structure struct dsd_webterm_dod_info
   is immediately followed by the INETA, length imc_len_str,
   in character-set ied_chs_idna_1 - IDNA RFC 3492 etc. - Punycode
*/

struct dsd_webterm_dod_info
{
      int             imc_len_str; // length string elements
      int             imc_port;
      BOOL            boc_with_macaddr;  /* macaddr is included */
      char            chrc_macaddr[6];
      int             imc_waitconn;
};

#ifdef HL_EXTERNAL_COMPONENT
/*
   structure for users of configuration.
   storage following this structure:
   1.  User-Name           WCHAR zero-terminated
   2.  Password            UTF-8
   3.  INETA-target        IDNA zero-terminated
   4.  INETA-SIP-gw        IPV4 = 4 / IPV6 = 16
   7.  SIP Fullname        UTF-8
   8.  SIP Ident           UTF-8
   9.  SIP display-number  UTF-8
   10. SIP shared secret   UTF-8
*/
struct dsd_user_entry {                     /* structure user entry    */
   struct dsd_user_entry *adsc_next;        /* chain                   */
   int        inc_len_name_bytes;           /* length of name in bytes */
   int        inc_len_password_bytes;       /* len of password in bytes */
   int        inc_len_target_bytes;         /* len of target in bytes  */
   char       chrc_priv[ (DEF_PERS_PRIV_LEN + 8 - 1) / 8 ];  /* privileges */
   UNSIG_MED  umc_out_ineta;                /* IP address multihomed   */
   BOOL       boc_with_target;              /* target is included      */
   int        inc_port_target;              /* target port             */
   BOOL       boc_with_macaddr;             /* macaddr is included     */
   char       chrc_macaddr[6];              /* macaddr switch on       */
   int        inc_waitconn;                 /* wait for connect compl  */
   int        imc_len_ineta_sip_gw;         /* length INETA SIP Gateway */
   int        imc_len_sip_fullname;         /* length SIP fullname     */
   int        imc_len_sip_ident;            /* length SIP ident        */
   int        imc_len_sip_display_number;   /* length SIP display-number */
   int        imc_len_sip_shase;            /* length SIP shared secret */
   char       *achc_password;               /* address of password     */
   char       *achc_target;                 /* address of target - INETA Desktop-on-Demand */
   char       *achc_ineta_sip_gw;           /* address of INETA SIP Gateway */
   char       *achc_sip_fullname;           /* address of SIP fullname */
   char       *achc_sip_ident;              /* address of SIP ident    */
   char       *achc_sip_display_number;     /* address of SIP display-number */
   char       *achc_sip_shase;              /* address of SIP shared secret */
#ifdef NEW_1406
   struct dsd_unicode_string dsc_e_mail;    /* unicode string e-mail address */
   struct dsd_unicode_string dsc_aux_1;     /* unicode string auxiliary field 1 */
#endif
   struct dsd_config_ineta_1 *adsc_config_ineta_1_ppp;  /* configured INETA PPP */
   struct dsd_config_ineta_1 *adsc_config_ineta_1_appl;  /* configured INETA appl */
};
#endif
