/**
 * HEADER NAME:  hob_errlist.h
 *
 * This include file contains the structure declaration 'dsd_error{}'.
 * 
 * Comment:  For LDAP-definitions look at 'ds_ldap_errlist{}' 
 *
 * Copyright (C) HOB GmbH&Co. KG, Germany 2007
 *
 * @version  1.01
 * @author   Juergen-Lorenz Lauenstein
 * @date     2007/08/02
 */
#ifndef _hob_errlist_H
#define _hob_errlist_H


#define MIN_ERRMSG_LEN  160
#define MAX_ERRMSG_LEN  1024
   
// class dsd_ldap_cl;
extern "C" char  *m_inet_ntoa( struct sockaddr_storage * );
extern "C" void  *m_hl_memcpy( void *, const void *, size_t );

   
   
struct dsd_error
{
    char  ch_type;           // ("I")information, ("W")warning, ("E")error
	int	  im_resultCode;     // LDAP result code
	int   im_apicode;        // return code of other (external) APIs
	char *ach_matchedDN;     // copy of the LDAP DN-directory the error occured 
	char *ach_errMessage;    // pointer to the default error string 
    char *ach_ldapMessage;   // copy of the error string sent by the ldap server
protected:
    static struct dsd_error *ads_etab;
    
    // Functions for error message handling...
public:
   /**
    * dsd_error::m_init()
    *
    * Initializes the error structure.
    */
    void m_init()
    {
      this->ch_type         = ads_etab[0].ch_type;
      this->im_resultCode   = ads_etab[0].im_resultCode;
      this->im_apicode      = ads_etab[0].im_apicode;
      this->ach_matchedDN   = ads_etab[0].ach_matchedDN;
      this->ach_errMessage  = ads_etab[0].ach_errMessage;
      this->ach_ldapMessage = ads_etab[0].ach_ldapMessage;
    } // dsd_error::m_init()
    
   /**
    * dsd_error::m_format_msg()
    *
    * Formats a printable error message string. A minimum size of MIN_ERRMSG_LEN is required.
    *
    * @param [in,out] char                    *achp_msg    message string to print in
    * @param [in]     int                      inp_len     maximum string length
    * @param [in]     struct sockaddr_storage *adsp_conn   LDAP server ip-address
    * @param [in]     char                    *achrp_port  LDAP server ip-port    
    * 
    * @return         int   number of bytes printed or 0 if error
    */
    size_t m_format_msg( char *achp_msg, int imp_len, struct sockaddr_storage *adsp_conn, char *achrp_port )
    { 
      bool  bol_1;
      int   iml_1  = 0;
      char  chl_1  = this->ch_type;
      char *achl_1 = this->ach_ldapMessage;
      
      // valid parameter ?
      if (achp_msg && (imp_len >= MIN_ERRMSG_LEN && imp_len <= MAX_ERRMSG_LEN))
      { // search type and default message string...
        for (iml_1=0,bol_1=false; ads_etab[iml_1].ch_type != '?'; iml_1++)
        {  
           if (ads_etab[iml_1].im_resultCode == this->im_resultCode)
           { // fill members...
             if (!achl_1)
               achl_1 = ads_etab[iml_1].ach_errMessage;
             chl_1 = ads_etab[iml_1].ch_type;  
             bol_1 = true;
             break;
           }  
        } // end for() 
        
        if (bol_1 == FALSE)
          // set default error...
          achl_1 = "Unknown error";

        // message (LDAP<resultcode><type> (<ipaddr>:<ipport>) <message(apicode)> (<message(resultcode)>, DN:<matchedDN>)
        extern const char *m_hl_inet_ntop( int /*family*/, const void * /*src*/, char * /*dest*/, size_t /*cnt*/ );
        iml_1 = ::m_hlsnprintf( (void *)achp_msg, imp_len, ied_chs_utf_8, 
                                "LDAP%04d%c (%s:%s)  %s (%s, DN: %s)", 
                                this->im_resultCode, chl_1, "172.22.70.150" /*m_hl_inet_ntop( adsp_conn )*/, achrp_port, this->ach_errMessage, 
                                achl_1, (this->ach_matchedDN) ? this->ach_matchedDN : "none" );
      }
      return iml_1;
    } // dsd_error::m_format_msg()
   
   /**
    * dsd_error::m_get_error()
    *
    * Returns the last error code.
    *
    * @return   int   last error code
    */
    int m_get_error()  { return this->im_apicode; } 
    
   /**
    * dsd_error::m_reset()
    *
    * Resets the last error code and frees allocated storage.
    */
    void  m_reset()
    {  
      // free allocated storage...
      if (this->ach_matchedDN)    delete this->ach_matchedDN;
      if (this->ach_ldapMessage)  delete this->ach_ldapMessage;
         
      this->ch_type         = ads_etab[0].ch_type;
      this->im_resultCode   = ads_etab[0].im_resultCode;
      this->im_apicode      = ads_etab[0].im_apicode;
      this->ach_matchedDN   = ads_etab[0].ach_matchedDN;
      this->ach_errMessage  = ads_etab[0].ach_errMessage;
      this->ach_ldapMessage = ads_etab[0].ach_ldapMessage;
      return;
    } // dsd_error::m_error_reset()  
    
   /**
    * dsd_error::m_set_apicode()
    *
    * Sets the LDAP returned apicode.
    *
    * @param [in]  int imp_apicode   API error code 
    */
    void m_set_apicode( int imp_apicode )  
    { 
      int  iml_1;
      bool bol_1;
      
      this->im_apicode = imp_apicode; 
      // search type and default message string...
      for (iml_1=0,bol_1=false; ads_etab[iml_1].ch_type != '?'; iml_1++)
      {  if (ads_etab[iml_1].im_resultCode == this->im_apicode)
         { // fill members...
           this->ch_type = ads_etab[iml_1].ch_type;
           this->ach_errMessage = ads_etab[iml_1].ach_errMessage;
           bol_1 = true;
           break;
         }  
      } // end for() 
      
      if (bol_1 == FALSE)
      { // set default error...
        this->ch_type = 'I';
        this->ach_errMessage = "Unknown error";
      }
        
    } // dsd_error::m_set_apicode() 

    /**
    * dsd_error::m_set_error()
    *
    * Registers the last result code and any associated strings, if an error has occured.
    *
    * Comment:   LDAPResult ::= SEQUENCE { resultCode      ENUMERATED {...}
    *                                      matchedDN       LDAPDN,
    *                                      errorMessage    LDAPString,
    *                                      referral        [3] Referral OPTIONAL 
    *                                    }
    *
    * @param [in]  int   inp_resultCode      LDAP result code (ENUMERATED {...})
    * @param [in]  int   inp_apicode         optional: API error code 
    * @param [in]  char *achp_matchedDN      optional: (R)DN of the error
    * @param [in]  int   inp_len_matchedDN   optional: (R)DN length    
    * @param [in]  char *achp_ldapMessage    optional: error message (sent by LDAP)
    * @param [in]  int   inp_len_ldapMessage optional: error message length
    */
    void m_set_error( int   imp_resultCode, 
                      int   imp_apicode         = -1, 
                      char *achp_matchedDN      = NULL,
                      int   imp_len_matchedDN   = 0,
                      char *achp_ldapMessage    = NULL,
                      int   imp_len_ldapMessage = 0 )
    { 
      int  iml_1;
      bool bol_1; 
      
      // delete old allocated strings...
      if (this->ach_matchedDN)    delete this->ach_matchedDN;      
      if (this->ach_ldapMessage)  delete this->ach_ldapMessage;   
      
      // save LDAP result code  
      this->im_resultCode   = imp_resultCode;
      this->im_apicode      = imp_apicode;
      this->ach_matchedDN   = NULL;
      this->ach_ldapMessage = NULL;
      
      if (achp_matchedDN && imp_len_matchedDN)
      { // save (R)DN string...
        this->ach_matchedDN = new char[imp_len_matchedDN+1];
        ::m_hl_memcpy( (void *)this->ach_matchedDN, (const void *)achp_matchedDN, (size_t)imp_len_matchedDN );
        this->ach_matchedDN[imp_len_matchedDN] = '\0';
      }  
      if (achp_ldapMessage)
      { // save LDAP error message...
        this->ach_ldapMessage = new char[imp_len_ldapMessage+1];
        ::m_hl_memcpy( (void *)this->ach_ldapMessage, (const void *)achp_ldapMessage, (size_t)imp_len_ldapMessage );
        this->ach_ldapMessage[imp_len_ldapMessage] = '\0';
      }
      
      // search type and default message string...
      for (iml_1=0,bol_1=false; ads_etab[iml_1].ch_type != '?'; iml_1++)
      {  
         if (ads_etab[iml_1].im_resultCode == this->im_apicode)
         { // fill members...
           this->ch_type = ads_etab[iml_1].ch_type;
           this->ach_errMessage = ads_etab[iml_1].ach_errMessage;
           bol_1 = true;
           break;
         }  
      } // end for() 
      
      if (bol_1 == FALSE)
      { // set default error...
        this->ch_type = 'I';
        this->ach_errMessage = "Unknown error";
      }
      return;
    } // dsd_error::m_error_set()
    
}; // struct dsd_error

#endif /* _hob_errlist_H */
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
// end of 'hob_errlist.hpp'
/////////////////////////////////////////////////////////////////////////////////////////////////////////////
