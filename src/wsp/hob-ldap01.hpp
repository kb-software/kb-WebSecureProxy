/**
 * Header file: hob-ldap01.hpp
 * 
 * class dsd_ldap definitions (used by LDAP and other ASN.1 coded programs)
 * 
 * Required programs:
 * MS Visual Studio .NET 2005, 2010 or 2012
 * MS Linker
 * 
 * Copyright (C) HOB Germany 2005-2015                  
 *                                    
 * @version 1.05                                          
 * @author  Juergen-Lorenz Lauenstein                         
 * @date    2005/08/16   (creation)
 * @date    2013/07/02   
 * @date    2015/01/26 
 * @date    2015/02/27   (last changes)    
 *
 */
#ifndef _hob_ldap_H
#define _hob_ldap_H


#define LDAP_VERSION_3      3    /**< this client requires LDAPv3 */
#define LDAP_VERSION_3_S   "3"   

#define SM_BUGFIX_20140724  1
#define SM_BUGFIX_20140804  1

/// internal hob storage definitions...
extern "C" void   m_aux_stor_start( void ** );
extern "C" void  *m_aux_stor_alloc( void **, int );
extern "C" void   m_aux_stor_free( void **, void * );
extern "C" void  *m_aux_stor_realloc( void **, void *, int );
extern "C" void   m_aux_stor_end( void ** );

extern "C" int    m_hl_inet_ntop( struct sockaddr_storage *, char *, int );


/// macro definitions
#define _iscomma(c)    ((c) == ',')
#define _ishex(c)      (isdigit(c) || ((c) >= 'a' && (c) <= 'f') || ((c) >= 'A' && (c) <= 'F'))


#define START_MEM(a)         if(a) m_aux_stor_end(&a);   m_aux_stor_start(&a); 
#define END_MEM(a)           if(a) m_aux_stor_end(&a);          a = NULL;  
#define FREE_MEM(a,b)        if(a && b) m_aux_stor_free(&a,b);  b = NULL;  
#define GET_MEM_CHAR(a,b,c)  \
                             b = (char *)(b ? m_aux_stor_realloc(&a,b,c) : m_aux_stor_alloc(&a,c)); 

#define LDAP_REQ_STRUC(a)    struct dsd_co_ldap_1  a;   \
                             memset((void *)&a, int(0), sizeof(struct dsd_co_ldap_1)); 


#ifndef EOPNOTSUPP   
#define EOPNOTSUPP    44
#endif
#ifndef EAFNOSUPPORT
#define EAFNOSUPPORT  47
#endif
#ifndef ENOBUFS
#define ENOBUFS       55
#endif


/* ---------------------------------------------------------------------------------- */
#define LDAPREQ_INIT(a)      (a).imc_msgid    = this->m_get_msgid();    \
                             (a).ac_req       = "";                     \
                             (a).imc_resp[1]  = LDAP_RESP_EXTENDED;     \
                             (a).imc_resp[2]  =                         \
                             (a).imc_resp[3]  = LDAP_RESP_NONE;         \
                             (a).imc_l_status = dsd_ldap::dsd_ldapreq::REQ_BUILDING;
/* ---------------------------------------------------------------------------------- */
#define LDAPREQ_ABANDON(a)   LDAPREQ_INIT((a))                          \
                             (a).imc_req     = LDAP_REQ_ABANDON;        \
                             (a).ac_req      = "Abandon";               \
                             (a).imc_resp[0] = LDAP_RESP_EXTENDED;      \
                             (a).imc_resp[1] = LDAP_RESP_NONE;
/* ---------------------------------------------------------------------------------- */
#define LDAPREQ_ADD(a)       LDAPREQ_INIT((a))                          \
                             (a).imc_req     = LDAP_REQ_ADD;            \
                             (a).ac_req      = "Add";                   \
                             (a).imc_resp[0] = LDAP_RESP_ADD;
/* ---------------------------------------------------------------------------------- */
#define LDAPREQ_BIND(a)      LDAPREQ_INIT((a))                          \
                             (a).imc_req     = LDAP_REQ_BIND;           \
                             (a).ac_req      = "Bind";                  \
                             (a).imc_resp[0] = LDAP_RESP_BIND;
/* ---------------------------------------------------------------------------------- */
#define LDAPREQ_COMPARE(a)   LDAPREQ_INIT((a))                          \
                             (a).imc_req     = LDAP_REQ_COMPARE;        \
                             (a).ac_req      = "Compare";               \
                             (a).imc_resp[0] = LDAP_RESP_COMPARE;
/* ---------------------------------------------------------------------------------- */
#define LDAPREQ_DELETE(a)    LDAPREQ_INIT((a))                          \
                             (a).imc_req     = LDAP_REQ_DELETE;         \
                             (a).ac_req      = "Delete";                \
                             (a).imc_resp[0] = LDAP_RESP_DELETE;
/* ---------------------------------------------------------------------------------- */
#define LDAPREQ_MODIFY(a)    LDAPREQ_INIT((a))                          \
                             (a).imc_req     = LDAP_REQ_MODIFY;         \
                             (a).ac_req      = "Modify";                \
                             (a).imc_resp[0] = LDAP_RESP_MODIFY;
/* ---------------------------------------------------------------------------------- */
#define LDAPREQ_MODIFYDN(a)  LDAPREQ_INIT((a))                          \
                             (a).imc_req     = LDAP_REQ_MODDN;          \
                             (a).ac_req      = "ModifyDN";              \
                             (a).imc_resp[0] = LDAP_RESP_MODDN;
/* ---------------------------------------------------------------------------------- */
#define LDAPREQ_SEARCH(a)    LDAPREQ_INIT((a))                          \
                             (a).imc_req     = LDAP_REQ_SEARCH;         \
                             (a).ac_req      = "Search";                \
                             (a).imc_resp[0] = LDAP_RESP_SEARCH_ENTRY;  \
                             (a).imc_resp[1] = LDAP_RESP_SEARCH_DONE;   \
                             (a).imc_resp[2] = LDAP_RESP_SEARCH_REF;    \
                             (a).imc_resp[3] = LDAP_RESP_EXTENDED;
/* ---------------------------------------------------------------------------------- */
#define LDAPREQ_UNBIND(a)    LDAPREQ_INIT((a))                          \
                             (a).imc_req     = LDAP_REQ_UNBIND;         \
                             (a).ac_req      = "Unbind";                \
                             (a).imc_resp[0] = LDAP_RESP_EXTENDED;      \
                             (a).imc_resp[1] = LDAP_RESP_NONE;
/* ---------------------------------------------------------------------------------- */
#define LDAPREQ_PWMOD_EX(a)  LDAPREQ_INIT((a))                          \
                             (a).imc_req     = LDAP_REQ_EXTENDED;       \
                             (a).ac_req      = "Modify PasswordEx";     \
                             (a).imc_resp[0] = LDAP_RESP_EXTENDED;      \
                             (a).imc_resp[1] = LDAP_RESP_NONE;
/* ---------------------------------------------------------------------------------- */

#define BIND_WITH_DN()       { struct dsd_co_ldap_1  bind;                               \
                               memset( (void *)&bind, 0, sizeof(struct dsd_co_ldap_1) ); \
                               bind.iec_co_ldap    = ied_co_ldap_bind;                   \
                               bind.iec_ldap_auth  = ied_auth_dn;                        \
                               bind.iec_chs_userid = ied_chs_utf_8;                      \
                               bind.ac_userid      = this->achr_dn;                      \
                               bind.imc_len_userid = this->im_len_dn;                    \
                               bind.iec_chs_passwd = ied_chs_utf_8;                      \
                               bind.ac_passwd      = this->achr_pwd;                     \
                               bind.imc_len_passwd = this->im_len_pwd;                   \
                                                                                         \
                               int rc = this->m_ldap_bind( &bind );                      \
                                                                                         \
                               if (rc != ied_ldap_success)                               \
                                 return rc;                                              \
                             }

/* -------------------------------------------------------------------------------------*/                             

/** modify operations */
enum ied_ldap_mod_def
{
   ied_ldap_mod_add = 0, 
   ied_ldap_mod_delete,
   ied_ldap_mod_replace,
   ied_ldap_mod_undef = -1
};

/** ldap attribute type */
enum ied_ldap_attr_def
{
   ied_ldap_attr_undef = 0,
   ied_ldap_attr_single,
   ied_ldap_attr_multi
};

/*
 * structure representing an ldap session which can
 * encompass connections to multiple servers (in the
 * face of referrals).
 */
#define LDAP_DEREF_NEVER		0x00
#define LDAP_DEREF_SEARCHING	0x01
#define LDAP_DEREF_FINDING		0x02
#define LDAP_DEREF_ALWAYS		0x03

// default LDAP configuration parameters
#define D_LDAP_PORT	        389	 /**< default LDAP port           */
#define D_LDAPS_PORT	    636	 /**< default LDAP over TLS port  */
#define D_LDAP_GLOBAL_CAT  3268  /**< LDAP Global Catalog port    */ 

#define D_LDAP_OUT_INETA      0
#define D_LDAP_DN             "root"
#define D_LDAP_PASSWORD       "anonymous"
#define D_LDAP_SEARCH_TO      0
#define D_LDAP_TL_SIZE        10       // minimum size for an asn.1-TLV-format (replaces the value: 2)
#define D_LDAP_RBUF_SIZE      4096     // internal receive buffer size (should we increase this value ?)
#define D_LDAP_RBUF_MAXSIZE   0        // max. receive buffer size (e.g. 1MB, 0: no limitation)
#define D_LDAP_WAIT_RETRY     0
#define D_LDAP_MAX_SESSION    200
#define D_LDAP_SSL_BUFFER_LEN 16384
#define D_LDAP_PAGE_SIZE      200

#define D_LDAP_MAX_STRLEN     4096     // maximum string length for 'strn...'-functions


#if defined WIN32 || defined WIN64
  #define D_LDAP_WAIT         10*1000  // 10s 
#else
  #define D_LDAP_WAIT         10*1000  // 10s 
#endif
#ifdef _DEBUG
  #undef D_LDAP_WAIT
  #define D_LDAP_WAIT         -1       // infinite 
#endif

class dsd_bufm               /// C++ - LDAP buffer management class
{
public:
   int      imc_buflen;      ///< maximum internal or extended buffer length
   int      imc_datalen;     ///< actual length of received data (written by tcpcomp)
   int      imc_datalen_s;   ///< saved length of received data
   int      imc_pos;         ///< actual receive buffer address 
   int      imc_nextpos;     ///< position of the next ldap response 
protected:   
   //void    *avoc_hl_stor;    ///< internal hob storage handler 
   BOOL     boc_ext;         ///< TRUE: external buffer in use
   char    *achc_buf_ext;    ///< allocated extended buffer address 
   char     chrc_buf[D_LDAP_RBUF_SIZE]; ///< internal buffer

   void m_reset_buf() {
        this->achc_buf_ext = this->chrc_buf;     
        this->boc_ext      = FALSE;
		this->imc_buflen   = D_LDAP_RBUF_SIZE;
   }

public:
   
   void *m_init( void **avop_hl_stor /** storage handler */, int imp_len = 0 /** storage length */ )   ///< constructor
   {  
      this->imc_datalen  = imc_datalen_s = imc_pos = imc_nextpos = 0;
      
      //this->avoc_hl_stor = avop_hl_stor;
      
      if (imp_len > sizeof(this->chrc_buf))
      { // allocate external buffer...
        this->achc_buf_ext = (char *)m_aux_stor_alloc( avop_hl_stor, imp_len );
        this->boc_ext = TRUE;
		this->imc_buflen   = imp_len; 
        return this->achc_buf_ext;  
      }

      // use internal buffer ...
      this->m_reset_buf();
      return this->chrc_buf;  
      
   }; // m_init()
   
   
   void m_free(void **avop_hl_stor)   ///< destructor
   {
      this->imc_datalen = this->imc_datalen_s = this->imc_pos = this->imc_nextpos = 0;
      
      if (this->boc_ext == TRUE && this->achc_buf_ext != NULL)
        // free external storage...
        m_aux_stor_free(avop_hl_stor, this->achc_buf_ext);
       
      this->m_reset_buf();
		//this->avoc_hl_stor = NULL;

   }; // m_free()  


   void m_clear()  ///< clear buffer...
   {
      this->imc_datalen = this->imc_datalen_s = this->imc_pos = this->imc_nextpos = 0;
   }; // m_clear()  

   
   void *m_alloc( void **avop_hl_stor, int imp_len )  
   { 
      this->imc_datalen = this->imc_pos = 0;

	  if (imp_len <= this->imc_buflen)
      { // we use the internal buffer
		  return this->achc_buf_ext;  
      }  
      // we have to use an external allocated buffer 
      return this->m_realloc( avop_hl_stor, imp_len );
      
   }; // m_alloc()  

   bool m_ensure_capacity(void **avop_hl_stor, int imp_len) {
	   int iml_valid_rest = this->imc_pos - this->imc_nextpos;
	   if(iml_valid_rest <= 0) {
			this->imc_nextpos = 0;
			this->imc_pos = 0;
	   }
	   else if(iml_valid_rest < this->imc_nextpos) {
		   char* achl_buf = (char*)this->m_get_bufaddr();
		   memcpy(achl_buf, achl_buf + this->imc_nextpos, iml_valid_rest);
		   this->imc_nextpos = 0;
		   this->imc_pos = iml_valid_rest;
	   }
	   int iml_buf_rest = this->imc_buflen - this->imc_pos;
	   if(iml_buf_rest < imp_len) {
		   char* achl_buf = (char*)this->m_get_bufaddr();
		   int iml_buflen_new = this->imc_pos + imp_len;
		   char* achl_buf_new = (char *)m_aux_stor_alloc( avop_hl_stor, iml_buflen_new );
		   if(achl_buf_new == NULL)
			   return false;
		   memcpy(achl_buf_new, achl_buf + this->imc_nextpos, iml_valid_rest);
           m_free(avop_hl_stor);
		   this->boc_ext = TRUE;
		   this->imc_nextpos = 0;
		   this->imc_pos = iml_valid_rest;
		   this->achc_buf_ext = achl_buf_new;
		   this->imc_buflen = iml_buflen_new;  // set new buffer length...
	   }
	   return true;
   }
   
   void *m_realloc( void **avop_hl_stor, int imp_len )        
   {
	  if (imp_len <= this->imc_buflen)
      { // we use the internal buffer
		  return this->achc_buf_ext;  
      }  
      //char *al_buf = this->achc_buf_ext;
	  int iml_buflen = this->imc_buflen;
	  /*
      if (imp_len<=this->imc_buflen)
	  {
		  return al_buf;
	  }
	  */
      this->imc_buflen = imp_len;  // set new buffer length...
 
      if (this->boc_ext == TRUE)
          // we use already an external buffer
          this->achc_buf_ext = (char *)m_aux_stor_realloc( avop_hl_stor, this->achc_buf_ext, imp_len );
      else
      { // it's the first that we use an external buffer
          this->boc_ext = TRUE;
          this->achc_buf_ext = (char *)m_aux_stor_alloc( avop_hl_stor, imp_len );
          // transfer data to external buffer
          if (this->imc_pos)
            memcpy( (void *)this->achc_buf_ext, (const void *)this->chrc_buf, size_t(this->imc_pos) );
      }
      return this->achc_buf_ext;
   }; // m_realloc()        
   
        
   void *m_get_bufaddr()  
   { 
      return this->achc_buf_ext;         

   }; // m_get_bufaddr()    
       
};  // end of 'class dsd_bufm'



/**
 * This includes the structure declaration 'dsd_error{}'.
 * 
 * Comment:  For LDAP-definitions look at 'ds_ldap_errlist{}' 
 *
 * Copyright (C) HOB GmbH&Co. KG, Germany 2007-2014
 *
 * @version  1.01
 * @author   Juergen-Lorenz Lauenstein
 * @date     2007/08/02
 */
struct dsd_error
{
#define HL_ERRMSG_LEN  384

    char  ch_type;           ///< ("I")information, ("W")warning, ("E")error
	int	  im_result_code;    ///< LDAP result code
	const char *ach_err_msg; ///< pointer to the default error string 
public:
	int   im_apicode;        ///< return code of other (external) APIs
	char *ach_matched_dn;    ///< copy of the LDAP DN-directory the error occurred 
    char *ach_ldap_msg;      ///< copy of the error string sent by the ldap server

    void *ads_hl_stor;       ///< internal hob permanent storage handle
	BOOL  bo_alloc_dn;       ///< TRUE: external (allocated) dn-string
    BOOL  bo_alloc_msg;      ///< TRUE: external (allocated) message
    struct sockaddr_storage ds_conn; ///< ineta
    char  chr_ineta[64];             ///< "ineta"
protected:
    static struct dsd_error *ads_etab;

    
    // Functions for error message handling...
public:
   /**
    * dsd_error::m_init()
    *
    * Initializes the error structure.
    *
    * @param[in]  adsp_hl_stor    hob internal storage handler
    *
    */
    void m_init( void *adsp_hl_stor )
    {
      this->ch_type        = ads_etab[0].ch_type;
      this->im_result_code = ads_etab[0].im_result_code;
      this->ach_err_msg    = ads_etab[0].ach_err_msg;

      this->im_apicode = 0;
      this->ach_matched_dn = this->ach_ldap_msg = NULL;

      this->bo_alloc_msg = FALSE;
      this->bo_alloc_dn  = FALSE;
      this->ads_hl_stor  = adsp_hl_stor;
      
      memset( (void *)&this->ds_conn, int(0), sizeof(struct sockaddr_storage) );
 
    } // dsd_error::m_init()
    
   
   /**
    * dsd_error::m_format_msg()
    *
    * Formats a printable error message string. A minimum size of MIN_ERRMSG_LEN is required.
    *
    * @param[in,out]  achp_msg    message string to print in
    * @param[in]      imp_len     maximum string length 
    * @param[in]      adsp_conn   LDAP socket address information
    * @param[in]      imp_port    LDAP socket port
    * 
    * @return         number of bytes printed or 0 if error
    */
    size_t m_format_msg( char *achp_msg, int imp_len, 
                         struct sockaddr_storage *adsp_conn = NULL, int imp_port = 0 )
    { 
      int   iml_1 (0);
      
      // valid parameter ?
      if (achp_msg)
      { // search type and default message string...
        BOOL  bol_1 (FALSE);
        char  chl_1 (this->ch_type);
        char *achl_1 (this->ach_ldap_msg);

        for (iml_1=0; ads_etab[iml_1].ch_type != '?'; iml_1++)
        {  
           if (ads_etab[iml_1].im_result_code == this->im_result_code)
           { // fill members...
             if (!achl_1)
               achl_1 = (char *)ads_etab[iml_1].ach_err_msg;
             chl_1 = ads_etab[iml_1].ch_type;  
             bol_1 = TRUE;
             break;
           }  
        } // end for() 
        
        if (bol_1 == FALSE)
          // set default error...
          achl_1 = (char *)"Unknown error";

        // message (LDAP<resultcode><type> (<ipaddr>:<ipport>) <message(apicode)> (<message(resultcode)>, DN:<matchedDN>)
        if (adsp_conn)
        { // convert ip-address, if not yet or if the address has changed
          if (memcmp( &this->ds_conn, adsp_conn, sizeof(struct sockaddr_storage) ))
          { // convert the new address...
            memcpy( &this->ds_conn, adsp_conn, sizeof(struct sockaddr_storage) );
            // set the ip-address as a string...
            m_hl_inet_ntop( adsp_conn, this->chr_ineta, sizeof(this->chr_ineta) );
          }
          // format output string...
          iml_1 = m_hlsnprintf( (void *)achp_msg, imp_len, ied_chs_utf_8, "LDAP%04d%c (%s:%i)  %s (%s, DN: %s)", 
                                  this->im_result_code, chl_1 /* type: I,W,E */, this->chr_ineta, imp_port, 
                                  this->ach_err_msg, achl_1, this->ach_matched_dn ? this->ach_matched_dn : "none" );
           // check for a buffer overrun
           if (iml_1 < 0) 
           { // shorten the string... 
             iml_1 = imp_len;        
             achp_msg[imp_len - 1] = '\0';
           }                         
        }                                            
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
    int m_get_error()  
    { 
       return this->im_apicode; 
    } // dsd_error::m_get_error() 
   
    
   /**
    * dsd_error::m_get_errormsg()
    *
    * Returns the error message string for a given error number.
    *
    * @param[in]  imp_err    error 
    *
    * @return     error message
    */
    char *m_get_errormsg(int imp_err)
    {
       for (int iml_1=0; ads_etab[iml_1].ch_type != '?'; iml_1++)
       {  
          if (ads_etab[iml_1].im_result_code == imp_err)
            return (char *)ads_etab[iml_1].ach_err_msg;
       } 

       return (char *)"Unknown error";
           
    } // dsd_error::m_get_errormsg()
    
     
   /**
    * dsd_error::m_free()
    *
    * Resets the last error code and frees allocated storage.
    */
    void  m_free()
    {  
      // free allocated storage...
      if (this->ach_matched_dn && this->bo_alloc_dn) 
      { m_aux_stor_free( &this->ads_hl_stor, (void *)this->ach_matched_dn );
        this->ach_matched_dn = NULL;
      }
            
      if (this->ach_ldap_msg && this->bo_alloc_msg)  
      { m_aux_stor_free( &this->ads_hl_stor, (void *)this->ach_ldap_msg );
        this->ach_ldap_msg = NULL;
      }       

      this->ch_type        = ads_etab[0].ch_type;
      this->im_result_code = ads_etab[0].im_result_code;
      this->ach_err_msg    = ads_etab[0].ach_err_msg;

      this->im_apicode = 0;
      this->bo_alloc_msg = FALSE;
      this->bo_alloc_dn  = FALSE;
      
      memset( (void *)&this->ds_conn, int(0), sizeof(struct sockaddr_storage) );
 
    } // dsd_error::m_free()  
   
    
   /**
    * dsd_error::m_set_apicode()
    *
    * Sets the LDAP returned apicode.
    *
    * @param[in]  imp_apicode   API error code 
    */
    void m_set_apicode( int imp_apicode )  
    { 
      int  iml_1;
      BOOL bol_1;
      
      this->im_apicode = imp_apicode; 
      // search type and default message string...
      for (iml_1=0,bol_1=FALSE; ads_etab[iml_1].ch_type != '?'; iml_1++)
      {  if (ads_etab[iml_1].im_result_code == this->im_apicode)
         { // fill members...
           this->ch_type     = ads_etab[iml_1].ch_type;
           this->ach_err_msg = ads_etab[iml_1].ach_err_msg;
           bol_1 = TRUE;
           break;
         }  
      } // end for() 
      
      if (bol_1 == FALSE)
      { // set default error...
        this->ch_type     = 'W';
        this->ach_err_msg = "Unknown error";
      }
        
    } // dsd_error::m_set_apicode() 

   
    /**
    * dsd_error::m_set_error()
    *
    * Registers the last result code and any associated strings, if an error has occurred.
    *
    * @param[in]  imp_result_code     LDAP result code (ENUMERATED {...})
    * @param[in]  imp_apicode         optional: API code 
    * @param[in]  achp_matched_dn     optional: (R)DN of the error
    * @param[in]  imp_len_matched_dn  optional: (R)DN length    
    * @param[in]  achp_ldap_msg       optional: error message (sent by LDAP)
    * @param[in]  imp_len_ldap_msg    optional: error message length
    *
    * Remarks:  
    *      
    *     LDAPResult ::= SEQUENCE { resultCode      ENUMERATED {...}
    *                               matchedDN       LDAPDN,
    *                               errorMessage    LDAPString,
    *                               referral        [3] Referral OPTIONAL 
    *                             }
    */
    void m_set_error( int   imp_result_code,
                      int   imp_apicode     = ied_ldap_failure, 
                      char *achp_matched_dn = NULL, int imp_len_matched_dn = 0,
                      char *achp_ldap_msg   = NULL, int imp_len_ldap_msg   = 0 )
    { 
      int  iml_1;
      BOOL bol_1; 
      
      // delete old allocated strings...
      if (this->ach_matched_dn && this->bo_alloc_dn) 
      { m_aux_stor_free( &this->ads_hl_stor, (void *)this->ach_matched_dn );      
        this->ach_matched_dn = NULL;
      }
      
      if (this->ach_ldap_msg && this->bo_alloc_msg)  
      { m_aux_stor_free( &this->ads_hl_stor, (void *)this->ach_ldap_msg );   
        this->ach_ldap_msg = NULL;
      }
        
      // save LDAP result code  
      this->im_result_code = imp_result_code;
      this->im_apicode     = imp_apicode;
      this->bo_alloc_dn  = FALSE;
      this->bo_alloc_msg = FALSE;
      
      if (achp_matched_dn && imp_len_matched_dn)
      { // save (R)DN string...
        this->ach_matched_dn = (char *)m_aux_stor_alloc( &this->ads_hl_stor, imp_len_matched_dn + 1 );
        memcpy( (void *)this->ach_matched_dn, (const void *)achp_matched_dn, size_t(imp_len_matched_dn) );
        this->ach_matched_dn[imp_len_matched_dn] = '\0';
        this->bo_alloc_dn = TRUE;
      }  

      if (achp_ldap_msg)
      { // save LDAP error message...
        this->ach_ldap_msg = (char *)m_aux_stor_alloc( &this->ads_hl_stor, imp_len_ldap_msg + 1 );
        memcpy( (void *)this->ach_ldap_msg, (const void *)achp_ldap_msg, size_t(imp_len_ldap_msg) );
        this->ach_ldap_msg[imp_len_ldap_msg] = '\0';
        this->bo_alloc_msg = TRUE;
      }
      
      // search type and default message string...
      for (iml_1=0,bol_1=FALSE; ads_etab[iml_1].ch_type != '?'; iml_1++)
      {  
         if (ads_etab[iml_1].im_result_code == this->im_apicode)
         { // fill members...
           this->ch_type = ads_etab[iml_1].ch_type;
           this->ach_err_msg = ads_etab[iml_1].ach_err_msg;
           bol_1 = TRUE;
           break;
         }  
      } // end for() 
      
      if (bol_1 == FALSE)
      { // set default error...
        this->ch_type     = 'W';
        this->ach_err_msg = "Unknown error";
      }

    } // dsd_error::m_error_set()
    
}; // struct dsd_error



/**
 * This includes the class declaration 'dsd_trace{}'.
 * 
 * Copyright (C) HOB GmbH&Co. KG, Germany 2007, 2014
 *
 * @version  1.01
 * @author   Juergen-Lorenz Lauenstein
 * @date     2010/10/22
 */
class dsd_trace
{
#define HL_TRACEMSG_LEN    512

public:
    enum ied_def_trace_level
    { 
      LEVEL_NONE = 0,
      LEVEL_ERROR,
      LEVEL_INFO, 
      LEVEL_DATA 
    };
    
    enum ied_def_trace_str
    {
       S_BIND_AUTH,
       S_SEARCH_SCOPE 
    };   
       
protected:       
    static const char *achs_t_bind_auth[];     // translation tables
    static const char *achs_t_sear_scope[]; 

    int   im_trace_level;     ///< trace level (0: nothing to trace)
    void *ads_hl_stor;        ///< internal hob permanent storage handle   
    char  chr_prefix[9];      ///< trace message prefix (e.g. "LDAP\0")    
    char  chr_buffer[8];              
    
    struct sockaddr_storage  ds_conn; 
    char  chr_ineta[64];      ///< "ineta"
    int   im_port;            ///< port


    // Functions for trace message handling...
public:
   /**
    * dsd_trace::m_init()
    *
    * Initializes the trace class (constructor).
    *
    * @param[in]  achp_prefix      trace message prefix
    * @param[in]  imp_prefix_len   trace message prefix length
    * @param[in]  imp_trace_level  trace level (0: none)
    */
    void m_init( const char *achp_prefix     = "LDAP", 
                 int         imp_prefix_len  = sizeof "LDAP"-1,
                 int         imp_trace_level = -1 )
    {
      memset( (void *)this->chr_prefix, 0, sizeof(this->chr_prefix) );
      memset( (void *)this->chr_ineta,  0, sizeof(this->chr_ineta) );
      memset( (void *)&this->ds_conn,   0, sizeof(struct sockaddr_storage) ); 

      this->im_trace_level = imp_trace_level;
#if defined WIN32 || defined WIN64
      strncpy_s( this->chr_prefix, sizeof(this->chr_prefix), achp_prefix, 
                 imp_prefix_len > sizeof(this->chr_prefix)-1 ? sizeof(this->chr_prefix)-1 : imp_prefix_len );
#else
      strncpy( this->chr_prefix, achp_prefix, 
               imp_prefix_len > sizeof(this->chr_prefix)-1 ? sizeof(this->chr_prefix)-1 : imp_prefix_len );
#endif
      
      this->im_port = 0;
      this->ds_conn.ss_family = AF_INET;
      // set the ip-address as a string...
      m_hl_inet_ntop( &this->ds_conn, this->chr_ineta, sizeof(this->chr_ineta) );
 
    } // dsd_trace::m_init()
    
    
   /**
    * dsd_trace::m_free()
    *
    * Resets this class (destructor)
    */
    void  m_free()
    {  
      this->im_trace_level = LEVEL_NONE;
      
      memset( (void *)this->chr_prefix, 0, sizeof(this->chr_prefix) );
      memset( (void *)this->chr_ineta,  0, sizeof(this->chr_ineta) );
      memset( (void *)&this->ds_conn,   0, sizeof(struct sockaddr_storage) ); 
      
      this->im_port = 0;
      this->ds_conn.ss_family = AF_INET;

    } // dsd_trace::m_free()  


   /**
    * dsd_trace::m_get_level()
    *
    * Returns the trace level.
    *
    * @return  trace level (0: none)
    */
    int m_get_level()
    {
      return this->im_trace_level;
    } // dsd_trace::m_get_level()


   /**
    * dsd_trace::m_set_level()
    *
    * Sets the trace level.
    *
    * @param [in]  imp_trace_level   trace level (0: none)
    */
    void m_set_level( int imp_trace_level = LEVEL_NONE )
    {
      this->im_trace_level = imp_trace_level;
    } // dsd_trace::m_set_level()


   /**
    * dsd_trace::m_is_enabled()
    * 
    * Checks if the requested trace level is enabled.
    *
    * @param[in] imp_trace_level  requested trace level
    *
    * @return   TRUE if the trace level is set else returns FALSE
    */
    int m_is_enabled( int imp_trace_level )  
    {
      if (this->im_trace_level != LEVEL_NONE && imp_trace_level <= this->im_trace_level
#if defined HL_WT_CORE_LDAP && defined HOB_WSP_TRACE
          && img_wsp_trace_core_flags1 & HL_WT_CORE_LDAP
#endif            
         )
        return TRUE;

      return FALSE;
    } // dsd_trace::m_is_enabled()

   
   /**
    * dsd_trace::m_translate()
    *
    * Translates a given enum-value into a string.
    *
    * @param[in]  iep_value      enum value of the choosen parameter
    * @param[in]  iep_parameter  parameter to translate
    *
    * @return     pointer to string translation
    */
    const char* m_translate( int iep_value, int iep_parameter )
    {
       static const char *ach_unknown = "unknown";
       
       // check parameter (currently we support BIND_AUTH and SEARCH_SCOPE only)
       switch (iep_parameter)
       {
         case S_BIND_AUTH: 
                   if (iep_value > ied_auth_sid)
                   { // out of range
                     m_hlsnprintf( this->chr_buffer, sizeof chr_buffer, ied_chs_utf_8, "%d", iep_value );
                     return this->chr_buffer;
                   }

                   return this->achs_t_bind_auth[ iep_value ];
                             
         case S_SEARCH_SCOPE:
                   if (iep_value > ied_sear_attronly)
                   { // out of range
                     m_hlsnprintf( this->chr_buffer, sizeof chr_buffer, ied_chs_utf_8, "%d", iep_value );
                     return this->chr_buffer;
                   }
 
                   return this->achs_t_sear_scope[ iep_value ];

         default:  return ach_unknown;
       } // switch()

    } // dsd_trace::m_translate()
    
    
   /**
    * dsd_trace::m_trace()
    *
    * Formats a printable trace message string. 
    *
    * @param[in]  imp_trace_level  trace level expected
    * @param[in]  imp_msg_num      message number
    * @param[in]  imp_sess_num     session number
    * @param[in]  illp_epoch_ms    epoch time in milliseconds
    * @param[in]  adsp_conn        socket address information  
    * @param[in]  adsp_entry       configuration entry (e.g. dsd_ldap_entry)
    * @param[in]  achp_msg         message
    * @param[in]  ...              additional parameters
    * 
    * @return     void
    */
    template <class T>
    void m_trace( int imp_trace_level, int imp_msg_num, int imp_sess_num,
                  HL_LONGLONG illp_epoch_ms, struct sockaddr_storage *adsp_conn,
                  T *adsp_entry, 
                  const char *achp_msg, ... )
    { 

      // set pointer to the parameter list   
      va_list  dsp_list;
      va_start(dsp_list, achp_msg);

      // check the trace level...
      if (imp_trace_level <= this->im_trace_level && achp_msg)
      { 
        int   iml_len_name;
        char *achl_name;
    
        // is this parameters set?
        if (adsp_conn)
        { // convert ip-address, if not yet or if the address has changed
          if (memcmp( &this ->ds_conn, adsp_conn, sizeof(struct sockaddr_storage) ))
          { // convert the new address...
            memcpy( &this->ds_conn, adsp_conn, sizeof(struct sockaddr_storage) );
            // set the ip-address as a string...
            m_hl_inet_ntop( adsp_conn, this->chr_ineta, sizeof(this->chr_ineta) );
          }
        }
        
        // and is this parameter set, too?
        if (adsp_entry)
        { // yes...
          iml_len_name  = adsp_entry->imc_len_name;
          achl_name     = (char *)(adsp_entry + 1);
          this->im_port = adsp_entry->imc_port;
        }
        else
        { // no, use default values
          iml_len_name  = sizeof "?" - 1;
          achl_name     = (char *)"?";
          this->im_port = 0;
        }
        
        // format and display the trace message
        // message format: "LDAP<number>T  Name=..., <message>"
        char chrl_tracebuf_1[HL_TRACEMSG_LEN];
        
        int iml_1 (m_hlsnprintf( chrl_tracebuf_1, HL_TRACEMSG_LEN, ied_chs_utf_8, 
                                 (const char *)"%s%04iT  Name=\"%.*(.*)s\" S-id=%i Time=%10u Ineta=%s:%i ", 
                                 this->chr_prefix, imp_msg_num, iml_len_name, ied_chs_utf_8, achl_name, 
                                 imp_sess_num, (unsigned int)illp_epoch_ms, this->chr_ineta, this->im_port ));
        m_hlvsnprintf( (void *)(chrl_tracebuf_1 + iml_1), HL_TRACEMSG_LEN - iml_1, ied_chs_utf_8, 
                       (const char *)achp_msg, dsp_list );
        m_hlnew_printf( 0/*HLOG_INFO1*/, chrl_tracebuf_1 );
      } 
      va_end(dsp_list);   

    } // dsd_trace::m_trace()
    
    
   /**
    * dsd_trace::m_trace_data()
    *
    * Formats a printable trace data message string. 
    *
    * @param[in]  imp_trace_level   trace level expected
    * @param[in]  imp_msg_id        message id
    * @param[in]  imp_sess_id       session id
    * @param[in]  imp_ldap_msg_id   ldap message id
    * @param[in]  achp_ldap_req     ldap request name
    * @param[in]  illp_epoch_ms     epoch time in milliseconds
    * @param[in]  adsp_conn         socket address information  
    * @param[in]  adsp_entry        configuration entry (e.g. dsd_ldap_entry)
    * @param[in]  aucp_data         data buffer address
    * @param[in]  ump_size          data buffer size   
    * 
    * @return     void
    *
    * Remarks:
    *
    *     0         1  1  1  1  2  2  2  3   3  3  4  4  4  5  5  5   6        6       7 7 7
    *     0         0  3  6  9  2  5  8  1   5  8  1  4  7  0  3  6   0        9       7 8 9
    *     xxxxxxxx  xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  ........ ........ \n\0 (length: 80)
    */
    template <class T>
    void m_trace_data( int imp_trace_level, int imp_msg_id, int imp_sess_id, int imp_ldap_msg_id,
                       const char *achp_ldap_req, HL_LONGLONG illp_epoch_ms, struct sockaddr_storage *adsp_conn,
                       T *adsp_entry,
                       const unsigned char *aucp_data, unsigned int ump_size )
    { 

      // check the trace level...
      if (imp_trace_level <= this->im_trace_level && aucp_data)
      { 
        int   iml_len_name;
        char *achl_name;

        // is this parameters set?
        if (adsp_conn)
        { // convert ip-address, if not yet or if the address has changed
          if (memcmp( &this ->ds_conn, adsp_conn, sizeof(struct sockaddr_storage) ))
          { // convert the new address...
            memcpy( &this->ds_conn, adsp_conn, sizeof(struct sockaddr_storage) );
            // set the ip-address as a string...
            m_hl_inet_ntop( adsp_conn, this->chr_ineta, sizeof(this->chr_ineta) );
          }
        }
        
        // and is this parameter set, too?
        if (adsp_entry)
        { // yes...
          iml_len_name  = adsp_entry->imc_len_name;
          achl_name     = (char *)(adsp_entry + 1);
          this->im_port = adsp_entry->imc_port;
        }
        else
        { // no, use default values
          iml_len_name  = sizeof "?" - 1;
          achl_name     = (char *)"?";
          this->im_port = 0;
        }
        
        // format and display the trace message
        // message format: "LDAP<number>T  Name=..., <data>"
        char *achl_1;
        char  chrl_tracebuf_1[HL_TRACEMSG_LEN];
        
        int iml_1 (m_hlsnprintf( (void *)chrl_tracebuf_1, HL_TRACEMSG_LEN, ied_chs_utf_8, 
                                 (const char *)"%s%04iT  Name=\"%.*(.*)s\" S-id=%i Time=%10u Ineta=%s:%i Response(%i) %s\n", 
                                 this->chr_prefix, imp_msg_id, iml_len_name, ied_chs_utf_8, achl_name, imp_sess_id, 
                                 (unsigned int)illp_epoch_ms, this->chr_ineta, this->im_port, imp_ldap_msg_id, achp_ldap_req ));
        // set address for data area
        achl_1 = chrl_tracebuf_1 + iml_1;
        
        unsigned int  uml_data_offset (0);
        int           iml_index, iml_data_i, iml_text_i;
        unsigned char uchl_1, uchl_2;
        
        // hint: m_hlnew_printf() supports a length of 512 bytes only, so we have to split longer blocks
        int   iml_out_count (0);
        int   iml_max (60);   // maximum of 60 blocks (each 64 bytes)
        

        // step over all lines
        while (ump_size && iml_max > 0)  
        {  // format print out line    
           iml_out_count++;

           m_hlsnprintf( (void *)achl_1, 80, ied_chs_utf_8, 
                         "%08x                                                    ........ ........ \n",
                         uml_data_offset );
           // set data- and text zone offset      
           iml_data_i = 10;
           iml_text_i = 60;
           iml_index  = 0;
          
           do // fill a single print out line...                
           {  // read data byte
              uchl_1 = *aucp_data >> 4;
              uchl_2 = *aucp_data & 0x0f;
              // convert to ascii
              uchl_1 += (uchl_1 <= 9) ? 0x30 : 0x57;  
              uchl_2 += (uchl_2 <= 9) ? 0x30 : 0x57;          
              // set ascii bytes
              achl_1[iml_data_i]     = uchl_1;
              achl_1[iml_data_i + 1] = uchl_2;
              // set text byte
              if (isalnum( (int)*aucp_data ))                 
                achl_1[iml_text_i] = *aucp_data;
    
              if (iml_index == 7)
              { // half of the data array reached (set ' ')
                iml_data_i++;  
                iml_text_i++;
              }
           
              // step to the next
              iml_data_i += 3;
              iml_text_i += 1;
              iml_index++;
              ump_size--;
              aucp_data++;
           } while (iml_index < 16 && ump_size);
    
           // set next line number
           uml_data_offset += 16;
           achl_1 += 79;
 
           // should we print out a part of the data dump?
           if (iml_out_count == 4 && ump_size && iml_max > 0)
           {
             *(achl_1 - 2) = '\0';
             m_hlnew_printf( 0/*HLOG_INFO1*/, chrl_tracebuf_1 );

             iml_max--;
             achl_1 = chrl_tracebuf_1;
             iml_out_count = 0;
           }
        } // while (ump_size && iml_max > 0)
  
        // display message...
        if (iml_max == 0)
          m_hlnew_printf( 0/*HLOG_INFO1*/, (char *)"more..." );
        else
        {
          if (iml_out_count != 0)
          {
            *(achl_1 - 2) = '\0';
            m_hlnew_printf( 0/*HLOG_INFO1*/, chrl_tracebuf_1 );
          }
        }
      } // valid parameters
        
    } // dsd_trace::m_trace_data()


   /**
    * dsd_trace::m_trace_gather_data()
    *
    * Formats a printable trace data message string. The function works like the 
    * dsd_trace::m_trace_data(), but uses gather data.
    *
    * @param[in]  imp_trace_level  trace level expected
    * @param[in]  imp_msg_id       trace message id    
    * @param[in]  imp_sess_id      session id     
    * @param[in]  imp_ldap_msg_id  ldap message id
    * @param[in]  achp_ldap_req    ldap request name
    * @param[in]  illp_epoch_ms    epoch time in milliseconds
    * @param[in]  adsp_conn        socket address information  
    * @param[in]  adsp_entry       configuration entry (e.g. dsd_ldap_entry)
    * @param[in]  adsp_data        data address
    * 
    * @return     void
    *
    * Remarks:
    *
    *     0         1  1  1  1  2  2  2  3   3  3  4  4  4  5  5  5   6        6       7 7 7
    *     0         0  3  6  9  2  5  8  1   5  8  1  4  7  0  3  6   0        9       7 8 9
    *     xxxxxxxx  xx xx xx xx xx xx xx xx  xx xx xx xx xx xx xx xx  ........ ........ \n\0 (length: 80)
    */
    template <class T>
    void m_trace_gather_data( int imp_trace_level, int imp_msg_id, int imp_sess_id, int imp_ldap_msg_id,
                              const char *achp_ldap_req, HL_LONGLONG illp_epoch_ms, struct sockaddr_storage *adsp_conn, 
                              T *adsp_entry,
                              struct dsd_gather_i_1 *adsp_data )
{ 

      // check the trace level...
      if (imp_trace_level <= this->im_trace_level && adsp_data)
      { 
        int   iml_len_name;
        char *achl_name;

        // is this parameters set?
        if (adsp_conn)
        { // convert ip-address, if not yet or if the address has changed
          if (memcmp( &this ->ds_conn, adsp_conn, sizeof(struct sockaddr_storage) ))
          { // convert the new address...
            memcpy( &this->ds_conn, adsp_conn, sizeof(struct sockaddr_storage) );
            // set the ip-address as a string...
            m_hl_inet_ntop( adsp_conn, this->chr_ineta, sizeof(this->chr_ineta) );
          }
        }

        // and is this parameter set, too?
        if (adsp_entry)
        { // yes...
          iml_len_name  = adsp_entry->imc_len_name;
          achl_name     = (char *)(adsp_entry + 1);
          this->im_port = adsp_entry->imc_port;
        }
        else
        { // no, use default values
          iml_len_name  = sizeof "?" - 1;
          achl_name     = (char *)"?";
          this->im_port = 0;
        }
        
        // format and display the trace message
        // message format: "LDAP<number>T  Name=..., <data>"
        int  uml_size (0);
        struct dsd_gather_i_1 *adsl_gather_1 (adsp_data);

        do
        {  // add gather lengths...
           uml_size += (int)(adsl_gather_1->achc_ginp_end - adsl_gather_1->achc_ginp_cur);
           adsl_gather_1 = adsl_gather_1->adsc_next;
        } while (adsl_gather_1);
        
        char *achl_1;
        char  chrl_tracebuf_1[HL_TRACEMSG_LEN];
        
        int iml_1 (m_hlsnprintf( (void *)chrl_tracebuf_1, HL_TRACEMSG_LEN, ied_chs_utf_8, 
                                 (const char *)"%s%04iT  Name=\"%.*(.*)s\" S-id=%i Time=%10u Ineta=%s:%i Request(%i) %s\n", 
                                 this->chr_prefix, imp_msg_id, iml_len_name, ied_chs_utf_8, achl_name, imp_sess_id, 
                                 (unsigned int)illp_epoch_ms, this->chr_ineta, this->im_port, imp_ldap_msg_id, achp_ldap_req ));
        // set address for data area
        achl_1 = chrl_tracebuf_1 + iml_1;
        
        unsigned int  uml_data_offset (0);
        int           iml_index, iml_data_i, iml_text_i;
        unsigned char uchl_1, uchl_2, *auchl_data;
        
        // hint: m_hlnew_printf() supports a length of 512 bytes only, so we have to split longer blocks
        int  iml_out_count (0);    
		int  iml_max (60);      // maximum of 60 blocks (each 64 bytes)
        
        // step over all lines
        adsl_gather_1 = adsp_data;
        auchl_data = (unsigned char *)adsl_gather_1->achc_ginp_cur;

        while (uml_size && iml_max > 0)  
        {  // format print out line    
           iml_out_count++;

           m_hlsnprintf( (void *)achl_1, 80, ied_chs_utf_8, 
                         "%08x                                                    ........ ........ \n",
                         uml_data_offset );
           // set data- and text zone offset      
           iml_data_i = 10;
           iml_text_i = 60;
           iml_index  = 0;
          
           do // fill a single print out line...                
           {  // read data byte
              uchl_1 = *auchl_data >> 4;
              uchl_2 = *auchl_data & 0x0f;
              // convert to ascii
              uchl_1 += (uchl_1 <= 9) ? 0x30 : 0x57;  
              uchl_2 += (uchl_2 <= 9) ? 0x30 : 0x57;          
              // set ascii bytes
              achl_1[iml_data_i]     = uchl_1;
              achl_1[iml_data_i + 1] = uchl_2;
              // set text byte
              if (isalnum( (int)*auchl_data ))                 
                achl_1[iml_text_i] = *auchl_data;
    
              if (iml_index == 7)
              { // half of the data array reached (set ' ')
                iml_data_i++;  
                iml_text_i++;
              }
           
              // step to the next
              iml_data_i += 3;
              iml_text_i += 1;
              iml_index++;
              uml_size--;
              
              auchl_data++;
              if (auchl_data >= (unsigned char*)adsl_gather_1->achc_ginp_end && 
                  uml_size && adsl_gather_1->adsc_next)
              { // step to the next gather structure
                adsl_gather_1 = adsl_gather_1->adsc_next;
                auchl_data    = (unsigned char *)adsl_gather_1->achc_ginp_cur;
              }
              
           } while (iml_index < 16 && uml_size);  // single line finished
    
           // set next line number
           uml_data_offset += 16;
           achl_1 += 79;
 
           // should we print out a part of the data dump?
           if (iml_out_count == 4 && uml_size && iml_max > 0)
           {
             *(achl_1 - 2) = '\0';
             m_hlnew_printf( 0/*HLOG_INFO1*/, chrl_tracebuf_1 );

			 iml_max--;
             achl_1 = chrl_tracebuf_1;
             iml_out_count = 0;
           }
 
        }; // while (uml_size && iml_max > 0)
  
        // display message...
        if (iml_max == 0)
          m_hlnew_printf( 0/*HLOG_INFO1*/, (char *)"more..." );
        else
        {
          if (iml_out_count != 0)
          {
            *(achl_1 - 2) = '\0';
            m_hlnew_printf( 0/*HLOG_INFO1*/, chrl_tracebuf_1 );
		  }
        }
      
      } // valid parameters
        
    } // dsd_trace::m_trace_data_gather()


}; // class dsd_trace



struct dsd_ldap_attr;
struct dsd_ldap_attr_desc;

/**
 * ASN.1 definitions (used by LDAP and other ASN.1 coded programs)
 * 
 * Required programs:
 * MS Visual Studio .NET 2005
 * MS Linker
 * 
 * Copyright (C) HOB Germany 2005, 2007, 2014
 *                                    
 * @version 1.02                      
 * @author  Juergen-Lorenz Lauenstein                         
 * @date    2005/08/16   (creation)
 * @date    2008/03/10   (last changes)    
 *
 * Overview of ASN1 tag construction
 *
 *	     Bits
 *	   _______
 *	   | 8 7 | CLASS
 *	     0 0 = UNIVERSAL
 *	     0 1 = APPLICATION
 *	     1 0 = CONTEXT-SPECIFIC
 *	     1 1 = PRIVATE
 *		     _____
 *		     | 6 | DATA-TYPE
 *		       0 = PRIMITIVE
 *		       1 = CONSTRUCTED
 *	  		     ___________
 *			     | 5 ... 1 | TAG-NUMBER
 *
 */
#define LASN1_CLASS_UNIVERSAL	((unsigned int) 0x00U)  
#define LASN1_CLASS_APPLICATION	((unsigned int) 0x40U)
#define LASN1_CLASS_CONTEXT		((unsigned int) 0x80U)  
#define LASN1_CLASS_PRIVATE		((unsigned int) 0xc0U)  
#define LASN1_CLASS_MASK		((unsigned int) 0xc0U)

/**< BER encoding type and mask */
#define LASN1_DATA_PRIMITIVE	((unsigned int) 0x00U)
#define LASN1_DATA_CONSTRUCTED	((unsigned int) 0x20U)
#define LASN1_DATA_MASK		    ((unsigned int) 0x20U)

#define LASN1_BIG_TAG_MASK		((unsigned int) 0x1fU)
#define LASN1_MORE_TAG_MASK		((unsigned int) 0x80U)

#define LDAP_TAG_NEWSUPERIOR	((unsigned int) 0x80U)	/**< context-specific + primitive + 0 */

#define LDAP_TAG_EXOP_REQ_OID   ((unsigned int) 0x80U)	/**< context specific + primitive */
#define LDAP_TAG_EXOP_REQ_VALUE ((unsigned int) 0x81U)	/**< context specific + primitive */
#define LDAP_TAG_EXOP_MOD_USER 	((unsigned int) 0x80U)
#define LDAP_TAG_EXOP_MOD_PWD_O	((unsigned int) 0x81U)
#define LDAP_TAG_EXOP_MOD_PWD_N	((unsigned int) 0x82U)

/** LDAP Request and Response Messages */
#define LDAP_REQ_BIND		   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 0))  /**< application[0] + constructed  : 0x60 */
#define LDAP_RESP_BIND		   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 1))  /**< application[1] + constructed  : 0x61 */

#define LDAP_REQ_UNBIND		   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_PRIMITIVE   | 2))  /**< application[2] + primitive    : 0x42 */

#define LDAP_REQ_SEARCH	   	   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 3))  /**< application[3] + constructed  : 0x63 */
#define LDAP_RESP_SEARCH_ENTRY ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 4))  /**< application[4} + constructed  : 0x64 */
#define LDAP_RESP_SEARCH_DONE  ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 5))  /**< application[5] + constructed  : 0x65 */
#define LDAP_RESP_SEARCH_REF   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 19)) /**< application[19] + constructed : 0x73 */

#define LDAP_REQ_MODIFY		   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 6))  /**< application[6] + constructed  : 0x66 */
#define LDAP_RESP_MODIFY	   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 7))  /**< application[7] + constructed  : 0x67 */

#define LDAP_REQ_ADD		   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 8))  /**< application[8] + constructed  : 0x68 */
#define LDAP_RESP_ADD		   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 9))  /**< application[9] + constructed  : 0x69 */

#define LDAP_REQ_DELETE		   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_PRIMITIVE   | 10)) /**< application[10] + primitive   : 0x4A */
#define LDAP_RESP_DELETE	   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 11)) /**< application[11] + constructed : 0x6B */

#define LDAP_REQ_MODDN		   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 12)) /**< application[12] + constructed : 0x6C */
#define LDAP_RESP_MODDN		   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 13)) /**< application[13} + constructed : 0x6D */

#define LDAP_REQ_COMPARE	   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 14)) /**< application[14] + constructed : 0x6E */
#define LDAP_RESP_COMPARE	   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 15)) /**< application[15] + constructed : 0x6F */

#define LDAP_REQ_ABANDON	   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_PRIMITIVE   | 16)) /**< application[16] + primitive   : 0x50 */

#define LDAP_REQ_EXTENDED	   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 23)) /**< application[23] + constructed : 0x77 */
#define LDAP_RESP_EXTENDED	   ((unsigned int)(LASN1_CLASS_APPLICATION | LASN1_DATA_CONSTRUCTED | 24)) /**< application[24] + constructed : 0x78 */

#define LDAP_RESP_NONE         ((unsigned int)0xffU)  /**< no response expected      */

/** authentication methods available */
#define LDAP_AUTH_NONE   ((unsigned int) 0x00U) /**< no authentication */
#define LDAP_AUTH_SIMPLE ((unsigned int) 0x80U) /**< context specific + primitive */
#define LDAP_AUTH_SASL   ((unsigned int) 0xa3U) /**< context specific + constructed */

/**< general BER types we know about */
#define LASN1_BOOLEAN		((unsigned int) 0x01UL)
#define LASN1_INTEGER		((unsigned int) 0x02UL)
#define LASN1_BITSTRING		((unsigned int) 0x03UL)
#define LASN1_OCTETSTRING	((unsigned int) 0x04UL)
#define LASN1_NULL			((unsigned int) 0x05UL)
#define LASN1_ENUMERATED	((unsigned int) 0x0aUL)
#define LASN1_SEQUENCE		((unsigned int) 0x30UL)	    /**< constructed                  */
#define LASN1_SET			((unsigned int) 0x31UL)	    /**< constructed                  */
#define LASN1_SASL_CREDS	((unsigned int) 0x87UL)	    /**< context specific + primitive */
#define LASN1_UNKNOWN       ((unsigned int) -1)         /**< ignore the tag type          */

/**< filter types */
#define LASN1_FILTER_AND	    ((unsigned int)0xa0U)   /**< context specific + constructed */
#define LASN1_FILTER_OR         ((unsigned int)0xa1U)   /**< context specific + constructed */
#define LASN1_FILTER_NOT    	((unsigned int)0xa2U)   /**< context specific + constructed */
#define LASN1_FILTER_EQUALITY   ((unsigned int)0xa3U)   /**< context specific + constructed */
#define LASN1_FILTER_SUBSTRINGS ((unsigned int)0xa4U)   /**< context specific + constructed */
#define LASN1_FILTER_GE         ((unsigned int)0xa5U)   /**< context specific + constructed */
#define LASN1_FILTER_LE         ((unsigned int)0xa6U)   /**< context specific + constructed */
#define LASN1_FILTER_PRESENT    ((unsigned int)0x87U)   /**< context specific + primitive   */
#define LASN1_FILTER_APPROX     ((unsigned int)0xa8U)   /**< context specific + constructed */
#define LASN1_FILTER_EXT	    ((unsigned int)0xa9U)   /**< context specific + constructed */

/**< extended filter component types */
#define LASN1_FILTER_EXT_MATCH   ((unsigned int)0x81U)	/**< context specific */
#define LASN1_FILTER_EXT_OID	 ((unsigned int)0x81U)	/**< context specific */
#define LASN1_FILTER_EXT_TYPE	 ((unsigned int)0x82U)	/**< context specific */
#define LASN1_FILTER_EXT_VALUE	 ((unsigned int)0x83U)	/**< context specific */
#define LASN1_FILTER_EXT_DNATTRS ((unsigned int)0x84U)	/**< context specific */

/**< substring filter component types */
#define LASN1_SUBSTRING_INITIAL	((unsigned int)0x80U)	/**< context specific */
#define LASN1_SUBSTRING_ANY		((unsigned int)0x81U)	/**< context specific */
#define LASN1_SUBSTRING_FINAL	((unsigned int)0x82U)	/**< context specific */

/**< return values... */
#define LASN1_SUCCESS           ((unsigned int)  0)
#define LASN1_ERROR		        ((unsigned int) -1)
#define LASN1_WAIT_MORE         ((unsigned int) -2)

/** substring filter component types */
#define LDAP_SUBSTRING_INITIAL	((unsigned int) 0x80U)	/**< context specific */
#define LDAP_SUBSTRING_ANY		((unsigned int) 0x81U)	/**< context specific */
#define LDAP_SUBSTRING_FINAL	((unsigned int) 0x82U)	/**< context specific */

/**< controls */
#define LASN1_CONTROLS          ((unsigned int)0xa0U)   /**< context specific + constructed */


/** OID supported for extended operations */
#define OID_CANCEL_EX    "1.3.6.1.1.8"                  /**< rfc 3909 */
#define OID_STARTTLS_EX  "1.3.6.1.4.1.1466.20037"       /**< rfc 2830 */                           
#define OID_PW_MODIFY_EX "1.3.6.1.4.1.4203.1.11.1"      /**< rfc 3062 */
#define OID_WHOAMI       "1.3.6.1.4.1.4203.1.11.3"
#define OID_DELTREE      "1.2.840.113556.1.4.805"       /**< draft-armijo-ldap-treedelete-03.txt */
#define OID_PAGE_RESULTS "1.2.840.113556.1.4.319"       /**< rfc 2696 */  



class dsd_asn1
{
    struct dsd_elem_1;

    struct dsd_seqof_1
    {  
      dsd_asn1::dsd_seqof_1 *adsc_prev;    ///< previous ASN.1-sequenceOf in chain
      dsd_asn1::dsd_seqof_1 *adsc_next;    ///< next     ASN.1-sequenceOf in chain
      dsd_asn1::dsd_elem_1  *adsc_elem;    ///< chain of all associated elements
      BOOL                   boc_set;      ///< sequence completed ('}')
      int                    imc_gath_cnt; ///< number of gathers to sent
      int                    imc_len_all;  ///< length of all associated elements
      int                    imc_tag;      ///< tag (e.g. ASN.1: SeqOf)
      int                    imc_len;      ///< length of the TL(v) data
      char                  *achc_buf;     ///< TL(v) data...
    };
    
    struct dsd_elem_1
    {
      dsd_asn1::dsd_seqof_1 *adsc_seqof;   ///< parent sequence structure
      dsd_asn1::dsd_elem_1  *adsc_next;    ///< next ASN.1-element in chain
      int                    imc_tag;      ///< tag (ASN.1)
      int                    imc_len;      ///< length of the TLV-data
      char                  *achc_buf;     ///< TLV data...
    };

public:
	int   im_tag;          ///< T(ag)
	int   im_len;          ///< L(ength)
	char *ach_val;         ///< V(alue)
	int   im_msgid;        ///< ldap message id
	int   im_op;           ///< LDAP protocol operation (e.g. BIND, SEARCH, ...)
	
private:	
	int   im_usertag;      ///< if not set, use LASN1_SEQUENCE
	void **aavo_hl_stor;   ///< internal hob storage handle for ASN.1-request

public:
	char *asn1_beg;        ///< start address of read or write data
	char *asn1_end;        ///< end address of data buffer
	BOOL  bo_no_data;      ///< no more data available (asn1_beg == asn1_end)
    struct dsd_gather_i_1  *ads_gather;  ///< tcp send/recv gather structure

private:	
    dsd_asn1::dsd_seqof_1      ds_seqof;       ///< anchor of ASN.1-sequenceOf chains
    dsd_asn1::dsd_seqof_1     *ads_seqof_act;  ///< actual sequenceOf-structure
    
// public methods
public:
	void m_init( void **adsp_hl_stor = NULL );    

    int  m_test_resp( class dsd_bufm *, int *, int *imp_nextpos = NULL ); ///< wait for a complete TLV-response...                                                         
	int  m_set_gather( HL_LONGLONG * );

	int  m_get_tag  ( int *aimp_tag );
    int  m_get_len  ( int *aimp_len );
    int  m_get_msgid( int *aimp_msgid );
    int  m_get_op   ( int *aimp_op );

	int	 m_printf( const char *fmt, ... );
	int  m_scanf( const char *fmt, ... );

    int  m_put_filter( const char *, int, enum ied_charset );

private:                                                  
    int  m_get_val ( char **achp_val );

	int  m_get_bool( BOOL *aimp_bool );
	int  m_get_enum( int *aimp_enum );
	int  m_get_int ( int *aimp_int );
	int	 m_get_string( char **aachp_string, int *imp_len, void **aavop_handle = NULL );
	int  m_get_stringar( struct dsd_ldap_val **aadsp_attr_vals, void **aavop_handle = NULL );

	int	 m_put_tag( int /**< tag */, int /**< taglen */, char * /**< buf */ );
	int	 m_put_len( int /**< len */, int /**< lenlen */, char * /**< buf */ );
	
	int  m_put_bool( int /**< value */, int /**< tag */ );
	int  m_put_enum( int /**< value */, int /**< tag */ );
	int  m_put_int ( int /**< value */, int /**< tag */ );
	int	 m_put_null( int /**< tag */ );
	int  m_put_string( char * /**< string value */, int /**< string length */, enum ied_charset /**< charset */, int /**< tag */ );
	int  m_put_string_uc( struct dsd_unicode_string * /**< unicode string */, int /**< tag */ );
	int  m_put_octetstring( char *, int, int );

	int  m_calc_lenlen( int imp_len );
	int	 m_calc_taglen( int imp_tag );

	dsd_asn1::dsd_elem_1  *m_get_element();

	int	  m_start_seq( int /**< tag */ );
	int   m_end_seq();
	int	  m_start_set( int /**< tag */ );
	int   m_end_set();

	int	  m_put_filter_list( char * /**< filter */, int /**< tag */ );
	int	  m_put_substring_filter( char * /**< type*/, char * /**< val */ );
	int	  m_put_simple_filter( char * /**< filter*/ );
	int   m_put_filter_value_unescape( char * /*val*/ );
	
	char *m_put_complex_filter( char * /**< filter*/, int /**< tag */ );
	char *m_find_filter_right_parent( char * /**< filter */ );    ///< find the ending ')' of the parent
	char *m_find_filter_wildcard( const char * /**< filter */ );
	
};	// class dsd_asn1


/// ldap control class
class dsd_ldap_control
{
public:
   dsd_ldap_control( class dsd_ldap *adsp_ldap = NULL )   ///< create objects...
   { 
     // initialize objects...
     this->ads_ldap = adsp_ldap;

#ifdef DEF_TC_OWN_NS
     memset( (void *)&this->ds_tcpcomp, int(0), size_t(sizeof(class ns_tcpcomp_mh::dsd_tcpcomp)) ); 
#else
     memset( (void *)&this->ds_tcpcomp, int(0), size_t(sizeof(class dsd_tcpcomp)) ); 
#endif     
     this->bo_tcperr        =         // no tcp error 
     this->bo_connected     =         // no connect called
     this->bo_recv_complete =         // no complete data received
     this->bo_recv          =  FALSE; // receive disabled
#if SM_BUGFIX_20140804
	 this->inc_ref_count    = 0;
#endif

     int iml_error;
     this->ds_ev_response.m_create( &iml_error );
   } // dsd_ldap_control()  


   ~dsd_ldap_control()   ///< free objects...
   {
     int iml_error;
     this->ds_ev_response.m_close( &iml_error );
   } // ~dsd_ldap_control()

#ifdef DEF_TC_OWN_NS
   class  ns_tcpcomp_mh::dsd_tcpcomp  ds_tcpcomp; ///< tcpcomp connection object
#else
   class  dsd_tcpcomp  ds_tcpcomp;                ///< tcpcomp connection object
#endif
   BOOL   bo_tcperr;                  ///< tcpcomp error set
   BOOL   bo_recv;                    ///< receive enabled
   BOOL   bo_recv_complete;           ///< complete data received
   BOOL   bo_connected;               ///< connection established
  
   class dsd_ldap         *ads_ldap;  ///< LDAP object
   class dsd_hcla_event_1  ds_ev_response;
                           
#if SM_BUGFIX_20140804
#if HL_UNIX
   volatile int inc_ref_count;
#else
   volatile LONG inc_ref_count;
#endif
   
   void m_ref_inc();
   bool m_ref_dec();
	int m_wait(int imp_waitmsec, int *aimp_ext_error);
#endif
}; // class dsd_ldap_control



class dsd_ldap_schema;

#define dsd_ldap_cl dsd_ldap 

struct dsd_gatherlist {
	dsd_gather_i_1* adsc_first;
	dsd_gather_i_1* adsc_last;
};

#define SM_USE_RECV_GATHERS	1


/**
 * this class implements an interface to the HOB ldap library
 */
class dsd_ldap
{
public:
   // static members
   static int    im_init_cnt;                             ///< counter for number of running instances	
#if !SM_BUGFIX_20140804
   static int    im_sess_cnt;                             ///< counter for number of running ldap connections (active tcpip)
#endif
   static class  dsd_hcla_critsect_1  ds_cs_ldap;         ///< synchronization object for all class instances
   static class  dsd_ldap_schema     *ads_schema_anc;     ///< ldap schema class anchor for nonMSAD servers
   static void  *ads_hl_stor_glob;                        ///< global storage handler
   static struct dsd_timer_ele        ds_timer_1;         ///< utc timer update interval
   static HL_LONGLONG  il_utc_time;                       ///< current utc time (in 100ns since 1.1.1601 12a.m)

   static volatile int im_utc_update;                     ///< utc timer must be updated  
   static volatile int im_init_cs;                        ///< only one initialization of the critical section

   static int   m_hex2value(int);                         
   static char *m_get_version();                          ///< get LDAP client version

#ifdef DEF_TC_OWN_NS
   static struct ns_tcpcomp_mh::dsd_tcpcallback ds_tcpcb; ///< tcpcomp callbacks 
#else   
   static struct dsd_tcpcallback  ds_tcpcb;               ///< tcpcomp callbacks 
#endif
   struct sockaddr_storage  ds_conn;                      ///< sockaddr (error / success)

#if SM_BUGFIX_20140724
	class  dsd_hcla_critsect_1  dsc_cs_ldap2;
	bool boc_pending_request;
#endif
	class  dsd_hcla_event_1  ds_ev_connect;
#ifdef _DEBUG
    int imc_req_counter;
#endif
   ///< entry functions
   int   m_ldap_request( struct dsd_ldap_group *, 
                         struct dsd_co_ldap_1 *, 
                         void  *vpp_userfld = NULL,
                         int    (*m_cb_func)(void *, class dsd_ldap *, struct dsd_co_ldap_1 *) = NULL );
                           
   void  m_ldap_init();   ///< -> constructor 'dsd_ldap()'
   void  m_ldap_free();   ///< -> destructor  '~dsd_ldap()'
   
   /// tcpcomp callback functions are called indirect because the origin callback functions
   /// have to be static (global)!!!
   void   m_cb_connect( struct sockaddr *, socklen_t );  ///< connect callback function
   void   m_cb_connect_err( struct sockaddr *, socklen_t, int, int, int );             
                                                          ///< connect error callback function
   void   m_cb_send();                                    ///< send callback function
   int    m_cb_getrecvbuf( void**, char**,  int** );      ///< get receive buffer callback function
   int    m_cb_recv( void* );                             ///< receive callback function
   void   m_cb_error( char*, int, int );                  ///< error callback function
   void   m_cb_cleanup_serverside( class dsd_tcpcomp*, class dsd_ldap_control* adsp_req ); ///< cleanup callback function for server-side close

   void  *ads_hl_stor_per;                  ///< hob permanent storage handle (must be initialized to NULL by class creator)

	void* m_client_storage_alloc(struct dsd_co_ldap_1* adsp_ldap_req, void** avol_stor_alternative, int inp_size);

   struct dsd_ldap_group  *ads_ldap_group;  ///< configuration group
   struct dsd_ldap_entry  *ads_ldap_entry;  ///< configuration entry inside the group
   int    im_ldap_templ;                    ///< configuration ldap template index;
   int    im_ldap_type;                     ///< ldap server type (in the case of generic!)
   
   struct dsd_error  ds_ldap_error;         ///< error message class structure
   class  dsd_trace  ds_ldap_trace;         ///< trace class structure


   struct dsd_ldapreq         ///< description of the actual LDAP request
   {
     enum L_Status{ REQ_BUILDING, REQ_INPROGRESS, REQ_COMPLETED, REQ_FLUSHING };
     L_Status  imc_l_status;   ///< status of request

     int         imc_msgid;    ///< LDAP message ID
     int         imc_req;      ///< LDAP request (e.g. BIND)
     const char *ac_req;       ///< LDAP request string (e.g. "Bind")
     int         imc_resp[4];  ///< LDAP one or more response(s) expected (e.g. BIND_RESP)   
   };  

public:
   /// access to nonblocking LDAP functions...
   void m_wt_ldap_request( struct dsd_hco_wothr *, struct dsd_co_ldap_1 * );

   class  dsd_ldap_control  *ads_ldap_control;  ///< ldap control class 

private:
   // LDAP functions...
   int  m_ldap_bind( struct dsd_co_ldap_1 * );                ///< bind to the LDAP server
   int  m_ldap_search( struct dsd_co_ldap_1 *, 
                       BOOL bop_attr_only = FALSE,
                       char **aachp_dn = NULL, int *aimp_len_dn = NULL, ied_charset *aiep_chs_dn = NULL ); 
                                                               ///< search for a LDAP entry
   int  m_ldap_modify( struct dsd_co_ldap_1 * );                ///< modify LDAP entry
   int  m_ldap_add( struct dsd_co_ldap_1 * );                   ///< insert LDAP entry
   int  m_ldap_compare( struct dsd_co_ldap_1 * );               ///< compare LDAP entry
   int  m_ldap_delete( struct dsd_co_ldap_1 * );                ///< delete LDAP entry
   int  m_ldap_modify_dn( struct dsd_co_ldap_1 * );             ///< move LDAP entry to a new DN

   int  m_ldap_get_attrlist( struct dsd_co_ldap_1 * );          ///< get attribute list of the user 
   int  m_ldap_get_membership( struct dsd_co_ldap_1 * );        ///< get 'memberOf'-membership of an entry
   int  m_ldap_get_membership_nested( struct dsd_co_ldap_1 * ); ///< get nested 'memberOf'-values of an entry
   int  m_ldap_get_members( struct dsd_co_ldap_1 * );           ///< get 'member'-value of an entry
   int  m_ldap_get_members_nested( struct dsd_co_ldap_1 * );    ///< get nested 'member'-values of an entry

   int  m_ldap_get_sysinfo( struct dsd_co_ldap_1 * );           ///< get LDAP server system information
   int  m_ldap_get_bind( struct dsd_co_ldap_1 *,
                         BOOL bop_pwd = FALSE );                ///< get the current LDAP bind-context
   int  m_ldap_lookup( struct dsd_co_ldap_1 *,                  ///< test the validity of a DN
                       BOOL bop_attr_only = FALSE );
   int  m_ldap_check_pwd_age( struct dsd_co_ldap_1 * );         ///< check the password age
   int  m_ldap_explode_dn( struct dsd_co_ldap_1 * );            ///< part the DN into RDNs
   int  m_ldap_clone_dn( struct dsd_co_ldap_1 * );              ///< clone the DN to the next LDAP
   int  m_ldap_abandon();                                       ///< cancel LDAP request
   int  m_ldap_unbind();                                        ///< unbind/close to the LDAP server
   int  m_ldap_get_last_error();                                ///< return the last error condition
   int  m_ldap_connect( struct dsd_ldap_group * );              ///< connect to the LDAP server
   int  m_ldap_close(class dsd_ldap_control* adsp_req);         ///< disconnect to the LDAP server
   int  m_ldap_password( struct dsd_co_ldap_1 * );              ///< change user password

   class dsd_bufm  ds_buf_ldap;  ///< instance receive buffer
#if SM_USE_RECV_GATHERS
	dsd_gatherlist dsc_recv_data;	///< Received data
	int inc_recv_data_len;
#else
   class dsd_bufm  ds_buf_ssl;   ///< instance ssl receive buffer
#endif
   void *ads_hl_stor_tmp;        ///< internal hob temporary storage handle for LDAP (must be initialized to NULL by class creator)

   int   im_ldap_msgid;          ///< LDAP request message ID
   int   m_get_msgid();          ///< get a new LDAP message ID
   
   int   im_sess_no;             ///< session number
   
   // helper functions...
   int	 m_aux_parse_resp( class  dsd_bufm *,
                           class  dsd_asn1 *, 
                           struct dsd_ldapreq * );                           ///< standard LDAP response
   int   m_aux_bind_simple( struct dsd_unicode_string *,
                            struct dsd_unicode_string * );                   ///< simple bind (helper routine)
   int   m_aux_bind_sasl( struct dsd_unicode_string *, 
                          struct dsd_unicode_string *,
                          enum ied_auth_ldap_def,
                          struct dsd_aux_get_domain_info_1 * );              ///< sasl bind (helper routine)
   int   m_aux_bind_admin();                                                 ///< admin bind (helper routine)
   int   m_aux_add( char *, int, enum ied_charset, struct dsd_ldap_attr * ); ///< add (helper routine)
   int   m_aux_deletetree( struct dsd_co_ldap_1 * );                         ///< deletetree (helper routine)
   int   m_aux_modify( char *, int, enum ied_charset, 
                       struct dsd_ldap_attr *, enum ied_ldap_mod_def );      ///< modify (helper routine)
   int   m_aux_msad_modify_pw( char *, int, enum ied_charset,                
                               struct dsd_ldap_attr *, 
                               struct dsd_ldap_attr * );                     ///< modify msad password (helper routine)        
   int   m_aux_password_ex( struct dsd_co_ldap_1 * );                        ///< modify password extended operation                       
   
   int   m_aux_search_tree( struct dsd_co_ldap_1 * );            ///< search for LDAP entry(ies) along the tree
   int   m_aux_search_root( struct dsd_co_ldap_1 * );            ///< search for LDAP entry(ies) starting at root
   int   m_aux_search_result_entry( struct dsd_ldap_attr_desc **,
                                    char **aachp_dn = NULL, int *aimp_len_dn = NULL, enum ied_charset *aiep_chs_dn = NULL );
   int   m_aux_search_result_ref();                              ///< search for LDAP references
   int   m_aux_is_singlevalued( struct dsd_ldap_attr *, enum ied_ldap_attr_def * ); 
                                                                 ///< ask for the attribute single- or multi-valued property
   int   m_aux_search_RootDSE();                                 ///< get the schema contexts and supported operations
   int   m_aux_msad_val( char *, int, enum ied_charset, char **, int *, enum ied_charset * );
                                                                 ///< build quoted unicode values for msad environments

   // helper functions (subdomain controller referals)
   struct dsd_referral
   {
      struct dsd_referral       *adsc_next;
      struct dsd_unicode_string  dsc_devicecontext;
      struct dsd_unicode_string  dsc_ldap_url;
      int    imc_port;
   } *ads_referral;                              ///< anchor of referrals;

   int   m_ref_check_subdomain( struct dsd_co_ldap_1  *,         ///< check subdomains
                                struct dsd_referral   *,
                                struct dsd_ldap_entry * );
   int   m_ref_bind_subdomain( struct dsd_tcpsync_1 *,
                               struct dsd_co_ldap_1 * );         ///< bind for LDAP subdomain user
   int   m_ref_search_subdomain( struct dsd_tcpsync_1 *,
                                 struct dsd_co_ldap_1 * );       ///< search for LDAP subdomain user


//la;private:
//   class  dsd_ldap_control  *ads_ldap_control;  ///< ldap control class 
private:
   struct dsd_gather_i_1     ds_gather_send;    ///< temporary pointer to the send buffer
    
   // statistics...
   HL_LONGLONG  il_start_time;                  ///< search start-time

   class  dsd_asn1                ds_asn1;      ///< ASN.1 class
   struct dsd_ldap::dsd_ldapreq   ds_ldapreq;   ///< LDAP request structure
 
   enum C_Status{ DISCONNECTED, CONNECTED, BIND_SASL, BIND, UNBIND };
   C_Status  im_c_status;             ///< state of the connection

protected:
   /// SSL definitions...
   struct dsd_hl_ssl_c_1  ds_sslstruct;     ///< SSL structure
   struct dsd_gather_i_1  ds_appltossl;     ///< SSL input from client and server
   struct dsd_gather_i_1  ds_socktossl;     ///< SSL input from client and server
   char  *ach_ssltoappl_buf,                ///< buffer for output(ssl -> ldap)
         *ach_ssltosock_buf;                ///< buffer for output(ssl -> tcp)
public:
   void  *ads_hl_stor_ssl;                  ///< internal hob ssl storage handle

private:
#if SM_BUGFIX_20140724
   void   m_set_request_active(bool bop_active);
#endif
   int    m_ssl_init( struct dsd_ldap_entry * );  ///< initialize the LDAP SSL server
   int    m_ssl_hello( struct dsd_ldap_entry * ); ///< send 'hello' to the LDAP SSL server
   int    m_ssl_close();
   int    m_send( struct dsd_gather_i_1 *, int ); ///< send data to the LDAP server (SSL or nonSSL)   
   int    m_recv( int );                          ///< receive data from the LDAP server (SSL or nonSSL)   
public:   
   BOOL   bo_ssl_completed;     ///< SSl completion flag 

protected:    
   char  *achr_dn,              ///< DN (Bind), UTF-8 formatted
         *achr_pwd;      
   int    im_len_dn, im_len_pwd;        
   
   /// RootDSE - schema  
   static const char *achs_RootDSE[];
   enum iRootDSE { ied_nctx,        /**< namingContexts         */ 
                   ied_def_nctx,    /**< defaultNamingContext   */
                   ied_sch_nctx,    /**< schemaNamingContext    */
                   ied_sub_schema,  /**< subschemaSubentry      */
                   ied_sasl_mech,   /**< supportedSASLMechanisms*/
                   ied_extent,      /**< supportedExtensions    */
                   ied_vname,       /**< vendor name            */
                   ied_vver,        /**< vendor version         */ 
                   ied_dns_name,    /**< dnsHostName            */
                   ied_ldap_ver,    /**< supported LDAP version */ 
                   ied_control      /**< supportedControl       */ };

   BOOL bo_RootDSE;                   
   BOOL bo_page_results;   
   BOOL bo_deltree;

   void *avo_cookie;
   int   im_cookie_len;

   struct dsd_RootDSE
   {
     struct dsd_ldap_val  *ads_namingcontexts;   ///< DNs of all 'namingcontexts'
     struct dsd_ldap_val  *ads_defaultcontext;   ///< default DN of the 'namingcontext'used for search
     struct dsd_ldap_val  *ads_subschemaentry;   ///< list of all attributetypes
     struct dsd_ldap_val  *ads_schemacontext;    ///< schema-DN for a single attributetype
     struct dsd_ldap_val  *ads_SASLmechanisms;   ///< supported secure bind mechanisms
     struct dsd_ldap_val  *ads_extendedOIDs;     ///< supported extended OIDs
     struct dsd_ldap_val  *ads_vendorname;       ///< rfc 3045: vendorname
     struct dsd_ldap_val  *ads_vendorversion;    ///< rfc 3045: vendorversion
     struct dsd_ldap_val  *ads_dnshostname;      ///< dns host name
   } ds_RootDSE;
   

   class dsd_ldap_schema *ads_ldap_schema;       ///< AVL tree for nonMSAD schema attribute lists
   
   // nt authorities
   enum nt_authority { NULL_SID_AUTHORITY,              // 0x00
                       WORLD_SID_AUTHORITY,             // 0x01
                       LOCAL_SID_AUTHORITY,             // 0x02
                       CREATOR_SID_AUTHORITY,           // 0x03
                       NON_UNIQUE_AUTHORITY,            // 0x04
                       NT_AUTHORITY,                    // 0x05
                       SEC_MANDATORY_LABEL_AUTHORITY }; // 0x06
                       
   struct dsd_sid
   {
     unsigned char  uchc_revision;      ///< revision-level of the SID 
     unsigned char  uchc_count_subIDs;  ///< subID count (max. 15)                            
     unsigned char  uchc_authority[6];  ///< nt-authority
     unsigned char  uchcr_subID[15][4]; ///< subID (32-bit integer, LE)
   };
    
   struct dsd_sid  *ads_domainSID;      ///< domainSID
   BOOL   bo_le;                        ///< TRUE: le-endianess, FALSE: be-endianess
   
   ///< convertion routines for SIDs
   int  m_aux_sid_to_hex(char *,                
                         int,                   
                         struct dsd_sid *);    
   int  m_aux_hex_to_sid(struct dsd_sid      *, 
                         struct dsd_ldap_val *, 
                         void *);              
   
   ///< deltree node-structure (look at dsd_ldap::m_aux_deletetree()) 
#pragma pack()
   struct dsd_node
   {
     struct dsd_node  *adsc_parent;  ///< parent node (current level - 1) (null, if the first one)
     struct dsd_node  *adsc_child;   ///< child node (current level + 1) (null, if the last one)
     struct dsd_node  *adsc_next;    ///< next neighbor of this node (current level)(null, if no neighbor)
     char  *ac_dn;                   ///< dn of this node (level 0)
     int    imc_len_dn;              ///< length of dn
   };


private:                        
   /// for non-blocking calls of m_ldap_request()
   struct dsd_call_para_1 ds_call_para;

   void *vp_userfld;
   int  (*m_cb_func)( void *, class dsd_ldap *, struct dsd_co_ldap_1 * );

}; // class dsd_ldap



/// ldap schema class (nonMSAD ldap server)
class dsd_ldap_schema
{
public:
   class  dsd_ldap_schema *ads_next;        ///< next in chain
   struct dsd_ldap_group  *ads_ldap_group;  ///< configuration context
   struct dsd_ldap_entry  *ads_ldap_entry;  ///< configuration context

   /// constructor   
   void m_init( struct dsd_ldap_group *adsp_ldap_group = NULL, struct dsd_ldap_entry *adsp_ldap_entry = NULL )
   {
      dsd_ldap::ds_cs_ldap.m_enter();
      this->ads_next = dsd_ldap::ads_schema_anc;      
      dsd_ldap::ads_schema_anc = this;
      dsd_ldap::ds_cs_ldap.m_leave();
      
      // save configuration context
      this->ads_ldap_group = adsp_ldap_group;
      this->ads_ldap_entry = adsp_ldap_entry;
                                               
      this->im_avl_status = (m_htree1_avl_init( NULL, 
                                                &this->ds_htree_control,  
                                                &(dsd_ldap_schema::m_htree1_avl_compare) ) == TRUE) ? dsd_ldap_schema::SUCCESS
                                                                                                    : dsd_ldap_schema::TREE_ERROR;
   };
   

   /** 
    * m_htree1_avl_insert() - Insert a new entry to the tree  
    *                                                             
    * @param[in]  achp_attr     attribute name to insert            
    * @param[in]  imp_len_attr  attribute name length                 
    * @param[in]  iep_attr_def  'ied_ldap_attr_single' or 'ied_ldap_attr_multi'      
    *                                                                                  
    * @return     \b TRUE    if successful or
    *             \b FALSE   if the operation failed. A more detailed information 
    *                        is set in dsd_ldap_schema::im_avl_status
    */
   BOOL m_htree_avl_insert( char *achp_attr, int imp_len_attr, enum ied_ldap_attr_def iep_attr_def )
   {
      struct dsd_avl_schema_attr  dsl_schema_search;
                                  dsl_schema_search.iec_attr_def = iep_attr_def;
                                  dsl_schema_search.imc_len_val  = imp_len_attr;
                                  dsl_schema_search.ac_val       = achp_attr;

		struct dsd_htree1_avl_work   ds_htree_work;      ///< work structure for HOB tree AVL

      dsd_ldap::ds_cs_ldap.m_enter();
      if (m_htree1_avl_search( NULL, 
                               &this->ds_htree_control, 
                               &ds_htree_work, 
                               &dsl_schema_search.dsc_htree1 ) == TRUE)
      { // is the entry already inserted ?
        if (ds_htree_work.adsc_found == NULL) 
        { // no, insert this element...
 		  struct dsd_avl_schema_attr  *adsl_schema_attr = (struct dsd_avl_schema_attr *)m_aux_stor_alloc(&dsd_ldap::ads_hl_stor_glob, 
                                                                                                         sizeof(struct dsd_avl_schema_attr) + imp_len_attr);
		  memset( adsl_schema_attr, 0, sizeof(struct dsd_avl_schema_attr) );
		  adsl_schema_attr->iec_attr_def = iep_attr_def;
		  adsl_schema_attr->imc_len_val  = imp_len_attr;
		  adsl_schema_attr->ac_val       = (char *)adsl_schema_attr + sizeof(struct dsd_avl_schema_attr);
		  memcpy( (void *)adsl_schema_attr->ac_val, (const void *)achp_attr, imp_len_attr );
          if (m_htree1_avl_insert( NULL, 
                                   &this->ds_htree_control,
                                   &ds_htree_work, 
                                   &adsl_schema_attr->dsc_htree1 ) == TRUE)
          { // insert was successful!
            this->im_avl_status = dsd_ldap_schema::SUCCESS;
            dsd_ldap::ds_cs_ldap.m_leave();
            return TRUE;
          }
		  m_aux_stor_free(&dsd_ldap::ads_hl_stor_glob, adsl_schema_attr);
		}
        else
        { // yes, the entry is already in use
          this->im_avl_status = dsd_ldap_schema::ALREADY_INSERTED;
          dsd_ldap::ds_cs_ldap.m_leave();
          return FALSE;
        }
      }  
         
      // search or insert error, tree corrupted
      this->im_avl_status = dsd_ldap_schema::TREE_ERROR;
      dsd_ldap::ds_cs_ldap.m_leave();
      return FALSE;
      
   } // m_htree_avl_insert()


   /** 
    * m_htree1_avl_search() - Search an entry in the tree  
    *                
    * @param[in]     achp_attr      attribute name to search  
    * @param[in]     imp_len_attr   attribute name length  
    * @param[in,out] aiep_attr_def  returns the 'single' or 'multivalued'-state  
    *  
    * @return     \b TRUE    if successful, the entry is found (aiep_attr_def is valid).  
    *             \b FALSE   if the operation failed. A a more detailed information   
    *                        is set in dsd_ldap_schema::im_avl_status.  
    */
   BOOL m_htree_avl_search( char *achp_attr, int imp_len_attr, enum ied_ldap_attr_def *aiep_attr_def ) 
   {
      struct dsd_avl_schema_attr  dsl_schema_attr;
      
      memset( &dsl_schema_attr, 0, sizeof(struct dsd_avl_schema_attr) );
      dsl_schema_attr.imc_len_val  = imp_len_attr;
      dsl_schema_attr.ac_val       = achp_attr;
      dsl_schema_attr.iec_attr_def = ied_ldap_attr_undef;
      
      // set attribute property      
      *aiep_attr_def = ied_ldap_attr_undef;
      
	  struct dsd_htree1_avl_work   ds_htree_work;      ///< work structure for HOB tree AVL
      dsd_ldap::ds_cs_ldap.m_enter();
      
      if (m_htree1_avl_search( NULL, 
                               &this->ds_htree_control, 
                               &ds_htree_work, 
                               &dsl_schema_attr.dsc_htree1 ) == TRUE)   
      { // have we found our attribute?
        if (ds_htree_work.adsc_found == NULL) 
        { // no, entry not found
          this->im_avl_status = dsd_ldap_schema::NOT_FOUND;
          dsd_ldap::ds_cs_ldap.m_leave();
          return FALSE;
        } 

        // yes, entry found
        *aiep_attr_def = ((struct dsd_avl_schema_attr *)((char *)ds_htree_work.adsc_found - offsetof(dsd_avl_schema_attr, dsc_htree1)))->iec_attr_def;
        
        this->im_avl_status = dsd_ldap_schema::SUCCESS;
        dsd_ldap::ds_cs_ldap.m_leave();
        return TRUE;
      }
      
      // search error, tree corrupted
      this->im_avl_status = dsd_ldap_schema::TREE_ERROR;
      dsd_ldap::ds_cs_ldap.m_leave();
      return FALSE;
      
   }; // m_htree_avl_search()

   
   /** 
    * m_htree1_avl_check() - Do an integrity check of the tree  
    *                                                             
    * @return     \b TRUE    if successful or
    *             \b FALSE   if the operation failed. A more detailed information 
    *                        is set in dsd_ldap_schema::im_avl_status
    */
   BOOL m_htree_avl_check( void )
   {
	 struct dsd_htree1_avl_work   ds_htree_work;      ///< work structure for HOB tree AVL
	 
	 dsd_ldap::ds_cs_ldap.m_enter();
     if (m_htree1_avl_getnext( NULL,
                               &this->ds_htree_control, 
                               &ds_htree_work, 
                               TRUE ) == FALSE)
     {
       // search error, tree corrupted
       this->im_avl_status = dsd_ldap_schema::TREE_ERROR;  
	   dsd_ldap::ds_cs_ldap.m_leave();
       return FALSE;
     }

     // step through avl-tree...
     while (ds_htree_work.adsc_found)
     {
        if (m_htree1_avl_getnext( NULL,
                                  &this->ds_htree_control, 
                                  &ds_htree_work, 
                                  FALSE ) == FALSE)
        {
          // search error, tree corrupted
          this->im_avl_status = dsd_ldap_schema::TREE_ERROR;
	      dsd_ldap::ds_cs_ldap.m_leave();
          return FALSE;
        }
     } // while()
     
     dsd_ldap::ds_cs_ldap.m_leave();
     return TRUE; 
   }; // m_htree_avl_check()


   /// callback routine for comparing elements
   static int m_htree1_avl_compare( void *, struct dsd_htree1_avl_entry *, struct dsd_htree1_avl_entry * );

   /// tree state definitions
   enum ied_avl_status_def { UNDEFINED, SUCCESS, TREE_ERROR, ALREADY_INSERTED, NOT_FOUND };

   struct dsd_htree1_avl_cntl   ds_htree_control;   ///< control structure for HOB tree AVL
   
   enum ied_avl_status_def  im_avl_status;          ///< state of the HOB tree AVL

private:   
   struct dsd_avl_schema_attr    ///< structure for defining a schema attribute
   {                                                          
     char                        *ac_val;        ///< attribute (utf-8)
     int                          imc_len_val;   ///< attribute length
     enum ied_ldap_attr_def       iec_attr_def;  ///< 'single-' or 'multivalued' state
     // tree control
     struct dsd_htree1_avl_entry  dsc_htree1;    ///< contains header for tree 
   };

}; // class dsd_ldap_schema



/**
  static LDAP functions...
*/
extern "C" void m_ldap_init( class dsd_ldap * );   ///< -> constructor
extern "C" void m_ldap_free( class dsd_ldap * );   ///< -> destructor

extern "C" int  m_ldap_request( class  dsd_ldap *,         /**< ldap class instance   */ 
                                struct dsd_ldap_group *,   /**< ldap configuration    */
                                struct dsd_co_ldap_1 *,    /**< ldap command structure*/     
                                void  *vpp_userfld = NULL, /**< user field            */
                                int   (*m_cb_func)( void *,                /**< user field             */ 
                                                    class dsd_ldap *,      /**< ldap class instance    */ 
                                                    struct dsd_co_ldap_1 * /**< ldap command structure */ ) = NULL /**< callback function */ );

extern "C" enum ied_ret_ldap_def  m_ldap_auth( struct dsd_ldap_group *,     /**< configuration */
                                               struct dsd_unicode_string *, /**< user id        */
                                               struct dsd_unicode_string *  /**< password      */ );  
   
extern "C" int m_hl_memicmp( const void *, const void *, int );   ///< _memicmp() replacement for Linux 
                                        
#endif	// _hob_ldap_H

///////////////////////////////////////////////////////////////////////////////////////////////////
// end of 'hob-ldap01.hpp'
///////////////////////////////////////////////////////////////////////////////////////////////////