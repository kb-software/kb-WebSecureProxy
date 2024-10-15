/*
 * The Apache Software License, Version 1.1
 *
 * Copyright (c) 1999-2000 The Apache Software Foundation.  All rights
 * reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The end-user documentation included with the redistribution,
 *    if any, must include the following acknowledgment:
 *       "This product includes software developed by the
 *        Apache Software Foundation (http://www.apache.org/)."
 *    Alternately, this acknowledgment may appear in the software itself,
 *    if and wherever such third-party acknowledgments normally appear.
 *
 * 4. The names "Xerces" and "Apache Software Foundation" must
 *    not be used to endorse or promote products derived from this
 *    software without prior written permission. For written
 *    permission, please contact apache\@apache.org.
 *
 * 5. Products derived from this software may not be called "Apache",
 *    nor may "Apache" appear in their name, without prior written
 *    permission of the Apache Software Foundation.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of voluntary contributions made by many
 * individuals on behalf of the Apache Software Foundation, and was
 * originally based on software copyright (c) 1999, International
 * Business Machines, Inc., http://www.ibm.com .  For more information
 * on the Apache Software Foundation, please see
 * <http://www.apache.org/>.
 */

/*
 * $Log: DOMCount.hpp,v $
 * Revision 1.9  2003/02/05 18:53:22  tng
 * [Bug 11915] Utility for freeing memory.
 *
 * Revision 1.8  2002/11/05 21:46:19  tng
 * Explicit code using namespace in application.
 *
 * Revision 1.7  2002/06/18 16:19:40  knoaman
 * Replace XercesDOMParser with DOMBuilder for parsing XML documents.
 *
 * Revision 1.6  2002/02/01 22:35:01  peiyongz
 * sane_include
 *
 * Revision 1.5  2000/10/20 22:00:35  andyh
 * DOMCount sample Minor cleanup - rename error handler class to say that it is an error handler.
 *
 * Revision 1.4  2000/03/02 19:53:39  roddey
 * This checkin includes many changes done while waiting for the
 * 1.1.0 code to be finished. I can't list them all here, but a list is
 * available elsewhere.
 *
 * Revision 1.3  2000/02/11 02:43:55  abagchi
 * Removed StrX::transcode
 *
 * Revision 1.2  2000/02/06 07:47:17  rahulj
 * Year 2K copyright swat.
 *
 * Revision 1.1.1.1  1999/11/09 01:09:52  twl
 * Initial checkin
 *
 * Revision 1.5  1999/11/08 20:43:35  rahul
 * Swat for adding in Product name and CVS comment log variable.
 *
 */

#ifdef B100518
// ---------------------------------------------------------------------------
//  Includes
// ---------------------------------------------------------------------------
#include <xercesc/dom/DOMErrorHandler.hpp>
#include <xercesc/util/XMLString.hpp>
#ifdef OLD01
#include <iostream.h>
#else
#include <iostream>
#endif

XERCES_CPP_NAMESPACE_USE

// ---------------------------------------------------------------------------
//  Simple error handler deriviative to install on parser
// ---------------------------------------------------------------------------
class DOMCountErrorHandler : public DOMErrorHandler
{
public:
    // -----------------------------------------------------------------------
    //  Constructors and Destructor
    // -----------------------------------------------------------------------
    DOMCountErrorHandler();
    ~DOMCountErrorHandler();


    // -----------------------------------------------------------------------
    //  Getter methods
    // -----------------------------------------------------------------------
    bool getSawErrors() const;


    // -----------------------------------------------------------------------
    //  Implementation of the DOM ErrorHandler interface
    // -----------------------------------------------------------------------
    bool handleError(const DOMError& domError);
    void resetErrors();


private :
    // -----------------------------------------------------------------------
    //  Unimplemented constructors and operators
    // -----------------------------------------------------------------------
    DOMCountErrorHandler(const DOMCountErrorHandler&);
    void operator=(const DOMCountErrorHandler&);


    // -----------------------------------------------------------------------
    //  Private data members
    //
    //  fSawErrors
    //      This is set if we get any errors, and is queryable via a getter
    //      method. Its used by the main code to suppress output if there are
    //      errors.
    // -----------------------------------------------------------------------
    bool    fSawErrors;
};


// ---------------------------------------------------------------------------
//  This is a simple class that lets us do easy (though not terribly efficient)
//  trancoding of XMLCh data to local code page for display.
// ---------------------------------------------------------------------------
class StrX
{
public :
    // -----------------------------------------------------------------------
    //  Constructors and Destructor
    // -----------------------------------------------------------------------
    StrX(const XMLCh* const toTranscode)
    {
        // Call the private transcoding method
        fLocalForm = XMLString::transcode(toTranscode);
    }

    ~StrX()
    {
        XMLString::release(&fLocalForm);
    }


    // -----------------------------------------------------------------------
    //  Getter methods
    // -----------------------------------------------------------------------
    const char* localForm() const
    {
        return fLocalForm;
    }

private :
    // -----------------------------------------------------------------------
    //  Private data members
    //
    //  fLocalForm
    //      This is the local code page form of the string.
    // -----------------------------------------------------------------------
    char*   fLocalForm;
};

#ifdef XYZ1 /* 20.10.04 KB */
inline ostream& operator<<(ostream& target, const StrX& toDump)
{
    target << toDump.localForm();
    return target;
}
#endif

inline bool DOMCountErrorHandler::getSawErrors() const
{
    return fSawErrors;
}

#ifdef READDISKXML
//XERCES_CPP_NAMESPACE_BEGIN

/**
 * DOMInputSource creating a BinMemInputStream.
 */
class dsd_xml_mis_1 : public DOMInputSource
{
protected:
   XMLByte * auc_data;              // XML data area
   int im_len;                      // length of data area
   BinMemInputStream *ds_mem;       // DOMInputSource to hand over to parser
   XMLCh * astr_baseuri;            // base URI
   XMLCh * astr_encoding;           // encoding
   XMLCh * astr_publicid;           // public id
   XMLCh * astr_systemid;           // system id
   bool abo_flag;                   // flag true: issue error if no data
                                    //      false: issue only warning

public:
   inline dsd_xml_mis_1( XMLByte * auc_datain, int im_lenin );

   ~dsd_xml_mis_1(){};

   BinInputStream* makeStream() const
   {
      if( auc_data == NULL )
      {
         return NULL;
      }
      return ds_mem;
   }; // makeStream()


   const XMLCh* getBaseURI() const
   {
      return astr_baseuri;
   };
   void setBaseURI( const XMLCh * const baseURI)
   {
      astr_baseuri = (XMLCh *)baseURI;
   };

   const XMLCh* getEncoding() const
   {
      return astr_encoding;
   };
   void setEncoding( const XMLCh * const encodingStr)
   {
      astr_encoding = (XMLCh *)encodingStr;
   };

//#ifdef XYZ1 /* 20.10.04 KB */
   bool getIssueFatalErrorIfNotFound() const
   {
      return abo_flag;
   };
//#endif
   void setIssueFatalErrorIfNotFound( const bool flag)
   {
      abo_flag = flag;
   };

   const XMLCh* getPublicId() const
   {
      return astr_publicid;
   };
   void setPublicId( const XMLCh * const publicId)
   {
      astr_publicid = (XMLCh *)publicId;
   };

   const XMLCh* getSystemId() const
   {
      return astr_systemid;
   };
   void setSystemId( const XMLCh * const systemId)
   {
      astr_systemid = (XMLCh *)systemId;
   };

   void release(){};

}; // dsd_xml_mis_1

/**
 * Constructor: create the memory input stream and initialize members.
 */
inline dsd_xml_mis_1::dsd_xml_mis_1( XMLByte * auc_datain, int im_lenin )
{
   auc_data = auc_datain;
   im_len = im_lenin;
   ds_mem = new BinMemInputStream( auc_data,
                                   im_len,
                                   BinMemInputStream::BufOpt_Reference,
              // Instead of BufOpt_Reference the following valuea are possible:
              // BufOpt_Adopt: the buffer is deleted after use by the object
              // BufOpt_Copy: A copy is used by the object
                                   XMLPlatformUtils::fgMemoryManager);
   astr_baseuri = NULL;
   astr_encoding = NULL;
   astr_publicid = NULL;
   astr_systemid = NULL;
   abo_flag = false;
};

#endif
#else
/*+---------------------------------------------------------------------+*/
/*| functions forward declaration:                                      |*/
/*+---------------------------------------------------------------------+*/
#ifndef PTYPE
    #ifdef __cplusplus
        #define PTYPE "C"
    #else
        #define PTYPE
    #endif
#endif
extern PTYPE int m_hlnew_printf( int imp_type, char *aptext, ... );
#ifndef HLOG_XYZ1
    #define HLOG_XYZ1 0
#endif


XERCES_CPP_NAMESPACE_USE


XERCES_CPP_NAMESPACE_BEGIN
/**
 * class dsd_xml_element_1
 * extends Xerces DOMElement Objects with line and column information
 *
 * @author: Michael Jakobs
 * @date:   10/05/04
 *
 * ATTENTION: this functionality requires that document is parsed
 *            with class dsd_xml_parser_1!!!
*/
class dsd_xml_element_1 : public DOMElementImpl {
public:
    dsd_xml_element_1( DOMDocument *ads_doc,
                       const XMLCh *wach_name,
                       XMLFileLoc  ull_line,
                       XMLFileLoc  ull_col ) : DOMElementImpl( ads_doc, wach_name )
    {
        ullc_line = ull_line;
        ullc_col  = ull_col;
    };


    /**
     * public function dsd_xml_element_1::m_get_line
     * get line of current DOMElement
     *
     * @return XMLFileLoc (used to be unsigned int64_t)
    */
    XMLFileLoc m_get_line()
    {
        if ( this->getNodeType() == TEXT_NODE ) {
            return ((dsd_xml_element_1*)(this->fNode.fOwnerNode))->m_get_line();
        }
        return ullc_line;
    }; // end of dsd_xml_element_1::m_get_line


    /**
     * public function dsd_xml_element_1::m_get_column
     * get column of current DOMElement
     *
     * @return XMLFileLoc (used to be unsigned int64_t)
    */
    XMLFileLoc m_get_column()
    {
        if ( this->getNodeType() == TEXT_NODE ) {
            return ((dsd_xml_element_1*)(this->fNode.fOwnerNode))->m_get_column();
        }
        return ullc_col;
    }; // end of dsd_xml_element_1::m_get_column

private:
    XMLFileLoc ullc_line;               // line of node
    XMLFileLoc ullc_col;                // column of node
}; // end of class dsd_xml_element_1
XERCES_CPP_NAMESPACE_END

// easy to use macros for getting line and column from a DOMNode
#define GET_LINE(ads_node)   (((dsd_xml_element_1*)ads_node)->m_get_line())
#define GET_COLUMN(ads_node) (((dsd_xml_element_1*)ads_node)->m_get_column())

#ifdef READDISKXML

/**
 * class dsd_xml_mis_1
 *   implements a single input source for Xerces
 *
 * @see    "xercesc/sax/InputSource.hpp"
 * @author Michael Jakobs
 * @date   10/04/28
*/
class dsd_xml_mis_1 : public InputSource {
public:
    /**
     * constructor
     *
     * @param[in]   XMLByte*    achp_data       pointer to xml data
     * @param[in]   int         inp_len         length of xml data
    */
    dsd_xml_mis_1( XMLByte* achp_data, int inp_len )
    {
        achc_data      = achp_data;
        inc_len        = inp_len;
        achc_encoding  = NULL;
        achc_public_id = NULL;
        achc_system_id = NULL;
        boc_flag       = false;
    };

    // destructor:
    ~dsd_xml_mis_1() {};

    // inherited virtual getter functions:
    BinInputStream* makeStream() const { 
        return new BinMemInputStream( achc_data, inc_len,
                                      BinMemInputStream::BufOpt_Reference,
                                      XMLPlatformUtils::fgMemoryManager );
    };
    const XMLCh*    getEncoding()                  const { return achc_encoding; };
    const XMLCh*    getPublicId()                  const { return achc_public_id; };
    const XMLCh*    getSystemId()                  const { return achc_system_id; };
    bool            getIssueFatalErrorIfNotFound() const { return boc_flag; };

    // inherited virtual setter functions:
    void setEncoding(const XMLCh* const encodingStr)   { achc_encoding = encodingStr; };
    void setPublicId(const XMLCh* const publicId)      { achc_public_id = publicId; };
    void setSystemId(const XMLCh* const systemId)      { achc_system_id = systemId; };
    void setIssueFatalErrorIfNotFound(const bool flag) { boc_flag = flag; };

private:
    // variables:
    XMLByte*           achc_data;
    int                inc_len;
    const XMLCh*       achc_encoding;
    const XMLCh*       achc_public_id;
    const XMLCh*       achc_system_id;
    bool               boc_flag;
}; // end of class dsd_xml_mis_1


/**
 * error handling class
 * Xerces will call this class if error are found
*/
class dsd_xml_error_1 : public ErrorHandler {
public:
    /**
     * constructor
    */
    dsd_xml_error_1()
    {
        boc_error = false;
    };

    /**
     * inherited destructor
    */
    ~dsd_xml_error_1(){};

    /**
     * inherited public function warning
     * callback for Xerces warnings
     *
     * @param[in]   SAXParseException& exc
    */
    void warning(const SAXParseException& exc)
    {
        boc_error = true;
        m_hlnew_printf( HLOG_XYZ1,
                        "HWSPXMLL010W Xerces reported Warning at Input-File Line=%llu Column=%llu.",
                        exc.getLineNumber(), exc.getColumnNumber() );
    }; // end of warning

    /**
     * inherited public function error
     * callback for Xerces errors
     *
     * @param[in]   SAXParseException& exc
    */
    void error(const SAXParseException& exc)
    {
        boc_error = true;
        m_hlnew_printf( HLOG_XYZ1,
                        "HWSPXMLL011W Xerces reported Error at Input-File Line=%llu Column=%llu.",
                        exc.getLineNumber(), exc.getColumnNumber() );
    }; // end of error

    /**
     * inherited public function fatalError
     * callback for Xerces fatal errors
     *
     * @param[in]   SAXParseException& exc
    */
    void fatalError(const SAXParseException& exc)
    {
        boc_error = true;
        m_hlnew_printf( HLOG_XYZ1,
                        "HWSPXMLL012W Xerces reported Fatal Error at Input-File Line=%llu Column=%llu.",
                        exc.getLineNumber(), exc.getColumnNumber() );
    }; // end of fatalError

    /**
     * inherited public function resetErrors
     * reset error variable
    */
    void resetErrors() { boc_error = false; };

    /**
     * public function m_error_happened
     * report if xerces callbacked for a warning, error or fatal error
     *
     * @return  bool
    */
    bool m_error_happened()
    {
        return boc_error;
    }; // end of m_error_happened

private:
    // variables:
    bool boc_error;
};

XERCES_CPP_NAMESPACE_BEGIN
/**
 * this class extends the XercesDOMParser
 * it adds information about the line and column to a DOMElement
 *
 * @author: Michael Jakobs
 * @date:   10/05/04
*/
class dsd_xml_parser_1 : public XercesDOMParser {
protected:
    virtual DOMElement* createElement (const XMLCh* name)
    {
        // initialize some variables:
        const Locator*     adsl_locator;
        XMLFileLoc         ull_line;
        XMLFileLoc         ull_col;

        // get line and column number:
        adsl_locator = fScanner->getLocator();
        ull_line     = adsl_locator->getLineNumber();
        ull_col      = adsl_locator->getColumnNumber();

        return new (fDocument, DOMMemoryManager::ELEMENT_OBJECT )
            dsd_xml_element_1( fDocument, name, ull_line, ull_col );
    };
};
XERCES_CPP_NAMESPACE_END

#endif


#endif // USE_OLD_XERCES
