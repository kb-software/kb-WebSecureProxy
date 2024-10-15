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
        achc_encoding  = NULL;
        achc_public_id = NULL;
        achc_system_id = NULL;
        boc_flag       = false;
        adsc_stream    = new BinMemInputStream( achp_data, inp_len,
                                             BinMemInputStream::BufOpt_Reference,
                                             XMLPlatformUtils::fgMemoryManager );
    };

    // destructor:
    ~dsd_xml_mis_1() {
        adsc_stream = NULL; // get freed in Xerces:ScanDocument call, we will just reset the pointer
    };

    /**
     * public function dsd_xml_mis_1::m_create_stream
     *
     * @param[in]   XMLByte*    achp_data       pointer to xml data
     * @param[in]   int         inp_len         length of xml data
     * @return      nothing
    */
    void m_create_stream( XMLByte* achp_data, int inp_len )
    {
        adsc_stream = new BinMemInputStream( achp_data, inp_len,
                                             BinMemInputStream::BufOpt_Reference,
                                             XMLPlatformUtils::fgMemoryManager );
    }; // end of m_create_stream

    // inherited virtual getter functions:
    BinInputStream* makeStream()                   const { return adsc_stream; };
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
    const XMLCh*       achc_encoding;
    const XMLCh*       achc_public_id;
    const XMLCh*       achc_system_id;
    bool               boc_flag;
    BinMemInputStream* adsc_stream;
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


