XSL/HSL README

What is XSL?
XSL stands for EXtensible Stylesheet Language. It is an xml-based syntax for 
transforming xml documents, normal xsl files are included into a xml document 
like CSS Files are into a HTML page.

How differs HSL from XSL?
HSL only supports inline elements of XSL inside an xml document but no rule based
transformation of the document by (automatic) application of the specified 
templates to the document. In a XSL Stylesheet XPath selectors refer to the document 
it is applied to whereas in HSL they refer to an internal data tree. So HLS really 
is more like a PHP page using the syntax of xsl. Furthermore only specific parts 
of the XSL definition are implemented.


Concepts used in HSL:

Selectors: a slash separated list of entries, i.e. lang/html/all/welcome
A selector describes an element in a tree and is used to include external data
into the generated page. Other XPath selector syntax is not supported.

Variables: $name
A Variable is a storage for a generated selector, it is usefull in loops and
template calls. HSL only supports ONE variable at a time, any existing variable is
discarded when another one is set. If you try to use any other variable than the
one last set an error is generated.

Supported XSL Elements:

<xsl:value-of select="selector"/>
---------------------------------
The tag is replaced with data associated with the specified selector. Using the
current variable as the selector is supported. (Variable must contain a valid 
selector, printing the content of the variable is not supported.)
Additionally an encoding for the value can be specified. Supported encodings
are: html (default), uri, js (string), utf8 (plain) and b64 (Base64)
Example:
<p><xsl:value select="user/name" /></p>
<xsl:value select="user/name enc:uri" />
becomes
<p>Prog01</p>

<xsl:for-each select="selector">
---------------------------------
The content of evaluated and written for every element of the list specified by
the selector. Specifying the variable as the selector is not supported and
implementing this would be of no value as there does not exist a "list of lists"
entry. All data paths that support / require iteration can be found in 
ds_xsl::m_cb_no_childs
Example:
<xsl:for-each select="user/portlet">
    <span><xsl:value-of select="user/portlet/handle"/></span>
</xsl:for-each>
becomes:
    <span>wsg</span>
    <span>jterm</span>
    <span>settings</span>
    ...

<xsl:if test="expression">
---------------------------------
The content of the tag is only written to the generated page if the expression
evaluates to true. The following types of expressions are supported:
- "selector"         =>  value > 0
- "not(selector)"    => -value > 0   this not the same as !(value > 0) !!!
- "selector op int|string"         =>  value op int|string
- "not(selector op int|string)"    => -value op int|string
The selector in the expression can always be replaced by the current variable, then
the content of the variable will be used as the selector. For how selectors are 
resolved to values see ds_xsl::m_cb_is_true. Many Strings resolve to their
lengths, and selectors for lists resolve either to the list length or always to 
1 if the associated list is non empty and 0 (!) otherwise, most selectors representing 
a boolean evaluate to -1/1 here. String comparison is only supported for selectors 
from lang/ group or without a special value handling and represents a comparison 
based on lexiographic order. The String values of Selectors that do not have a 
special handling are tried to be convertet to int if used in an integer comparison, 
if this fails the string length is used. 

op can be one of the following operations (See achr_xsl_compare)
"&gt;",         // greater >
"&gt;=",        // greater equal >=
"&lt;",         // lower <
"&lt;=",        // lower equal <=
"==",           // equal
"!="            // not equal

Examples:
<xsl:if test="user/jwtsa-config &lt;= 0">
    <option disabled><xsl:value-of select="lang/html/welcome/empty" /></option>
</xsl:if>

<xsl:for-each select="user/portlet">
    <xsl:if test="not(user/portlet/hide)">
    <xsl:if test="user/portlet/open">
    <xsl:if test="user/portlet/name != settings">
        <xsl:call-template name="portlet"/>
    </xsl:if>
    </xsl:if>
    </xsl:if>
</xsl:for-each>

<xsl:attribute name="string">
---------------------------------
adds an attribute to the preceeding/outer tag with name given by the attribute
and value of the contents of the tag.

Example:
<a id="logo"> 
    <xsl:attribute name="href"><xsl:value-of select="user/welcomesite"/></xsl:attribute>
</a>
Becomes:
<a id = "logo" href="/protected/welcome.hsl">
</a>

<xsl:template match="id">
---------------------------------
Declares a template identified by id. Templates must be declared at the root 
level of the document and are ignored if present inside other tags.
All templates are gathered before interpretation of the file and may therefore
be used everywhere in the file independent from declaration order

Example:
<xsl:template match="html-header">
    <link rel="shortcut icon"><xsl:attribute name="href">//<xsl:value-of select="rdvpn/iws/host"/>/public/img/favicon.ico</xsl:attribute></link>
    <link rel="stylesheet" href="/public/css/hobrdvpn.css" />
    <title>HOB RD VPN</title>
    <script src="/public/js/portal.js"></script>
</xsl:template>

<xsl:call-template name="id"/>
---------------------------------
Evaluate a template. Replace the tag with the contents of the template referenced
by id. The iterator position of a surrounding for-each loop can be used inside of
the template and the value of the variable (context is global), other than this
there exists no method of parametrizing a template call.

Example:
    <xsl:call-template name="html-header"/>
Becomes:
    <link rel="shortcut icon" href="//a7.hob.de/public/img/favicon.ico"></link>
    <link rel="stylesheet" href="/public/css/hobrdvpn.css" />
    <title>HOB RD VPN</title>
    <script src="/public/js/portal.js"></script>


<xsl:variable name="id"/>
---------------------------------
Set the value of the variable. The name of the variable is set to id and its value
to the content of the tag.

Example:
<xsl:variable name="name">lang/html/welcome/<xsl:value-of select="user/portlet/name"/>/title</xsl:variable>
<p><xsl:value-of select="$name"/></p>
Becomes:
<p>Filesystems</p>

<xsl:include href="filepath"/>
---------------------------------
Includes templates from another file. Includes must like Templates be declared at 
the root level of the document and are ignored if present inside other tags.
It is treated as if all template and include tags from the referenced file are 
placed inside the file to be interpeted.
The filepath may either be absolute, based on the www dir or relativ to the 
current file.

Example:
<xsl:include href="/public/template_header.hsl" />

<xsl:comment>
---------------------------------
A true comment in an hsl file. The contents of the element will be emitted
when the page is served to a client. But still must be valid xml, for serverside
parsing of the document.

Example:
<xsl:comment>No Client will see this!</xsl:comment>