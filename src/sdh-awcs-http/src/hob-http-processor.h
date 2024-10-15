#ifndef _HOB_HTTP_PROCESSOR_H
#define _HOB_HTTP_PROCESSOR_H
/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| PROGRAM-NAME                                                        |*/
/*| ============                                                        |*/
/*|   hob-http-processor.h                                              |*/
/*|   header file for http processor                                    |*/
/*|                                                                     |*/
/*| COPYRIGHT                                                           |*/
/*| =========                                                           |*/
/*|   Copyright (C) HOB Germany 2011                                    |*/
/*|                                                                     |*/
/*| AUTHOR                                                              |*/
/*| ======                                                              |*/
/*|   Michael Jakobs                                                    |*/
/*|                                                                     |*/
/*| DATE                                                                |*/
/*| ====                                                                |*/
/*|   01/19/2011                                                        |*/
/*|                                                                     |*/
/*| NEEDED INCLUDES                                                     |*/
/*| ===============                                                     |*/
/*|   hob-xsclib01.h                   - for gather structure           |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| forward declarations:                                               |*/
/*+---------------------------------------------------------------------+*/
struct dsd_gather_i_1;

/*+---------------------------------------------------------------------+*/
/*| defines:                                                            |*/
/*+---------------------------------------------------------------------+*/
#define DEF_HTTP_REQUEST  1
#define DEF_HTTP_RESPONSE 2

/*+---------------------------------------------------------------------+*/
/*| http methods:                                                       |*/
/*+---------------------------------------------------------------------+*/
enum ied_http_methods {                   /* compare to dss_http_methods */
    ied_mt_http_unknown         = -1,
    ied_mt_http_get             =  0,
    ied_mt_http_head            =  1,
    ied_mt_http_post            =  2,
    ied_mt_http_put             =  3,
    ied_mt_http_options         =  4,
    ied_mt_http_delete          =  5,
    ied_mt_http_trace           =  6,
    ied_mt_http_connect         =  7,
    ied_mt_http_bdelete         =  8,
    ied_mt_http_bmove           =  9,
    ied_mt_http_bproppatch      = 10,
    ied_mt_http_copy            = 11,
    ied_mt_http_lock            = 12,
    ied_mt_http_mkcol           = 13,
    ied_mt_http_move            = 14,
    ied_mt_http_poll            = 15,
    ied_mt_http_propfind        = 16,
    ied_mt_http_proppatch       = 17,
    ied_mt_http_subscribe       = 18,
    ied_mt_http_search          = 19,
    ied_mt_http_bcopy           = 20,
    ied_mt_http_bpropfind       = 21,
    ied_mt_http_notify          = 22,
    ied_mt_http_unlock          = 23,
    ied_mt_http_unsubscribe     = 24,
    ied_mt_http_x_ms_enumatts   = 25
};

/*+---------------------------------------------------------------------+*/
/*| http versions:                                                      |*/
/*+---------------------------------------------------------------------+*/
enum ied_http_versions {                 /* compare to dss_http_versions */
    ied_vs_http_unknown = -1,
    ied_vs_http_0_9     =  9,   // HTTP/0.9
    ied_vs_http_1_0     = 10,   // HTTP/1.0
    ied_vs_http_1_1     = 11    // HTTP/1.1
};

/*+---------------------------------------------------------------------+*/
/*| http header lines:                                                  |*/
/*+---------------------------------------------------------------------+*/
enum ied_http_hdr_lines {               /* compare to dss_http_hdr_lines */
    ied_hdr_ln_http_unknown                 = -1,
    ied_hdr_ln_http_accept                  =  0,   // Content-Types that are acceptable                                                                            Accept: text/plain
    ied_hdr_ln_http_accept_charset          =  1,   // Character sets that are acceptable                                                                           Accept-Charset: iso-8859-5
    ied_hdr_ln_http_accept_encoding         =  2,   // Acceptable encodings                                                                                         Accept-Encoding: compress, gzip
    ied_hdr_ln_http_accept_language         =  3,   // Acceptable languages for response                                                                            Accept-Language: da
    ied_hdr_ln_http_accept_ranges           =  4,   // Allows the server to indicate its acceptance of range requests for a resource                                Accept-Ranges: bytes
    ied_hdr_ln_http_age                     =  5,   // The age the object has been in a proxy cache in seconds                                                      Age: 12
    ied_hdr_ln_http_allow                   =  6,   // Valid actions for a specified resource. To be used for a 405 Method not allowed                              Allow: GET, HEAD
    ied_hdr_ln_http_authorization           =  7,   // Authentication credentials for HTTP authentication                                                           Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
    ied_hdr_ln_http_cache_control           =  8,   // Used to specify directives that MUST be obeyed by all caching mechanisms along the request/response chain    Cache-Control: no-cache
    ied_hdr_ln_http_connection              =  9,   // What type of connection the user-agent would prefer                                                          Connection: close
    ied_hdr_ln_http_content_disposition     = 10,   // An opportunity to raise a "File Download" dialogue box for a known MIME type                                 Content-Disposition: attachment; filename=fname.ext
    ied_hdr_ln_http_content_encoding        = 11,   // The type of encoding used on the data                                                                        Content-Encoding: gzip
    ied_hdr_ln_http_content_language        = 12,   // The language the content is in                                                                               Content-Language: da
    ied_hdr_ln_http_content_length          = 13,   // The length of the response body in 8-bit bytes                                                               Content-Length: 348
    ied_hdr_ln_http_content_location        = 14,   // An alternate location for the returned data                                                                  Content-Location: /index.htm
    ied_hdr_ln_http_content_md5             = 15,   // An MD5 sum of the content of the response                                                                    Content-MD5: 3167b9c13ad2b6d36946493fc47976c8
    ied_hdr_ln_http_content_range           = 16,   // Where in a full body message this partial message belongs                                                    Content-Range: bytes 21010-47021/47022
    ied_hdr_ln_http_content_type            = 17,   // The mime-type of the body of the request (used with POST and PUT requests)                                   Content-Type: application/x-www-form-urlencoded
    ied_hdr_ln_http_cookie                  = 18,   // an HTTP cookie previously sent by the server with Set-Cookie (below)                                         Cookie: $Version=1; UserId=JohnDoe
    ied_hdr_ln_http_date                    = 19,   // The date and time that the message was sent                                                                  Date: Tue, 15 Nov 1994 08:12:31 GMT
    ied_hdr_ln_http_etag                    = 20,   // An identifier for a specific version of a resource, often a Message Digest, see ETag                         ETag: 737060cd8c284d8af7ad3082f209582d
    ied_hdr_ln_http_expect                  = 21,   // Indicates that particular server behaviors are required by the client                                        Expect: 100-continue
    ied_hdr_ln_http_expires                 = 22,   // Gives the date/time after which the response is considered stale                                             Expires: Thu, 01 Dec 1994 16:00:00 GMT
    ied_hdr_ln_http_host                    = 23,   // The domain name of the server (for virtual hosting), mandatory since HTTP/1.1                                Host: en.wikipedia.org
    ied_hdr_ln_http_if_match                = 24,   // Only perform the action if the client supplied entity matches the same entity on the server.                 If-Match: "737060cd8c284d8af7ad3082f209582d"
    ied_hdr_ln_http_if_modified_since       = 25,   // Allows a 304 Not Modified to be returned if content is unchanged                                             If-Modified-Since: Sat, 29 Oct 1994 19:43:31 GMT
    ied_hdr_ln_http_if_none_match           = 26,   // Allows a 304 Not Modified to be returned if content is unchanged, see HTTP ETag                              If-None-Match: "737060cd8c284d8af7ad3082f209582d"
    ied_hdr_ln_http_if_range                = 27,   // If the entity is unchanged, send me the part(s) that I am missing; otherwise, send me the entire new entity  If-Range: "737060cd8c284d8af7ad3082f209582d"
    ied_hdr_ln_http_if_unmodified_since     = 28,   // Only send the response if the entity has not been modified since a specific time.                            If-Unmodified-Since: Sat, 29 Oct 1994 19:43:31 GMT
    ied_hdr_ln_http_last_modified           = 29,   // The last modified date for the requested object, in RFC 2822 format                                          Last-Modified: Tue, 15 Nov 1994 12:45:26 GMT
    ied_hdr_ln_http_location                = 30,   // Used in redirection                                                                                          Location: http://www.w3.org/pub/WWW/People.html
    ied_hdr_ln_http_max_forwards            = 31,   // Limit the number of times the message can be forwarded through proxies or gateways.                          Max-Forwards: 10
    ied_hdr_ln_http_pragma                  = 32,   // Implementation-specific headers that may have various effects anywhere along the request-response chain.     Pragma: no-cache
    ied_hdr_ln_http_proxy_authenticate      = 33,   // Request authentication to access the proxy.                                                                  Proxy-Authenticate: Basic
    ied_hdr_ln_http_proxy_authorization     = 34,   // Authorization credentials for connecting to a proxy.                                                         Proxy-Authorization: Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==
    ied_hdr_ln_http_range                   = 35,   // Request only part of an entity.                                                                              Range: bytes=500-999
    ied_hdr_ln_http_referer                 = 36,   // This is the address of the previous web page from which a link to the currently requested page was followed. Referer: http://en.wikipedia.org/wiki/Main_Page
    ied_hdr_ln_http_retry_after             = 37,   // If an entity is temporarily unavailable, this instructs the client to try again after a specified period     Retry-After: 120
    ied_hdr_ln_http_server                  = 38,   // A name for the server                                                                                        Server: Apache/1.3.27 (Unix) (Red-Hat/Linux)
    ied_hdr_ln_http_set_cookie              = 39,   // an HTTP cookie                                                                                               Set-Cookie: UserID=JohnDoe; Max-Age=3600; Version=1
    ied_hdr_ln_http_te                      = 40,   // The transfer encodings the user is willing to accept.                                                        TE: trailers, deflate;q=0.5
    ied_hdr_ln_http_trailer                 = 41,   // The Trailer general field value indicates that the given set of header fields...                             Trailer: Max-Forwards
    ied_hdr_ln_http_transfer_encoding       = 42,   // The form of encoding used to safely transfer the entity to the user.                                         Transfer-Encoding: chunked
    ied_hdr_ln_http_upgrade                 = 43,   // Ask the server to upgrade to another protocol.                                                               Upgrade: HTTP/2.0, SHTTP/1.3, IRC/6.9, RTA/x11
    ied_hdr_ln_http_user_agent              = 44,   // The user agent string of the user agent                                                                      User-Agent: Mozilla/5.0 (Linux; X11; UTF-8)
    ied_hdr_ln_http_vary                    = 45,   // Tells downstream proxies how to match future request headers to decide ...                                   Vary: *
    ied_hdr_ln_http_via                     = 46,   // Informs the server of proxies through which the request was sent.                                            Via: 1.0 fred, 1.1 nowhere.com (Apache/1.1)
    ied_hdr_ln_http_warn                    = 47,   // A general warning about possible problems with the entity body.                                              Warn: 199 Miscellaneous warning
    ied_hdr_ln_http_www_authenticate        = 48,   // Indicates the authentication scheme that should be used to access the requested entity.                      WWW-Authenticate: Basic
    /* WebSocket Stuff */
    ied_hdr_ln_http_ws_key1                 = 49,
    ied_hdr_ln_http_ws_key2                 = 50,
    ied_hdr_ln_http_ws_key                  = 51,
    ied_hdr_ln_http_ws_origin               = 52,
    ied_hdr_ln_http_ws_protocol             = 53,
    ied_hdr_ln_http_ws_version              = 54,
    ied_hdr_ln_http_ws_accept               = 55,
    ied_hdr_ln_http_ws_nonce                = 56,
    ied_hdr_ln_http_ws_location             = 57
};

/*+---------------------------------------------------------------------+*/
/*| http status codes:                                                  |*/
/*| please watch http://en.wikipedia.org/wiki/List_of_HTTP_status_codes |*/
/*+---------------------------------------------------------------------+*/
enum ied_http_status {                    /* compare to achs_http_status */
    ied_st_http_unknown                         = 0,
    /*
        1xx Informational
        Request received, continuing process.
        This class of status code indicates a provisional response, consisting only of the Status-Line and optional headers, and is terminated by an empty u. Since HTTP/1.0 did not define any 1xx status codes, servers must not send a 1xx response to an HTTP/1.0 client except under experimental conditions.
    */
    ied_st_http_continue                        = 100,  // This means that the server has received the request headers, and that the client should proceed to send the request body (in the case of a request for which a body needs to be sent; for example, a POST request). If the request body is large, sending it to a server when a request has already been rejected based upon inappropriate headers is inefficient. To have a server check if the request could be accepted based on the request's headers alone, a client must send Expect: 100-continue as a header in its initial request (see RFC 2616 §14.20: Expect header) and check if a 100 Continue status code is received in response before continuing (or receive 417 Expectation Failed and not continue).
    ied_st_http_switching_protocols             = 101,
    ied_st_http_processing                      = 102,  //(WebDAV) (RFC 2518)
    ied_st_http_request_uri_too_long_ie         = 122,  // A Microsoft extension which occurs only in IE7, when the request URI is longer than 2032 characters.
    /*
        2xx Success
        The action was successfully received, understood, and accepted.
        This class of status code indicates that the client's request was successfully received, understood, and accepted.
    */
    ied_st_http_ok                              = 200,  // Standard response for successful HTTP requests.
    ied_st_http_created                         = 201,  // The request has been fulfilled and resulted in a new resource being created.
    ied_st_http_accepted                        = 202,  // The request has been accepted for processing, but the processing has not been completed. The request might or might not eventually be acted upon, as it might be disallowed when processing actually takes place.
    ied_st_http_non_authoritative_info          = 203,  // Non-Authoritative Information (since HTTP/1.1)
    ied_st_http_no_content                      = 204,
    ied_st_http_reset_content                   = 205,
    ied_st_http_partial_content                 = 206,  // Notice that a file has been partially downloaded. This is used by tools like wget to enable resuming of interrupted downloads, or split a download into multiple simultaneous streams.
    ied_st_http_multi_status                    = 207,  // The message body that follows is an XML message and can contain a number of separate response codes, depending on how many sub-requests were made.
    /*
        3xx Redirection
        The client must take additional action to complete the request.
        This class of status code indicates that further action needs to be taken by the user agent in order to fulfil the request. The action required may be carried out by the user agent without interaction with the user if and only if the method used in the second request is GET or HEAD. A user agent should not automatically redirect a request more than five times, since such redirections usually indicate an infinite loop.
    */
    ied_st_http_multiple_choices                = 300,  // Indicates multiple options for the resource that the client may follow. It, for instance, could be used to present different format options for video, list files with different extensions, or word sense disambiguation.
    ied_st_http_moved_permanently               = 301,  // This and all future requests should be directed to the given URI.
    ied_st_http_found                           = 302,  // This is the most popular redirect code, but also an example of industrial practice contradicting the standard. HTTP/1.0 specification (RFC 1945) required the client to perform a temporary redirect (the original describing phrase was "Moved Temporarily"), but popular browsers implemented it as a 303 See Other. Therefore, HTTP/1.1 added status codes 303 and 307 to disambiguate between the two behaviours. However, the majority of Web applications and frameworks still use the 302 status code as if it were the 303.
    ied_st_http_see_other                       = 303,  // The response to the request can be found under another URI using a GET method. When received in response to a PUT, it should be assumed that the server has received the data and the redirect should be issued with a separate GET message.
    ied_st_http_not_modified                    = 304,  // Indicates the resource has not been modified since last requested. Typically, the HTTP client provides a header like the If-Modified-Since header to provide a time against which to compare. Utilizing this saves bandwidth and reprocessing on both the server and client.
    ied_st_http_use_proxy                       = 305,  // Many HTTP clients (such as Mozilla[2] and Internet Explorer) do not correctly handle responses with this status code, primarily for security reasons.
    ied_st_http_siwtch_proxy                    = 306,  // No longer used.
    ied_st_http_temporary_redirect              = 307,  // In this occasion, the request should be repeated with another URI, but future requests can still use the original URI. In contrast to 303, the request method should not be changed when reissuing the original request. For instance, a POST request must be repeated using another POST request.
    /*
        4xx Client Error
        The 4xx class of status code is intended for cases in which the client seems to have erred. Except when responding to a HEAD request, the server should include an entity containing an explanation of the error situation, and whether it is a temporary or permanent condition. These status codes are applicable to any request method. User agents should display any included entity to the user. These are typically the most common error codes encountered while online.
    */
    ied_st_http_bad_request                     = 400,  // The request contains bad syntax or cannot be fulfilled.
    ied_st_http_unauthorized                    = 401,  // Similar to 403 Forbidden, but specifically for use when authentication is possible but has failed or not yet been provided. See Basic access authentication and Digest access authentication.
    ied_st_http_payment_required                = 402,  // The original intention was that this code might be used as part of some form of digital cash or micropayment scheme, but that has not happened, and this code has never been used.
    ied_st_http_forbidden                       = 403,  // The request was a legal request, but the server is refusing to respond to it. Unlike a 401 Unauthorized response, authenticating will make no difference.
    ied_st_http_not_found                       = 404,  // The requested resource could not be found but may be available again in the future. Subsequent requests by the client are permissible.
    ied_st_http_method_not_allowed              = 405,  // A request was made of a resource using a request method not supported by that resource; for example, using GET on a form which requires data to be presented via POST, or using PUT on a read-only resource.
    ied_st_http_not_acceptable                  = 406,
    ied_st_http_proxy_auth_required             = 407,  // proxy authentication required
    ied_st_http_request_timeout                 = 408,  // Client failed to continue the request
    ied_st_http_conflict                        = 409,  // Indicates that the request could not be processed because of conflict in the request, such as an edit conflict. This kind of response is also generated by a registrar server to reject a registration request which has a conflicting action parameter[citation needed].
    ied_st_http_gone                            = 410,  // Indicates that the resource requested is no longer available and will not be available again. This should be used when a resource has been intentionally removed; however, in practice, a 404 Not Found is often issued instead. Upon receiving a 410 status code, the client should not request the resource again in the future. Clients such as search engines should remove the resource from their indexes to prevent repeated requests.
    ied_st_http_length_required                 = 411,  // The request did not specify the length of its content, which is required by the requested resource.
    ied_st_http_precondition_failed             = 412,
    ied_st_http_request_entity_too_large        = 413,  // The resource that was requested is too large to transmit using the current protocol.
    ied_st_http_request_uri_too_long            = 414,  // The URI provided was too long for the server to process.
    ied_st_http_unsupported_media_type          = 415,  // The request did not specify any media types that the server or resource supports. For example the client specified that an image resource should be served as image/svg+xml, but the server cannot find a matching version of the image.
    ied_st_http_requested_range_not_satisfiable = 416,  // The client has asked for a portion of the file, but the server cannot supply that portion (for example, if the client asked for a part of the file that lies beyond the end of the file).
    ied_st_http_expectation_failed              = 417,
    ied_st_http_im_a_teapot                     = 418,  // The HTCPCP server is a teapot. The responding entity MAY be short and stout. Defined by the April Fools' specification RFC 2324. See Hyper Text Coffee Pot Control Protocol for more information.
    ied_st_http_unprocessable_entity            = 422,  // (WebDAV) (RFC 4918), The request was well-formed but was unable to be followed due to semantic errors.
    ied_st_http_locked                          = 423,  // (WebDAV) (RFC 4918), The resource that is being accessed is locked
    ied_st_http_failed_dependency               = 424,  // (WebDAV) (RFC 4918), The request failed due to failure of a previous request (e.g. a PROPPATCH).
    ied_st_http_unordered_collection            = 425,  // Defined in drafts of WebDav Advanced Collections, but not present in "Web Distributed Authoring and Versioning (WebDAV) Ordered Collections Protocol" (RFC 3648).
    ied_st_http_upgrade_required                = 426,  // (RFC 2817), The client should switch to TLS/1.0.
    ied_st_http_retry_with                      = 449,  // A Microsoft extension. The request should be retried after doing the appropriate action.
    ied_st_http_blocked                         = 450,  // A Microsoft extension. Used for blocking sites with Windows Parental Controls.[3]
    /*
        5xx Server Error
        The server failed to fulfil an apparently valid request.
        Response status codes beginning with the digit "5" indicate cases in which the server is aware that it has encountered an error or is otherwise incapable of performing the request. Except when responding to a HEAD request, the server should include an entity containing an explanation of the error situation, and indicate whether it is a temporary or permanent condition. Likewise, user agents should display any included entity to the user. These response codes are applicable to any request method.
    */
    ied_st_http_internal_server_error           = 500,
    ied_st_http_not_implemented                 = 501,  // This error should be very rare in any Web browser. It is more likely if the client is not a Web browser—particularly if the Web server is old. In either case if the client has specified a valid request type, then the Web server is either responding incorrectly or simply needs to be upgraded.
    ied_st_http_bad_gateway                     = 502,
    ied_st_http_service_unavailable             = 503,
    ied_st_http_gateway_timeout                 = 504,
    ied_st_http_http_version_not_supported      = 505,
    ied_st_http_variant_also_negotiates         = 506,  // (RFC 2295)
    ied_st_http_insufficient_storage            = 507,  // (WebDAV) (RFC 4918)
    ied_st_http_bandwidth_limit_exceeded        = 509,  // (Apache bw/limited extension) This status code, while used by many servers, is not specified in any RFCs.
    ied_st_http_not_extended                    = 510   // (RFC 2774)
};

enum ied_url_protos {
    ied_proto_not_supported = -1,
    ied_proto_http          =  0,
    ied_proto_https         =  1,
    ied_proto_ws            =  2,
    ied_proto_wss           =  3
};

/*+---------------------------------------------------------------------+*/
/*| http header structures:                                             |*/
/*+---------------------------------------------------------------------+*/
typedef struct dsd_http_request {
    enum ied_http_methods        ienc_method;   /* request method        */
    /*
        splitted url (all in utf8)
           -> host part (if absolute request)
           -> path part
           -> query part (if existing)
    */
    enum ied_url_protos          ienc_proto;    /* protocol              */
    char                         *achc_host;    /* host pointer in utf8  */
    int                          inc_host_len;  /* length of host        */
    char                         *achc_path;    /* path pointer in utf8  */
    int                          inc_path_len;  /* length of path        */
    char                         *achc_query;   /* query pointer in utf8 */
    int                          inc_query_len; /* length of query       */

    enum ied_http_versions       ienc_version;  /* HTTP version          */
} dsd_http_request;


typedef struct dsd_http_response {
    enum ied_http_versions       ienc_version;  /* HTTP version          */
    enum ied_http_status         ienc_status;   /* status code           */
    char                         *achc_key;     /* status keyword        */
    int                          inc_len_key;   /* length of keyword     */
} dsd_http_response;


typedef struct dsd_http_known_line {
    char                        *achc_value;    /* value of line         */
    int                         inc_length;     /* length of value       */
} dsd_http_known_line;

typedef struct dsd_http_unknown_line {
    char                        *achc_line;     /* complete line         */
    int                         inc_length;     /* length of line        */
} dsd_http_unknown_line;

typedef struct dsd_http_hdr_line {
    enum ied_http_hdr_lines     ienc_type;      /* type of header line   */
    union {
        dsd_http_known_line     dsc_known;      /* known line            */
        dsd_http_unknown_line   dsc_unkown;     /* unknown line          */
    } u;
} dsd_http_hdr_line;


typedef struct dsd_http_header {
    int                          inc_type;      /* type of header 
                                                       DEF_HTTP_REQUEST
                                                    or DEF_HTTP_RESPONSE */
    union {
        struct dsd_http_request  dsc_request;   /* request header        */
        struct dsd_http_response dsc_response;  /* response header       */
    } u;
    size_t                       uinc_lines;    /* number of lines       */
    struct dsd_http_hdr_line     *adsc_lines;   /* list of hdr lines     */
} dsd_http_header;


typedef struct dsd_http_trailer {
    size_t                       uinc_lines;    /* number of lines       */
    struct dsd_http_hdr_line     *adsc_lines;   /* list of hdr lines     */
} dsd_http_trailer;


/*+---------------------------------------------------------------------+*/
/*| http callback methods:                                              |*/
/*+---------------------------------------------------------------------+*/
typedef struct dsd_http_parser_cbs {
    void *avc_usrfld;                        // user field for callbacks

    /**
     * function pointer amc_alloc
     *   will be called if parser needs to allocate memory
     *
     * @param[in]   void*                    pointer to given user field
     * @param[in]   size_t                   size of memory
     * @return      void*                    pointer to memory
     *                                       or NULL in error cases
    */
    void* (*amc_alloc)        ( void*, size_t );

    /**
     * function pointer amc_free
     *   will be called if parser needs to free memory
     *
     * @param[in]   void*                    pointer to given user field
     * @param[in]   void*                    pointer to be freed
     * @return      void*                    pointer to memory
     *                                       or NULL in error cases
    */
    void (*amc_free)          ( void*, void* );

    /**
     * function pointer amc_header_compl
     *  will be called when incoming HTTP header is complete
     *
     * @param[in]   void*                    pointer to given user field
     * @param[in]   struct dsd_http_header*  pointer to parsed header
     * @return      BOOL                     TRUE  = continue working
     *                                       FALSE = error => stop
    */
    BOOL (*amc_header_compl)  ( void*, struct dsd_http_header* );

    /**
     * function pointer amc_data_block
     *  will be called when a data block is found in data
     *
     * ATTENTION:
     * ----------
     *  don't forget to mark gather as processed!
     *
     * @param[in]   void*                    pointer to given user field
     * @param[in]   struct dsd_http_header*  pointer to parsed header
     * @param[in]   struct dsd_gather_i_1*   data block
     * @return      BOOL                     TRUE  = continue working
     *                                       FALSE = error => stop
    */
    BOOL (*amc_data_block)    ( void *,
								struct dsd_http_header*,
                                struct dsd_gather_i_1* );

    /**
     * function pointer amc_trailer_compl
     *  will be called when trailing header lines are complete
     *
     * @param[in]   void*                    pointer to given user field
     * @param[in]   struct dsd_http_header*  pointer to parsed header
     * @param[in]   struct dsd_http_trailer* pointer to parsed header
     * @return      BOOL                     TRUE  = continue working
     *                                       FALSE = error => stop
    */
    BOOL (*amc_trailer_compl) ( void*, struct dsd_http_header*,
                                struct dsd_http_trailer* );

    /**
     * function pointer amc_ws_handshake
     *  will be called when parser detects an opening websockets
     *  handshake
     *
     * @param[in]   void*                    pointer to given user field
     * @param[in]   struct dsd_http_header*  pointer to parsed header
     * @param[in]   struct dsd_gather_i_1*   data block
     * @return      BOOL                     TRUE  = continue working
     *                                       FALSE = error => stop
    */
    BOOL (*amc_ws_handshake)  ( void*, struct dsd_http_header*, struct dsd_gather_i_1* );
} dsd_http_parser_cbs;


typedef struct dsd_http_creator_cbs {
    void *avc_usrfld;                        // user field for callbacks

    /**
     * function pointer amc_alloc
     *   will be called if creator needs to allocate memory
     *
     * @param[in]   void*                    pointer to given user field
     * @param[in]   size_t                   size of memory
     * @return      void*                    pointer to memory
     *                                       or NULL in error cases
    */
    void* (*amc_alloc) ( void*, size_t );

    /**
     * function pointer amc_free
     *   will be called if creator needs to free memory
     *
     * @param[in]   void*                    pointer to given user field
     * @param[in]   void*                    pointer to be freed
     * @return      void*                    pointer to memory
     *                                       or NULL in error cases
    */
    void (*amc_free)   ( void*, void* );

    /**
     * function pointer amc_out
     *  will be called when creator has created some output
     *
     * @param[in]   void*                    pointer to given user field
     * @param[in]   const char*              pointer to output data
     * @param[in]   size_t                   length of output data
     * @return      BOOL                     TRUE  = continue working
     *                                       FALSE = error => stop
    */
    BOOL (*amc_out)    ( void*, const char*, size_t );
} dsd_http_creator_cbs;


/*+---------------------------------------------------------------------+*/
/*| public functions http parser:                                       |*/
/*+---------------------------------------------------------------------+*/
/**
 * public function m_new_http_parser
 *   create a new http parse instance
 *
 * @param[in]   dsd_http_parser_cbs *adsp_cbs           parser callbacks
 * @param[in]   size_t              uinp_max_hdr_len    max header length
 * @param[in]   size_t              uinp_max_lines      max number of header lines
 * @param[in]   size_t              uinp_max_url_len    max length of req url
 * @return      void*                                   parser handle
 *                                                      NULL in error cases
*/
extern void* m_new_http_parser( struct dsd_http_parser_cbs *adsp_cbs,
                                size_t uinp_max_hdr_len,
                                size_t uinp_max_lines,
                                size_t uinp_max_url_len );

/**
 * public function m_del_http_parser
 *   delete http parser
 *
 * @param[in]   void            *avp_parser     parser handle
*/
extern void m_del_http_parser( void **aavp_parser );

/**
 * public function m_parse_http
 *   process given data through http parser
 *
 * @param[in]   void            *avp_parser     parser handle
 * @param[in]   dsd_gather_i_1  *adsp_data      data to be parsed
 * @param[out]  struct dsd_html5_event_out     *adsp_parsed_events
 * @return      BOOL
*/
extern BOOL m_parse_http( void                    *avp_parser, 
                          struct dsd_gather_i_1   *adsp_data );

/**
 * public function m_search_hdr_line
 *   search for header line with given key
 *
 * @param[in]       dsd_http_header     *adsp_header    http header structure
 * @param[in]       ied_http_hdr_lines  ienp_line       line type
 * @param[in/out]   size_t              *auin_offset    in:  start at line number
 *                                                      out: found at line number
 * @return          dsd_http_hdr_line*                  found header line
 *                                                      or NULL if not found
*/
extern struct dsd_http_hdr_line* m_search_hdr_line( struct dsd_http_header *adsp_header,
                                                    enum ied_http_hdr_lines ienp_line,
                                                    size_t *auin_offset );

/*+---------------------------------------------------------------------+*/
/*| public functions http creator:                                      |*/
/*+---------------------------------------------------------------------+*/
/**
 * public function m_new_http_creator
 *   create a new http creator instance
 *
 * @param[in]   dsd_http_creator_cbs *adsp_cbs          creator callbacks
 * @param[in]   size_t               uinp_max_line_len  max header line length
 * @return      void*                                   creator handle
 *                                                      NULL in error cases
*/
extern void* m_new_http_creator( struct dsd_http_creator_cbs *adsp_cbs,
                                 size_t uinp_max_line_len );

/**
 * public function m_del_http_creator
 *   delete http creator
 *
 * @param[in]   void            **aavp_creator    creator handle
*/
extern void m_del_http_creator( void **aavp_creator );

/**
 * public function m_create_request
 *   create new request header
 *
 * @param[in]   void                *avp_creator    creator handle
 * @param[in]   ied_http_methods    ienp_method     request method
 * @param[in]   const char          *achp_url       requested url
 * @param[in]   int                 inp_url_len     length of url
 * @param[in]   ied_http_versions   ienp_version    HTTP version
 * return       BOOL
*/
extern BOOL m_create_request( void *avp_creator,
                              enum ied_http_methods  ienp_method,
                              const char             *achp_url,
                              int                    inp_url_len,
                              enum ied_http_versions ienp_version );

/**
 * public function m_create_response
 *   create new response header
 *
 * @param[in]   void                *avp_creator    creator handle
 * @param[in]   ied_http_versions   ienp_version    HTTP version
 * @param[in]   ied_http_status     ienp_status     status code
 * @return      BOOL
*/
extern BOOL m_create_response( void *avp_creator,
                               enum ied_http_versions ienp_version,
                               enum ied_http_status   ienp_status   );


/**
 * public function m_create_line_f
 *   create string header line and add it to output
 *
 * @param[in]   void                *avp_creator    creator handle
 * @param[in]   ied_http_hdr_lines  ienp_line       line type
 * @param[in]   const char          *achp_format    format
 * @param[in]   ...
 * @return      BOOL
*/
extern BOOL m_create_line_f( void *avp_creator,
                             enum ied_http_hdr_lines ienp_line,
                             const char *achp_format, ... );

/**
 * public function m_create_line_s
 *   create string header line and add it to output
 *
 * @param[in]   void                *avp_creator    creator handle
 * @param[in]   ied_http_hdr_lines  ienp_line       line type
 * @param[in]   const char          *achp_value     line value
 * @param[in]   int                 inp_length      length of value
 * @return      BOOL
*/
extern BOOL m_create_line_s( void *avp_creator,
                             enum ied_http_hdr_lines ienp_line,
                             const char *achp_value, int inp_length );


/**
 * public function m_create_line_szt
 *   create string header line and add it to output
 *
 * @param[in]   void                *avp_creator    creator handle
 * @param[in]   ied_http_hdr_lines  ienp_line       line type
 * @param[in]   const char          *achp_value     line value zero terminated
 * @return      BOOL
*/
extern BOOL m_create_line_szt( void *avp_creator,
                               enum ied_http_hdr_lines ienp_line,
                               const char *achp_value             );

/**
 * public function m_create_line_n
 *   create numeric header line and add it to output
 *
 * @param[in]   void                *avp_creator    creator handle
 * @param[in]   ied_http_hdr_lines  ienp_line       line type
 * @param[in]   int                 inp_value       line value
 * @return      BOOL
*/
extern BOOL m_create_line_n( void *avp_creator,
                             enum ied_http_hdr_lines ienp_line,
                             int inp_value );

/**
 * public function m_finish_header
 *   end http header
 *
 * @param[in]   void                *avp_creator    creator handle
 * @return      BOOL
*/
extern BOOL m_finish_header( void *avp_creator );

#endif // _HOB_HTTP_PROCESSOR_H
