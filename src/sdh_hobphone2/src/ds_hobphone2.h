#ifndef _DS_HOBPHONE2_H
#define _DS_HOBPHONE2_H

/*+---------------------------------------------------------------------+*/
/*|                                                                     |*/
/*| Program:                                                            |*/
/*| ========                                                            |*/
/*|   ds_hobphone2                                                      |*/
/*|   main working class for sdh_hobphone2                              |*/
/*|                                                                     |*/
/*| Author:                                                             |*/
/*| =======                                                             |*/
/*|   Heino Stoemmer 2010/03                                            |*/
/*|                                                                     |*/
/*| Copyright:                                                          |*/
/*| ==========                                                          |*/
/*|   HOB GmbH Germany 2010                                             |*/
/*|                                                                     |*/
/*+---------------------------------------------------------------------+*/

/*+---------------------------------------------------------------------+*/
/*| includes:                                                           |*/
/*+---------------------------------------------------------------------+*/

#include <types_defines.h>
#include <hob-netw-01.h>
#include <ds_ldap.h>
#include <ds_hashtable.h>
#include <ds_xml.h>

#ifndef HOB_XSLUNIC1_H
	#define HOB_XSLUNIC1_H
	#include <hob-xslunic1.h>
#endif // HOB_XSLUNIC1_H

#ifndef _HOB_XSCLIB01_H
#define _HOB_XSCLIB01_H
#include <hob-xsclib01.h>
#endif

#include <sdh_hobphone2.h>

class ds_wsp_helper;                            // forward declaration
typedef struct dsd_sdh_config dsd_sdh_config_t; // forward declaration

#define DEBUG_RECONNECT 0
#define DEBUG_SYSMSG DEBUG_RECONNECT | 0
#define DEBUG_CHANNELS DEBUG_RECONNECT | 0
#define NO_DEVID 0

#define RELOAD_NAME_MAXLEN 255

/**
* Enumeration which defines the states of the SDH:
* GREETING, NORMAL or UNSUPPORTED_PROTOCOL if the handshake fails.
*/
enum ied_sdh_hobphone_state {
	SDH_HOBPHONE_STATE_GREETING,
    SDH_HOBPHONE_STATE_DISCONNECTED,
	SDH_HOBPHONE_STATE_UNSUPPORTED_PROTOCOL,
	SDH_HOBPHONE_STATE_NORMAL
};

enum ied_sdh_hobphone_runstate {    
    SDH_HOBPHONE_RUNSTATE_ERROR = -1,
    SDH_HOBPHONE_RUNSTATE_OK = 0,    
    SDH_HOBPHONE_RUNSTATE_SAVESDH = 1,
    SDH_HOBPHONE_RUNSTATE_RELOAD = 2,
    SDH_HOBPHONE_RUNSTATE_SHUTDOWN = 3,
    SDH_HOBPHONE_RUNSTATE_HELLO = 4,
    SDH_HOBPHONE_RUNSTATE_RELOAD2 = 8,
    SDH_HOBPHONE_RUNSTATE_OK_NODATA = 16
};

/**
* Enumeration which defines return values for this SDH. 
* In case of an exception the value should be unique so that the
* cause of the exception can be derived.
*/
enum ied_sdh_hobphone_status {
    // general
    SDH_HOBPHONE_STATUS_OK,
    SDH_HOBPHONE_STATUS_UNKNOWN_CHANNEL_TYPE,
    SDH_HOBPHONE_ILLEGAL_STATE,
    SDH_HOBPHONE_STATUS_SEND_FAILED,
    // system messages
    SDH_HOBPHONE_STATUS_INVALID_SYSTEM_MESSAGE,
    SDH_HOBPHONE_STATUS_UNSUPPROTED_IP_VERSION,
    // get configuration
    SDH_HOBPHONE_STATUS_ERROR_GETTING_CONFIG_INVALID_INETA,
    SDH_HOBPHONE_STATUS_ERROR_REGISTERING_SIP_REQUEST,
    // pbx configuration
    SDH_HOBPHONE_STATUS_ERROR_GETTING_CONFIG_SOURCE,
    SDH_HOBPHONE_STATUS_INVALID_LDAP_SRV,
    SDH_HOBPHONE_STATUS_ERROR_ACCESSING_LDAP,
    SDH_HOBPHONE_STATUS_ERROR_GETTING_PBX_CONFIG,
    SDH_HOBPHONE_STATUS_NO_PBX_CONFIG_FOUND,
    SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG,
    SDH_HOBPHONE_STATUS_EMPTY_PBX_CONFIG,
    SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_NAME,
    SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_INETA,
    SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_PORT,
    SDH_HOBPHONE_STATUS_INVALID_PBX_CONFIG_NO_UDP_GW,
    // user configuration
    SDH_HOBPHONE_STATUS_NO_USER_CONFIG,
    SDH_HOBPHONE_STATUS_ERROR_GETTING_PHONE_CONFIG,
    SDH_HOBPHONE_STATUS_NO_PHONE_CONFIG,
    SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG,
    SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG_NO_IDENT,
    SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG_NO_PBX_PROFILE_DEFINED,
    SDH_HOBPHONE_STATUS_INVALID_PHONE_CONFIG_PBX_PROFILE_NOT_FOUND,
    // create channel
    SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_NO_TYPE,
    SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_UNKNOWN_TYPE,
    SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_UNSUPPROTED_TYPE,
    SDH_HOBPHONE_STATUS_ERROR_CREATING_CHANNEL_NO_FREE_CHANNEL,
    SDH_HOBPHONE_STATUS_INVALID_CREATE_CHANNEL_MESSAGE_NO_CALL_ID,
    SDH_HOBPHONE_STATUS_INVALID_UDP_GW_CONFIGURATION,
    SDH_HOBPHONE_STATUS_ERROR_REGISTERING_UDP_REQUEST,
    // set channel
    SDH_HOBPHONE_STATUS_INVALID_SET_CHANNEL_MESSAGE_INVALID_CHANNEL_TYPE,
    SDH_HOBPHONE_STATUS_INVALID_SET_CHANNEL_MESSAGE_UNSUPPORTED_CHANNEL_TYPE,
    SDH_HOBPHONE_STATUS_INVALID_SET_CHANNEL_MESSAGE_INVALID_CHANNEL,
    SDH_HOBPHONE_STATUS_ERROR_SETTING_CHANNEL_NO_CHANNEL,
    // remove channel
    SDH_HOBPHONE_STATUS_INVALID_REMOVE_CHANNEL_MESSAGE_INVALID_CHANNEL_TYPE,
    SDH_HOBPHONE_STATUS_INVALID_REMOVE_CHANNEL_MESSAGE_UNSUPPORTED_CHANNEL_TYPE,
    SDH_HOBPHONE_STATUS_INVALID_REMOVE_CHANNEL_MESSAGE_INVALID_CHANNEL,
    SDH_HOBPHONE_STATUS_ERROR_REMOVING_CHANNEL_NO_CHANNEL,
    SDH_HOBPHONE_STATUS_ERROR_FREEING_SIP_REQUEST_NO_REQUEST,
    SDH_HOBPHONE_STATUS_ERROR_FREEING_UDP_REQUEST_NO_REQUEST,
    // redirect
    SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_SIP_TO_PBX_NO_REQUEST,
    SDH_HOBPHONE_STATUS_ERROR_REDIRECTING_UDP_TO_PBX_NO_REQUEST,
    // close request
    SDH_HOBPHONE_STATUS_ERROR_CLOSING_SIP_REQUEST_NO_REQUEST,
    SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_REQUEST_NO_REQUEST,
    SDH_HOBPHONE_STATUS_ERROR_CLOSING_SIP_REQUEST_CLOSE_FAILED,
    SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_REQUEST_CLOSE_FAILED,
    // NHASN
    SDH_HOBPHONE_STATUS_EMPTY_NHASN,
    SDH_HOBPHONE_STATUS_INCOMPLETE_NHASN,
    SDH_HOBPHONE_STATUS_NHASN_OUT_OF_RANGE,
    // set request - secondary exception
    SDH_HOBPHONE_STATUS_ERROR_SETTING_SIP_REQUEST,
    SDH_HOBPHONE_STATUS_ERROR_SETTING_UDP_REQUEST,
    // udp gate
    SDH_HOBPHONE_STATUS_ERROR_GETTING_RANDOM,
    SDH_HOBPHONE_STATUS_ERROR_CREATING_UPD_GATE,
    SDH_HOBPHONE_STATUS_ERROR_UNKNOWN_UDPGATE_STATE,
    SDH_HOBPHONE_STATUS_UDP_GATE_NOT_CONFIGURED,
    SDH_HOBPHONE_STATUS_INVALID_ENABLE_UDP_GATE_MESSAGE,
    SDH_HOBPHONE_STATUS_UDP_GATE_ENABLED,
    SDH_HOBPHONE_STATUS_UDP_GATE_DISABLED,
    SDH_HOBPHONE_STATUS_ERROR_INVALID_STATE_ON_ENABLE_UDP_GATE,
    SDH_HOBPHONE_STATUS_ERROR_CREATING_UDP_GATE_SUBCHANNEL,
    SDH_HOBPHONE_STATUS_ERROR_CLOSING_UDP_GATE_SUBCHANNEL,
    // cluster instance check
    SDH_HOBPHONE_STATUS_ERROR_ACTIVE_INSTANCE_ON_CLUSTER,
    SDH_HOBPHONE_STATUS_ERROR_CREATING_CMA,
    SDH_HOBPHONE_STATUS_VERSION_ERROR,
    //search number
    SDH_HOBPHONE_STATUS_NONFATAL = 200,
    SDH_HOBPHONE_STATUS_NUMSEARCH_NOTFOUND,
    SDH_HOBPHONE_STATUS_NUMSEARCH_INVALID_REQUEST ,
    SDH_HOBPHONE_STATUS_NUMSEARCH_LDAP_ERROR,
    SDH_HOBPHONE_STATUS_NUMSEARCH_ERROR,
    //ping
    SDH_HOBPHONE_STATUS_KEEPALIVE_ERROR,
    //reconnect
    SDH_HOBPHONE_STATUS_SHUTDOWN,
    //SIP
    SDH_HOBPHONE_STATUS_SIP_ERROR,
    SDH_HOBPHONE_STATUS_SIP_PARSER,
    //reload
    //client sent something wrong in the name
    SDH_HOBPHONE_STATUS_SAVESDH_NAMEERROR,
    //save the SDH for reload
    SDH_HOBPHONE_STATUS_SAVESDH_SAVE
};

/**
* Enumeration that defines the supported channel types used for 
* communication with the client.
*/
enum ied_sdh_hobphone_channel_type {
	SDH_HOBPHONE_CHANNEL_TYPE_UNDEFINED = -1, 
	SDH_HOBPHONE_CHANNEL_TYPE_SYSTEM,
	SDH_HOBPHONE_CHANNEL_TYPE_UDP_SIP,
	SDH_HOBPHONE_CHANNEL_TYPE_UDP,
    SDH_HOBPHONE_CHANNEL_TYPE_UDP_DIRECT
};
/* A character used to identify the channel type SYSTEM. */
const char SDH_HOBPHONE_CHAR_CHANNEL_TYPE_SYSTEM = '0';
/* A character used to identify the channel type UDP SIP. */
const char SDH_HOBPHONE_CHAR_CHANNEL_TYPE_UDP_SIP = '1';
/* A character used to identify the channel type UDP. */
const char SDH_HOBPHONE_CHAR_CHANNEL_TYPE_UDP = '2';
/* A character used to identify the channel type UDP direct. */
const char SDH_HOBPHONE_CHAR_CHANNEL_TYPE_UDP_DIRECT = '3';

/**
* A simple iterator over gather structures. The next and has_more 
* methods act as expected, except that calling next on an empty
* or completely read gather chain will return 0.
*/
class __declspec(dllexport) ds_gather_iterator {
public:
    /** 
    * Default constructor that builds an iterator over the given gatherchain with
    * a limited number of characters.
    * When all characters of the chain have been read using next or when the maximum
    * count is reached calling next will return 0 and calling has_more will return
    * false.
    * @param adsp_gather the first element of the gather chain
    * @param imp_max_length the maximum number of characters readable from this iterator
    */
	ds_gather_iterator(dsd_gather_i_1 *adsp_gather, int imp_max_length);
    /**
    * Gets the pointer to the next character in the gather chain or null if all where 
    * read. 
    * If the underlying gather structure is modified this iterator becomes invalid and 
    * will return 0.
    * @return a pointer to the next character in the gather chain or 0 if none left
    */
	char * m_next();
    /**
    * Gets the last returned character pointer or NULL if none was received yet.
    * @return the last pointer returned by the iterator of NULL
    */
    char * m_recall();
    /**
    * Returns true if the iterator contains at least one more valid character and
    * the maximum length of the iterator was not yet reached. Empty gather elements are
    * skipped.
	* If the underlying gather structure is modified this iterator becomes invalid and
    * will return false.
    * @return true, if the iterator contains more characters
    */
    BOOL m_has_more();
    /**
    * Marks the characters read so far as used by setting the beginning of a completely
    * read gather to the end pointer and by setting the beginning of a partial read
    * gather to the next not yet read value.
    */
	void m_mark_used();
    /**
    * Resets the internal pointers to the last values where mark_used was called or to
    * the inital values of the iterator. This can be used to restore a previous state if 
    * for instance, a comparison failed.
    */
	void m_reset();
    /**
    * Detects CR LF as line end and returns appends all characters except CR LF to the 
    * given hstring.
    * If no CR LF is detected the whole gather will be returned as char sequence.
    * @param hstrp_line a hstring to receive the detected line
    */
	void m_get_line(ds_hstring &hstrp_line);
    /**
     * Same as m_get_line but does not mark the data as used
     */
    void m_get_line_nomark(ds_hstring &hstrp_line);
    /**
    * Gets the gather of the last character read or the initial gather of the iterator.
    * As this method returns internals of the iterator changes to the gather might
    * corrupt the iterator. A typical usecase of this method is to retrieve the gather
    * and afterwards disregard the iterator.
    * @return a pointer to the current gather element
    */
	dsd_gather_i_1 *m_get_current_gather();
    /**
    * Gets the number of remaining characters until reaching the maximum length. This 
    * will not give the number of characters inside the iterator. Consistency between
    * the gather and the maximum length has to be insured by the constructor parameters.
    * @return the number of remaining char pointers until max length
    */
	int m_get_remaining_length();
    /**
    * Splits the gather chain at the last char pointer and returns the second part in
    * the given gather element. The second part contains all data that is not part of
    * this iterator.
    * Calling this on the input gather chain will lead to an unreachable second part
    * (unreachable for the GC). Therefore this method should only be used on self created
    * gather chains which will be destroyed by the caller.
    * @param adsp_return a gather element to receive the second part of the gather chain
    * used by this iterator
    */
    void m_split(dsd_gather_i_1 *adsp_return);
    /**
    * Creates a duplicate of iterator's gather chain containing only data valid inside
    * of this iterator. The original chain remains unchanged.
    * The elements of this chain are allocated, so caller has to insure that they are
    * destroyed after usage.
    * @param adsp_wsp_helper a pointer to a valid dsd_wsp_helper needed to allocate
    * memory
    * @return a pointer to the first gather element 
    */
    dsd_gather_i_1 * m_duplicate(ds_wsp_helper * const adsp_wsp_helper);
private:
    /* The first gather element used by this iterator or, after marking, the first element
    * containing unread data. */
	dsd_gather_i_1 *ads_anchor;
    /* The gather element containing the current character pointer. */
	dsd_gather_i_1 *ads_current;
    /* A pointer to the current character. */
	char *ach_current;
    /* The last character pointer returned by the iterator or NULL. */
    char *ach_last;
    /* The maximum number of characters that can be read from this iterator. After marking
    * this value is reduced to the remaining character count. */
	int im_max_length;
    /* The number of characters remaining starting at the current character. After reset
    * this value is the same as the max_length. */
	int im_remaining;
};

/** 
* A data capsule for the pbx entries in ldap configuration mode. It contains all neccessary
* data. The setter-methods delete old values when a new value is received.
*/
class ds_pbx_entry {
public:
    /**
    * Construct the entry using the given adsp_wsp_helper for memory allocation.
    * @param adsp_wsp_helper the helper to be used for memory allocation 
    */
    ds_pbx_entry(ds_wsp_helper *adsp_wsp_helper);
    /**
    * Destructor that will free all elements. Users should be aware of this!
    */
    ~ds_pbx_entry();
    /**
    * This new operator provides a way to create an instance of the class in a given memory
    * area.
    * @param av_location a pointer to the memory to be used; it has to be large enough - no checks
    * @return untyped pointer to the memory area; will be equal to av_location
    */
    void * operator new(size_t, void* av_location) {
		return av_location;
	}
    /**
    * Only implemented to avoid a warning. The delete operator should NEVER be used on 
    * instances of this class as the memory is managed by the WSP.
    * @param avo_ptr1 the pointer to the memory area
    * @param avo_ptr2 a pointer with no defined function
    */
    void operator delete(void *avo_ptr1, void *avo_ptr2) {};
    /**
    * Gets the entry's name.
    * @return the name of the entry
    */
    const char * m_get_name();
    /**
    * Gets the length of the entry's name in byte.
    * @return the length of the entry's name in byte
    */
    int m_get_name_len();
    /**
    * Gets the ineta of the pbx as a text expression.
    * @return the ineta of the pbx
    */
    const char * m_get_pbx_ineta();
    /**
    * Gets the length of the ineta in byte.
    * @return the length in byte
    */
    int m_get_pbx_ineta_len();
    /**
    * Gets the port of the pbx.
    * @return the port as text expression
    */
    const char * m_get_pbx_port();
    /**
    * Gets the length of the registrar port.
    * @return the length as int
    */
    int m_get_pbx_port_len();
   /**
    * Gets the ineta of the proxy as a text expression.
    * @return the ineta of the proxy
    */
    const char * m_get_proxy_ineta();
    /**
    * Gets the length of the proxy ineta in byte.
    * @return the length in byte
    */
    int m_get_proxy_ineta_len();
    /**
    * Gets the port of the proxy.
    * @return the port as text expression
    */
    const char * m_get_proxy_port();
    /**
    * Gets the length of the proxy port.
    * @return the length as int
    */
    int m_get_proxy_port_len();
    /**
    * Gets the protocol id.
    * @return the protocol
    */
    const char * m_get_protocolid();
    /**
    * Gets the length of the protocol id.
    * @return the length of the protocol id
    */
    int m_get_protocolid_len();
    /**
    * Gets the protocol name.
    * @return the protocol
    */
    const char * m_get_protocolname();
    /**
    * Gets the length of the protocol name.
    * @return the length of the protocol name
    */
    int m_get_protocolname_len();
    /**
    * Gets the name of the udp gw to use.
    * @return the name as text expression
    */
    const char * m_get_udp_gw_name();
    /**
    * Gets the length of the gw name.
    * @return the length as int
    */
    int m_get_udp_gw_name_len();
    /**
    * Set the comment to the char chain with the given length.
    * @param achp_comment the char chain to be used
    * @param imp_len the length in bytes
    */
    void m_set_comment(const char * const achp_comment, int imp_len);
    /**
    * Set the max session count to the given value.
    * @param imp_max_sessions
    */
    void m_set_max_sessions(int imp_max_sessions);
    /**
    * Set the name to the char chain with the given length.
    * @param achp_name the char chain to be used
    * @param imp_len the length in bytes
    */
    void m_set_name(const char * const achp_name, int imp_len);
    /**
    * Set the pbx ineta to the char chain with the given length.
    * @param achp_pbx_ineta the char chain to be used
    * @param imp_len the length in bytes
    */
    void m_set_pbx_ineta(const char * const achp_pbx_ineta, int imp_len);
    /**
    * Set the pbx port to the char chain with the given length.
    * @param achp_pbx_port the char chain to be used
    * @param imp_len the length in bytes
    */
    void m_set_pbx_port(const char * const achp_pbx_port, int imp_len);
    /**
    * Set the proxy ineta to the char chain with the given length.
    * @param achp_proxy_ineta the char chain to be used
    * @param imp_len the length in bytes
    */
    void m_set_proxy_ineta(const char *const achp_proxy_ineta, int imp_len);
    /**
    * Set the proxy port to the char chain with the given length.
    * @param achp_proxy_port the char chain to be used
    * @param imp_len the length in bytes
    */
    void m_set_proxy_port(const char *const achp_proxy_port, int imp_len);
    /**
    * Set the protocol id for this configuration.
    * @param achp_protocolid the char chain as id
    * @param imp_len the length of the id
    */
    void m_set_protocolid(const char * const achp_protocolid, int imp_len);
    /**
    * Set the protocol name for this configuration.
    * @param achp_protocolname the char chain as name
    * @param imp_len the length of the name
    */
    void m_set_protocolname(const char * const achp_protocolname, int imp_len);
    /**
    * Set the udp gw name to the char chain with the given length.
    * @param achp_udp_gw_name the char chain to be used
    * @param imp_len the length in bytes
    */
    void m_set_udp_gw_name(const char * const achp_udp_gw_name, int imp_len);

private:
    /* A pointer to the helper used to allocate and free memory. */
    ds_wsp_helper *ads_wsp_helper;
    /* The name of the entry. */
    char *ach_name;
    /* The name's length. */
    int im_name_len;
    /* A comment. */
    char *ach_comment;
    /* The length of the comment. */
    int im_comment_len;
    /* The ineta as text expression. */
    char *ach_pbx_ineta;
    /* The length of the ineta in bytes. */
    int im_pbx_ineta_len;    
    /* The port as text expression. */
    char *ach_pbx_port;
    /* The length of the port in bytes. */
    int im_pbx_port_len;
    /* The proxy ineta as text expression. */
    char *ach_proxy_ineta;
    /* The length of the proxy ineta in bytes. */
    int im_proxy_ineta_len;
    /* The proxy port as text expression. */
    char *ach_proxy_port;
    /* The length of the proxy port in bytes. */
    int im_proxy_port_len;
    /* The protocol id. */
    char *ach_protocolid;
    /* The length of the protocol id. */
    int im_protocolid_len;
    /* The protocol name. */
    char *ach_protocolname;
    /* The length of the protocol name. */
    int im_protocolname_len;
    /* The maximum simultanous session count for this pbx. */
    int im_max_sessions;
    /* The name of the udp gw. */
    char *ach_udp_gw_name;
    /* The length of the udp gw name to be used. */
    int im_udp_gw_name_len;
    /**
    * Replaces the target with the given char chain and frees any old value existing.
    * @param aach_target pointer to the pointer of a char chain to be used
    * @param aimp_target_len pointer to an int to be used for the length
    * @param achp_text the new char chain
    * @param imp_len the length of the new char chain
    */
    void m_replace(char **aach_target, int *aimp_target_len, const char * const achp_text, int imp_len);
};


/**
* Structure containing an IPv4 or IPv6 address and the information needed to distinguish.
* This is an internal replacement of the SOCKADDR_STORAGE structure.
*/
struct dsd_ineta_container {
    /* The type of the address AF_INET or AF_INET6. */
    unsigned short int usc_family;
    /* The length of the address - correlates with the type. */
    unsigned short int usc_length;
    /* The address in byte big endian. */
    //unsigned char chrc_ineta[16];
    unsigned char chrc_ineta[sizeof(sockaddr_in6)];
    /* The port as ushort. */
    unsigned short us_port;
};

class c_request;


enum ied_headerindex{
IM_REQUEST_METHOD_POS,
IM_REQUEST_METHOD_LEN,
IM_REQUEST_URI_POS,
IM_REQUEST_URI_LEN,
IM_RESPONSE_STATUS_POS,
IM_RESPONSE_STATUS_LEN,
IM_Accept_POS,
IM_Accept_LEN,
IM_Accept_Encoding_POS,
IM_Accept_Encoding_LEN,
IM_Accept_Language_POS,
IM_Accept_Language_LEN,
IM_Alert_Info_POS,
IM_Alert_Info_LEN,
IM_Allow_POS,
IM_Allow_LEN,
IM_Authentication_Info_POS,
IM_Authentication_Info_LEN,
IM_Authorization_POS,
IM_Authorization_LEN,
IM_Call_ID_POS,
IM_Call_ID_LEN,
IM_Call_Info_POS,
IM_Call_Info_LEN,
IM_Content_Disposition_POS,
IM_Content_Disposition_LEN,
IM_Content_Encoding_POS,
IM_Content_Encoding_LEN,
IM_Content_Language_POS,
IM_Content_Language_LEN,
IM_Content_Length_POS,
IM_Content_Length_LEN,
IM_Content_Type_POS,
IM_Content_Type_LEN,
IM_CSeq_POS,
IM_CSeq_LEN,
IM_Date_POS,
IM_Date_LEN,
IM_Error_Info_POS,
IM_Error_Info_LEN,
IM_Expires_POS,
IM_Expires_LEN,
IM_Event_POS,
IM_Event_LEN,
IM_From_content_POS,
IM_From_content_LEN,
IM_From_protocol_POS,
IM_From_protocol_LEN,
IM_From_fullname_POS,
IM_From_fullname_LEN,
IM_From_name_POS,
IM_From_name_LEN,
IM_From_hostname_POS,
IM_From_hostname_LEN,
IM_From_hostport_POS,
IM_From_hostport_LEN,
IM_From_hosttags_POS,
IM_From_hosttags_LEN,
IM_From_tags_POS,
IM_From_tags_LEN,
IM_From_fields_POS,
IM_From_fields_LEN,
IM_From_uri_POS,
IM_From_uri_LEN,
IM_In_Reply_To_POS,
IM_In_Reply_To_LEN,
IM_Max_Forwards_POS,
IM_Max_Forwards_LEN,
IM_MIME_Version_POS,
IM_MIME_Version_LEN,
IM_Min_Expires_POS,
IM_Min_Expires_LEN,
IM_Organization_POS,
IM_Organization_LEN,
IM_Priority_POS,
IM_Priority_LEN,
IM_Proxy_Require_POS,
IM_Proxy_Require_LEN,
IM_Reply_to_content_POS,
IM_Reply_to_content_LEN,
IM_Reply_to_protocol_POS,
IM_Reply_to_protocol_LEN,
IM_Reply_to_fullname_POS,
IM_Reply_to_fullname_LEN,
IM_Reply_to_name_POS,
IM_Reply_to_name_LEN,
IM_Reply_to_hostname_POS,
IM_Reply_to_hostname_LEN,
IM_Reply_to_hostport_POS,
IM_Reply_to_hostport_LEN,
IM_Reply_to_hosttags_POS,
IM_Reply_to_hosttags_LEN,
IM_Reply_to_tags_POS,
IM_Reply_to_tags_LEN,
IM_Reply_to_fields_POS,
IM_Reply_to_fields_LEN,
IM_Reply_to_uri_POS,
IM_Reply_to_uri_LEN,
IM_Require_POS,
IM_Require_LEN,
IM_Retry_After_POS,
IM_Retry_After_LEN,
IM_Server_POS,
IM_Server_LEN,
IM_Subject_POS,
IM_Subject_LEN,
IM_Supported_POS,
IM_Supported_LEN,
IM_Timestamp_POS,
IM_Timestamp_LEN,
IM_To_content_POS,
IM_To_content_LEN,
IM_To_protocol_POS,
IM_To_protocol_LEN,
IM_To_fullname_POS,
IM_To_fullname_LEN,
IM_To_name_POS,
IM_To_name_LEN,
IM_To_hostname_POS,
IM_To_hostname_LEN,
IM_To_hostport_POS,
IM_To_hostport_LEN,
IM_To_hosttags_POS,
IM_To_hosttags_LEN,
IM_To_tags_POS,
IM_To_tags_LEN,
IM_To_fields_POS,
IM_To_fields_LEN,
IM_To_uri_POS,
IM_To_uri_LEN,
IM_Unsupported_POS,
IM_Unsupported_LEN,
IM_User_Agent_POS,
IM_User_Agent_LEN,
IM_Warning_POS,
IM_Warning_LEN,
    //SIP extensions
IM_subscription_state_POS,
IM_subscription_state_LEN,
IM_refer_to_POS,
IM_refer_to_LEN,
IM_3581_received_POS,
IM_3581_received_LEN,
IM_3581_rport_VAL,
IM_HEADERS_END
};

enum ied_uri_offsets{
IM_URI_content_POS,
IM_URI_content_LEN,
IM_URI_protocol_POS,
IM_URI_protocol_LEN,
IM_URI_fullname_POS,
IM_URI_fullname_LEN,
IM_URI_name_POS,
IM_URI_name_LEN,
IM_URI_hostname_POS,
IM_URI_hostname_LEN,
IM_URI_hostport_POS,
IM_URI_hostport_LEN,
IM_URI_hosttags_POS,
IM_URI_hosttags_LEN,
IM_URI_tag_POS,
IM_URI_tag_LEN,
IM_URI_fields_POS,
IM_URI_fields_LEN,
IM_URI_uri_POS,
IM_URI_uri_LEN
};


enum ied_headertype{
IM_Accept,
IM_Accept_Encoding,
IM_Accept_Language,
IM_Alert_Info,
IM_Allow,
IM_Authentication_Info,
IM_Authorization,
IM_Call_ID,
IM_Call_Info,
IM_Contact,
IM_Content_Disposition,
IM_Content_Encoding,
IM_Content_Language,
IM_Content_Length,
IM_Content_Type,
IM_CSeq,
IM_Date,
IM_Error_Info,
IM_Event,
IM_Expires,
IM_From,
IM_In_Reply_To,
IM_Max_Forwards,
IM_MIME_Version,
IM_Min_Expires,
IM_Organization,
IM_Priority,
IM_Proxy_Authenticate,
IM_Proxy_Authorization,
IM_Proxy_Require,
IM_Record_Route,
IM_Reply_To,
IM_Require,
IM_Retry_After,
IM_Route,
IM_Server,
IM_Subject,
IM_Supported,
IM_Timestamp,
IM_To,
IM_Unsupported,
IM_User_Agent,
IM_Via,
IM_Warning,
IM_WWW_Authenticate,
IM_subscription_state,
IM_refer_to
};

/**
 * Data structure that represents a parsed SIP message. Taken from hobphone_common project with unneeded parts removed/commented
 */
typedef struct dsd_c_parsedmessage2
{    
    #define IM_MAX_INT_32 2147483647 //2^31-1 , INT_MAX for 32 bit signed ints
	#define IM_CSEQ_MAX_VAL IM_MAX_INT_32 
	#define uri_items_NUM 20
	#define IM_NUM_HEADERS IM_HEADERS_END
    int imrc_message[IM_NUM_HEADERS * 2]; //POS-LEN pairs
    //c_sdpsession* adsc_content;
    void* adsc_content;
    
    #define IM_SDPEXTRA_START -8

    #define IM_AUTHPARTS_NUM = 21;
    
    //headers that can have more than 1 value. Contact can have multiple values
    //in the same header, the others can appear multiple times.
    
    /**private PHEADERLIST dsc_contact; 
    PHEADERLIST dsc_via; 
    PHEADERLIST dsc_route;
    PHEADERLIST dsc_record_route;
    private PHEADERLIST dsc_proxy_authenticate;
    private PHEADERLIST dsc_proxy_authorization;
    private PHEADERLIST dsc_www_authenticate;
     */
    void* dsc_contact; 
//    void* dsc_via; 
    //Since we only deal with replies here we only need to copy whatever is in the VIA back in the reply
    int imc_viapos;
    int imc_vialen;
    

    void* dsc_route;
    void* dsc_record_route;
    void* dsc_proxy_authenticate;
    void* dsc_proxy_authorization;
    void* dsc_www_authenticate;

    //-1 if invalid, else value from ied_valid_requests, i.e. 0 == REPONSE,    
    int imc_is_request; 
    //Numbers between 100 and 699 can be used to indicate what kind of error response to send
    //eg: 400 means we can send a 400: Bad Request error
    int imc_error;
    int imc_sipstatus;
    int imc_cseq;
   
	char* byrc_message; //the original message
    //private c_parsedmessage2* adsc_sipfragmessage;
    void* adsc_sipfragmessage;
    int imc_messagelen; //length of the original message
    
    int imc_content_len;
    int imc_content_type;
}c_parsedmessage2;

/**
* The working class of the SDH. It contains all relevant methods and controls the data
* flow between the PBX and the client.
*/
class __declspec( dllexport ) ds_hobphone2 {

public:	
    /**
     * A memory area used as data storage. 
     */
    void* av_storage;

    /** 
     * Response to reload when reload is successful 
     */
    static const char * const astr_reload_response_ok;

    /** 
     * Response to reload when reload fails.
     */
    static const char * const astr_reload_response_fail;

    /**
    * Create an instance of the hobphone.
    */
	ds_hobphone2();

    /**
    * Deletes the instance and frees all resources including the sip/udp requests.
    */
	~ds_hobphone2();

    /**
    * This new operator provides a way to create an instance of the class in a given memory
    * area.
    * @param av_location a pointer to the memory to be used; it has to be large enough - no checks
    * @return untyped pointer to the memory area; will be equal to av_location
    */
	void* operator new(size_t, void* av_location) {
		return av_location;
	}

    /**
    * Only implemented to avoid a warning. The delete operator should NEVER be used on 
    * instances of this class as the memory is managed by the WSP.
    * @param avo_ptr1 the pointer to the memory area
    * @param avo_ptr2 a pointer with no defined function
    */
    void operator delete(void * avo_ptr1, void *avo_ptr2) {};

    

	/**
    * Initialize this instance of the class using the given wsp helper.
    * @param ads_wsp_helper_in the wsp helper instance to be used
    */
    void m_init( ds_wsp_helper* ads_wsp_helper_in );

    /**
     * Set the auxiliary routine handler.
     */
    void m_set_aux( BOOL (* amp_aux) ( void *, int, void *, int ), void* vpp_userfld );

    /**
    * The 'main' method of the server data hook. Called each time when data was received
    * and needs to be processed. Depending on the data and the internal state, other
    * methods are called to do the actual work.
    * @return false if a severe exception occured and the SDH should be terminated
    */
	int m_run ();

    /**
     * Check if the TCP timeout has expired. If yes, sends the keepalive to the client and resets the timer
     */
    void m_check_timeout(struct dsd_hl_clib_1* adsp_trans, BOOL bop_reset) ;

    /**
     * Method to be called when the server detects a client disconnection. Sets the SDH state.
     */
    void m_client_disco();

    
    /**
     * Method to be called when the server detects a client reconnection. 
     * Sets the SDH state and possibly restarts the UDP Gate.
     */
    void m_reloaded();

    /**
     * Get information about the device ID for a reload.
     * @ahstrp_devid aachp_devid OUT pointer to the device identifier string.
     * @return Length of the device identifier string.
     */
    int m_getdevid(const char** aachp_devid);

private:
    /** 
     * The protocol greeting expected to be sent by the client. 
     */
    static const dsd_const_string astr_protocol_greeting;    

    /**
     * The protocol response to be sent to the client. 
     */
	static const dsd_const_string astr_greeting_response;

    /**
     * The SDH version - can be sent to client upon request
     */
    static const dsd_const_string astr_server_version;

    /** 
     * Request to get the SDH version (old version)
     */
    static const char * const astr_get_version;

    /** 
     * Request to get the SDH version (new version) and gives the client version
     */
    static const char * const astr_client_version;

    /** 
     * Request to save the SDH for reload
     */
    static const char * const astr_save_sdh;

    /**
     * The system message to request the configuration.
     */
	static const char * const astr_get_config;

    /** 
     * The system message to create a channel. 
     */
	static const char * const astr_create_channel;

    /** 
     * The system message to set channel details
     */
	static const char * const astr_set_channel;

    /** 
     * The system message to remove a channel. 
     */
    static const char * const astr_remove_channel;

    /**
     * The system message to close (shutdown) the SDH instance
     */
    static const char * const astr_shutdown;

    /**
     * The tag 'username'. 
     */
	static const char * const astr_username;

    /**
     * The tag 'udp gw name'. 
     */
	static const char * const astr_udp_gateway_name;

    /**
     * The tag 'channel type'. 
     */
	static const char * const astr_channel_type;

    /**
     * The tag 'call id'. 
     */
	static const char * const astr_call_id;

    /**
     * The tag 'enable udp gate'. 
     */
    static const char * const astr_enable_udp_gate;

    /**
     * The tag 'enabled:YES\r\n'. 
     */
    static const char * const astr_enabled_yes;

    /**
     * The tag 'enabled:NO\r\n'. 
     */
    static const char * const astr_enabled_no;

    /**
     * The tag 'srtp:NO\r\n' 
     */
    static const char * const astr_srtp_no;

    /** 
     * Client request to do reverse lookup in LDAP.
     */
    static const char* const astr_search_number;

    /**
     * Client keepalive request (PING) 
     */
    static const char* const astr_keepalive;

    /**
     * Length of the SIP reply
     */
    int imc_sipreplylen;

    /**
     * Reconnect request. 
     */
    static const dsd_const_string astr_protocol_reconnect;


    /**
     * An instance of the wsp helper class. 
     */
	ds_wsp_helper *ads_wsp_helper;

    /**
     * The configuration of the SDH. 
     */
	dsd_sdh_config_t *ads_config;

    /**
     * The current state of the SDH. 
     */
    ied_sdh_hobphone_state ie_state;

    /**
     * An LDAP access module. 
     */
	ds_ldap ds_ldap_instance;

	/**
     * Array of SIP requests - every account has its own sip request 
     */
    dsd_sdh_sip_requ_1 *adsr_sip_requests[im_max_account_count];

    /**
     * Array of UDP requests. Every channel can have its UDP request.
     */
    dsd_sdh_udp_requ_1 *adsr_udp_requests[im_max_channel_count];

    /**
     * Array of UDP gate subchannels 
     */
    void *adsr_udp_subchannels[im_max_channel_count];

    /** 
     * An XML parser module. 
     */
    ds_xml dsc_xml;

    /**
     * A hashtable containing the pbx entries configured in LDAP. 
     */
    ds_hashtable<ds_pbx_entry *> dsc_pbx_table;

    /**
     * An hstring containing the last error message. 
     */
    ds_hstring hstr_exception_message;

    /**
     * A structure used to represent the udp gate 
     */
    dsd_aux_cmd_udp_gate ds_udp_gate;

    /**
     * Flag indicating that a udp gate can be used 
     */
    BOOL bo_use_udp_gate;

    /**
     * On the first run the domain/username is stored here 
     */
    ds_hstring hstr_cma_name;

    /** 
     * function pointer to auxiliary routine handler
     */
    BOOL (* amc_aux) ( void *, int, void *, int ) ;


    void* vpc_userfld;

    int imc_clientversion;

    //RECONNECT

    /**
     * Stores the configuration as retrieved from LDAP - avoids repetition of LDAP requests on reconnect.
     */
    ds_hstring hstrc_config; 
    ///
#if DEBUG_CHANNELS
    ds_hstring hstr_channels;
#endif

    /**
     * Holds SIP replies for each channel.
     */
    char adsc_sipreply[im_max_channel_count][2048];
    
    /**
     * Holds the SIP contact header - One for each account.
     */
    ds_hstring hstr_sipcontact[im_max_account_count];

    /**
     * The device identifier for reconnect
     */
    ds_hstring hstrc_devid;

    /**
    * Helper method that compares the given char chain with the content of the gather iterator.
    * On success, the read bytes are marked as used.
    * @param astrp_excpected the expected char chain (zero terminated)
    * @param dsp_it a gather iterator containing the received data to be compared
    * @return true if the char chain equals the dsp_it content
    */
    static BOOL m_compare(const char *astrp_expected, ds_gather_iterator &dsp_it);   

    /**
    * Helper method that compares the given char chain with the content of the gather iterator.
    * On success, the read bytes are marked as used.
    * @param astrp_excpected the expected char chain (zero terminated)
    * @param dsp_it a gather iterator containing the received data to be compared
    * @param imp_maxlen The maximum length to compare
    * @return true if the char chain equals the dsp_it content
    */
    static BOOL m_compare(const char *astrp_expected, ds_gather_iterator &dsp_it, int imp_maxlen);

    /** 
    * Helper method that decodes a NHASN coded number from the beginning of the gather chain.
    * Several tests are performed to ensure the validity of the number. A range test is 
    * performed using the imp_max_value as the smallest number that will cause a range 
    * exception. If imp_max_value is set to 0, the range check is disabled.
    * @param dsp_gather the gather chain containing the data
    * @param imp_nhasn_length an int value to take the length of the decoded NHASN on success
    * @param imp_max_length the maximum number of bytes to be read from this gather chain
    * @param imp_max_value the samllest number that might cause an out of range exception
    * @param imp_retur_length an int value to take the decoded length on success
    * @return a status according to ied_sdh_hobphone status
    *       SDH_HOBPHONE_STATUS_OK: on success
    *       SDH_HOBPHONE_STATUS_EMPTY_NHASN: no data received 
    *       SDH_HOBPHONE_STATUS_INCOMPLETE_NHASN: the NHASN is not terminated by a byte < 128
    *           and no data is left
    *       SDH_HOBPHONE_STATUS_NHASN_OUT_OF_RANGE: the calculated value is larger or equals
    *           imp_max_value
    */
	ied_sdh_hobphone_status m_decode_nhasn(struct dsd_gather_i_1 &dsp_gather, 
        int &imp_nhasn_length, int imp_max_length, int imp_max_value, int &imp_ret_length);

    /** 
    * Helper method that checks, whether the given gather iterator conatins the expected
    * greeting.
    * @param dsp_it a gather iterator that contains the data
    * @return true if the gather iterator conatins the expected greeting message;
    *       on success, the bytes read are marked as used
    */
	BOOL m_check_greeting(ds_gather_iterator &dsp_it);

    /** 
    * Helper method that marks the given number of bytes from the gather chain as used.
    * If the number exceeds the length of the gather chain, the whole chain will be 
    * marked.
    * @param adsp_gather the gather chain containing the data
    * @param ds_size the number of bytes to be marked
    */
	static void m_mark_used(struct dsd_gather_i_1 *adsp_gather, const size_t ds_size);

    /**
    * Helper method that reads the first byte from the gather iterator and 
    * derives the channel type from this byte. The byte is marked as used.
    * @param dsp_it the gather iterator containing the data
    * @return a value of ied_sdh_hobphone_channel_type representing the channel type or
    *       SDH_HOBPHONE_CHANNEL_TYPE_UNDEFINED if it could not be derived
    */
	ied_sdh_hobphone_channel_type m_get_channel_type(ds_gather_iterator &dsp_it);

    /** 
    * Helper method that reads the first byte from the gather iterator and
    * interprets it as a channel id. The byte is marked as used.
    * @param dsp_it the gather iterator containing the data
    * @return the read byte as character
    */
	char m_get_channel_id(ds_gather_iterator &dsp_it);

    /** 
    * Helper method that writes the textual representation of the ineta contained in the
    * ineta container to the given hstring.
    * @param hstrp_text the string to append the ineta to
    * @param dsp_ineta a dsd_ineta_container containing one of the supported ineta formats
    */
    void m_write_ineta(ds_hstring &hstrp_text, const dsd_ineta_container &dsp_ineta);

    /**
    * Helper method that tries to parse a char chain into a IPv4 or IPv6 address. The parsed
    * address is stored in a dsd_ineta_container.
    * @param ach_ineta the char chain containing the data
    * @param in_length the length of the data to parse
    * @param dsp_ineta a container to return the parsed ineta
    * @return true if the char chain could be parsed to a supported format
    */
    BOOL m_parse_ineta(const char *ach_ineta, int in_length, dsd_ineta_container &dsp_ineta);

    /**
    * Helper method to get a zero terminated message relating to iep_status. The message
    * may contain printf-style placeholders to customize the content.
    * @param iep_status the HOBPhone status to get the message for
    * @return The exception message
    */
    const char * const m_get_exception_message(ied_sdh_hobphone_status iep_status);

    /**
    * Helper method to get a zero terminated message relating to iep_val. The message
    * may contain printf-style placeholders to customize the content.
    * @param iep_val the SIP status to get the message for
    * @return The exception message
    */
    const char * const m_get_exception_message(ied_ret_sip_requ_1_def iep_val);

    /**
    * Treats the content of the gather iterator as system message and calls the appropriate
    * method.
    * @param dsp_it the gather iterator containing the message
    * @return a value of ied_sdh_hobphone_status
    *       SDH_HOBPHONE_STATUS_INVALID_SYSTEM_MESSAGE: if the message could not be parsed
    *       other values according to the received message (see m_system_xxx(...))
    */
    ied_sdh_hobphone_status m_handle_system_message(ds_gather_iterator &dsp_it);

    /** 
    * Generates the configuration using the specified source (LDAP or XML). For each valid
    * account a sip request is requistered.
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_system_message_get_config();

    /**
    * Requests a nonce as identification for the wsp udp connection and generates a message
    * to the client.
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_system_initialize_wsp_udp(BOOL bol_reload);

    /** 
    * Enables/disables the udp gate for this session depending on the content of this 
    * message.
    * @param dsp_it the gather iterator containing the message
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_system_message_enable_udp_gate(ds_gather_iterator &dsp_it);

    /**
    * Creates a channel of the type specified in the message.
    * @param dsp_it the gather iterator containing the message
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_system_message_create_channel(ds_gather_iterator &dsp_it);

    /**
    * Sets the properties of the channel defined in the message. Properties are e.g. port or
    * ineta.
    * @param dsp_it the gather iterator containing the message
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_system_message_set_channel(ds_gather_iterator &dsp_it);

    /**
    * Removes the channel defined in the message.
    * @param dsp_it the gather iterator containing the message
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_system_message_remove_channel(ds_gather_iterator &dsp_it);

    /**
     * Does a lookup by telephone number in LDAP.
     * @param dsp_it the gather iterator containing the message
     * @return a value of ied_sdh_hobphone_status
     */
    ied_sdh_hobphone_status m_system_message_search_number(ds_gather_iterator &dsp_it);

    /** 
     * Handle a TCP keepalive request fromt the client by sending a TCP keepalive reply, 
     * Possibly sending a new keepalive interval to the client.
     * @param dsp_it the gather iterator containing the message
     * @return a value of ied_sdh_hobphone_status
     */
    ied_sdh_hobphone_status m_system_message_keepalive(ds_gather_iterator &dsp_it);

    /**
     * Handle a version request from the client. 
     * The SDH version can be used by the client to identify SDH features.
     * @param dsp_it the gather iterator containing the message
     * @param bop_clientv If true the client version is provided
     * @return a value of ied_sdh_hobphone_status
     */
    ied_sdh_hobphone_status m_system_message_get_version(ds_gather_iterator &dsp_it, BOOL bop_clientv);


    /**
     * Handle a save SDH request from the client. The client must provide an identifier. 
     * This is used, together with the account id, to save the session for reload
     * @param dsp_it the gather iterator containing the message
     * @return a value of ied_sdh_hobphone_status
     */
    ied_sdh_hobphone_status m_system_message_save_sdh(ds_gather_iterator &dsp_it);
    /**
    * Tries to match a number retrieved from LDAP to the number requested in a reverse lookup.
    * Does a match ignoring white space and initial '+'.
    * @param achp_string The phone number to match (the number retrieved from LDAP)
    * @param imp_len Length of achp_string
    * @param achp_matchto The number to match to.
    * @param imp_len2 The length of achp_matchto.
    * @return TRUE on match, FALSE on no match.
    */
    BOOL m_match_number(const char* achp_string, int imp_len, const char* achp_matchto, int imp_len2);

    /**
     * Sends a reply to a search number request. If the request is not found achp_value should be NULL.
     * In this case the data sent to the client will be contain the original 
     * number and a "*" as the display name. It is up to the client to handle
     * this since the client may have other means to get the name (eg: through the SIP message).
     * @param achp_number The number in the search request.
     * @param imp_numlen The length of the number in the request.
     * @param achp_value The return value - the name associated with the number if found or NULL if not found
     * @param imp_value_len The length of the return value when found, ignored if achp_value == NULL.
     * @return TRUE if the reply was sent, false otherwise
     */
    BOOL m_send_search_number_reply(const char* achp_number, int imp_numlen, const char* achp_value, int imp_value_len);

    /**
     * Send the TCP keepalive response (PONG)
     * @param imp_interval The interval in ms to be sent to the client - The client will send its part of the keepalive (PING) at this interval.
     * @return TRUE if the data is sent, FALSE otherwise
     */
    BOOL m_send_keepalive(int imp_interval);


	/**
    * Sends the data to the corresponding pbx. The pbx is determined from the channel id.
    * @param dsp_it the gather iterator containing the data
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_redirect_sip_to_pbx(ds_gather_iterator &dsp_it);

	/**
    * Sends received sip data to the client.
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_redirect_sip_to_client();

	/**
    * Sends received udp data to the pbx.
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_redirect_udp_to_pbx(ds_gather_iterator &dsp_it);

    /**
    * Sends received udp data to the client.
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_redirect_udp_to_client();

    /**
    * Determines the next free/unused channel index.
    * @return an int as the next free channel index or -1 if none free
    */
    int m_get_free_channel_index();

    /**
    * Gets the sip request for the given channel or NULL if none found or if the 
    * channel is out of the valid range. The valid range is defined by im_max_account_count.
    * @param imp_channel_index the index of the request to get
    * @return a pointer to the request of NULL if none
    */
    dsd_sdh_sip_requ_1 *m_get_sip_request(int imp_channel_index);

    /**
    * Gets the udp request for the given channel or NULL if none found or if the 
    * channel is out of the valid range. The valid range is defined by im_max_channel_count.
    * @param imp_channel_index the index of the request to get
    * @return a pointer to the request of NULL if none
    */
    dsd_sdh_udp_requ_1 *m_get_udp_request(int imp_channel_index);

    /**
    * Sets the sip request for the given channel. If channel is out of range nothing will
    * be done. The valid range is defined by im_max_account_count.
    * If a request was previously registered it will be closed and freed.
    * @param imp_channel_index the index of the request
    * @param adsp_sip_request the request
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_set_sip_request(int imp_channel_index, dsd_sdh_sip_requ_1 *adsp_sip_request);

    /**
    * Sets the udp request for the given channel. If channel is out of range nothing will
    * be done. The valid range is defined im_max_channel_count.
    * If a request was previously registered it will be closed and freed.
    * @param imp_channel_index the index of the request
    * @param adsp_udp_request the request
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_set_udp_request(int imp_channel_index, dsd_sdh_udp_requ_1 *adsp_udp_request);

    /** 
    * Close the given channel (unregister it from the server).
    * @param imp_channel_index the index of the channel to close
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_close_sip_request(int imp_channel_index);

    /** 
    * Close the given channel (unregister it from the server).
    * @param imp_channel_index the index of the channel to close
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_close_udp_request(int imp_channel_index);

    /** 
    * Free the given channel (remove it from the list and release resources).
    * @param imp_channel_index the index of the channel to free
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_free_sip_request(int imp_channel_index);

    /** 
    * Free the given channel (remove it from the list and release resources).
    * @param imp_channel_index the index of the channel to free
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_free_udp_request(int imp_channel_index);

    /**
    * Adds the pbx entry for the given entry replacing every existing entry for the same key.
    * Existing values will be freed.
    * @param achp_key the key to register for
    * @param imp_key_len the length of the key
    * @param adsp_pbx_entry the entry to be registered
    */
    void m_add_pbx_entry(const char * const achp_key, int imp_key_len, ds_pbx_entry * adsp_pbx_entry);

    /** 
    * Helper method that populates a ineta container from the given char chain. If the char chain
    * contains no supported format, a exception value is returned.
    * @param dsp_ineta a ineta container to receive the return value
    * @param achp_sockaddr a char chain containing a sockaddr_in(6) structure
    * @return a value of ied_sdh_hobphone_status
    */
    ied_sdh_hobphone_status m_get_ineta_container(dsd_ineta_container &dsp_ineta, sockaddr_storage *adsp_sockaddr);

    /**
    * Evaluates iep_status and sends an appropriate exception message to the client.
    * @param iep_status the status that should be send
    * @param hstrp_ex_message the message to send
    * @param bop_fatal a flag to order the client to terminate - default false
    */
    void m_send_exception(ied_sdh_hobphone_status iep_status, ds_hstring& hstrp_ex_message, BOOL bop_fatal = FALSE);

    /**
    * Evaluates iep_status and logs an appropriate error message.
    * @param iep_status the status that should be logged
    * @param hstrp_ex_message the message to log
    */
    void m_log_error(ied_sdh_hobphone_status iep_status, ds_hstring& hstrp_ex_message);

    /**
    * Evaluates iep_status and logs an appropriate warning.
    * @param iep_status the status that should be logged
    * @param hstrp_ex_message the message to log
    */
    void m_log_warning(ied_sdh_hobphone_status iep_status, ds_hstring& hstrp_ex_message);

    /** 
     * Logs a warning.
     * @param chrp_message The warning message to log.
     */
    void m_log_warning(const dsd_const_string& chrp_message);

    /**
    * Evaluates iep_status and logs an appropriate info message.
    * @param iep_status the status that should be logged
    * @param hstrp_ex_message the message to log
    * @param achp_extra An additional string (zero-termianted char array) to write to the info message. This string is written before hstrp_ex_message.
    */
    void m_log_info(ied_sdh_hobphone_status iep_status, ds_hstring& hstrp_ex_message, const char* achp_extra = NULL);

    /**
    * Evaluates iep_status and logs an appropriate info message.
    * @param iep_status the status that should be logged
    * @param achp_message The string(zero-terminated char array) to be written to the output message
    */
    void m_log_info(ied_sdh_hobphone_status iep_status, const dsd_const_string& achp_message);

    /**
    * Shutdown the SDH by unregistering the SIP and UDP requests.
    * After this, the SDH cannot be restarted.
    */
    void m_shutdown();

    /**
    * Returns the Base64 equivalent for the given input char.
    * @param imp_channel_index the index to be transformed
    * @return a Base64 character with the corresponding value
    */
    char m_convert_to_channel_id(int imp_channel_index);

    /**
    * Returns the index of given Base64 character.
    * @param chp_char the character to be transformed
    * @return the index of the given Base64 character
    */
    int m_get_index(char chp_channel_id);
    

    /**
     * Check if the data in the dsp_it parameter is a reconnection request.
     * @param dsp_it The iterator containing the received data.
     * @return TRUE if the received data matches the astr_protocol_reconnect string.
     */
    BOOL m_check_reconnect(ds_gather_iterator &dsp_it);


    //TODO (if needed)
    void m_setcontactineta(dsd_ineta_container dsp_ineta);
    //TODO (if needed)
    void m_setcontact(char chp_channelid,const char* achp_value,int imp_valuelen);

    /**
    * Frees a given gatherchain and releases the associated memory.
    * @param adsp_gather the gatherchain to be freed
    */
    void m_free_gatherchain(dsd_gather_i_1 *adsp_gather);

    /**
    * Update the exception message by replacing the content with the created
    * string message.
    * @param iep_status the status to create the message for
    * @param avop_param optional paramter to include
    */
    void m_update_exception_message(ied_sdh_hobphone_status iep_status, int imp_line, const void * const avop_param,  const void * const avop_param2 = NULL);

    /**
    * Update the exception message by replacing the content with the created
    * string message.
    * @param iep_status the status to create the message for
    * @param dsp_it a gather iterator where the characters are taken from 
    *           until 0 is read or end is reached
    */
    void m_update_exception_message(ied_sdh_hobphone_status iep_status,int imp_line, ds_gather_iterator& dsp_it);

    /**
    * Update the exception message by replacing the content with the created
    * string message.
    * @param iep_status the status to create the message for
    * @param imp_line The line number.
    * @param achp_param a char chain to include
    * @param imp_length the length of the char chain to include
    */
    void m_update_exception_message_l(ied_sdh_hobphone_status iep_status, int imp_line, const char * const achp_param, const int imp_length);

    /**
    * Update the exception message by replacing the content with the created
    * string message.
    * @param iep_status the status to create the message for
    * @param imp_line The line number.
    * @param achp_param The constant string to add.
    */
    void m_update_exception_message_l(ied_sdh_hobphone_status iep_status, int imp_line, const dsd_const_string achp_param);

    /**
    * Write the addressbook configuration data to the given string.
    * @param adsp_addressbook_config the configuration to read
    * @param hstrp_target the container to write to
    */
    void m_write_addressbook_config(dsd_sdh_addressbook_config *adsp_addressbook_config,
        ds_hstring &hstrp_target, ds_hstring& achp_domainname);

    /**
     * enum used to define the state during a reverse lookup
     */
    enum eid_namestate{        
        IM_NAMESTATE_INIT,              /*initial state - stays until match is found or list is traversed*/
        IM_NAMESTATE_ENDLIST,           /*state when all list is traveresed without match*/
        IM_NAMESTATE_FOUND_POTENTIAL,   /*state when a display name matches - we still have to check dn*/
        IM_NAMESTATE_FOUND_CONFIRM      /*state when a match is found - both display name and dn match*/
    };

    //
    BOOL m_isclientnewer(int,int,int);

    ///SIP  
    /**
     * Handle a possible SIP request.
     * Can generate replies to OPTIONS and NOTIFY requests, depending on the configuration.
     * @param ads_buffer The buffer containing the SIP request
     * @param adsp_reply OUT Buffer for the generated reply
     * @param imp_maxlen Maximum length for reply
     * @param imp_replylen OUT length of generated sip reply
     * @return TRUE if a reply was generated. FALSE otherwise. 
     *   If a parsing error is encountered or the request is not to be handled the function returns FALSE.
     */
    BOOL m_handlesip( dsd_sdh_udp_recbuf_1 *ads_buffer, char* adsp_reply,int imp_maxlen, int* imp_replylen);

    /** 
     * Handle a received SIP request by sending the appropriate reply if the SIP request is to be handled.
     * @param ds_msg_in The incoming SIP request
     * @param byrp_reply OUT The generated reply.
     * @param imp_maxlen The maximum length of the reply.
     * @param imp_replyle OUT The length of the generated reply.
     * @return false If the request should not be handled by the SDH.
     */
    BOOL m_received_siprequest(c_parsedmessage2* ds_msg_in,char* byrp_reply,int imp_maxlen, int* imp_replylen);

    /**
     * Prepare a SIP response.
     * @param chr_contact The contact string. TODO (if required)
     * @param imp_msgkey The request type
     * @param dsp_msg_in The SIP request
     * @param imp_maxlen The maximum length of the reply.
     * @param imrp_length The length of the generated reply.
     * @param byrp_request The response.
     */
    BOOL m_prepare_response(const char* chr_contact, int imp_msgkey, c_parsedmessage2& dsp_msg_in, int imp_maxlen, int imrp_length[], char* byrp_request);
    
    //The following methods are imported from hobphone_common as required.


    /** Parse a byte array */
    int m_parserequest(char byrp_packet[],int imp_offset, int imp_len, int imrp_dest[], int imrp_isreq[]);

    /** Compare strings ignoring case*/
    static BOOL m_eqlowercase2(const int dsrrp_strings[][2],int imp_size, int imp_compareto, char byrp_packet[], int imp_start, int imp_len) ;

    /** Calculate adler checksum*/
    static int m_calc_adler( char achp_buffer[], int imp_start, int imp_end);

    /** Check if this is a valid SIP request*/
    int m_is_validrequest(char byrp_packet[], int imp_start, int imp_len);

    /** Check if a byte array represents a valid number*/
    static BOOL m_checkint(char byrp_packet[], int imp_start, int imp_len, int imp_min, long ilp_max, long ilr_outval[]);

    /** Parse a SIP URI */
    int m_parse_sip_uri(char byrp_packet[], int imp_start, int imp_end,int imrp_dest[], int imp_index);

    /** 
     * Trim trailing whitespace 
     * @return Position of last non-whitespace char.
     */
    static int m_trimtrailing(char byrp_packet[], int imp_start, int imp_end);

    /** 
     * Trim leading whitespace 
     * @return position of first non-whitespace char
     */
    static int m_trimleading(char byrp_packet[], int imp_start, int imp_end);

    /** Find the position of the next byp_char */
    static int m_findnext(char byrp_packet[], int imp_start, int imp_end, char byp_char);

    /** Parse the host part of a SIP address */
    int m_parse_host(char byrp_packet[], int imp_start, int imp_end,int imrp_dest[], int imp_index);

    /** Parse the buffer and find a SIP header */
    int m_findheader(char byrp_packet[], int imp_start, int imp_end);

    /** Parse SIP URI content part */
    int m_parse_uri_content(char byrp_packet[], int imp_start, int imp_len, int imrp_dest[], int imp_index);

    /** Parse SIP tags */
    int m_parse_tags(char byrp_packet[], int imp_start, int imp_end,int imrp_dest[], int imp_index);

    /** Parse SIP CSEQ */
    int m_parse_cseq(char byrp_packet[], int imp_start, int imp_len,int imrp_dest[], int imp_index, long ilrl_cseqval[]);

    /** Parse SIP (rfc1123) Date */
    static BOOL m_parse_rfc1123_date(char byrp_packet[], int imp_start, int imp_len,int imrp_dest[], int imp_index);

    /** Check if a buffer contains a valid SIP weekday*/
    static BOOL m_is_weekday(char byrp_packet[], int imp_start, int imp_len);

    /** Check if a buffer contains a valid SIP month */
    static BOOL m_is_month(char byrp_packet[], int imp_start, int imp_len);

    /** Get the SIP METHOD name*/
    static const char* m_get_sip_method(int imp_method);

    /** Get the SIP KEY name*/
    static const char* get_keyname(int key);

    
    ////
    //from hobphone_common pu utility class

    /** Find the last instance of a char in a range of a buffer*/
    static int m_findlast(char byrp_packet[], int imp_start, int imp_end, char byp_char);

    /** Check if the buffer starts with a specific char, ignoring leading whitespace */
    static int m_startswith(char byrp_packet[], int imp_start, int imp_end, char byp_char);

    /** Check if a range within a buffer is only whitespace */
    static BOOL m_iswhitespace(char byrp_packet[], int imp_start, int imp_end);

    /** Check if a buffer range ends with a specific char, ignoring trailing whitespace */
    static int m_endswith(char byrp_packet[], int imp_start, int imp_end, char byp_char);

};


//c_request - changed to use memory allocated from caller - does not allocate or change size of memory used
#define IM_RESPONSE_INITSIZE 2048

/** 
 * The c_request class holds a generated SIP message and has utility methods to build the SIP message.
 * SDH version notes: 
 * 1. This class never creates any buffer itself. The buffer and size must be passed 
 *  to the contructor and is used to generate the SIP message. The owner of the buffer remains the caller, 
 *  and is responsible for freeing memory if required.
 * 2. The buffer is not resizable. If a request to add data encounters the maximum length as given in
 *  the constructor the request fails.
 */
class c_request{
    
public:
    /** 
     * The buffer to the SIP message
     */
    char* byrc_request;

    /**
     * the current offset, if negative there was an error during a previous entry - consider the buffer as invalid
     */
    int imc_offset; 

    /**
     * If imc_offset is negative this will point to the offset where the error was caused
     */
    int imc_error; 

private:
    int imc_size; //The size of the buffer - only used internally
    //private static const int IM_RESIZE_THRESHOLD = 100; //if less than this amount remains free the array is resized
    //private static const int IM_RESPONSE_INITSIZE = 2048; //default start size
    
    c_request(){}

public:
    /**
     * Create a new request with default start values
     */
    c_request(char* byrp_request, int imp_maxsize);
    /**
     * Destructor.
     * NOTE: the underlying array is not deleted at this point and can be used after the object has been deleted.
     * At this point the request cannot be used to add items so the contents of the buffer are, in a way, fixed.
     * The caller must not forget to delete the buffer.
     */
    ~c_request()
    {
    }

    /** 
    * Add a byte sequence to a byte array. 
    * The byte sequence is either a null terminated string (c/c++) or an array of bytes (c/c++/java)
    * If an array of bytes it can be optionally null terminated, in which case the null character is ignored
    * @param byrp_src The source string.
    * @return The new offset.
    */    
    int m_addstring(const char byrp_src[]);

    /** 
    * Add a byte sequence to a byte array.        
    * If the remaining space in the underlying buffer is less than 
    * the length of the array to copy + the resize threshold
    * the array is resized. Note however that if, after resizing, 
    * the src array does not fit in the buffer, an error is returned.
    * @param byrp_src The source array.
    * @param imp_srcpos The offset in byrp_src from where to begin copying
    * @param imp_srclen The number of bytes to copy
    * @return The new offset.
    */
    int m_addbytes(const char byrp_src[],int imp_srcpos, int imp_srclen);

    /**
     * Add a single character to the buffer
     * @param byp_src The character to add
     * @return The new offset.
     */
    int m_addchar(char byp_src) ;
     /**
     * Add a space (0x20) character to the buffer
     * @return The new offset.
     */
    int m_addspace() ;

    /**
     * Add an unsigned integer to the buffer
     * @param iml_val The integer to add
     * @return The new offset.
     */
    int m_addint(long iml_val);

    /**
     * Add a \r\n sequence to the buffer
     * @return The new offset.
     */
    int m_endline();
};

////


#endif 
