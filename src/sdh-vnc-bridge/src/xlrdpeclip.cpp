//#define HOB_RDPACC_ALLOW_THROW
/*+--------------------------------------------------------------------------+*/
/*| Macro Definitions.                                                       |*/
/*+--------------------------------------------------------------------------+*/
// define to 1 if you want the library to get data from the clipboard only if
// it has changed since the last time it was obtained, or if the requested
// format is different.
//#define USE_CB_MEMORY       1

// define to 1 if you want the library to support only CF_TEXT and
// CF_UNICODETEXT clipboard formats
//#define CB_ONLY_TEXT        1  (now we support graphics)

#define USE_FMT_NAME_STRINGS 1




/*+--------------------------------------------------------------------------+*/
/*| Include Header Files.                                                    |*/
/*+--------------------------------------------------------------------------+*/

#if !(defined HL_UNIX || defined HL_LINUX || defined HOB_UNIX || defined HL_LINUX64)
    #include <winsock2.h>
    #include <windows.h>
#else
    #include <unistd.h>
    #include <sys/sem.h>
    #include <errno.h>
    #include <arpa/inet.h>
    #include <hob-unix01.h>
    #include <strings.h>
    #define _TRUNCATE ((size_t)-1)
    #include <stdlib.h>
    #include <stdio.h>
    #include <stddef.h>
#endif

#include "hob-cdrdef1.h"
#include "hmd5.h"
#include "hsha.h"
#include "hrc4cons.h"
#include <hob-avl03.h>

#pragma warning(disable:4005)
#include <hob-rdpserver1.h>
#pragma warning(default:4005)

#include <stdarg.h>
#include <memory>
#ifdef HOB_RDPACC_ALLOW_THROW
#include <memory>
#include <hob-throw_error.hpp>
#endif


#include <hob-gather_reader.hpp>
#include <hob-rdpacc_vector.hpp>
#include <hob-rdpacc_clipboard.h>

/*+--------------------------------------------------------------------------+*/
/*| Macro Definitions.                                                       |*/
/*+--------------------------------------------------------------------------+*/

#define LOG_LEVEL_TRACE                     300
#define LOG_LEVEL_INFO                      800
#define LOG_LEVEL_WARNING                   900
#define LOG_LEVEL_ERROR                    1000
#define LOG_LEVEL_DEFAULT                   LOG_LEVEL_INFO
// Some of the definition's values are specified in the RDP.                                                

// 2.2.1 Clipboard PDU Header (CLIPRDR_HEADER)  
#define SZ_CLIPDR_HEADER            8           // length of header

// type
#define CB_MONITOR_READY            0X0001
#define CB_FORMAT_LIST              0X0002
#define CB_FORMAT_LIST_RESPONSE     0X0003
#define CB_FORMAT_DATA_REQUEST      0X0004
#define CB_FORMAT_DATA_RESPONSE     0X0005
#define CB_TEMP_DIRECTORY           0X0006
#define CB_CLIP_CAPS                0X0007
#define CB_FILECONTENTS_REQEUST     0X0008
#define CB_FILECONTENTS_RESPONSE    0X0009

static const char* get_text_msg_type(int inl_msg_type){
   switch(inl_msg_type){
      case CB_MONITOR_READY:         return "CB_MONITOR_READY";
      case CB_FORMAT_LIST:           return "CB_FORMAT_LIST";
      case CB_FORMAT_LIST_RESPONSE:  return "CB_FORMAT_LIST_RESPONSE"; 
      case CB_FORMAT_DATA_REQUEST:   return "CB_FORMAT_DATA_REQUEST";
      case CB_FORMAT_DATA_RESPONSE:  return "CB_FORMAT_DATA_RESPONSE";
      case CB_TEMP_DIRECTORY:        return "CB_TEMP_DIRECTORY";
      case CB_CLIP_CAPS:             return "CB_CLIP_CAPS";
      case CB_FILECONTENTS_REQEUST:  return "CB_FILECONTENTS_REQEUST";
      case CB_FILECONTENTS_RESPONSE: return "CB_FILECONTENTS_RESPONSE";
      default:                       return "UNKNOWN";
   }
}

// flags
#define CB_FLAG_RESPONSE_OK         0X0001
#define CB_FLAG_RESPONSE_FAIL       0X0002
#define CB_FLAG_ASCII_NAMES         0X0004

// MS-RDPECLIP 2.2.2.1
#define SZ_CLIPDR_CAPS              4 // Length of capability-PDU, excluding the header
// MS-RDPECLIP 2.2.2.1.1                           
#define CB_CAPSTYPE_GENERAL         0X0001               //Value from RDPECLIP doc
// MS-RDPECLIP 2.2.2.1.1.1     
#define SZ_CLIPDR_GENERAL_CAPABILITY    12               // Length general capability-set
//    version
#define CB_CAPS_VERSION_1               0X00000001
#define CB_CAPS_VERSION_2               0X00000002
//    flags
#define CB_FLAG_USE_LONG_FORMAT_NAMES        0X00000002
#define CB_FLAG_STREAM_FILECLIP_ENABLED      0X00000004
#define CB_FLAG_FILECLIP_NO_FILE_PATHS       0X00000008

typedef struct dsd_clipdr_monitor_ready
{
//    struct dsd_clipdr_header    dsc_header;
} dsd_clipdr_monitor_ready_t, *adsd_clipdr_monitor_ready_t;


/*+--------------------------------------------------------------------------+*/
/*| MS-RDPECLIP 2.2.2.3                                                      |*/
/*| This pdu informs the server of a location on the client file system      |*/
/*| that must be used to deposit files being copied to the client.           |*/
/*+--------------------------------------------------------------------------+*/
#define SZ_CLIPDR_TEMP_DIRECTORY    528

typedef struct dsd_clipdr_temp_directory
{
//    struct dsd_clipdr_header    dsc_header;
    char                        chrc_tmp_dir[520];
} dsd_clipdr_temp_directory_t, *adsd_clipdr_temp_directory_t;

/*+--------------------------------------------------------------------------+*/
/*| MS-RDPECLIP 2.2.3.1                                                      |*/
/*| Sent by client or server when its clipboard is updated.                  |*/ 
/*+--------------------------------------------------------------------------+*/
#define SZ_CLIPDR_FORMAT_LIST       8

typedef struct dsd_clipdr_format_list
{
//    struct dsd_clipdr_header    dsc_header;
    unsigned char               uchrc_formatlist_data[1];
} dsd_clipdr_format_list_t, *adsd_clipdr_format_list_t;

/*+--------------------------------------------------------------------------+*/
/*| MS-RDPECLIP 2.2.3.1.1.1                                                  |*/
/*+--------------------------------------------------------------------------+*/
#define SZ_CLIPDR_SHORT_FORMAT_NAME     36

typedef struct dsd_clipdr_short_format_name
{
    unsigned int    umc_format_id;
    char            chrc_format_name[32];
} dsd_clipdr_short_format_name_t, *adsd_clipdr_short_format_name_t;

/*+--------------------------------------------------------------------------+*/
/*| MS-RDPECLIP 2.2.3.1.1                                                    |*/
/*| This struct holds a collection of dsd_clipdr_short_format_name struct.   |*/ 
/*+--------------------------------------------------------------------------+*/
typedef struct dsd_clipdr_short_format_names
{
    struct dsd_clipdr_short_format_name dsrc_short_names[1];
} dsd_clipdr_short_format_names_t, *adsd_clipdr_short_format_names_t;

/*+--------------------------------------------------------------------------+*/
/*| MS-RDPECLIP 2.2.3.1.2.1                                                  |*/
/*+--------------------------------------------------------------------------+*/

/*+--------------------------------------------------------------------------+*/
/*| MS-RDPECLIP 2.2.3.1.2                                                    |*/
/*| This struct holds a collection of dsd_clipdr_long_format_name struct.    |*/
/*+--------------------------------------------------------------------------+*/


/*+--------------------------------------------------------------------------+*/
/*| MS-RDPECLIP 2.2.4.1                                                      |*/
/*| (not used so far)                                                        |*/
/*+--------------------------------------------------------------------------+*/

/*+--------------------------------------------------------------------------+*/
/*| MS-RDPECLIP 2.2.5.1                                                      |*/
/*| Sent by the recipient of Format_list pdu. Used to request the data       |*/
/*| for 1 of the formats that was listed in the format_list pdu.             |*/
/*+--------------------------------------------------------------------------+*/
#define SZ_CLIPDR_FORMAT_DATA_REQUEST   4 // excluding header

/*+--------------------------------------------------------------------------+*/
/*| MS-RDPECLIP 2.2.5.2                                                      |*/
/*| This PDU is sent as a reply to the Request pdu. Used to indicate whether |*/ 
/*| processing of the format_data request pdu was successful.                |*/
/*+--------------------------------------------------------------------------+*/
#define SZ_CLIPDR_FORMAT_DATA_RESPONSE  8

typedef struct dsd_clipdr_format_data_response
{
//    struct dsd_clipdr_header    dsc_header;
    unsigned char               uchrc_data[1];
} dsd_clipdr_format_data_response_t, *adsd_clipdr_format_data_response_t;

/*+--------------------------------------------------------------------------+*/
/*| MS-RDPECLIP 2.2.5.2.1                                                    |*/
/*| This sturct is used to transfer a Win metafile.                          |*/
/*+--------------------------------------------------------------------------+*/
#define SZ_CLIPDR_MFPICT    12

#if !defined _WIN32 && !defined _WIN64  // these are also defined in wingdi.h
#ifdef _BIGENDIAN
#define MM_TEXT             0X01000000
#define MM_LOMETRIC         0X02000000
#define MM_HIMETRIC         0X03000000
#define MM_LOENGLISH        0X04000000
#define MM_HIENGLISH        0X05000000
#define MM_TWIPS            0X06000000
#define MM_ISOTROPIC        0X07000000
#define MM_ANISOTROPIC      0X08000000
#else
#define MM_TEXT             0X00000001
#define MM_LOMETRIC         0X00000002
#define MM_HIMETRIC         0X00000003
#define MM_LOENGLISH        0X00000004
#define MM_HIENGLISH        0X00000005
#define MM_TWIPS            0X00000006
#define MM_ISOTROPIC        0X00000007
#define MM_ANISOTROPIC      0X00000008
#endif
#endif

typedef struct dsd_clipdr_mfpict
{
    unsigned int    umc_mapping_mode;
    unsigned int    umc_xext;
    unsigned int    umc_yext;
    unsigned char   uchrc_metafile_data[1];
} dsd_clipdr_mfpict_t, *adsd_clipdr_mfpict_t;

/*+--------------------------------------------------------------------------+*/
/*| MS-RDPECLIP 2.2.5.2.2.1                                                  |*/
/*| This struct contrains a single palette entry.                            |*/
/*+--------------------------------------------------------------------------+*/
#define SZ_PALETTEENTRY     4

typedef struct dsd_paletteentry
{
    unsigned char   uchc_red;
    unsigned char   uchc_green;
    unsigned char   uchc_blue;
    unsigned char   uchc_extra;
} dsd_paletteentry_t, *adsd_paletteentry_t;

/*+--------------------------------------------------------------------------+*/
/*| MS-RDPECLIP 2.2.5.2.2                                                    |*/
/*| This struct is used to transfer palette format data.                     |*/
/*+--------------------------------------------------------------------------+*/
// forward declaration.
struct dsd_paletteentry;

typedef struct dsd_clipdr_palette
{
    struct dsd_paletteentry dsrc_palette_entries[1];
} dsd_clipdr_palette_t, *adsd_clipdr_palette_t;


/*+--------------------------------------------------------------------------+*/
/*| MS-RDPECLIP 2.2.5.2.3                                                    |*/
/*| (unused so far)                                                          |*/
/*+--------------------------------------------------------------------------+*/

/*+--------------------------------------------------------------------------+*/
/*| MS-RDPECLIP 2.2.5.3                                                      |*/
/*| This pdu is sent by the recipient of the format_list pdu and is used     |*/
/*| to request either the size of a remote file copied to the clipboard or   |*/
/*| a portion of the data in the file.                                       |*/
/*+--------------------------------------------------------------------------+*/
#define SZ_CLIPDR_FILECONTENTS_REQUEST  32

#ifdef _BIGENDIAN
#define FILECONTENTS_SIZE               0X01000000
#define FILECONTENTS_RANGE              0X02000000
#else
#define FILECONTENTS_SIZE               0X00000001
#define FILECONTENTS_RANGE              0X00000002
#endif

typedef struct dsd_clipdr_filecontents_request
{
//    struct dsd_clipdr_header    dsc_header;
    unsigned int                umc_stream_id;
    int                         imc_index;
    unsigned int                umc_flags;
    unsigned int                umc_position_low;
    unsigned int                umc_position_high;
    unsigned int                umc_cb_requested;
} dsd_clipdr_filecontents_request_t, *adsd_clipdr_filecontents_request_t;

/*+--------------------------------------------------------------------------+*/
/*| MS-RDPECLIP 2.2.4.4                                                      |*/
/*| Used to indicate if the file content request pdu was succuessful.        |*/
/*+--------------------------------------------------------------------------+*/
#define SZ_CLIPDC_FILECONTENTS_RESPONSE 12

typedef struct dsd_clipdr_filecontents_response
{
//    struct dsd_clipdr_header    dsc_header;
    unsigned int                umc_stream_id;
    unsigned char               uchrc_data[1];
} dsd_clipdr_filecontents_response_t, *adsd_clipdr_filecontents_response_t;

#ifndef strncasecmp
#define strncasecmp _strnicmp
#endif

#if !(defined HL_UNIX || defined HL_LINUX || defined HOB_UNIX || defined HL_LINUX64)
  #define CLIPBOARD_LOG(LOG_LEVEL, MESSAGE, ...) {m_rdpacc_clipboard_log(adsl_rdpacc_clipboard, avo_usrfld, __FUNCTION__, __LINE__, LOG_LEVEL, MESSAGE, __VA_ARGS__);}

#ifdef HOB_RDPACC_ALLOW_THROW
    #define RETURN_FALSE_OR_THROW(MESSAGE, ...) {CLIPBOARD_LOG(LOG_LEVEL_ERROR, MESSAGE, __VA_ARGS__); \
                                             THROW_HOB_ERRROR(MESSAGE, __VA_ARGS__);}
    #define CHECK_RETURN(COMMAND) (COMMAND)
  #else
    #define RETURN_FALSE_OR_THROW(MESSAGE, ...) {CLIPBOARD_LOG(LOG_LEVEL_ERROR, MESSAGE, __VA_ARGS__); \
                                             return false; }
    #define CHECK_RETURN(COMMAND) if((COMMAND) == false) return false; 
  #endif
#else
  #define CLIPBOARD_LOG(LOG_LEVEL, MESSAGE, ...) {m_rdpacc_clipboard_log(adsl_rdpacc_clipboard, avo_usrfld, __FUNCTION__, __LINE__, LOG_LEVEL, MESSAGE, ##__VA_ARGS__);}

#ifdef HOB_RDPACC_ALLOW_THROW
    #define RETURN_FALSE_OR_THROW(MESSAGE, ...) {CLIPBOARD_LOG(LOG_LEVEL_ERROR, MESSAGE, ##__VA_ARGS__); \
                                             THROW_HOB_ERRROR(MESSAGE, ##__VA_ARGS__);}
    #define CHECK_RETURN(COMMAND) (COMMAND)
  #else
    #define RETURN_FALSE_OR_THROW(MESSAGE, ...) {CLIPBOARD_LOG(LOG_LEVEL_ERROR, MESSAGE, ##__VA_ARGS__); \
                                             return false; }
    #define CHECK_RETURN(COMMAND) if((COMMAND) == false) return false; 
  #endif
#endif 

#define CHECK_POINTER_NOT_NULL(POINTER) if((POINTER) == NULL) RETURN_FALSE_OR_THROW("Error in clipboard! %s == NULL", (POINTER));
#define CHECK_PARSE(CALL) if((CALL) == false){RETURN_FALSE_OR_THROW("Parse error function=%s line=%i", __FUNCTION__, __LINE__);}

/*+--------------------------------------------------------------------------+*/
/*| Local Function Declarations.                                             |*/
/*+--------------------------------------------------------------------------+*/

static bool m_parse_statemachine(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader);
static bool m_parse_header      (dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader);
static bool m_parse_switch_mtype(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader);
static bool m_parse_format_list (dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader);
static bool m_parse_fmt_data_req(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader);
static bool m_parse_format_d_res(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader);
static bool m_parse_capabilities(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader);
static bool m_parse_cap_general (dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader);

static bool m_write_monitor_ready_pdu(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld);
static bool m_write_fmt_list_long    (dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld);
static bool m_write_fmt_list_short   (dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld);
static bool m_write_fmt_list_rsp     (dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, bool bol_ok);
static bool m_write_fmt_data_req     (dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, ied_clip_formats iel_format);
static bool m_write_fmt_data_rsp_fail(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld);
static bool m_write_fmt_data_rsp_ok  (dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* ads_reader);
static bool m_write_server_caps_pdu  (dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld);

/*+--------------------------------------------------------------------------+*/
/*| Local Global variables.                                                  |*/
/*+--------------------------------------------------------------------------+*/

static const unsigned short wstrgs_fmt_names[][MAX_CUSTOM_NAME] = 
{  
    {0x0000},
    {0x0043, 0x0046, 0x005f, 0x0054, 0x0045, 0x0058, 0x0054, 0x0000},  // CF_TEXT
    {0x0043, 0x0046, 0x005f, 0x0042, 0x0049, 0x0054, 0x004d, 0x0041, 0x0050, 0x0000}, //CF_BITMAP
    {0x0043, 0x0046, 0x005f, 0x004d, 0x0045, 0x0054, 0x0041, 0x0046, 0x0049, 0x0045, 0x0050, 0x0049, 0x0043, 0x0054, 0x0000}, //CF_METAFIEPICT 
    {0x0043, 0x0046, 0x005f, 0x0053, 0x0059, 0x004b, 0x0000}, //CF_SYK
    {0x0043, 0x0046, 0x005f, 0x0044, 0x0049, 0x0046, 0x0000}, //CF_DIF
    {0x0043, 0x0046, 0x005f, 0x0054, 0x0049, 0x0046, 0x0046, 0x0000}, //CF_TIFF
    {0x0043, 0x0046, 0x005f, 0x004f, 0x0045, 0x004d, 0x0054, 0x0045, 0x0058, 0x0054, 0x0000}, //CF_OEMTEXT
    {0x0043, 0x0046, 0x005f, 0x0044, 0x0049, 0x0042, 0x0000}, //CF_DIB
    {0x0043, 0x0046, 0x005f, 0x0050, 0x0041, 0x004c, 0x0045, 0x0054, 0x0054, 0x0045, 0x0000}, //CF_PALETTE
    {0x0043, 0x0046, 0x005f, 0x0050, 0x0045, 0x004e, 0x0044, 0x0041, 0x0054, 0x0041, 0x0000}, //CF_PENDATA
    {0x0043, 0x0046, 0x005f, 0x0052, 0x0049, 0x0046, 0x0046, 0x0000}, // CF_RIFF
    {0x0043, 0x0046, 0x005f, 0x0057, 0x0041, 0x0056, 0x0045, 0x0000}, //CF_WAVE
    {0x0043, 0x0046, 0x005f, 0x0055, 0x004e, 0x0049, 0x0043, 0x004f, 0x0044, 0x0045, 0x0054, 0x0045, 0x0058, 0x0054, 0x0000}, //CF_UNICODETEXT
    {0x0043, 0x0046, 0x005f, 0x0045, 0x004e, 0x0048, 0x004d, 0x0045, 0x0054, 0x0041, 0x0046, 0x0049, 0x0045, 0x0000}, //CF_ENHMETAFIE
    {0x0043, 0x0046, 0x005f, 0x0048, 0x0044, 0x0052, 0x004f, 0x0050, 0x0000}, //CF_HDROP
    {0x0043, 0x0046, 0x005f, 0x004c, 0x004f, 0x0043, 0x0041, 0x004c, 0x0045, 0x0000}, //CF_LOCALE
    {0x0043, 0x0046, 0x005f, 0x0044, 0x0049, 0x0042, 0x0056, 0x0035, 0x0000} //CF_DIBV5
};

/*+--------------------------------------------------------------------------+*/
/*| Log Helper Definition.                                                   |*/
/*+--------------------------------------------------------------------------+*/
static bool m_rdpacc_clipboard_log(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld,
                                   const char* achl_function, int inl_line, 
                                   int inl_lvl, const char *achl_message, ...){

   if(adsl_rdpacc_clipboard == NULL)
      return false;
   amd_log_cb aml_log_cb = adsl_rdpacc_clipboard->dsc_callbacks.amc_log_cb;
   if(aml_log_cb == NULL)
      return false; 

   // resolve achl_message and va-args
   static const int inls_max_message_size = 0x200;
   char chrl_message_tmp_1[inls_max_message_size];
   va_list dsl_argptr;    
   va_start(dsl_argptr, achl_message);
#if !(defined HL_UNIX || defined HL_LINUX || defined HOB_UNIX || defined HL_LINUX64)
   int inl_len_message_1 = vsnprintf_s(chrl_message_tmp_1, inls_max_message_size, _TRUNCATE, achl_message, dsl_argptr);
#else
   int inl_len_message_1 = vsnprintf(chrl_message_tmp_1, inls_max_message_size, (char*) achl_message, dsl_argptr);
#endif
   va_end(dsl_argptr);

   // Now print with functionname and linenumber
   char chrl_message_tmp_2[inls_max_message_size];
#if !(defined HL_UNIX || defined HL_LINUX || defined HOB_UNIX || defined HL_LINUX64)
   int inl_len_message_2 = sprintf_s(chrl_message_tmp_2, inls_max_message_size, "xlrdpeclip.cpp clipb=%p func=%s line=%i: %s", adsl_rdpacc_clipboard, achl_function, inl_line, chrl_message_tmp_1);
#else
   int inl_len_message_2 = snprintf(chrl_message_tmp_2, inls_max_message_size, "xlrdpeclip.cpp clipb=%p func=%s line=%i: %s", adsl_rdpacc_clipboard, achl_function, inl_line, chrl_message_tmp_1);
#endif
      

   if(aml_log_cb(avo_usrfld, inl_lvl, chrl_message_tmp_2, inl_len_message_2) == false){
      return false;
   }
    
   return true;    
}

//+-----------------------------------------------------------------+
//|          _                   __              _   _              |
//|  _____ _| |_ ___ _ _ _ _    / _|_  _ _ _  __| |_(_)___ _ _  ___ |
//| / -_) \ /  _/ -_) '_| ' \  |  _| || | ' \/ _|  _| / _ \ ' \(_-< |
//| \___/_\_\\__\___|_| |_||_| |_|  \_,_|_||_\__|\__|_\___/_||_/__/ |
//|                                                                 |
//+-----------------------------------------------------------------+

/**
 * Initialises the Clipboard
 *
 * @param[in]  adsp_vc   Virtual Channel
 * @param[in]  ap_con    Connection object
 * @param[out] aap_clip  Pointer to structure where clipboard will be stored
 * @param[in]  adsp_cb   Callback functions
 *
 * @return dsd_sc_co1 command that is to be sent to the RDP Clients
 */

extern bool m_rdpacc_clipboard_init(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, 
                             dsd_rdp_vc_1 *adsl_vc, dsd_rdpacc_clipboard_callbacks* adsl_callbacks){

   CHECK_POINTER_NOT_NULL(adsl_rdpacc_clipboard);
   CHECK_POINTER_NOT_NULL(adsl_vc);

   CLIPBOARD_LOG(LOG_LEVEL_INFO, "virtual channel no=0x%x", adsl_vc->usc_vch_no);

   // Check pointers and name of virtual channel
#if !(defined HL_UNIX || defined HL_LINUX || defined HOB_UNIX || defined HL_LINUX64)
   if(strcasecmp(adsl_vc->byrc_name, achrs_clipe_name, sizeof(achrs_clipe_name)))
#else
   if(strcasecmp(adsl_vc->byrc_name, achrs_clipe_name))
#endif
      RETURN_FALSE_OR_THROW("adsl_vc->byrc_name=%s", adsl_vc->byrc_name);

   // Check, if callbacks are not zero!
   CHECK_POINTER_NOT_NULL(adsl_callbacks->amc_on_copy_data_cb);
   CHECK_POINTER_NOT_NULL(adsl_callbacks->amc_on_copy_fmts_cb);
   CHECK_POINTER_NOT_NULL(adsl_callbacks->amc_on_paste_cb);
   CHECK_POINTER_NOT_NULL(adsl_callbacks->amc_log_cb);
   CHECK_POINTER_NOT_NULL(adsl_callbacks->amc_command_for_rdpacc);
   CHECK_POINTER_NOT_NULL(adsl_callbacks->amc_get_memory);
   CHECK_POINTER_NOT_NULL(adsl_callbacks->amc_free_memory);
   
   // Copy callbacks and other settings
   memset(adsl_rdpacc_clipboard, 0, sizeof(dsd_rdpacc_clipboard));
   memcpy(&adsl_rdpacc_clipboard->dsc_callbacks, adsl_callbacks, sizeof(dsd_rdpacc_clipboard_callbacks));
   adsl_rdpacc_clipboard->adsc_vc = adsl_vc;
   adsl_rdpacc_clipboard->iec_parse_state = ied_parse_header;

   // Create two PDUs
   CHECK_RETURN(m_write_server_caps_pdu(adsl_rdpacc_clipboard, avo_usrfld));
   CHECK_RETURN(m_write_monitor_ready_pdu(adsl_rdpacc_clipboard, avo_usrfld));

   // Init buffers
   adsl_rdpacc_clipboard->dsc_format_list.init();
   adsl_rdpacc_clipboard->dsc_buffer_names.init();
   adsl_rdpacc_clipboard->dsc_data_buffer.init();

   return true;
} // bool m_rdpacc_clipboard_init(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_rdp_vc_1 *adsl_vc, dsd_rdpacc_clipboard_callbacks* adsl_callbacks)

extern bool m_rdpacc_clipboard_close(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld){
   CHECK_POINTER_NOT_NULL(adsl_rdpacc_clipboard);
   CLIPBOARD_LOG(LOG_LEVEL_INFO, "");

   adsl_rdpacc_clipboard->dsc_format_list.close(adsl_rdpacc_clipboard->dsc_callbacks.amc_free_memory, avo_usrfld);
   adsl_rdpacc_clipboard->dsc_buffer_names.close(adsl_rdpacc_clipboard->dsc_callbacks.amc_free_memory, avo_usrfld);
   adsl_rdpacc_clipboard->dsc_data_buffer.close(adsl_rdpacc_clipboard->dsc_callbacks.amc_free_memory, avo_usrfld);

   return true; 
} // void m_rdpacc_clipboard_close(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld)

bool m_rdpacc_clipboard_srvr_copy(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, 
                                  int inl_number_formats, dsd_format_list_entry* adsl_format_list){

   CHECK_POINTER_NOT_NULL(adsl_rdpacc_clipboard);
   if(inl_number_formats == 0){
      CLIPBOARD_LOG(LOG_LEVEL_WARNING, "m_rdpacc_clipboard_srvr_copy: inl_number_formats = 0!");
      return true; 
   }
   CHECK_POINTER_NOT_NULL(adsl_format_list);
   adsl_rdpacc_clipboard->boc_server_is_owner = true;
   CLIPBOARD_LOG(LOG_LEVEL_TRACE, "Server copied and is owner now. Number of available formats=%i", inl_number_formats);

   // Count unicodes
   int inl_num_unicodes = 0;
   for(int inl_i = 0; inl_i < inl_number_formats; inl_i++){
      dsd_format_list_entry* ads_entry = adsl_format_list + inl_i;
      if(ads_entry->inc_len_format_name == 0){
         inl_num_unicodes++;
         continue;
      }
      if(ads_entry->awcc_format_name == NULL)
         RETURN_FALSE_OR_THROW("m_rdpacc_clipboard_srvr_copy: format #%i id=0x%x len_name=%i, awcc_format_name=NULL!", 
            inl_i, ads_entry->inc_format_id, ads_entry->inc_len_format_name);
      inl_num_unicodes += ads_entry->inc_len_format_name + 1;
   }

   CHECK_RETURN(adsl_rdpacc_clipboard->dsc_format_list.ensure_elements(inl_number_formats, 
                adsl_rdpacc_clipboard->dsc_callbacks.amc_get_memory,
                adsl_rdpacc_clipboard->dsc_callbacks.amc_free_memory,
                avo_usrfld));
   CHECK_RETURN(adsl_rdpacc_clipboard->dsc_buffer_names.ensure_elements(inl_num_unicodes, 
                adsl_rdpacc_clipboard->dsc_callbacks.amc_get_memory,
                adsl_rdpacc_clipboard->dsc_callbacks.amc_free_memory,
                avo_usrfld));

   // Save formats in list
   HL_WCHAR* ach_names = adsl_rdpacc_clipboard->dsc_buffer_names.get_data();
   dsd_format_list_entry* ads_entry_dst = adsl_rdpacc_clipboard->dsc_format_list.get_data();
   dsd_format_list_entry* ads_entry_src = adsl_format_list;
   for(int inl_i = 0; inl_i < inl_number_formats; inl_i++){
      ads_entry_dst->inc_format_id       = ads_entry_src->inc_format_id;
      ads_entry_dst->inc_len_format_name = ads_entry_src->inc_len_format_name;
      ads_entry_dst->awcc_format_name    = ach_names;
      memcpy(ach_names, ads_entry_src->awcc_format_name, ads_entry_src->inc_len_format_name * sizeof(HL_WCHAR));
      ach_names += ads_entry_src->inc_len_format_name;
      *ach_names++ = 0;

      ads_entry_dst++;
      ads_entry_src++;
   }

   adsl_rdpacc_clipboard->inc_number_formats = inl_number_formats;


   if(adsl_rdpacc_clipboard->boc_long_names)
      return m_write_fmt_list_long(adsl_rdpacc_clipboard, avo_usrfld);

   return m_write_fmt_list_short(adsl_rdpacc_clipboard, avo_usrfld);

} // bool m_rdpacc_clipboard_srvr_copy(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, int inl_number_formats, dsd_format_list_entry* adsl_format_list)


extern bool m_rdpacc_clipboard_srvr_data(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_i_1* ads_gather){
   dsd_gather_reader ads_gather_reader(ads_gather);
   return m_rdpacc_clipboard_srvr_data(adsl_rdpacc_clipboard, avo_usrfld, &ads_gather_reader);
};

// return: false = severe error 
extern bool m_rdpacc_clipboard_srvr_data(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* ads_reader){

   CHECK_POINTER_NOT_NULL(adsl_rdpacc_clipboard);
   CHECK_POINTER_NOT_NULL(ads_reader);

   if(!adsl_rdpacc_clipboard->boc_server_is_owner){
      RETURN_FALSE_OR_THROW("server sends 0x%x data, but is not owner of clipboard!", ads_reader->get_bytes_left());
   }
   
   if(adsl_rdpacc_clipboard->inc_last_rcv != CB_FORMAT_DATA_REQUEST){
      RETURN_FALSE_OR_THROW("Last command received != CB_FORMAT_DATA_REQUEST (0x%08x)", adsl_rdpacc_clipboard->inc_last_rcv);
   }

   CLIPBOARD_LOG(LOG_LEVEL_TRACE, "Server sending data. 0x%x bytes", ads_reader->get_bytes_left());

   return m_write_fmt_data_rsp_ok(adsl_rdpacc_clipboard, avo_usrfld, ads_reader);
}

/**
 *
 */
bool m_rdpacc_clipboard_server_paste(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, ied_clip_formats iel_format){

   CHECK_POINTER_NOT_NULL(adsl_rdpacc_clipboard);
   if(iel_format == ied_cf_empty){
      CLIPBOARD_LOG(LOG_LEVEL_WARNING, "server is pasting, iel_format=ied_cf_empty");
      return false; 
   }

   if (adsl_rdpacc_clipboard->boc_server_is_owner){
      CLIPBOARD_LOG(LOG_LEVEL_WARNING, "server is owner asking for data.");
      return false;
   }

#if CB_ONLY_TEXT
   if((iel_format != ied_cf_text) && (iel_format != ied_cf_unicodetext)){
      CLIPBOARD_LOG(LOG_LEVEL_WARNING, "Clipboard can only do text, but iel_format=0x%x is requested", iel_format);
      return false;
   }
#endif

   if((adsl_rdpacc_clipboard->inc_last_rcv != CB_FORMAT_LIST) &&
      (adsl_rdpacc_clipboard->inc_last_rcv != CB_FORMAT_DATA_RESPONSE)){
      CLIPBOARD_LOG(LOG_LEVEL_WARNING, "server_paste, but adsl_rdpacc_clipboard->inc_last_rcv=0x%x", adsl_rdpacc_clipboard->inc_last_rcv);
      return false;
   }

   // Now search for this format in format-list
   int inl1 = adsl_rdpacc_clipboard->inc_number_formats;
   while(inl1 > 0){
      inl1--;
      if(adsl_rdpacc_clipboard->dsc_format_list.get_data()[inl1].inc_format_id == iel_format){
         CLIPBOARD_LOG(LOG_LEVEL_INFO, "server is pasting, known format=0x%x", iel_format);
         return m_write_fmt_data_req(adsl_rdpacc_clipboard, avo_usrfld, iel_format);
      }
   }

   CLIPBOARD_LOG(LOG_LEVEL_WARNING, "format=0x%x not found, paste failed. adsl_rdpacc_clipboard->inc_number_formats%i", 
      iel_format, adsl_rdpacc_clipboard->inc_number_formats);
   return true;
} // bool m_rdpacc_clipboard_server_paste(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, ied_clip_formats iel_format)

bool m_rdpacc_clipboard_process_and_reply(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, 
                                          dsd_cl_vch_in* adsl_cl_vch_in){

   // Check pointers, length...
   CHECK_POINTER_NOT_NULL(adsl_rdpacc_clipboard);
   CHECK_POINTER_NOT_NULL(adsl_cl_vch_in);
   
   if(adsl_cl_vch_in->adsc_rdp_vc_1 != adsl_rdpacc_clipboard->adsc_vc)
      RETURN_FALSE_OR_THROW("Wrong virtual channel. adsl_cl_vch_in->adsc_rdp_vc_1=%p, adsl_rdpacc_clipboard->adsc_vc=%p",
         adsl_cl_vch_in->adsc_rdp_vc_1, adsl_rdpacc_clipboard->adsc_vc);

   if(adsl_cl_vch_in->umc_vch_ulen == 0){
      CLIPBOARD_LOG(LOG_LEVEL_WARNING, "adsl_cl_vch_in->umc_vch_ulen == 0");
      return true; 
   }

   CHECK_POINTER_NOT_NULL(adsl_cl_vch_in->adsc_gai1_in);

   adsl_rdpacc_clipboard->chr_seg_flags[0] = adsl_cl_vch_in->chrc_vch_segfl[0];
   adsl_rdpacc_clipboard->chr_seg_flags[1] = adsl_cl_vch_in->chrc_vch_segfl[1];
   adsl_rdpacc_clipboard->inc_vch_len      = adsl_cl_vch_in->umc_vch_ulen;

   // Create reader
   dsd_gather_reader dsl_reader(adsl_cl_vch_in->adsc_gai1_in);
   
   // Was there data stored before?
   dsd_gather_i_1 ds_gather_old_data;
   int inl_old_data_len = adsl_rdpacc_clipboard->inc_data_len;
   if(inl_old_data_len > 0){
      CLIPBOARD_LOG(LOG_LEVEL_TRACE, "Data left from last call: 0x%x bytes", inl_old_data_len);
      ds_gather_old_data.adsc_next = NULL;
      ds_gather_old_data.achc_ginp_cur = adsl_rdpacc_clipboard->dsc_data_buffer.get_data();
      ds_gather_old_data.achc_ginp_end = ds_gather_old_data.achc_ginp_cur + inl_old_data_len;
      dsl_reader.add_front(&ds_gather_old_data);
   }

   CHECK_RETURN(m_parse_statemachine(adsl_rdpacc_clipboard, avo_usrfld, &dsl_reader));

   if(dsl_reader.empty()){
      adsl_rdpacc_clipboard->inc_data_len = 0;
      return true; 
   }

   // Unparsed data left -> Check size of buffer
   if(adsl_rdpacc_clipboard->dsc_data_buffer.get_act_size() < dsl_reader.get_bytes_left()){
      // Still old data in reader?
      if((inl_old_data_len > 0) && (ds_gather_old_data.achc_ginp_cur < ds_gather_old_data.achc_ginp_end)){
         int inl_data_in_old_gather = (int) (ds_gather_old_data.achc_ginp_end - ds_gather_old_data.achc_ginp_cur);
         adsl_rdpacc_clipboard->dsc_data_buffer.ensure_elements(dsl_reader.get_bytes_left(), 
            adsl_rdpacc_clipboard->dsc_callbacks.amc_get_memory, adsl_rdpacc_clipboard->dsc_callbacks.amc_free_memory, avo_usrfld, true);
         ds_gather_old_data.achc_ginp_cur = adsl_rdpacc_clipboard->dsc_data_buffer.get_data() + (inl_old_data_len - inl_data_in_old_gather);
         ds_gather_old_data.achc_ginp_end = ds_gather_old_data.achc_ginp_cur + inl_data_in_old_gather;
      } else {
         // No old data there, or old data comsumed. 
         adsl_rdpacc_clipboard->dsc_data_buffer.ensure_elements(dsl_reader.get_bytes_left(), 
            adsl_rdpacc_clipboard->dsc_callbacks.amc_get_memory, adsl_rdpacc_clipboard->dsc_callbacks.amc_free_memory, avo_usrfld);
         inl_old_data_len = 0;
      }
   }
   
   adsl_rdpacc_clipboard->inc_data_len = dsl_reader.get_bytes_left();
   CLIPBOARD_LOG(LOG_LEVEL_TRACE, "Data left after this call: 0x%x bytes", adsl_rdpacc_clipboard->inc_data_len);
   CHECK_PARSE(dsl_reader.copy_to(adsl_rdpacc_clipboard->dsc_data_buffer.get_data(), dsl_reader.get_bytes_left()));

   return true; 
}

//+-----------------------------------------------------------------+
//|                              __              _   _              |
//|  _ __  __ _ _ _ ___ ___ ___ / _|_  _ _ _  __| |_(_)___ _ _  ___ |
//| | '_ \/ _` | '_(_-</ -_)___|  _| || | ' \/ _|  _| / _ \ ' \(_-< |
//| | .__/\__,_|_| /__/\___|   |_|  \_,_|_||_\__|\__|_\___/_||_/__/ |
//| |_|                                                             |
//+-----------------------------------------------------------------+

bool m_parse_statemachine(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader){

   while(!adsl_reader->empty()){
      switch(adsl_rdpacc_clipboard->iec_parse_state){

         case ied_parse_header: {
            if(adsl_reader->get_bytes_left() < SZ_CLIPDR_HEADER)
               return true; // Wait until all the bytes for the header are there
            DSD_GATHER_READER(dsl_subreader, adsl_reader, SZ_CLIPDR_HEADER);
            CHECK_RETURN(m_parse_header(adsl_rdpacc_clipboard, avo_usrfld, &dsl_subreader));
            adsl_rdpacc_clipboard->iec_parse_state = ied_parse_wait_for_len;
         } continue;

         case ied_parse_wait_for_len: {
            if(adsl_reader->get_bytes_left() < adsl_rdpacc_clipboard->inc_pdu_len)
               return true; // Wait until the whole PDU is there
            DSD_GATHER_READER(dsl_subreader, adsl_reader, adsl_rdpacc_clipboard->inc_pdu_len);
            CHECK_RETURN(m_parse_switch_mtype(adsl_rdpacc_clipboard, avo_usrfld, &dsl_subreader));
            adsl_rdpacc_clipboard->iec_parse_state = ied_parse_header;
         } continue;

         default:
            RETURN_FALSE_OR_THROW("Unknown state in clipboard statemachine: 0x%x", adsl_rdpacc_clipboard->iec_parse_state);
      }
   }
   return true; 
}

bool m_parse_header(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader){

   // Parse header
   CHECK_PARSE(adsl_reader->read_16_le(&adsl_rdpacc_clipboard->inc_msg_type));
   CHECK_PARSE(adsl_reader->read_16_le(&adsl_rdpacc_clipboard->inc_msg_flags));
   CHECK_PARSE(adsl_reader->read_32_le(&adsl_rdpacc_clipboard->inc_pdu_len));
   adsl_rdpacc_clipboard->inc_last_rcv = adsl_rdpacc_clipboard->inc_msg_type;

   if((adsl_rdpacc_clipboard->inc_msg_flags & CB_FLAG_RESPONSE_FAIL) != 0){
      CLIPBOARD_LOG(LOG_LEVEL_INFO, "sf=0x%02x/0x%02x vl=0x%x CB_RESPONSE_FAIL: msg_type=%s msg_flags=0x%x data_len=0x%x", 
         adsl_rdpacc_clipboard->chr_seg_flags[0], adsl_rdpacc_clipboard->chr_seg_flags[1], adsl_rdpacc_clipboard->inc_vch_len,
         get_text_msg_type(adsl_rdpacc_clipboard->inc_msg_type), adsl_rdpacc_clipboard->inc_msg_flags, adsl_rdpacc_clipboard->inc_pdu_len);
      return true; 
   }

   return true;
}

bool m_parse_switch_mtype(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader){
   bool bol_ret = true; 
   switch(adsl_rdpacc_clipboard->inc_msg_type){
      case CB_FORMAT_LIST:
         bol_ret = m_parse_format_list(adsl_rdpacc_clipboard, avo_usrfld, adsl_reader);
         break;
      case CB_FORMAT_DATA_REQUEST:
         bol_ret = m_parse_fmt_data_req(adsl_rdpacc_clipboard, avo_usrfld, adsl_reader);
         break;
      case CB_FORMAT_DATA_RESPONSE: 
         bol_ret = m_parse_format_d_res(adsl_rdpacc_clipboard, avo_usrfld, adsl_reader);
         break;
      case CB_CLIP_CAPS:
         bol_ret = m_parse_capabilities(adsl_rdpacc_clipboard, avo_usrfld, adsl_reader);
         break;

      case CB_MONITOR_READY:        // only the server sends this packet so we should never receive it.
      case CB_FORMAT_LIST_RESPONSE: // We do nothing with this PDU. CHECK RETURN-FLAGS???
      case CB_TEMP_DIRECTORY:       // we do nothing (yet) with this PDU.
      case CB_FILECONTENTS_REQEUST: // as yet unsupported.
      case CB_FILECONTENTS_RESPONSE:// as yet unsupported.
         CLIPBOARD_LOG(LOG_LEVEL_TRACE, "sf=0x%02x/0x%02x vl=0x%x Client sent %s, msg_flags=0x%x data_len=0x%x", 
            adsl_rdpacc_clipboard->chr_seg_flags[0], adsl_rdpacc_clipboard->chr_seg_flags[1], adsl_rdpacc_clipboard->inc_vch_len,
            get_text_msg_type(adsl_rdpacc_clipboard->inc_msg_type), adsl_rdpacc_clipboard->inc_msg_flags, adsl_rdpacc_clipboard->inc_pdu_len);
         adsl_reader->skip_rest();  
         return true;
      default:
         CLIPBOARD_LOG(LOG_LEVEL_WARNING, "sf=0x%02x/0x%02x vl=0x%x Unknown PDU-type 0x%x, msg_flags=0x%x data_len=0x%x", 
            adsl_rdpacc_clipboard->chr_seg_flags[0], adsl_rdpacc_clipboard->chr_seg_flags[1], adsl_rdpacc_clipboard->inc_vch_len,
            adsl_rdpacc_clipboard->inc_msg_type, adsl_rdpacc_clipboard->inc_msg_flags, adsl_rdpacc_clipboard->inc_pdu_len);
         adsl_reader->skip_rest();
         return true; 
   }

   if(!adsl_reader->empty()){
      CLIPBOARD_LOG(LOG_LEVEL_WARNING, "sf=0x%02x/0x%02x vl=0x%x Still data left in %s-PDU: 0x%x bytes, msg_flags=0x%x data_len=0x%x", 
         adsl_rdpacc_clipboard->chr_seg_flags[0], adsl_rdpacc_clipboard->chr_seg_flags[1], adsl_rdpacc_clipboard->inc_vch_len,
         get_text_msg_type(adsl_rdpacc_clipboard->inc_msg_type), adsl_reader->get_bytes_left(), adsl_rdpacc_clipboard->inc_msg_flags, adsl_rdpacc_clipboard->inc_pdu_len);
      adsl_reader->skip_rest();
   }
   return bol_ret; 
}

bool m_parse_format_list(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader){
   
   // This PDU is tricky, as we don't know the length of the data and the number of the list-entries. 
   // So at first we peek the data just to figure out the number of characters and the number of entries. 
   int inl_num_formats = 0;
   int inl_num_unicodes = 0; 
   if(adsl_rdpacc_clipboard->boc_long_names){
      int inl_i = 0;
      while(inl_i < adsl_reader->get_bytes_left()){
         inl_num_formats++;   // new entry
         inl_i += 4;          // skip id
         
         while(true){
            inl_num_unicodes++;
            HL_WCHAR wcl_unicode;
            CHECK_PARSE(adsl_reader->peek_data((char*) &wcl_unicode, inl_i, sizeof(HL_WCHAR)));
            inl_i += 2; 
            if(wcl_unicode == 0)
               break;
         }
      }
   } else {
      // Short names -> just number of unicodes is difficult
      inl_num_formats = adsl_reader->get_bytes_left() / (4 + 32);
      for(int inl_i = 0; inl_i < inl_num_formats; inl_i++){
         int inl_u = 0;
         while(true){
            inl_num_unicodes++;
            HL_WCHAR wcl_unicode;
            CHECK_PARSE(adsl_reader->peek_data((char*) &wcl_unicode, inl_i * (32 + 4) + 4 + inl_u, sizeof(HL_WCHAR)));
            inl_u += 2; 
            if(wcl_unicode == 0)
               break;
            if(inl_u < 32)
               continue;
            inl_num_unicodes++; // make space for terminating zero
            break;
         }
      }
   }

   CLIPBOARD_LOG(LOG_LEVEL_TRACE, "sf=0x%02x/0x%02x vl=0x%x Client sent CB_FORMAT_LIST, msg_flags=0x%x data_len=0x%x num_formats=%i", 
      adsl_rdpacc_clipboard->chr_seg_flags[0], adsl_rdpacc_clipboard->chr_seg_flags[1], adsl_rdpacc_clipboard->inc_vch_len,
      adsl_rdpacc_clipboard->inc_msg_flags, adsl_rdpacc_clipboard->inc_pdu_len, inl_num_formats);

   // Now make buffers big enough
   CHECK_RETURN(adsl_rdpacc_clipboard->dsc_format_list.ensure_elements(inl_num_formats, 
                adsl_rdpacc_clipboard->dsc_callbacks.amc_get_memory,
                adsl_rdpacc_clipboard->dsc_callbacks.amc_free_memory,
                avo_usrfld));
   CHECK_RETURN(adsl_rdpacc_clipboard->dsc_buffer_names.ensure_elements(inl_num_unicodes, 
                adsl_rdpacc_clipboard->dsc_callbacks.amc_get_memory,
                adsl_rdpacc_clipboard->dsc_callbacks.amc_free_memory,
                avo_usrfld));

   dsd_format_list_entry* ads_act_entry = adsl_rdpacc_clipboard->dsc_format_list.get_data();
   HL_WCHAR* awcl_format_names = adsl_rdpacc_clipboard->dsc_buffer_names.get_data();

   adsl_rdpacc_clipboard->inc_number_formats = inl_num_formats;
   while(inl_num_formats > 0){
      inl_num_formats--;
      
      // parse ID
      CHECK_PARSE(adsl_reader->read_32_le(&ads_act_entry->inc_format_id));
      ads_act_entry->awcc_format_name = awcl_format_names;
      ads_act_entry->inc_len_format_name = 0;

      if(adsl_rdpacc_clipboard->boc_long_names){
         while(true){
            CHECK_PARSE(adsl_reader->copy_to((char*) awcl_format_names, sizeof(HL_WCHAR)));
            if(*awcl_format_names++ == 0)
               break;
            ads_act_entry->inc_len_format_name++;
         }
      } else {
         while(true){
            CHECK_PARSE(adsl_reader->copy_to((char*) awcl_format_names, sizeof(HL_WCHAR)));
            if(*awcl_format_names++ == 0)
               break;
            ads_act_entry->inc_len_format_name++;
            if(ads_act_entry->inc_len_format_name >= 16)
               break;
         }
      }
      ads_act_entry++;
   }

   adsl_rdpacc_clipboard->boc_server_is_owner = false;

   // Now call callback-function
   adsl_rdpacc_clipboard->dsc_callbacks.amc_on_copy_fmts_cb(avo_usrfld, 
      adsl_rdpacc_clipboard->inc_number_formats, adsl_rdpacc_clipboard->dsc_format_list.get_data());

   // Write format list response PDU
   return m_write_fmt_list_rsp(adsl_rdpacc_clipboard, avo_usrfld, true); 
}

static bool m_parse_fmt_data_req(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader){

   if(!adsl_rdpacc_clipboard->boc_server_is_owner){ // Return CB_RESPONSE_FAIL
      CLIPBOARD_LOG(LOG_LEVEL_WARNING, "sf=0x%02x/0x%02x vl=0x%x Client sent CB_FORMAT_DATA_REQUEST, msg_flags=0x%x data_len=0x%x, but server is not owner of clipboard!", 
         adsl_rdpacc_clipboard->chr_seg_flags[0], adsl_rdpacc_clipboard->chr_seg_flags[1], adsl_rdpacc_clipboard->inc_vch_len,
         adsl_rdpacc_clipboard->inc_msg_flags, adsl_rdpacc_clipboard->inc_pdu_len);
      return m_write_fmt_data_rsp_fail(adsl_rdpacc_clipboard, avo_usrfld);
   }

   int inl_requested_format;
   CHECK_PARSE(adsl_reader->read_32_le(&inl_requested_format));

   dsd_format_list_entry* adsl_format = adsl_rdpacc_clipboard->dsc_format_list.get_data();
   for(int inl_i = adsl_rdpacc_clipboard->inc_number_formats; inl_i > 0; inl_i--){
      if(adsl_format->inc_format_id == inl_requested_format){
         if(adsl_rdpacc_clipboard->dsc_callbacks.amc_on_paste_cb(avo_usrfld, adsl_format) == true){
            CLIPBOARD_LOG(LOG_LEVEL_TRACE, "sf=0x%02x/0x%02x vl=0x%x Client sent CB_FORMAT_DATA_REQUEST, msg_flags=0x%x data_len=0x%x, inl_requested_format=0x%x", 
               adsl_rdpacc_clipboard->chr_seg_flags[0], adsl_rdpacc_clipboard->chr_seg_flags[1], adsl_rdpacc_clipboard->inc_vch_len,
               adsl_rdpacc_clipboard->inc_msg_flags, adsl_rdpacc_clipboard->inc_pdu_len, inl_requested_format);
            return true; 
         }
         break; 
      }
      adsl_format++;
   }

   CLIPBOARD_LOG(LOG_LEVEL_TRACE, "sf=0x%02x/0x%02x vl=0x%x Client sent CB_FORMAT_DATA_REQUEST, msg_flags=0x%x data_len=0x%x, but format 0x%x is not in format-list", 
      adsl_rdpacc_clipboard->chr_seg_flags[0], adsl_rdpacc_clipboard->chr_seg_flags[1], adsl_rdpacc_clipboard->inc_vch_len,
      adsl_rdpacc_clipboard->inc_msg_flags, adsl_rdpacc_clipboard->inc_pdu_len, inl_requested_format);

   // Format not found! Return CB_RESPONSE_FAIL
   return m_write_fmt_data_rsp_fail(adsl_rdpacc_clipboard, avo_usrfld);
} // bool m_parse_fmt_data_req(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader)

bool m_parse_format_d_res(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader){

   if(adsl_rdpacc_clipboard->boc_server_is_owner){
      CLIPBOARD_LOG(LOG_LEVEL_WARNING, "sf=0x%02x/0x%02x vl=0x%x Client sent CB_FORMAT_DATA_RESPONSE, msg_flags=0x%x data_len=0x%x, but client is not owner of clipboard!", 
         adsl_rdpacc_clipboard->chr_seg_flags[0], adsl_rdpacc_clipboard->chr_seg_flags[1], adsl_rdpacc_clipboard->inc_vch_len,
         adsl_rdpacc_clipboard->inc_msg_flags, adsl_rdpacc_clipboard->inc_pdu_len);
      adsl_reader->skip_rest();
      return true;
   }

   if(((adsl_rdpacc_clipboard->inc_msg_flags & CB_FLAG_RESPONSE_OK) == 0) ||
      ((adsl_rdpacc_clipboard->inc_msg_flags & CB_FLAG_RESPONSE_FAIL) != 0)){
      CLIPBOARD_LOG(LOG_LEVEL_INFO, "sf=0x%02x/0x%02x vl=0x%x Client sent CB_FORMAT_DATA_RESPONSE, msg_flags=0x%x data_len=0x%x, failed!", 
         adsl_rdpacc_clipboard->chr_seg_flags[0], adsl_rdpacc_clipboard->chr_seg_flags[1], adsl_rdpacc_clipboard->inc_vch_len,
         adsl_rdpacc_clipboard->inc_msg_flags, adsl_rdpacc_clipboard->inc_pdu_len);
      adsl_reader->skip_rest();
      return true; 
   }
   
   CLIPBOARD_LOG(LOG_LEVEL_TRACE, "sf=0x%02x/0x%02x vl=0x%x Client sent CB_FORMAT_DATA_RESPONSE, msg_flags=0x%x data_len=0x%x", 
      adsl_rdpacc_clipboard->chr_seg_flags[0], adsl_rdpacc_clipboard->chr_seg_flags[1], adsl_rdpacc_clipboard->inc_vch_len,
      adsl_rdpacc_clipboard->inc_msg_flags, adsl_rdpacc_clipboard->inc_pdu_len);

   CHECK_RETURN(adsl_rdpacc_clipboard->dsc_callbacks.amc_on_copy_data_cb(avo_usrfld, adsl_reader));
   adsl_reader->skip_rest();
   return true;
} // bool m_parse_format_d_res(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader)

bool m_parse_capabilities(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader){

   int inl_num_capability_sets;
   CHECK_PARSE(adsl_reader->read_16_le(&inl_num_capability_sets));
   CHECK_PARSE(adsl_reader->skip(2));
   
   while(inl_num_capability_sets > 0){
      int inl_capability_set_type, inl_length_capability;
      CHECK_PARSE(adsl_reader->read_16_le(&inl_capability_set_type));
      CHECK_PARSE(adsl_reader->read_16_le(&inl_length_capability));

      DSD_GATHER_READER(dsl_subreader, adsl_reader, inl_length_capability - 4); // In this case the lenght included the type and the length itselfe. 
      
      switch(inl_capability_set_type){
         case CB_CAPSTYPE_GENERAL:
            CHECK_RETURN(m_parse_cap_general(adsl_rdpacc_clipboard, avo_usrfld, &dsl_subreader));
            break;
         default:
            CLIPBOARD_LOG(LOG_LEVEL_WARNING, "sf=0x%02x/0x%02x vl=0x%x Client sent CB_CLIP_CAPS, msg_flags=0x%x data_len=0x%x, unknown capability-type 0x%x, length=0x%x", 
               adsl_rdpacc_clipboard->chr_seg_flags[0], adsl_rdpacc_clipboard->chr_seg_flags[1], adsl_rdpacc_clipboard->inc_vch_len,
               adsl_rdpacc_clipboard->inc_msg_flags, adsl_rdpacc_clipboard->inc_pdu_len, inl_capability_set_type, inl_length_capability);               
            dsl_subreader.skip_rest();
            break;
      }

      if(!dsl_subreader.empty()){
         CLIPBOARD_LOG(LOG_LEVEL_WARNING, "Still 0x%x bytes left in capability type=0x%x len=0x%x. inl_msg_type=0x%x inl_msg_flags=0x%x inl_data_len=%i", 
            dsl_subreader.get_bytes_left(), inl_capability_set_type, inl_length_capability,
            adsl_rdpacc_clipboard->inc_msg_type, adsl_rdpacc_clipboard->inc_msg_flags, adsl_rdpacc_clipboard->inc_pdu_len);
         dsl_subreader.skip_rest();
      }

      inl_num_capability_sets--;
   }

   return true; 
}

bool m_parse_cap_general(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* adsl_reader){
   // Parse general capability
   int inl_version, inl_general_flags;
   CHECK_PARSE(adsl_reader->read_32_le(&inl_version));
   CHECK_PARSE(adsl_reader->read_32_le(&inl_general_flags));

   // Evaluate capability
   if((inl_general_flags & CB_FLAG_USE_LONG_FORMAT_NAMES) != 0)
      adsl_rdpacc_clipboard->boc_long_names = true;

   CLIPBOARD_LOG(LOG_LEVEL_INFO, "sf=0x%02x/0x%02x vl=0x%x Client sent CB_CLIP_CAPS, msg_flags=0x%x data_len=0x%x, version=0x%x flags=0x%x long_names=%s", 
      adsl_rdpacc_clipboard->chr_seg_flags[0], adsl_rdpacc_clipboard->chr_seg_flags[1], adsl_rdpacc_clipboard->inc_vch_len,
      adsl_rdpacc_clipboard->inc_msg_flags, adsl_rdpacc_clipboard->inc_pdu_len,         
      inl_version, inl_general_flags, adsl_rdpacc_clipboard->boc_long_names ? "true" : "false");

   return true; 
}

//+------------------------------------------------------------+
//|                  _      __              _   _              |
//|  ___ ___ _ _  __| |___ / _|_  _ _ _  __| |_(_)___ _ _  ___ |
//| (_-</ -_) ' \/ _` |___|  _| || | ' \/ _|  _| / _ \ ' \(_-< |
//| /__/\___|_||_\__,_|   |_|  \_,_|_||_\__|\__|_\___/_||_/__/ |
//|                                                            |
//+------------------------------------------------------------+

inline static bool ms_get_command_for_rdpacc(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, 
                                             int inl_length_pdu, char** aachl_write_ret){

   dsd_sc_vch_out* adsl_sc_vch_out = adsl_rdpacc_clipboard->dsc_callbacks.amc_command_for_rdpacc(avo_usrfld, inl_length_pdu);
   if(adsl_sc_vch_out == NULL)
      RETURN_FALSE_OR_THROW("amc_command_for_rdpacc returned NULL. Required bytes=%i", inl_length_pdu);

   adsl_sc_vch_out->adsc_rdp_vc_1 = adsl_rdpacc_clipboard->adsc_vc;
   adsl_sc_vch_out->chrc_vch_segfl[0] = 0x03;
   adsl_sc_vch_out->chrc_vch_segfl[1] = 0x00;
   adsl_sc_vch_out->umc_vch_ulen = inl_length_pdu;
   *aachl_write_ret = adsl_sc_vch_out->adsc_gai1_out->achc_ginp_cur;
   return true; 
}

// MS-RDPECLIP 2.2.2.2 Server Monitor Ready PDU (CLIPRDR_MONITOR_READY)
static bool m_write_monitor_ready_pdu(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld){

   char* achl_write;
   CHECK_RETURN(ms_get_command_for_rdpacc(adsl_rdpacc_clipboard, avo_usrfld, SZ_CLIPDR_HEADER, &achl_write));

   // 2.2.2.2 Server Monitor Ready PDU (CLIPRDR_MONITOR_READY)
   write_16_le(&achl_write, CB_MONITOR_READY);  // msgType
   write_16_le(&achl_write, 0);                 // msgFlags
   write_32_le(&achl_write, 0);                 // dataLen

   CLIPBOARD_LOG(LOG_LEVEL_TRACE, "sending CB_MONITOR_READY to RDP-client");
   return true;
} // static bool m_write_monitor_ready_pdu(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld)

// 2.2.3.1 Format List PDU (CLIPRDR_FORMAT_LIST)
static bool m_write_fmt_list_long(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld){

   // Calculate size of PDU
   int inl_num_unicodes = 0;
   dsd_format_list_entry* ads_entry = adsl_rdpacc_clipboard->dsc_format_list.get_data();
   for(int inl_i = adsl_rdpacc_clipboard->inc_number_formats; inl_i > 0; inl_i--){
      inl_num_unicodes += ads_entry->inc_len_format_name + 1;
      ads_entry++;
   }
   int inl_data_len = adsl_rdpacc_clipboard->inc_number_formats * 4 + inl_num_unicodes * 2;

   // Write PDU
   char* achl_write;
   CHECK_RETURN(ms_get_command_for_rdpacc(adsl_rdpacc_clipboard, avo_usrfld,
      SZ_CLIPDR_HEADER + inl_data_len, &achl_write));

   write_16_le(&achl_write, CB_FORMAT_LIST); // msgType
   write_16_le(&achl_write, 0);              // msgFlags
   write_32_le(&achl_write, inl_data_len);   // dataLen

   ads_entry = adsl_rdpacc_clipboard->dsc_format_list.get_data();
   for(int inl_i = adsl_rdpacc_clipboard->inc_number_formats; inl_i > 0; inl_i--){
      write_32_le(&achl_write, ads_entry->inc_format_id);
      memcpy(achl_write, ads_entry->awcc_format_name, ads_entry->inc_len_format_name * sizeof(HL_WCHAR));
      achl_write += ads_entry->inc_len_format_name * sizeof(HL_WCHAR);
      write_16_be(&achl_write, 0);
      ads_entry++;
   }

   CLIPBOARD_LOG(LOG_LEVEL_TRACE, "sending CB_FORMAT_LIST (long names) to client, #formats=%i, len=0x%x", 
      adsl_rdpacc_clipboard->inc_number_formats, inl_data_len);

   return true;
} // static bool m_write_fmt_list_long(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld)

static bool m_write_fmt_list_short(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld){

   char* achl_write;
   CHECK_RETURN(ms_get_command_for_rdpacc(adsl_rdpacc_clipboard, avo_usrfld,
      SZ_CLIPDR_HEADER + adsl_rdpacc_clipboard->inc_number_formats * 36, &achl_write));
   write_16_le(&achl_write, CB_FORMAT_LIST); // msgType
   write_16_le(&achl_write, 0);              // msgFlags
   write_32_le(&achl_write, adsl_rdpacc_clipboard->inc_number_formats * 36);   // dataLen

   dsd_format_list_entry* ads_entry = adsl_rdpacc_clipboard->dsc_format_list.get_data();
   for(int inl_i = adsl_rdpacc_clipboard->inc_number_formats; inl_i > 0; inl_i--){
      write_32_le(&achl_write, ads_entry->inc_format_id);
      int inl_len = ads_entry->inc_len_format_name * sizeof(HL_WCHAR);
      if(inl_len > 30)
         inl_len = 30; 
      memcpy(achl_write, ads_entry->awcc_format_name, inl_len);
      achl_write += inl_len;
      memset(achl_write, 0, 32 - inl_len);
      achl_write += 32 - inl_len;
      ads_entry++;
   }

   CLIPBOARD_LOG(LOG_LEVEL_TRACE, "sending CB_FORMAT_LIST (short names) to client, #formats=%i, len=0x%x", 
      adsl_rdpacc_clipboard->inc_number_formats, adsl_rdpacc_clipboard->inc_number_formats * 36);

   return true;
} // static bool m_write_fmt_list_short(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld)

// MS-RDPECLIP 2.2.3.2 Format List Response PDU (FORMAT_LIST_RESPONSE)
static bool m_write_fmt_list_rsp(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, bool bol_ok){
   char* achl_write;
   CHECK_RETURN(ms_get_command_for_rdpacc(adsl_rdpacc_clipboard, avo_usrfld, SZ_CLIPDR_HEADER, &achl_write));

   write_16_le(&achl_write, CB_FORMAT_LIST_RESPONSE);          // msgType
   write_16_le(&achl_write, bol_ok == true ? 
               CB_FLAG_RESPONSE_OK : CB_FLAG_RESPONSE_FAIL);   // msgFlags
   write_32_le(&achl_write, 0);                                // dataLen

   CLIPBOARD_LOG(LOG_LEVEL_TRACE, "sending CB_FORMAT_LIST_RESPONSE to client, bol_ok=%x", bol_ok ? "true" : "false");
   return true; 
} // static bool m_write_fmt_list_rsp(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, bool bol_ok)

// 2.2.5.1 Format Data Request PDU (CLIPRDR_FORMAT_DATA_REQUEST)
static bool m_write_fmt_data_req(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, ied_clip_formats iel_format){

   char* achl_write;
   CHECK_RETURN(ms_get_command_for_rdpacc(adsl_rdpacc_clipboard, avo_usrfld,
      SZ_CLIPDR_HEADER + SZ_CLIPDR_FORMAT_DATA_REQUEST, &achl_write));

   write_16_le(&achl_write, CB_FORMAT_DATA_REQUEST);        // msgType
   write_16_le(&achl_write, 0);                             // msgFlags
   write_32_le(&achl_write, SZ_CLIPDR_FORMAT_DATA_REQUEST); // dataLen
   write_32_le(&achl_write, iel_format);                    // requestedFormatID

   // Return success
   CLIPBOARD_LOG(LOG_LEVEL_TRACE, "sending CB_FORMAT_DATA_REQUEST to client, format%x", iel_format);
   return true;
} // static bool m_write_fmt_data_req(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, ied_clip_formats iel_format)

static bool m_write_fmt_data_rsp_fail(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld){

   // Response with error
   char* achl_write;
   CHECK_RETURN(ms_get_command_for_rdpacc(adsl_rdpacc_clipboard, avo_usrfld,
      SZ_CLIPDR_HEADER, &achl_write));
   write_16_le(&achl_write, CB_FORMAT_DATA_RESPONSE); // msgType
   write_16_le(&achl_write, CB_FLAG_RESPONSE_FAIL);   // msgFlags
   write_32_le(&achl_write, 0);                       // dataLen

   CLIPBOARD_LOG(LOG_LEVEL_TRACE, "sending CB_FORMAT_DATA_RESPONSE to client with msgFlags=CB_FLAG_RESPONSE_FAIL");
   return true; 
} // static bool m_write_fmt_data_rsp_fail(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld)

static bool m_write_fmt_data_rsp_ok(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* ads_reader){
   
   int inl_len_header = SZ_CLIPDR_HEADER;
   int inl_len_data = ads_reader->get_bytes_left();

   while(!ads_reader->empty()){
      int inl_write_now = ads_reader->get_bytes_left() + inl_len_header;
      if(inl_write_now > 1600)
         inl_write_now = 1600;

      dsd_sc_vch_out* adsl_sc_vch_out = adsl_rdpacc_clipboard->dsc_callbacks.amc_command_for_rdpacc(avo_usrfld, inl_write_now);
      if(adsl_sc_vch_out == NULL)
         RETURN_FALSE_OR_THROW("amc_command_for_rdpacc returned NULL. Required bytes=%i", inl_write_now);

      adsl_sc_vch_out->adsc_rdp_vc_1 = adsl_rdpacc_clipboard->adsc_vc;
      adsl_sc_vch_out->chrc_vch_segfl[0] = 0x00;
      adsl_sc_vch_out->chrc_vch_segfl[1] = 0x00;
      adsl_sc_vch_out->umc_vch_ulen = inl_len_data + inl_len_header;
      char* achl_write = adsl_sc_vch_out->adsc_gai1_out->achc_ginp_cur;

      if(inl_len_header > 0){
         inl_write_now -= SZ_CLIPDR_HEADER;
         write_16_le(&achl_write, CB_FORMAT_DATA_RESPONSE);    // msgType
         write_16_le(&achl_write, CB_FLAG_RESPONSE_OK);        // msgFlags
         write_32_le(&achl_write, inl_len_data);               // dataLen
         adsl_sc_vch_out->chrc_vch_segfl[0] |= 0x01;
         inl_len_header = 0;
      }

      CHECK_PARSE(ads_reader->copy_to(achl_write, inl_write_now));
      if(ads_reader->empty()){
         adsl_sc_vch_out->chrc_vch_segfl[0] |= 0x02;
      }
      CLIPBOARD_LOG(LOG_LEVEL_TRACE, "sending CB_FORMAT_DATA_RESPONSE to client. write_now=0x%x sf=0x%02x/0x%02x len_header=0x%x",
         inl_write_now, adsl_sc_vch_out->chrc_vch_segfl[0], adsl_sc_vch_out->chrc_vch_segfl[1], inl_len_header);
   }
   return true; 
} // static bool m_write_fmt_data_rsp_ok(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* ads_reader)

static bool m_write_server_caps_pdu(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld){

   char* achl_write;
   CHECK_RETURN(ms_get_command_for_rdpacc(adsl_rdpacc_clipboard, avo_usrfld,
      SZ_CLIPDR_HEADER + SZ_CLIPDR_CAPS + SZ_CLIPDR_GENERAL_CAPABILITY, &achl_write));

   // 2.2.2.1 Clipboard Capabilities PDU (CLIPRDR_CAPS)
   write_16_le(&achl_write, CB_CLIP_CAPS);   // msgType
   write_16_le(&achl_write, 0);              // msgFlags
   write_32_le(&achl_write, SZ_CLIPDR_CAPS + SZ_CLIPDR_GENERAL_CAPABILITY); // dataLen

   write_16_le(&achl_write, 1);              // cCapabilitiesSets: Number of capability sets
   write_16_le(&achl_write, 0);              // pad1
   
   // 2.2.2.1.1.1 General Capability Set (CLIPRDR_GENERAL_CAPABILITY)
   write_16_le(&achl_write, CB_CAPSTYPE_GENERAL);           // capabilitySetType
   write_16_le(&achl_write, SZ_CLIPDR_GENERAL_CAPABILITY);  // lengthCapability
   write_32_le(&achl_write, CB_CAPS_VERSION_1);             // version
   write_32_le(&achl_write, CB_FLAG_USE_LONG_FORMAT_NAMES); // generalFlags

   // Return success
   CLIPBOARD_LOG(LOG_LEVEL_TRACE, "sending CB_CLIP_CAPS to client.");
   return true;
} // static bool m_write_server_caps_pdu(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld)

