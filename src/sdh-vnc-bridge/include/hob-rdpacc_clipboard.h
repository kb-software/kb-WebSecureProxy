#ifndef ___HOB_RDPACC_CLIPBOARD___
#define ___HOB_RDPACC_CLIPBOARD___

#define RDPECLIP_ERROR  ((dsd_sc_co1 *)-1)

// Standard clipboard formats (windows) 
// source: http://msdn.microsoft.com/en-us/library/ff729168%28v=vs.85%29.aspx
typedef enum ied_clip_formats
{
    ied_cf_empty = 0,
    ied_cf_text,
    ied_cf_bitmap,
    ied_cf_metafilepict,
    ied_cf_sylk,
    ied_cf_dif,
    ied_cf_tiff,
    ied_cf_oemtext,
    ied_cf_dib,
    ied_cf_palette,
    ied_cf_pendata,
    ied_cf_riff,
    ied_cf_wave,
    ied_cf_unicodetext,
    ied_cf_enhmetafile,
    ied_cf_hdrop,
    ied_cf_locale,
    ied_cf_dibv5,
    ied_cf_custom = 49152
} ied_clip_formats_t;

struct dsd_format_list_entry {
   int              inc_format_id;
   int              inc_len_format_name;
   HL_WCHAR*        awcc_format_name; 
};

#define MAX_CUSTOM_NAME 30

static const unsigned short wstrgs_custom_fmt_names[][MAX_CUSTOM_NAME] = 
{  
    {0x0052, 0x0069, 0x0063, 0x0068, 0x0020, 0x0054, 0x0065, 0x0078, 0x0074, 0x0020, 0x0046, 0x006f, 0x0072, 0x006d, 0x0061, 0x0074, 0x0000} //Rich Text Format
};

/**
 *  <b>Copy Formats Callback Pointer to Function.</b><p>
 *
 *  This is the type of function that will be called when an application on the
 *  RDP Client's machine performs a COPY operation, and thus changes the
 *  contents of the clipboard on the Client's machine.
 *
 *  @param[in]  void*   The User field (or connection struct) handled to this
 *                      library when initializing the clipboard virtual channel.
 *  @param[in]  int     The number of clipboard formats available in the array.
 *  @param[in]  ied_clip_formats_t* An array of clipboard format IDs available
 *                                  at the client's end.
 *  @param[in]  usd_unichar_t** An array of unicode char strings giving the
 *                              names of the clipboard formats.
 *  @returns    Nothing.
 */
typedef void (* amd_on_copy_fmts_cb)(void* avol_usrfld, int inl_number_formats, dsd_format_list_entry* adsl_format_list);
/**
 *  <b>Copy Data Callback Pointer to Function.</b><p>
 *
 *  This is the type of function that will be called when the RDP Client
 *  responds to a request for data from the Server (on behalf of an application
 *  that is running on the Server's machine).
 *
 *  @param[in]  void*   The User field (or connection struct) handled to this
 *                      library when initializing the clipboard virtual channel.
 *  @param[in]  void*   A buffer containing the data received from the Client.
 *  @param[in]  int     The size in bytes of the data buffer.
 *  @returns    false on parse-error (severe error!)
 */
typedef bool (*amd_on_copy_data_cb)(void* avol_usrfld, dsd_gather_reader* ads_reader);

/**
 *  <b>Paste Callback Pointer To Function.</b><p>
 *
 *  This is the type of function that will be called when an application on the
 *  RDP Client's machine performs a PASTE operation, and requests the contents
 *  of the clipboard on the Server's machine.
 *
 *  @param[in]  void*   The User field (or connection struct) handled to this
 *                      library when initializing the clipboard virtual channel.
 *  @param[in]  ied_clip_formats_t  The format ID of the data requested.
 *  @param[in]  usd_unichar_t*  The name of the format of the data requested.
 *  @returns    true, if the type is available.
 */
typedef bool (* amd_on_paste_cb)(void* avol_usrfld, dsd_format_list_entry* adsl_format);

#ifndef LOG_CB_DEFINED
#define LOG_CB_DEFINED
/**
 *  <b>Log Callback Pointer To Function.</b><p>
 *
 *  This is the type of function that will be called when the RDPECLIP virtual
 *  channel implementation needs to write some information to the application's
 *  log file.
 *
 *  @param[in]  void *  The User field (or connection struct) handled to this
 *                      library when initializing hte clipboard virutal channel.
 *  @param[in]  int     The level of severity of the message that is to be
 *                      written.
 *  @param[in]  const char* The message, to be written. 
 *  @param[in]  int     The length of the text, to be written. 
 *  @returns    <b>true</b> if successful, <b>false</b> if an error occurs.
 */
typedef bool (* amd_log_cb)(void* avol_usrfld, int inl_lvl, const char *achl_message, int inl_bytes);
#endif /* LOG_CB_DEFINED */

// Returns NULL, if error or not enought space (min!) available. 
typedef dsd_sc_vch_out* (*amd_command_for_rdpacc)(void* avo_usrfld, int inl_bytes);

typedef bool (*amd_get_memory) (void* avo_usrfld, char** aach_memory, int inl_size);
typedef bool (*amd_free_memory)(void* avo_usrfld, void*  avol_memory, int inl_size);

struct dsd_rdpacc_clipboard_callbacks {
   amd_on_copy_fmts_cb    amc_on_copy_fmts_cb;
   amd_on_copy_data_cb    amc_on_copy_data_cb;
   amd_on_paste_cb        amc_on_paste_cb;
   amd_log_cb             amc_log_cb;
   amd_command_for_rdpacc amc_command_for_rdpacc;
   amd_get_memory         amc_get_memory;
   amd_free_memory        amc_free_memory; 
};

#if CB_ONLY_TEXT
#define MAX_CB_FORMATS  2
#else
#define MAX_CB_FORMATS  19
#endif

#if !(defined HL_UNIX || defined HL_LINUX || defined HOB_UNIX || defined HL_LINUX64)
    #ifndef strcasecmp
    #define strcasecmp _memicmp
    #endif
#endif


enum ied_parse_rdp {
   ied_parse_header = 0,
   ied_parse_wait_for_len
};

struct dsd_rdpacc_clipboard {
   dsd_rdp_vc_1* adsc_vc; ///< Virtual Channel from RDP Accelerator
   dsd_rdpacc_clipboard_callbacks dsc_callbacks;
   bool          boc_long_names;

   // States of the parsing-state-machine
   ied_parse_rdp iec_parse_state;
   char          chr_seg_flags[2];
   int           inc_vch_len;
   int           inc_msg_type;
   int           inc_msg_flags;
   int           inc_pdu_len; 

   // buffer of data
   dsd_rdpacc_vector<char, 0x100> dsc_data_buffer;
   int           inc_data_len;

   int           inc_last_rcv;
   bool          boc_server_is_owner;

   // available format IDs and names.
   dsd_rdpacc_vector<dsd_format_list_entry, 0x20> dsc_format_list;
   int           inc_number_formats;
   dsd_rdpacc_vector<HL_WCHAR, 0x20> dsc_buffer_names;

};

#ifndef HAVE_RDPECLIP_FUNCS
#define HAVE_RDPECLIP_FUNCS

extern bool m_rdpacc_clipboard_init(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, 
                  dsd_rdp_vc_1 *adsl_vc, dsd_rdpacc_clipboard_callbacks* adsl_callbacks);

extern bool m_rdpacc_clipboard_close(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld);
extern bool m_rdpacc_clipboard_srvr_copy(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, 
                                         int inl_number_formats, dsd_format_list_entry* adsl_format_list);
extern bool m_rdpacc_clipboard_srvr_data(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_i_1* ads_gather);
extern bool m_rdpacc_clipboard_srvr_data(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, dsd_gather_reader* ads_reader);
// Returns false, if format is not in format-list, is not a severe error
extern bool m_rdpacc_clipboard_server_paste(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, ied_clip_formats iel_format);
extern bool m_rdpacc_clipboard_process_and_reply(dsd_rdpacc_clipboard* adsl_rdpacc_clipboard, void* avo_usrfld, 
                                                 dsd_cl_vch_in* adsl_cl_vch_in);

static const char achrs_clipe_name[] = {'C', 'L', 'I', 'P', 'R', 'D', 'R', '\0' };

#endif

#endif
