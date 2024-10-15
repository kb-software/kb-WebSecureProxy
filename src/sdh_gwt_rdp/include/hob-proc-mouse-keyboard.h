#ifndef __HOB_PROCMK_HEADER__
#define __HOB_PROCMK_HEADER__
/**
#include <hob-xsclib01.h>
#include <hob-keyboard-handle.h>
are required before including this header.
*/

#define SM_USE_SEND_EVENTS 1

//gperf generated code:
/*Computed positions: -k'2-3,5,$'*/
struct ds_uievent_code {const char* ach_code; int im_val; };
#define TOTAL_KEYWORDS 157
#define MIN_WORD_LENGTH 2
#define MAX_WORD_LENGTH 18
#define MIN_HASH_VALUE 8
#define MAX_HASH_VALUE 259

#define IM_NUM_KEYS 312
// Session Keyboard data structure
struct dsd_keyboard_data {
	unsigned char byc_temp_key;                             /* Temporary KEY_DOWN for CTRL+key handling    */  
	int borc_keys_down[IM_NUM_KEYS];                                 /* Map with key states (0 for up, 1 for down)  */
	int borc_direct_keys_down[MAX_HASH_VALUE+1];
	struct dsd_browser_data dsc_browser_data;                    /* Browser data with browser type and platform */
	int imc_seq_count;
	int imc_combo_count;
	const struct dsd_key_combo *adsrc_key_combos_to_send[MAX_SEQUENCES][MAX_COMBOS];       /* Temporary storage of key combinations (An array of sequences of key combinations)*/  
	struct dsd_keyboard_layout const* adsc_current_layout;       /* Current keyboard layout                     */
#if SM_USE_SEND_EVENTS
	BOOL (*amc_send_mouse_event)(struct dsd_aux_helper *adsp_hl_clib_1, struct dsd_keyboard_data* adsp_keyboard_data, struct dsd_cl_mouse_eve* adsp_event);
	BOOL (*amc_send_keyboard_event)(struct dsd_aux_helper *adsp_hl_clib_1, struct dsd_keyboard_data* adsp_keyboard_data, struct dsd_cl_keyb_eve* adsp_event);
	BOOL (*amc_send_sync_event)(struct dsd_aux_helper *adsp_hl_clib_1, struct dsd_keyboard_data* adsp_keyboard_data, struct dsd_cl_sync_eve* adsp_event);
	BOOL (*amc_send_unicode_event)(struct dsd_aux_helper *adsp_hl_clib_1, struct dsd_keyboard_data* adsp_keyboard_data, struct dsd_cl_keyb_eve* adsp_event);
	char* achc_out_cur;
	char* achc_out_end;
#endif
};

// Keyboard init structure
struct dsd_keyboard_init {
  int imc_layout_id;                                      /* Keyboard Layout Id        */
  struct dsd_browser_data *adsc_browser_data;
};

// Keyboard public functions

int m_init_mouse_keyboard( dsd_keyboard_data *adsp_keyboard_data, 
                           const struct dsd_keyboard_init *adsp_keyboard_init );

#if SM_USE_SEND_EVENTS
int m_proc_mouse_keyboard( struct dsd_aux_helper *adsp_hl_clib_1,
                           struct dsd_keyboard_data *adsp_keyboard_data, 
#if CV_TOUCH_REDIR
                           struct dsd_dvc_input *adsp_input_ex,
#endif
                           int *aimp_keyboard_mouse,
									char *achp_inp, int imp_len_inp,
#if CV_TOUCH_REDIR
                           struct dsd_gather_i_1_fifo* adsp_touch_fifo_out,
                           int *aimp_touch_data_out
#endif
									);
#else
int m_proc_mouse_keyboard( struct dsd_aux_helper *adsp_hl_clib_1,
                           struct dsd_keyboard_data *adsp_keyboard_data, 
                           struct dsd_dvc_input *adsp_input_ex,
                           char *achp_out, int imp_len_out,
                           int *aimp_keyboard_mouse,
                           char *achp_inp, int imp_len_inp,
                           struct dsd_gather_i_1_fifo* adsp_touch_fifo_out,
                           int *aimp_touch_data_out );
#endif

static const struct ds_uievent_code wordlist[] =
    {
      {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0}, {"",0},
      {"",0},
      {"Tab",0x000F},
      {"",0},
      {"Quote",0x0028},
      {"",0}, {"",0},
      {"End",0xE04F},
      {"Undo",0xE008},
      {"Pause",0x0045},
      {"",0}, {"",0},
      {"Cut",0xE017},
      {"MediaPlayPause",0xE022},
      {"AudioVolumeMute",0xE020 },
      {"MediaSelect",0xE06D},
      {"Convert",0x0079},
      {"KanaMode",0x0070},
      {"MediaTrackNext",0xE019},
      {"NonConvert",0x007B},
      {"ContextMenu",0xE05D},
      {"",0}, {"",0},
      {"Home",0xE047},
      {"AudioVolumeDown",0xE02E},
      {"",0},
      {"F1",0x003B},
      {"",0}, {"",0},
      {"Eject",0xE02C},
      {"",0}, {"",0}, {"",0}, {"",0},
      {"Comma",0x0033},
      {"",0},
      {"F2",0x003C},
      {"",0},
      {"NumpadAdd",0x004E},
      {"",0},
      {"Period",0x0034},
      {"NumpadDivide",0xE035},
      {"F11",0x0057},
      {"Backquote",0x0029},
      {"Lang1",0x0072},
      {"NumpadComma",0x007E},
      {"NumLock",0x0045},
      {"F21",0x006C},
      {"NumpadSubtract",0x004A},
      {"Paste",0xE00A},
      {"",0},
      {"Numpad1",0x004F},
      {"F12",0x0058},
      {"MetaRight",0xE05C},
      {"Lang2",0x0071},
      {"IntlRo",0x0073},
      {"Numpad2",0x0050},
      {"F22",0x006D},
      {"",0},
      {"LaunchApp1",0xE06B},
      {"ControlLeft",0x001D},
      {"ControlRight",0xE01D},
      {"MediaTrackPrevious",0xE010},
      {"",0},
      {"LaunchApp2",0xE021},
      {"",0}, {"",0}, {"",0},
      {"Semicolon",0x0027},
      {"",0},
      {"BracketLeft",0x001A},
      {"BracketRight",0x001B},
      {"",0},
      {"KeyM",0x0032},
      {"Space",0x0039},
      {"Delete",0xE053},
      {"OSRight",0xE05C},
      {"",0},
      {"MediaStop",0xE024},
      {"",0},
      {"NumpadEnter",0xE01C},
      {"AltLeft",0x0038},
      {"AudioVolumeUp",0xE030},
      {"Backspace",0x000E},
      {"Slash",0x0035},
      {"",0}, {"",0}, {"",0},
      {"Backslash",0x002B},
      {"",0},
      {"BrowserHome",0xE032},
      {"LaunchMediaPlayer",0xE06D},
      {"MetaLeft",0xE05B},
      {"BrowserForward",0xE069},
      {"Enter",0x001C},
      {"",0},
      {"Numpad4",0x004B},
      {"BrowserSearch",0xE065},
      {"BrowserRefresh",0xE067},
      {"VolumeMute",0xE020},
      {"Insert",0xE052},
      {"Numpad3",0x0051},
      {"PageDown",0xE051},
      {"KeyS",0x001F},
      {"",0},
      {"BrowserBack",0xE06A},
      {"Numpad9",0x0049},
      {"",0},
      {"KeyZ",0x002C},
      {"VolumeDown",0xE02E},
      {"NumpadEqual",0x0059},
      {"Numpad8",0x0048},
      {"NumpadDecimal",0x0053},
      {"KeyR",0x0013},
      {"LaunchMail",0xE06C},
      {"OSLeft",0xE05B},
      {"F4",0x003E},
      {"IntlBackslash",0x0056},
      {"NumpadMultiply",0x0037},
      {"Power",0xE05E},
      {"",0},
      {"Numpad7",0x0047},
      {"",0},
      {"ShiftLeft",0x002A},
      {"ShiftRight",0x0036},
      {"Digit1",0x0002},
      {"F3",0x003D},
      {"",0},
      {"ArrowLeft",0xE04B},
      {"ArrowRight",0xE04D},
      {"Digit2",0x0003},
      {"Numpad6",0x004D},
      {"F14",0x0065},
      {"ArrowDown",0xE050},
      {"",0}, {"",0},
      {"F9",0x0043},
      {"F24",0x0076},
      {"Help",0xE03B},
      {"",0},
      {"BrowserFavorites",0xE066},
      {"Numpad5",0x004C},
      {"F13",0x0064},
      {"Copy",0xE018},
      {"",0},
      {"Escape",0x0001},
      {"F8",0x0042},
      {"F23",0x006E},
      {"KeyU",0x0016},
      {"Equal",0x000D},
      {"PageUp",0xE049},
      {"Numpad0",0x0052},
      {"F19",0x006A},
      {"KeyL",0x0026},
      {"",0}, {"",0},
      {"IntlYen",0x007D},
      {"",0},
      {"KeyD",0x0020},
      {"ScrollLock",0x0046},
      {"BrowserStop",0xE068},
      {"",0},
      {"F18",0x0069},
      {"KeyB",0x0030},
      {"",0},
      {"PrintScreen",0x0054},
      {"F7",0x0041},
      {"VolumeUp",0xE030},
      {"KeyX",0x002D},
      {"",0},
      {"Digit4",0x0005},
      {"",0},
      {"CapsLock",0x003A},
      {"KeyW",0x0011},
      {"",0},
      {"Digit3",0x0004},
      {"",0}, {"",0},
      {"KeyV",0x002F},
      {"",0},
      {"Digit9",0x000A},
      {"",0},
      {"F17",0x0068},
      {"KeyT",0x0014},
      {"",0},
      {"Digit8",0x0009},
      {"F6",0x0040},
      {"AltRight",0xE038},
      {"KeyQ",0x0010},
      {"",0}, {"",0},
      {"ArrowUp",0xE048},
      {"",0},
      {"KeyP",0x0019},
      {"",0},
      {"Digit7",0x0008},
      {"",0}, {"",0},
      {"KeyO",0x0018},
      {"",0}, {"",0}, {"",0},
      {"F16",0x0067},
      {"KeyY",0x0015},
      {"Minus",0x000C},
      {"Digit6",0x0007},
      {"F5",0x003F},
      {"",0},
      {"KeyN",0x0031},
      {"",0}, {"",0}, {"",0}, {"",0},
      {"KeyK",0x0025},
      {"",0},
      {"Digit5",0x0006},
      {"",0}, {"",0},
      {"KeyJ",0x0024},
      {"",0}, {"",0}, {"",0},
      {"F15",0x0066},
      {"KeyI",0x0017},
      {"",0},
      {"Digit0",0x000B},
      {"",0}, {"",0},
      {"KeyH",0x0023},
      {"",0}, {"",0}, {"",0}, {"",0},
      {"KeyG",0x0022},
      {"",0}, {"",0}, {"",0}, {"",0},
      {"KeyF",0x0021},
      {"",0}, {"",0}, {"",0},
      {"F10",0x0044},
      {"KeyE",0x0012},
      {"",0}, {"",0}, {"",0},
      {"F20",0x006B},
      {"KeyC",0x002E},
      {"",0}, {"",0}, {"",0}, {"",0},
      {"KeyA",0x001E}
    };

#endif  // __HOB_PROCMK_HEADER__
