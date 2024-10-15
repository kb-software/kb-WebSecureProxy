#include <hob-sdh-gwt-rdp-1.h>

#include <stdio.h>
#include <string.h>
#ifndef HL_UNIX
#include <windows.h>
#else
#include <sys/types.h>
#include <errno.h>
#include <hob-unix01.h>
#include <stdarg.h>
#endif
#ifndef LEN_SECURE_XOR_PWD
// hack: missing header guards in hob-xsclib01.h
#include <hob-xsclib01.h>
#endif
// hack: missing header guards in hob-xslunic1.h
#ifndef MAX_IDNAPART_LENGTH
#include <hob-xslunic1.h>
#endif
#if CV_TOUCH_REDIR
#include <hob-datarw.h>
#include <hob-dynvc-common.h>
#include <hob-dynvc-input.h>
#endif
#include <hob-browser-data.h>
#include <hob-keyboard-handle.h>
#include <hob-proc-mouse-keyboard.h>

#include <hob-encry-1.h>
#include <hob-cd-record-1.h>
#include <hob-rdpserver1.h>

#define CTRLKEY_HANDLE
#define DEBUG_KEYBOARD 0
#define DEBUG_TOUCH 0

/* subroutine for output to console                                    */
static int m_aux_printf( struct dsd_sdh_call_1 *adsp_sdh_call_1, const char *achptext, ... ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1;                         /* working variable        */
   va_list    dsl_argptr;
   char       chrl_out1[512];

   va_start( dsl_argptr, achptext );
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achptext, dsl_argptr );
   va_end( dsl_argptr );
   bol1 = (*adsp_sdh_call_1->amc_aux)( adsp_sdh_call_1->vpc_userfld,
                                       DEF_AUX_CONSOLE_OUT,  /* output to console */
                                       chrl_out1, iml1 );
   return iml1;
} /* end m_aux_printf()                                                */
/**********************
Private Functions
**********************/

/**
 * Converts a possibly signed value from an HASN1 expression. <br>
 * <br>
 * Positive values are converted to: <br>
 * s = u/2 <br>
 * Negative values are converted to: <br>
 * s = (u+1)/-2 <br>
 */
static int m_hasn1_unsigned_to_signed(unsigned int im_uval) {
	/* Is positive? */
	if((im_uval & 0x1) == 0) {
		return (int)((im_uval) >> 1);
	}
	return ~(int)((im_uval) >> 1);
}

static char* m_hasn32u_to_int2(unsigned int* aimp_out, char* achp_in, char* achp_in_end
                     /*, int* aimp_bytes*/)
{
    int iml_len = 0;
    int iml_len_nhasn = 0;

   // dsd_gather_i_1* adsl_currgather = adsp_gather;
    char* achl_cur = achp_in;
       
        while (achl_cur < achp_in_end) {
            iml_len <<= 7;                /* shift old value         */
            iml_len |= *achl_cur & 0x7f;    /* apply new bits          */
            iml_len_nhasn++;                 /* increment length bytes NHASN */
            if (!(*achl_cur & 0x80)) {        /* more bit not set      */
                // the length is complete
                *aimp_out = iml_len;
                //*aimp_bytes = iml_len_nhasn;
                return achp_in + iml_len_nhasn;
            }
            achl_cur++;
        }
        // we used all bytes in current gather
        
    
    // only arrives here if we ran out of bytes
    return NULL;
}

static char* m_hasn32s_to_int2(int* aimp_out, char* achp_in, char* achp_in_end
                     /*, int* aimp_bytes*/)
{
	 unsigned int unl_value;
    char* achl_end = m_hasn32u_to_int2(&unl_value, achp_in, achp_in_end);
	 if(achl_end == NULL)
		 return NULL;
	 *aimp_out = m_hasn1_unsigned_to_signed(unl_value);
	 return achl_end;
}


static char* m_hasn32u_to_int(unsigned int* aimp_out, char* achp_in, char* achp_in_end
                     /*, int* aimp_bytes*/)
{
    int iml_len = 0;
    int iml_len_nhasn = 0;

   // dsd_gather_i_1* adsl_currgather = adsp_gather;
    char* achl_cur = achp_in;
       
        while (achl_cur < achp_in_end) {
            iml_len <<= 7;                /* shift old value         */
            iml_len |= *achl_cur & 0x7f;    /* apply new bits          */
            iml_len_nhasn++;                 /* increment length bytes NHASN */
            if (!(*achl_cur & 0x80)) {        /* more bit not set      */
                // the length is complete
                *aimp_out = iml_len;
                //*aimp_bytes = iml_len_nhasn;
                return achp_in + iml_len_nhasn;
            }
            achl_cur++;
        }
        // we used all bytes in current gather
        
    
    // only arrives here if we ran out of bytes
    return achp_in_end+1;
}

/*  Helper function:
Reads a value from a unsigned "HASN1" field to
unsigned 16-bit little endian and returns pointer to after the
bytes read in, if no input buffer overflow or numeric overflow
is detected. Else returns achp_in_end+1. 
*/
static char* m_hasn32u_to_le2( char* achp_out, char* achp_in, char* achp_in_end ) {

  if( achp_in >= achp_in_end ) 
    return achp_in_end+1;

  if( (signed char)(*achp_in) < 0 ) {              /* two- or three-byte input */
    if( achp_in+1 >= achp_in_end ) 
      return achp_in_end+1;

    if( (signed char)(*(achp_in+1)) < 0 ) {          /* three-byte input */
      if( (achp_in+2 > achp_in_end )            /* input buffer ended */
        || ( (signed char)(*(achp_in+2)) < 0 )      /* more input bytes */
        || (*achp_in & 0xFC) )              /* number too big */
        return achp_in_end+1;

      *achp_out = *(achp_in+2) | (unsigned char)(*(achp_in+1) << 7);
      *(achp_out+1) = ((*(achp_in+1) & 0x7E) >> 1) | (unsigned char)(*achp_in << 6);
      return achp_in+3;
    } 
    else {                          /* two-byte input */
      *achp_out = *(achp_in+1) | (unsigned char)(*achp_in << 7);
      *(achp_out+1) = (*(achp_in) & 0x7F) >> 1;
      return achp_in+2;
    }
  } else {                          /* one-byte input */
    *achp_out = *achp_in;
    *(achp_out+1) = 0;
    return achp_in+1;
  }
}



/* maximum key range = 252, duplicates = 0 */

#ifdef __GNUC__
__inline
#else
#ifdef __cplusplus
inline
#endif
#endif
static unsigned int
hash (register const char *str, register unsigned int len)
{
  static const unsigned short asso_values[] =
    {
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 115,  15,
       20,  65,  60, 105,  95,  85,  75,  70, 260, 260,
      260, 260, 260, 260, 260, 180,  90, 175,  85, 170,
      165, 160, 155, 150, 145, 140,  80,   0, 135, 125,
      120, 115,  40,  30, 110,  75, 105, 100,  95, 130,
       35, 260, 260, 260, 260, 260, 260,   5,   0,  30,
        0,   0,   0,   0,   5, 105,  20,  15,  70,  25,
       10,   0,  70,   5,  40,  45,   5,   5, 260,  40,
      260,  75, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260, 260, 260, 260, 260,
      260, 260, 260, 260, 260, 260
    };
  register int hval = len;

  switch (hval)
    {
      default:
        hval += asso_values[(unsigned char)str[4]];
      /*FALLTHROUGH*/
      case 4:
      case 3:
        hval += asso_values[(unsigned char)str[2]];
      /*FALLTHROUGH*/
      case 2:
        hval += asso_values[(unsigned char)str[1]];
        break;
    }
  return hval + asso_values[(unsigned char)str[len - 1]];
}

#ifdef __GNUC__
__inline
#endif
const struct ds_uievent_code *
in_word_set (register const char *str, register unsigned int len, int* aimp_key)
{
  
   if (len <= MAX_WORD_LENGTH && len >= MIN_WORD_LENGTH)
    {
      register int key = hash (str, len);

      if (key <= MAX_HASH_VALUE && key >= 0)
        {
          register const char *s = wordlist[key].ach_code;
          //strncmp is used for completeness (if received value was not in list of known values it could match one of the other values)
          //TODO: handle Pause key - this must be sent as a ctrl+numlock with the FASTPATH_INPUT_KBDFLAGS_EXTENDED1 flag
          if (*str == *s && !strncmp (str + 1, s + 1, len - 1) && s[len] == '\0'){
              *aimp_key = key;
            return &wordlist[key];
          }
        }
    }
  return NULL;
}
//end gperf generated code

#define IM_UICODES_SEARCHBIAS 

static const int dsrr_uievent_codes[][2] = { 
    // EXtended keys E0 replaced here with 02
{ (unsigned int) 0X00BD0077,0x003B}, // "F1" 
{ (unsigned int) 0X00BE0078,0x003C}, // "F2" 
{ (unsigned int) 0X00BF0079,0x003D}, // "F3" 
{ (unsigned int) 0X00C0007A,0x003E}, // "F4" 
{ (unsigned int) 0X00C1007B,0x003F}, // "F5" 
{ (unsigned int) 0X00C2007C,0x0040}, // "F6" 
{ (unsigned int) 0X00C3007D,0x0041}, // "F7" 
{ (unsigned int) 0X00C4007E,0x0042}, // "F8" 
{ (unsigned int) 0X00C5007F,0x0043}, // "F9" 
{ (unsigned int) 0X016400A7,0x0044}, // "F10" 
{ (unsigned int) 0X016500A8,0x0057}, // "F11" 
{ (unsigned int) 0X016600A9,0x0058}, // "F12" 
{ (unsigned int) 0X020F0117,0x024F}, // "End" 
{ (unsigned int) 0X02200117,0x000F}, // "Tab" 
{ (unsigned int) 0X0227012C,0x0217}, // "Cut" 
{ (unsigned int) 0X038E016A,0x001E}, // "KeyA" 
{ (unsigned int) 0X038F016B,0x0030}, // "KeyB" 
{ (unsigned int) 0X0390016C,0x002E}, // "KeyC" 
{ (unsigned int) 0X0391016D,0x0020}, // "KeyD" 
{ (unsigned int) 0X0392016E,0x0012}, // "KeyE" 
{ (unsigned int) 0X0393016F,0x0021}, // "KeyF" 
{ (unsigned int) 0X03940170,0x0022}, // "KeyG" 
{ (unsigned int) 0X03950171,0x0023}, // "KeyH" 
{ (unsigned int) 0X03960172,0x0017}, // "KeyI" 
{ (unsigned int) 0X03970173,0x0024}, // "KeyJ" 
{ (unsigned int) 0X03970189,0x023B}, // "Help" 
{ (unsigned int) 0X03980174,0x0025}, // "KeyK" 
{ (unsigned int) 0X03990175,0x0026}, // "KeyL" 
{ (unsigned int) 0X039A0176,0x0032}, // "KeyM" 
{ (unsigned int) 0X039B0177,0x0031}, // "KeyN" 
{ (unsigned int) 0X039C0178,0x0018}, // "KeyO" 
{ (unsigned int) 0X039D0179,0x0019}, // "KeyP" 
{ (unsigned int) 0X039E017A,0x0010}, // "KeyQ" 
{ (unsigned int) 0X039F017B,0x0013}, // "KeyR" 
{ (unsigned int) 0X03A0017C,0x001F}, // "KeyS" 
{ (unsigned int) 0X03A1017D,0x0014}, // "KeyT" 
{ (unsigned int) 0X03A2017E,0x0016}, // "KeyU" 
{ (unsigned int) 0X03A3017F,0x002F}, // "KeyV" 
{ (unsigned int) 0X03A40180,0x0011}, // "KeyW" 
{ (unsigned int) 0X03A50181,0x002D}, // "KeyX" 
{ (unsigned int) 0X03A60182,0x0015}, // "KeyY" 
{ (unsigned int) 0X03A70183,0x002C}, // "KeyZ" 
{ (unsigned int) 0X03AC0189,0x0247}, // "Home" 
{ (unsigned int) 0X03B2019B,0x0218}, // "Copy" 
{ (unsigned int) 0X03D50196,0x0208}, // "Undo" 
{ (unsigned int) 0X054901B3,0x0072}, // "Lang1" 
{ (unsigned int) 0X054A01B4,0x0071}, // "Lang2" 
{ (unsigned int) 0X056A01EB,0x022C}, // "Eject" 
{ (unsigned int) 0X058D01ED,0x0033}, // "Comma" 
{ (unsigned int) 0X05A901FE,0x001C}, // "Enter" 
{ (unsigned int) 0X05AA01F8,0x000D}, // "Equal" 
{ (unsigned int) 0X05AD01EC,0x0039}, // "Space" 
{ (unsigned int) 0X05BA01FD,0x020A}, // "Paste" 
{ (unsigned int) 0X05BE01FE,0x0045}, // "Pause" 
{ (unsigned int) 0X05C001FB,0x0035}, // "Slash" 
{ (unsigned int) 0X05CC020C,0x000C}, // "Minus" 
{ (unsigned int) 0X05ED020D,0x025E}, // "Power" 
{ (unsigned int) 0X0603020E,0x0028}, // "Quote" 
{ (unsigned int) 0X0718022D,0x025B}, // "OSLeft" 
{ (unsigned int) 0X07940221,0x000B}, // "Digit0" 
{ (unsigned int) 0X07950222,0x0002}, // "Digit1" 
{ (unsigned int) 0X07960223,0x0003}, // "Digit2" 
{ (unsigned int) 0X07970224,0x0004}, // "Digit3" 
{ (unsigned int) 0X07980225,0x0005}, // "Digit4" 
{ (unsigned int) 0X07990226,0x0006}, // "Digit5" 
{ (unsigned int) 0X079A0227,0x0007}, // "Digit6" 
{ (unsigned int) 0X079B0228,0x0008}, // "Digit7" 
{ (unsigned int) 0X079C0229,0x0009}, // "Digit8" 
{ (unsigned int) 0X079D022A,0x000A}, // "Digit9" 
{ (unsigned int) 0X07AA0242,0x0249}, // "PageUp" 
{ (unsigned int) 0X07BD0253,0x0253}, // "Delete" 
{ (unsigned int) 0X07D10251,0x0001}, // "Escape" 
{ (unsigned int) 0X08030258,0x0073}, // "IntlRo" 
{ (unsigned int) 0X081E0263,0x0034}, // "Period" 
{ (unsigned int) 0X082F0275,0x0252}, // "Insert" 
{ (unsigned int) 0X09D202A0,0x025C}, // "OSRight" 
{ (unsigned int) 0X0A3202AC,0x0038}, // "AltLeft" 
{ (unsigned int) 0X0AAF02B9,0x0245}, // "NumLock" 
{ (unsigned int) 0X0ACA02C3,0x007D}, // "IntlYen" 
{ (unsigned int) 0X0ADC0295,0x0052}, // "Numpad0" 
{ (unsigned int) 0X0ADD0296,0x004F}, // "Numpad1" 
{ (unsigned int) 0X0ADE0297,0x0050}, // "Numpad2" 
{ (unsigned int) 0X0ADF0298,0x0051}, // "Numpad3" 
{ (unsigned int) 0X0AE00299,0x004B}, // "Numpad4" 
{ (unsigned int) 0X0AE1029A,0x004C}, // "Numpad5" 
{ (unsigned int) 0X0AE2029B,0x004D}, // "Numpad6" 
{ (unsigned int) 0X0AE3029C,0x0047}, // "Numpad7" 
{ (unsigned int) 0X0AE4029D,0x0048}, // "Numpad8" 
{ (unsigned int) 0X0AE5029E,0x0049}, // "Numpad9" 
{ (unsigned int) 0X0AE802D0,0x0248}, // "ArrowUp" 
{ (unsigned int) 0X0AF402E1,0x0079}, // "Convert" 
{ (unsigned int) 0X0D260300,0x0070}, // "KanaMode" 
{ (unsigned int) 0X0D430315,0x0251}, // "PageDown" 
{ (unsigned int) 0X0D4C0310,0x003A}, // "CapsLock" 
{ (unsigned int) 0X0D670312,0x025B}, // "MetaLeft" 
{ (unsigned int) 0X0D6B031F,0x0238}, // "AltRight" 
{ (unsigned int) 0X0E87033D,0x0230}, // "VolumeUp" 
{ (unsigned int) 0X10DE037D,0x000E}, // "Backspace" 
{ (unsigned int) 0X10EA0386,0x0224}, // "MediaStop" 
{ (unsigned int) 0X10F1038C,0x002B}, // "Backslash" 
{ (unsigned int) 0X11060385,0x025C}, // "MetaRight" 
{ (unsigned int) 0X1134039F,0x0029}, // "Backquote" 
{ (unsigned int) 0X11510389,0x002A}, // "ShiftLeft" 
{ (unsigned int) 0X1165036E,0x004E}, // "NumpadAdd" 
{ (unsigned int) 0X11830396,0x024B}, // "ArrowLeft" 
{ (unsigned int) 0X119D03A3,0x0250}, // "ArrowDown" 
{ (unsigned int) 0X11BF03A9,0x0027}, // "Semicolon" 
{ (unsigned int) 0X14CA03AD,0x026B}, // "LaunchApp1" 
{ (unsigned int) 0X14CB03AE,0x0221}, // "LaunchApp2" 
{ (unsigned int) 0X1557040C,0x007B}, // "NonConvert" 
{ (unsigned int) 0X156703FC,0x0036}, // "ShiftRight" 
{ (unsigned int) 0X15A403F8,0x0046}, // "ScrollLock" 
{ (unsigned int) 0X15A60409,0x024D}, // "ArrowRight" 
{ (unsigned int) 0X16160410,0x022E}, // "VolumeDown" 
{ (unsigned int) 0X163D0413,0x0220}, // "VolumeMute" 
{ (unsigned int) 0X18B80440,0x026D}, // "MediaSelect" 
{ (unsigned int) 0X18F90447,0x001A}, // "BracketLeft" 
{ (unsigned int) 0X19CD0452,0x007E}, // "NumpadComma" 
{ (unsigned int) 0X19E90463,0x021C}, // "NumpadEnter" 
{ (unsigned int) 0X19EA045D,0x0059}, // "NumpadEqual" 
{ (unsigned int) 0X1A020455,0x026A}, // "BrowserBack" 
{ (unsigned int) 0X1A28046C,0x001D}, // "ControlLeft" 
{ (unsigned int) 0X1A40047A,0x025D}, // "ContextMenu" 
{ (unsigned int) 0X1A41046D,0x0054}, // "PrintScreen" 
{ (unsigned int) 0X1A52046D,0x0232}, // "BrowserHome" 
{ (unsigned int) 0X1A9C048A,0x0268}, // "BrowserStop" 
{ (unsigned int) 0X1DCD04BA,0x001B}, // "BracketRight" 
{ (unsigned int) 0X1E8A04BA,0x0235}, // "NumpadDivide" 
{ (unsigned int) 0X1F2104DF,0x021D}, // "ControlRight" 
{ (unsigned int) 0X23020523,0x0056}, // "IntlBackslash" 
{ (unsigned int) 0X234C0514,0x0053}, // "NumpadDecimal" 
{ (unsigned int) 0X239D052F,0x0230}, // "AudioVolumeUp" 
{ (unsigned int) 0X2461053A,0x0265}, // "BrowserSearch" 
{ (unsigned int) 0X27B30574,0x0219}, // "MediaTrackNext" 
{ (unsigned int) 0X27BF0574,0x0222}, // "MediaPlayPause" 
{ (unsigned int) 0X29EF05AD,0x004A}, // "NumpadSubtract" 
{ (unsigned int) 0X2A1B05C5,0x0037}, // "NumpadMultiply" 
{ (unsigned int) 0X2A3105B3,0x0267}, // "BrowserRefresh" 
{ (unsigned int) 0X2A5705B9,0x0269}, // "BrowserForward" 
{ (unsigned int) 0X2F100602,0x022E}, // "AudioVolumeDown" 
{ (unsigned int) 0X2F370605,0x0220}, // "AudioVolumeMute" 
{ (unsigned int) 0X36E30697,0x0266}, // "BrowserFavorites" 
{ (unsigned int) 0X3ABD06A8,0x026D}, // "LaunchMediaPlayer" 
{ (unsigned int) 0X41D40732,0x0210}, // "MediaTrackPrevious" 


};



#define ADLER_BASE             65521        /* largest prime smaller than 65536 */

static int m_calc_adler( char* achp_buffer, int imp_start, int imp_end) {
    int        iml_adler;
    int        iml_sum2;
    //char       *achl_cur;
    //char       *achl_end;

    iml_adler = iml_sum2 = 0;
    //achl_cur = achp_buffer;
    //achl_end = achp_buffer + imp_len_buffer;

    do {
        iml_adler += achp_buffer[imp_start];
        imp_start++;
        iml_sum2 += iml_adler;
        if (iml_adler >= ADLER_BASE) iml_adler -= ADLER_BASE;
    } while (imp_start < imp_end);
    iml_sum2 %= ADLER_BASE;
    return iml_adler | (iml_sum2 << 16);
} 

static char* m_uicode_to_scancode(char* achp_out, char* achp_in, char* achp_in_end, int imp_codelen)
{
    if (achp_in + imp_codelen > achp_in_end)
        return achp_in_end +1; //Error - length too long
    
    int iml_adler = m_calc_adler(achp_in,0,imp_codelen);
	int iml1 = 0;
    int iml_numitems = sizeof(dsrr_uievent_codes) / (sizeof(int)*2);
    do {
        if (dsrr_uievent_codes[ iml1 ][0]== iml_adler) {  /* compare hash of name */
            achp_out[0] = (dsrr_uievent_codes[iml1][1]) & 0xFF;                       /* option found in table   */
            achp_out[1] = ((dsrr_uievent_codes[iml1][1]) >> 8) & 0xFF;                       /* option found in table   */
            return achp_in + imp_codelen;
        }
        iml1++;                                /* increment index         */
    } while (iml1 < iml_numitems) ;
    return achp_in_end +1; //not found
}

static char* m_uicode_to_scancode_hash(char* achp_out, char* achp_in, char* achp_in_end, int imp_codelen, int* key)
{
    if (achp_in + imp_codelen > achp_in_end)
        return achp_in_end +1; //Error - length too long

    const ds_uievent_code* dsl_code = in_word_set(achp_in,imp_codelen, key);
    if (!dsl_code)
        return achp_in_end +1;
    achp_out[0] = dsl_code->im_val & 0xFF;                       /* option found in table   */
    achp_out[1] = (dsl_code->im_val >> 8) & 0xFF;                       /* option found in table   */
    return achp_in + imp_codelen;   
}
/*  Helper Function:
Sets keyboard layout in sdh. 
Returns FALSE on Error ( Target keyboard layout was not found )
Returns TRUE on Success
*/
static BOOL m_get_layout_from_id(dsd_keyboard_data* adsp_keyboard_data, unsigned int imp_locale_id) {
  int iml_1;
  for ( iml_1 = 0; iml_1 < LAYOUT_COUNT; iml_1++ ) {
    if ( DSS_KEYBOARD_LAYOUTS.adsrc_layouts[iml_1]->unc_language_id == imp_locale_id) {
      adsp_keyboard_data->adsc_current_layout = DSS_KEYBOARD_LAYOUTS.adsrc_layouts[iml_1];
      return TRUE;
    }  
  }
  return FALSE;
}

/*  Mapping Function:
Maps keycodes to scancodes. 
Returns:
-1: Error 
0: No mapping found for the given unicode
1: A key combination was found for the given unicode
2: A key combination sequence was found for the given unicode
*/
static int m_map_unicode_to_scancode(dsd_keyboard_data* adsp_keyboard_data, wchar_t wcrp_unicode) {
  int iml_1;                                    /* Used as a counter */

  if (adsp_keyboard_data->adsc_current_layout->unc_language_id == 0) 
    return -1;                                   /* Keyboard layout not set. */

  if  (wcrp_unicode < 0)
    return -1;                                  /* Invalid unicode  */

  struct dsd_combo_to_uni_map ds_required_map = {{0x00}, 0};
  struct dsd_combo_to_uni_map_list ds_combo_map_list;

  // Check if unicode can be produced through a normal key combination.
  ds_combo_map_list = *(adsp_keyboard_data->adsc_current_layout->adsc_keyboard_mapping->adsc_normal_combos);

  for ( iml_1 = 0; iml_1 < MAX_LIST; iml_1++ ) {
	  const struct dsd_combo_to_uni_map *adsl_combo = ds_combo_map_list.adsrc_maps[iml_1];
    if ( adsl_combo == NULL /*|| ds_combo_map_list.adsrc_maps[iml_1]->wcr_unicode <= 0*/)
      break;

    if ( ds_combo_map_list.adsrc_maps[iml_1]->wcr_unicode[0] == wcrp_unicode ) {
      ds_required_map = *(ds_combo_map_list.adsrc_maps[iml_1]);
      break;
    }
  }

  if (ds_required_map.wcr_unicode[0] > 0) {
    for ( iml_1 = 0; iml_1 < MAX_COMBOS; iml_1++ ) {
      if (ds_required_map.adsrc_combos[iml_1]) {
        adsp_keyboard_data->adsrc_key_combos_to_send[0][iml_1] = ds_required_map.adsrc_combos[iml_1];  /* Normal map is found */
        return 1; // Attempt to fix double backslash - worked
      }
    }
    return 1;
  }

  // Check if unicode can be produced through a diacritical key combination.
  ds_combo_map_list = *(adsp_keyboard_data->adsc_current_layout->adsc_keyboard_mapping->adsc_diacritical_combos);

  for ( iml_1 = 0; iml_1 < MAX_LIST; iml_1++ ) {
    if ( !ds_combo_map_list.adsrc_maps[iml_1] /*|| ds_combo_map_list.adsrc_maps[iml_1]->wcr_unicode <= 0*/ ) 
      break;

    if ( ds_combo_map_list.adsrc_maps[iml_1]->wcr_unicode[0] == wcrp_unicode ) {
      ds_required_map = *(ds_combo_map_list.adsrc_maps[iml_1]);
      break;
    }
  }

  if (ds_required_map.wcr_unicode[0] && ds_required_map.wcr_unicode[0] > 0) {
    for ( iml_1 = 0; iml_1 < MAX_COMBOS; iml_1++ ) {
      if (ds_required_map.adsrc_combos[iml_1]) {
        adsp_keyboard_data->adsrc_key_combos_to_send[0][iml_1] = ds_required_map.adsrc_combos[iml_1];  /* Diacritical map is found */
        return 1; // Attempt to fix double backslash - worked 
      }
    }
    return 1;
  }

  dsd_cseq_to_uni_map ds_required_cseq_map = {{0x00}, {}};

  // Check if unicode can be produced through a sequence of key combinations.
  dsd_cseq_to_uni_map_list ds_cseq_map_list = *(adsp_keyboard_data->adsc_current_layout->adsc_keyboard_mapping->adsc_sequences);

  for ( iml_1 = 0; iml_1 < MAX_LIST; iml_1++ ) {
    if ( !ds_cseq_map_list.adsrc_maps[iml_1] /*|| ds_cseq_map_list.adsrc_maps[iml_1]->wcrc_unicode <= 0*/ ) 
      break;

    if ( ds_cseq_map_list.adsrc_maps[iml_1]->wcrc_unicode[0] == wcrp_unicode ) {
      ds_required_cseq_map = *(ds_cseq_map_list.adsrc_maps[iml_1]);
      break;
    }
  }

  if (ds_required_cseq_map.wcrc_unicode[0] > 0) {
    // Iterate over sequences
    for ( iml_1 = 0; iml_1 < MAX_SEQUENCES; iml_1++ ) {
      if (ds_required_cseq_map.adsrc_combo_sequences[iml_1]) {
        adsp_keyboard_data->adsrc_key_combos_to_send[iml_1][0] = ds_required_cseq_map.adsrc_combo_sequences[iml_1]->adsc_initial_combo;
        adsp_keyboard_data->adsrc_key_combos_to_send[iml_1][1] = ds_required_cseq_map.adsrc_combo_sequences[iml_1]->adsc_following_combo;
      }
    }
    return 2;                                  /* Key combinations sequence map is found */
  }

  return 0;                                    /* No mapping found */
}

/* Helper Function:
Sends keyboard data over the output buffer (achp_oc).
*/
#if SM_USE_SEND_EVENTS
static BOOL m_send_keyboard_data(struct dsd_aux_helper* adsp_aux, dsd_keyboard_data *adsp_keyboard_data, int* aimp_keyboard_mouse, BOOL bop_modify)
#else
static char* m_send_keyboard_data(dsd_keyboard_data *adsp_keyboard_data, char* achp_oc, char* achp_oe, int* aimp_keyboard_mouse, BOOL bop_modify)
#endif
{
  int inl_modifier;
  unsigned int unc_scan_code;
  int inl_seq, inl_combo;
  dsd_cl_keyb_eve dsl_cl_keyb_eve;

  // Iterate over all sequences
  for (inl_seq = 0; inl_seq < MAX_SEQUENCES; inl_seq++) {

    if (adsp_keyboard_data->adsrc_key_combos_to_send[inl_seq]) {

      // Iterate over all key combos
      for (inl_combo = 0; inl_combo < MAX_COMBOS; inl_combo++) {

        if (adsp_keyboard_data->adsrc_key_combos_to_send[inl_seq][inl_combo]) {

          // Retrieve the modifier (CTRL, SHIFT, ALT etc) and the scan code.
          inl_modifier = adsp_keyboard_data->adsrc_key_combos_to_send[inl_seq][inl_combo]->inc_modifier;
          unc_scan_code = adsp_keyboard_data->adsrc_key_combos_to_send[inl_seq][inl_combo]->unc_scan_code;

          // Workaround
          if (bop_modify)
            inl_modifier |= 16;

          /* 
          * Release all modifiers
          */

          if (adsp_keyboard_data->borc_keys_down[0x2a]) { 
#if SM_USE_SEND_EVENTS
				 dsl_cl_keyb_eve.chc_flags = 0x01;
				 dsl_cl_keyb_eve.usc_keycode = (unsigned char) 0x2a; // Shift
				 if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return FALSE;
#else
				 if (achp_oc + 2 > achp_oe) 
              return NULL;
            *achp_oc = 0x01;
            *++achp_oc = (unsigned char) 0x2a; // Shift
            achp_oc++;
#endif
				 (*aimp_keyboard_mouse)++;
          }

          if (adsp_keyboard_data->borc_keys_down[0x38]) {
#if SM_USE_SEND_EVENTS
				 dsl_cl_keyb_eve.chc_flags = 0x01;
				 dsl_cl_keyb_eve.usc_keycode = (unsigned char) 0x38; // Alt
				 if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return FALSE;
#else
            if (achp_oc + 2 > achp_oe) 
              return NULL;

            *achp_oc = 0x01;
            *++achp_oc = (unsigned char) 0x38; // Alt
            achp_oc++;
#endif
            (*aimp_keyboard_mouse)++;
          }
          if (adsp_keyboard_data->borc_keys_down[0x1d] /*&& (inl_modifier & 2)*/) {
#if SM_USE_SEND_EVENTS
				 dsl_cl_keyb_eve.chc_flags = 0x01;
				 dsl_cl_keyb_eve.usc_keycode = (unsigned char) 0x1d; // CTRL
				 if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return FALSE;
#else
            if (achp_oc + 2 > achp_oe) 
              return NULL;

            *achp_oc = 0x01;
            *++achp_oc = (unsigned char) 0x1d; // CTRL
            achp_oc++;
#endif
				 (*aimp_keyboard_mouse)++;
			 }

          /* 
          * Press required modifiers
          */
          /*if (inl_modifier & 1) {

          } 
          else*/ if (inl_modifier & 2) { // Press Shift
#if SM_USE_SEND_EVENTS
				 dsl_cl_keyb_eve.chc_flags = 0x00;
				 dsl_cl_keyb_eve.usc_keycode = (unsigned char) 0x2a; // shift
				 if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return FALSE;
#else
            if (achp_oc + 2 > achp_oe) 
              return NULL;

            *achp_oc = 0x00;
            *++achp_oc = (unsigned char) 0x2a;
            achp_oc++;
#endif
				 (*aimp_keyboard_mouse)++;
          }
          else if (inl_modifier & 8) { // Press AltGr
#if SM_USE_SEND_EVENTS
				 dsl_cl_keyb_eve.chc_flags = 0x00;
				 dsl_cl_keyb_eve.usc_keycode = (unsigned char) 0x1d; // CTRL
				 if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return FALSE;
				 (*aimp_keyboard_mouse)++;
				 dsl_cl_keyb_eve.chc_flags = 0x00;
				 dsl_cl_keyb_eve.usc_keycode = (unsigned char) 0x38; // CTRL
				 if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return FALSE;
				 (*aimp_keyboard_mouse)++;
#else
            if (achp_oc + 4 > achp_oe) 
              return NULL;

            *achp_oc = 0x00;
            *++achp_oc = (unsigned char) 0x1d;
            (*aimp_keyboard_mouse)++;
            *++achp_oc = 0x00;
            *++achp_oc = (unsigned char) 0x38;
            (*aimp_keyboard_mouse)++;
            achp_oc++;
#endif
          }
          else if (inl_modifier & 16) { // Press CTRL
#if SM_USE_SEND_EVENTS
				 dsl_cl_keyb_eve.chc_flags = 0x00;
				 dsl_cl_keyb_eve.usc_keycode = (unsigned char) 0x1d; // CTRL
				 if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return FALSE;
#else
            if (achp_oc + 2 > achp_oe) 
              return NULL;

            *achp_oc = 0x00;
            *++achp_oc = (unsigned char) 0x1d;
				achp_oc++;
#endif
				 (*aimp_keyboard_mouse)++;
          }

          /* 
          * Main Sending of Scan Code
          */

#if SM_USE_SEND_EVENTS
			dsl_cl_keyb_eve.chc_flags = 0x00;
			dsl_cl_keyb_eve.usc_keycode = (unsigned char) unc_scan_code;
			if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
				return FALSE;
			(*aimp_keyboard_mouse)++;
			dsl_cl_keyb_eve.chc_flags = 0x01;
			dsl_cl_keyb_eve.usc_keycode = (unsigned char) unc_scan_code;
			if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
				return FALSE;
			(*aimp_keyboard_mouse)++;
#else
          if (achp_oc + 4 > achp_oe) 
            return NULL;

          *achp_oc = 0x00; 
          *++achp_oc = (unsigned char) unc_scan_code; 
          (*aimp_keyboard_mouse)++; 
          *++achp_oc = 0x01; 
          *++achp_oc = (unsigned char) unc_scan_code; 
          (*aimp_keyboard_mouse)++; 
          achp_oc++;
#endif
          /*
          * Release pressed modifier keys
          */
          /*if (inl_modifier & 1) {

          } 
          else*/ if (inl_modifier & 2) { // Release Shift
#if SM_USE_SEND_EVENTS
				dsl_cl_keyb_eve.chc_flags = 0x01;
				dsl_cl_keyb_eve.usc_keycode = (unsigned char) 0x2a;
				if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return FALSE;
#else
            if (achp_oc + 2 > achp_oe) 
              return NULL;

            *achp_oc = 0x01;
            *++achp_oc = (unsigned char) 0x2a;
            achp_oc++;
#endif
            (*aimp_keyboard_mouse)++;
			 }
          else if (inl_modifier & 8) { // Release AltGr
#if SM_USE_SEND_EVENTS
				dsl_cl_keyb_eve.chc_flags = 0x01;
				dsl_cl_keyb_eve.usc_keycode = (unsigned char) 0x38;
				if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return FALSE;
            (*aimp_keyboard_mouse)++;
				dsl_cl_keyb_eve.chc_flags = 0x01;
				dsl_cl_keyb_eve.usc_keycode = (unsigned char) 0x1d;
				if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return FALSE;
            (*aimp_keyboard_mouse)++;
#else
            if (achp_oc + 4 > achp_oe) 
              return NULL;

            *achp_oc = 0x01;
            *++achp_oc = (unsigned char) 0x38;
            (*aimp_keyboard_mouse)++;
            *++achp_oc = 0x01;
            *++achp_oc = (unsigned char) 0x1d;
            (*aimp_keyboard_mouse)++;
            achp_oc++;
#endif
			 }
          else if (inl_modifier & 16) { // Release CTRL
#if SM_USE_SEND_EVENTS
				dsl_cl_keyb_eve.chc_flags = 0x01;
				dsl_cl_keyb_eve.usc_keycode = (unsigned char) 0x1d;
				if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return FALSE;
#else
				if (achp_oc + 2 > achp_oe) 
              return NULL;

            *achp_oc = 0x01;
            *++achp_oc = (unsigned char) 0x1d;
            achp_oc++;
#endif
            (*aimp_keyboard_mouse)++;
          }

          /*
          * Press previously released modifier keys
          */

          if (adsp_keyboard_data->borc_keys_down[0x2a]) {
#if SM_USE_SEND_EVENTS
				dsl_cl_keyb_eve.chc_flags = 0x00;
				dsl_cl_keyb_eve.usc_keycode = (unsigned char) 0x2a;
				if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return FALSE;
#else
            if (achp_oc + 2 > achp_oe) 
              return NULL;

            *achp_oc = 0x00;
            *++achp_oc = (unsigned char) 0x2a;
            achp_oc++;
#endif
            (*aimp_keyboard_mouse)++;
			 }
          
          if (adsp_keyboard_data->borc_keys_down[0x38]) {
#if SM_USE_SEND_EVENTS
				dsl_cl_keyb_eve.chc_flags = 0x00;
				dsl_cl_keyb_eve.usc_keycode = (unsigned char) 0x38;
				if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return FALSE;
#else
            if (achp_oc + 2 > achp_oe) 
              return NULL;

            *achp_oc = 0x00;
            *++achp_oc = (unsigned char) 0x38;
            achp_oc++;
#endif
            (*aimp_keyboard_mouse)++;
          }
          if (adsp_keyboard_data->borc_keys_down[0x1d] /* && (inl_modifier & 2)*/) {
#if SM_USE_SEND_EVENTS
				dsl_cl_keyb_eve.chc_flags = 0x00;
				dsl_cl_keyb_eve.usc_keycode = (unsigned char) 0x1d;
				if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return FALSE;
#else
				 if (achp_oc + 2 > achp_oe) 
              return NULL;

            *achp_oc = 0x00;
            *++achp_oc = (unsigned char) 0x1d;
            achp_oc++;
#endif
            (*aimp_keyboard_mouse)++;
          }            

        }

      }

    }
  }

  /*
  * Clean Up keyboard data by resetting all pointers.
  */
  for (inl_seq = 0; inl_seq < MAX_SEQUENCES; inl_seq++) {
    if (adsp_keyboard_data->adsrc_key_combos_to_send[inl_seq]) {    
      for (inl_combo = 0; inl_combo < MAX_COMBOS; inl_combo++) {
        if (adsp_keyboard_data->adsrc_key_combos_to_send[inl_seq][inl_combo]) {
          adsp_keyboard_data->adsrc_key_combos_to_send[inl_seq][inl_combo] = (dsd_key_combo*)0;
        }
      }
    }
  }

#if SM_USE_SEND_EVENTS
	return TRUE;
#else
  return achp_oc;
#endif
}


static BOOL m_send_mouse_event(struct dsd_aux_helper *adsp_aux, struct dsd_keyboard_data* adsp_keyboard_data, struct dsd_cl_mouse_eve* adsp_event) {
	char *achl_oc = adsp_keyboard_data->achc_out_cur;                /* current output pointer */
	char *achl_oe = adsp_keyboard_data->achc_out_end;  /* end of output-buffer */
	if (achl_oc + 7 > achl_oe)
       return FALSE;  /* output buffer would overflow */
	*(achl_oc++) = 0x20; /* eventHeader: FASTPATH_INPUT_EVENT_MOUSE << 5 */
   *(achl_oc++) = (char)adsp_event->usc_flags;
   *(achl_oc++) = (char)(adsp_event->usc_flags >> 8);
	*(achl_oc++) = (char)adsp_event->isc_coord_x;
   *(achl_oc++) = (char)(adsp_event->isc_coord_x >> 8);
	*(achl_oc++) = (char)adsp_event->isc_coord_y;
   *(achl_oc++) = (char)(adsp_event->isc_coord_y >> 8);
	adsp_keyboard_data->achc_out_cur = achl_oc;
	return TRUE;
}

static BOOL m_send_keyboard_event(struct dsd_aux_helper *adsp_aux, struct dsd_keyboard_data* adsp_keyboard_data, struct dsd_cl_keyb_eve* adsp_event) {
	char *achl_oc = adsp_keyboard_data->achc_out_cur;                /* current output pointer */
	char *achl_oe = adsp_keyboard_data->achc_out_end;  /* end of output-buffer */
	if (achl_oc + 2 > achl_oe)
       return FALSE;  /* output buffer would overflow */
	*(achl_oc++) = 0x00 | (adsp_event->chc_flags & 0x1f); /* eventHeader: FASTPATH_INPUT_EVENT_KEYBOARD << 5 */
	*(achl_oc++) = adsp_event->usc_keycode;
	adsp_keyboard_data->achc_out_cur = achl_oc;
	return TRUE;
}

static BOOL m_send_unicode_event(struct dsd_aux_helper *adsp_aux, struct dsd_keyboard_data* adsp_keyboard_data, struct dsd_cl_keyb_eve* adsp_event) {
	char *achl_oc = adsp_keyboard_data->achc_out_cur;                /* current output pointer */
	char *achl_oe = adsp_keyboard_data->achc_out_end;  /* end of output-buffer */
	if (achl_oc + 3 > achl_oe)
       return FALSE;  /* output buffer would overflow */
	*(achl_oc++) = 0x80 | (adsp_event->chc_flags & 0x1f); /* eventHeader: FASTPATH_INPUT_EVENT_UNICODE << 5 */
	*(achl_oc++) = (char)adsp_event->usc_keycode;
	*(achl_oc++) = (char)(adsp_event->usc_keycode >> 8);
	adsp_keyboard_data->achc_out_cur = achl_oc;
	return TRUE;
}

static BOOL m_send_sync_event(struct dsd_aux_helper *adsp_aux, struct dsd_keyboard_data* adsp_keyboard_data, struct dsd_cl_sync_eve* adsp_event) {
	char *achl_oc = adsp_keyboard_data->achc_out_cur;                /* current output pointer */
	char *achl_oe = adsp_keyboard_data->achc_out_end;  /* end of output-buffer */
	if (achl_oc + 1 > achl_oe)
       return FALSE;  /* output buffer would overflow */
	*(achl_oc++) = 0x60 | (adsp_event->chc_flags & 0x1f); /* eventHeader: FASTPATH_INPUT_EVENT_SYNC << 5 */
	adsp_keyboard_data->achc_out_cur = achl_oc;
	return TRUE;
}

/*********************
Public Functions
*********************/

/* Keyboard and Browser data initialization function
TODO: Replace strstr(char*,const char*) with the HOB Unicode Library's parallel function once implemented.
Returns:
0: Keyboard layout found and set.
-1: Keyboard layout not found.
-2: Browser Type not found from useragent string.
-3: Platform not found from platform string.
*/
int m_init_mouse_keyboard(dsd_keyboard_data* adsp_keyboard_data, const struct dsd_keyboard_init* adsp_keyboard_init) {

  BOOL iml_ret;
  iml_ret = 0;

  // Discuss whether we should default to english....
  if(!m_get_layout_from_id(adsp_keyboard_data, adsp_keyboard_init->imc_layout_id))
    iml_ret = -1;

  // Set browser data
  adsp_keyboard_data->dsc_browser_data.iec_browser = adsp_keyboard_init->adsc_browser_data->iec_browser;
  adsp_keyboard_data->dsc_browser_data.iec_platform = adsp_keyboard_init->adsc_browser_data->iec_platform;

  adsp_keyboard_data->imc_combo_count = 0;
  adsp_keyboard_data->amc_send_keyboard_event = m_send_keyboard_event;
  adsp_keyboard_data->amc_send_mouse_event = m_send_mouse_event;
  adsp_keyboard_data->amc_send_sync_event = m_send_sync_event;
  adsp_keyboard_data->amc_send_unicode_event = m_send_unicode_event;
  adsp_keyboard_data->achc_out_cur = NULL;
  adsp_keyboard_data->achc_out_end = NULL;
  return iml_ret;
}

/**
 * Maximum allowed value.
 */
static const int INPUT_FLAG_MOUSE_WHEEL_ROTATION_MAX = 0xff;
/**
 * Minimum allowed value.
 */
static const int INPUT_FLAG_MOUSE_WHEEL_ROTATION_MIN = -0xff;
/**
	* The PTRFLAGS_ROTATION_MASK value is negative and must be sign-extended before injection at the server.
	*/
static const int INPUT_FLAG_MOUSE_WHEEL_NEGATIVE = 0x0100;

int m_proc_mouse_keyboard( struct dsd_aux_helper *adsp_aux,
	struct dsd_keyboard_data *adsp_keyboard_data,
#if CV_TOUCH_REDIR
	struct dsd_dvc_input *adsp_input_ex,
#endif
#if !SM_USE_SEND_EVENTS
	char *achp_out, int imp_len_out,
#endif
	int *aimp_keyboard_mouse,
	char *achp_inp, int imp_len_inp
#if CV_TOUCH_REDIR
	,struct dsd_gather_i_1_fifo* adsp_touch_fifo_out,
	int *aimp_touch_data_out
#endif
)
{
	struct dsd_aux_helper dsl_output_area_1;  /* SDH call structure     */
	dsl_output_area_1.amc_aux = adsp_aux->amc_aux;  /* auxiliary subroutine */
	dsl_output_area_1.vpc_userfld = adsp_aux->vpc_userfld;  /* User Field Subroutine */
    char *achl_ic = achp_inp;                /* current input pointer */
    char *achl_ie = achp_inp + imp_len_inp;  /* end of input-buffer */
#if SM_USE_SEND_EVENTS
	 char *achl_out_start = adsp_keyboard_data->achc_out_cur;                /* current output pointer */
#else
    char *achl_oc = achp_out;                /* current output pointer */
    char *achl_oe = achp_out + imp_len_out;  /* end of output-buffer */
#endif
	 char *achl_ie_local;                     /* helper variable */
    unsigned char byrl_keycode[2];
    unsigned char byrl_code[2];
    unsigned int iml_codelen;
    unsigned int uml_ucode;
    int          iml_wheelmove;
    int          iml_ret;             /* helper variable */
	 dsd_cl_mouse_eve dsl_cl_mouse_eve;
	 dsd_cl_keyb_eve dsl_cl_keyb_eve;
#if DEBUG_KEYBOARD
    int iml_tmp1;
#endif
    while (achl_ic < achl_ie) {  /* still data to process present */
      switch (*achl_ic++) {      /* client_command */
        /* although we are using fastpath output format here, the pointerFlags are documented
        with the slowpath variant in 2.2.8.1.1.3.1.1.3  Mouse Event (TS_POINTER_EVENT) */
      case 0:                  /* MOUSE_MOVE */
#if SM_USE_SEND_EVENTS
		  dsl_cl_mouse_eve.usc_flags = PTRFLAGS_MOVE;
		  /* first input byte DSD_EVENT_FLAGS event_flags is ignored */
        achl_ic = m_hasn32s_to_int2(&iml_ret, achl_ic+1, achl_ie);  /* pos_x */ 
        if (achl_ic == NULL) 
          return -1;
		  dsl_cl_mouse_eve.isc_coord_x = iml_ret;
        achl_ic = m_hasn32s_to_int2(&iml_ret, achl_ic, achl_ie);  /* pos_y */ 
        if (achl_ic == NULL) 
          return -1;
		  dsl_cl_mouse_eve.isc_coord_y = iml_ret;
		  if(!adsp_keyboard_data->amc_send_mouse_event(adsp_aux, adsp_keyboard_data, &dsl_cl_mouse_eve))
			  return -1;
#  else
        if (achl_oc + 7 > achl_oe)
          return -1;  /* output buffer would overflow */
        *(achl_oc++) = 0x20; /* eventHeader: FASTPATH_INPUT_EVENT_MOUSE << 5 */
        *(achl_oc++) = 0; /* pointerFlags LSB */
        *(achl_oc++) = 0x08; /* pointerFlags MSB: PTRFLAGS_MOVE >> 8 */
        /* first input byte DSD_EVENT_FLAGS event_flags is ignored */
        achl_ic = m_hasn32u_to_le2( achl_oc, achl_ic+1, achl_ie );  /* pos_x */ 
        if (achl_ic >= achl_ie) 
          return -1;
        achl_oc += 2;
        achl_ic = m_hasn32u_to_le2( achl_oc, achl_ic, achl_ie );  /* pos_y */ 
        if (achl_ic > achl_ie) 
          return -1;
        achl_oc += 2;
#endif
        break;
      case 1:                  /* MOUSE_DOWN */          
#if DEBUG_KEYBOARD
        iml_tmp1 = 1;
#endif
      case 2:                  /* MOUSE_UP */
#if DEBUG_KEYBOARD
        iml_tmp1 = 2;
#endif
#if SM_USE_SEND_EVENTS
		  dsl_cl_mouse_eve.usc_flags = (*(achl_ic-1)) == 1 ? PTRFLAGS_DOWN : 0;
		  /* first input byte DSD_EVENT_FLAGS event_flags is ignored */
        achl_ic = m_hasn32s_to_int2(&iml_ret, achl_ic+1, achl_ie);  /* pos_x */ 
        if (achl_ic == NULL) 
          return -1;
		  dsl_cl_mouse_eve.isc_coord_x = iml_ret;
        achl_ic = m_hasn32s_to_int2(&iml_ret, achl_ic, achl_ie);  /* pos_y */ 
        if (achl_ic == NULL) 
          return -1;
		  dsl_cl_mouse_eve.isc_coord_y = iml_ret;
		  if(achl_ic >= achl_ie)
          return -1;
		  switch (*achl_ic++) {  /* parse DSD_MOUSE_BUTTON button into pointerFlags-LSB */
				case 0:  /* BUTTON_LEFT -> PTRFLAGS_BUTTON1 >> 8 */
					dsl_cl_mouse_eve.usc_flags |= PTRFLAGS_BUTTON1;
					break;
				case 1:  /* BUTTON_MIDDLE -> PTRFLAGS_BUTTON3 >> 8 */
					dsl_cl_mouse_eve.usc_flags |= PTRFLAGS_BUTTON3;
					break;
				case 2:  /* BUTTON_RIGHT -> PTRFLAGS_BUTTON2 >> 8 */
					dsl_cl_mouse_eve.usc_flags |= PTRFLAGS_BUTTON2;
					break;
				default:
					break;  /* ignore? error to return -1;? extra buttons needing a TS_FP_POINTERX_EVENT? UUUU */
        }
		  if(!adsp_keyboard_data->amc_send_mouse_event(adsp_aux, adsp_keyboard_data, &dsl_cl_mouse_eve))
			  return -1;
#else
        if (achl_oc + 7 > achl_oe)
          return -1;  /* output buffer would overflow */
		  *achl_oc = 0x20; /* eventHeader: FASTPATH_INPUT_EVENT_MOUSE << 5 */
        *(achl_oc+1) = 0; /* pointerFlags LSB */
        *(achl_oc+2) = *(achl_ic-1) << 7; /* pointerFlags MSB: if mousedown, PTRFLAGS_DOWN >> 8 */
        /* first input byte DSD_EVENT_FLAGS event_flags is ignored */
        achl_ic = m_hasn32u_to_le2( achl_oc+3, achl_ic+1, achl_ie );  /* pos_x */ 
        if (achl_ic >= achl_ie) 
          return -1;
        achl_ic = m_hasn32u_to_le2( achl_oc+5, achl_ic, achl_ie );  /* pos_y */ 
        if (achl_ic >= achl_ie) 
          return -1;
        switch (*achl_ic++) {  /* parse DSD_MOUSE_BUTTON button into pointerFlags-LSB */
      case 0:  /* BUTTON_LEFT -> PTRFLAGS_BUTTON1 >> 8 */
        *(achl_oc+2) |= 0x10;
        break;
      case 1:  /* BUTTON_MIDDLE -> PTRFLAGS_BUTTON3 >> 8 */
        *(achl_oc+2) |= 0x40;
        break;
      case 2:  /* BUTTON_RIGHT -> PTRFLAGS_BUTTON2 >> 8 */
        *(achl_oc+2) |= 0x20;
        break;
      default:
        break;  /* ignore? error to return -1;? extra buttons needing a TS_FP_POINTERX_EVENT? UUUU */
        }
#if DEBUG_KEYBOARD
        m_aux_printf( &dsl_output_area_1, "m_proc_mouse_keyboard-l%05d KBD Mouse %d button: %d  ",__LINE__,iml_tmp1,*(achl_oc+2) );
#endif
        achl_oc += 7;
#endif
        break;
      case 3:                  /* MOUSE_WHEEL */
#ifdef DEBUG_20140130
        printf("\n\n");
#endif
#if SM_USE_SEND_EVENTS
		  dsl_cl_mouse_eve.usc_flags = PTRFLAGS_WHEEL;
		  /* first input byte DSD_EVENT_FLAGS event_flags is ignored */
        achl_ic = m_hasn32s_to_int2(&iml_ret, achl_ic+1, achl_ie);  /* pos_x */ 
        if (achl_ic == NULL) 
          return -1;
		  dsl_cl_mouse_eve.isc_coord_x = iml_ret;
        achl_ic = m_hasn32s_to_int2(&iml_ret, achl_ic, achl_ie);  /* pos_y */ 
        if (achl_ic == NULL) 
          return -1;
		  dsl_cl_mouse_eve.isc_coord_y = iml_ret;
        achl_ic = m_hasn32s_to_int2(&iml_ret, achl_ic, achl_ie);  /* wheel rotation */ 
        if (achl_ic == NULL) 
          return -1;
		  /* Is negative? */
		  if(iml_ret < 0) {
			  if(iml_ret < INPUT_FLAG_MOUSE_WHEEL_ROTATION_MIN)
				  iml_ret = INPUT_FLAG_MOUSE_WHEEL_ROTATION_MIN;
			  dsl_cl_mouse_eve.usc_flags |= INPUT_FLAG_MOUSE_WHEEL_NEGATIVE;
		  }
		  else {
			  if(iml_ret > INPUT_FLAG_MOUSE_WHEEL_ROTATION_MAX)
				  iml_ret = INPUT_FLAG_MOUSE_WHEEL_ROTATION_MAX;
		  }
		  dsl_cl_mouse_eve.usc_flags |= (iml_ret & 0x1FF);
		  if(!adsp_keyboard_data->amc_send_mouse_event(adsp_aux, adsp_keyboard_data, &dsl_cl_mouse_eve))
			  return -1;
#else
        if (achl_oc + 7 > achl_oe)
          return -1;  /* output buffer would overflow */
		  *achl_oc = 0x20; /* eventHeader: FASTPATH_INPUT_EVENT_MOUSE << 5 */
        *(achl_oc+2) = 0x02; /* pointerFlags MSB: PTRFLAGS_WHEEL >> 8 */
        /* first input byte DSD_EVENT_FLAGS event_flags is ignored */
        achl_ic = m_hasn32u_to_le2( achl_oc+3, achl_ic+1, achl_ie );  /* pos_x */ 
        if (achl_ic >= achl_ie) 
          return -1;
        achl_ic = m_hasn32u_to_le2( achl_oc+5, achl_ic, achl_ie );  /* pos_y */ 
        if (achl_ic >= achl_ie) 
          return -1;
        /* read wheel data (parse HASN1_SINT32_BE delta_y), we can store 9 bits in WheelRotationMask and a signbit */
        if( (signed char)(*achl_ic) < 0 ) {  /* two-byte input */
          iml_wheelmove = (*achl_ic & 0x7F) << 6;
          ++achl_ic;
          if (achl_ic >= achl_ie) 
            return -1;
          if( (signed char)(*achl_ic) < 0 ) 
            return -1;  /* numeric overflow */
          iml_wheelmove |= *achl_ic >> 1;
          if (*achl_ic & 1) {  /* negative direction */
            if (iml_wheelmove > 0x1FE) 
              return -1;  /* numeric overflow (UUUU or use max/min?) */
            iml_wheelmove ++;
#ifdef DEBUG_20140130
            printf("m_proc_mouse_keyboard(): MOUSEWHEEL-Value (2 BYTE) -%3d\n", iml_wheelmove);
#endif
            iml_wheelmove ^= 0x1FF;
            *(achl_oc+2) |= 0x01; /* PTRFLAGS_WHEEL_NEGATIVE >> 8 into pointerFlags MSB */
#ifdef DEBUG_20140130
            printf("m_proc_mouse_keyboard(): MOUSEWHEEL-Value (2 BYTE) +%3d\n", iml_wheelmove);
#endif
          } else {
            if (iml_wheelmove > 0x1FF) 
              return -1;  /* numeric overflow (UUUU or use max?) */
          }
          *(achl_oc+1) = (unsigned char)iml_wheelmove;
          *(achl_oc+2) |= iml_wheelmove >> 8;
        } else {  /* one-byte input */
          *(achl_oc+1) = (unsigned char)(*achl_ic) >> 1;
#ifdef DEBUG_20140130
          printf("m_proc_mouse_keyboard(): MOUSEWHEEL-Value (1 byte) ");
#endif
          if (*achl_ic & 1) {  /* negative direction */
            achl_oc[1] ++;
#ifdef DEBUG_20140130
            printf("-%3d\n", achl_oc[1]);
#endif
            achl_oc[1] ^= 0xFF;
            *(achl_oc+2) |= 0x01; /* PTRFLAGS_WHEEL_NEGATIVE >> 8 into pointerFlags MSB */
#ifdef DEBUG_20140130
          } else {
            printf("+%3d\n", achl_oc[1]);
#endif
          }
        }
        achl_ic ++;
        achl_oc += 7;
#ifdef DEBUG_20140130
        printf("\n\n");
#endif
#endif
        break;
      case 4:
      case 64+4:/* KEY_DOWN DIRECT*/ 
          achl_ic = m_hasn32u_to_le2( (char*)byrl_keycode, achl_ic+1, achl_ie );    // First input byte DSD_EVENT_FLAGS event_flags is ignored
          if (achl_ic > achl_ie) {
#if DEBUG_KEYBOARD
          m_aux_printf( &dsl_output_area_1, "m_proc_mouse_keyboard-l%05d KBD Keydown  Buffer Error ",__LINE__ );
#endif
            return -1;
          }
          
          achl_ic = m_hasn32u_to_int(&iml_codelen, achl_ic, achl_ie); //read the code length
          if (achl_ic > achl_ie) {
#if DEBUG_KEYBOARD
          m_aux_printf( &dsl_output_area_1, "m_proc_mouse_keyboard-l%05d KBD Keydown  Buffer Error",__LINE__ );
#endif
            return -1;
          }
          
          if (iml_codelen > 0){
            int iml_key = 0;
            achl_ic = m_uicode_to_scancode_hash((char*)byrl_code, achl_ic, achl_ie, iml_codelen, &iml_key); 
            if (achl_ic > achl_ie) {
#if DEBUG_KEYBOARD
                m_aux_printf( &dsl_output_area_1, "m_proc_mouse_keyboard-l%05d KBD Keydown Unknown Code",__LINE__ );
#endif
                return -1;
            }
#if DEBUG_KEYBOARD
            m_aux_printf( &dsl_output_area_1, "m_proc_mouse_keyboard-l%05d KBD Keydown Direct code in: %.*s out: 0x%d 0x%d  ",__LINE__,iml_codelen,achl_ic-iml_codelen,byrl_code[0],byrl_code[1] );
#endif
              //convert the code to a scancode
            adsp_keyboard_data->borc_direct_keys_down[iml_key] = 1;
            //adsp_keyboard_data->borc_keys_down[INP_SC] = 1;
#if SM_USE_SEND_EVENTS
				dsl_cl_keyb_eve.chc_flags = 0;
            if (byrl_code[1] != 0)
                dsl_cl_keyb_eve.chc_flags |= 0x02;
				dsl_cl_keyb_eve.usc_keycode = (unsigned char)byrl_code[0];
				if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return -1;
#else
				if (achl_oc + 2 > achl_oe){
#if DEBUG_KEYBOARD
					m_aux_printf( &dsl_output_area_1, "m_proc_mouse_keyboard-l%05d KBD Keydown Buffer error ",__LINE__ );
#endif
					return -1;                                // Output buffer overflow 

				}
				*achl_oc = 0x00;
            if (byrl_code[1] != 0)
                *achl_oc |= 0x02;
            *++achl_oc = (unsigned char)byrl_code[0];
            achl_oc++;
#endif
            break;
          }

          //no code present - handle keycode
         
      //case 4:                  /* KEY_DOWN */ 
       /* if (achl_oc + 2 > achl_oe)
          return -1;                                // Output buffer overflow 

        achl_ic = m_hasn32u_to_le2( (char*)byrl_keycode, achl_ic+1, achl_ie );    // First input byte DSD_EVENT_FLAGS event_flags is ignored

        if (achl_ic > achl_ie) 
          return -1;*/
        if (byrl_keycode[1]) 
          return -1;                        // KeyCode > 255 (Unknown)
    
        switch (byrl_keycode[0]) {
#if SM_USE_SEND_EVENTS
		  // Send KeyDown event.
#define LKC(INP_SC)\
  adsp_keyboard_data->borc_keys_down[INP_SC] = 1;\
  dsl_cl_keyb_eve.chc_flags = 0x00;\
  dsl_cl_keyb_eve.usc_keycode = (unsigned char)INP_SC;\
  break;
          // Send KeyDown event with extended key code.
#define EKC(INP_SC)\
  adsp_keyboard_data->borc_keys_down[INP_SC] = 1;\
  dsl_cl_keyb_eve.chc_flags = 0x02;\
  dsl_cl_keyb_eve.usc_keycode = (unsigned char)(INP_SC & 0xff);\
  break;
#else
		  // Send KeyDown event.
#define LKC(INP_SC)\
  adsp_keyboard_data->borc_keys_down[INP_SC] = 1;\
  *achl_oc = 0x00;\
  *++achl_oc = (unsigned char)INP_SC;\
  break;
          // Send KeyDown event with extended key code.
#define EKC(INP_SC)\
  adsp_keyboard_data->borc_keys_down[INP_SC] = 1;\
  *achl_oc = 0x00;\
  *achl_oc |= 0x02;\
  *++achl_oc = (unsigned char)INP_SC;\
  break;
#endif
          // Left Side of Keyboard, organised row by row top-down
      case  27: LKC(0x01);  /* [  1] ESC */
      case 112: LKC(0x3b);  /* [ 59] F1 */
      case 113: LKC(0x3c);  /* [ 60] F2 */
      case 114: LKC(0x3d);  /* [ 61] F3 */
      case 115: LKC(0x3e);  /* [ 62] F4 */
      case 116: LKC(0x3f);  /* [ 63] F5 */
      case 117: LKC(0x40);  /* [ 64] F6 */
      case 118: LKC(0x41);  /* [ 65] F7 */
      case 119: LKC(0x42);  /* [ 66] F8 */
      case 120: LKC(0x43);  /* [ 67] F9 */
      case 121: LKC(0x44);  /* [ 68] F10 */
      case 122: LKC(0x57);  /* [ 87] F11 */
      case 123: LKC(0x58);  /* [ 88] F12 */

      case   8: LKC(0x0e);  /* [ 14] Backspace */

      case   9: LKC(0x0f);  /* [ 15] Tab */
      case  13: LKC(0x1c);  /* [ 28] Return */

      case  20: continue; /* [ 58] Caps Lock */                    // Caps Lock event is not sent to prevent erraneous state changes

      case  16: LKC(0x2a);  /* [ 42] Shift * 2 */

      case  17: LKC(0x1d);  /* [ 29] Ctrl * 2 */      
      case  91: continue;      /* Left Win Key */                  // Still have to handle windows keys
      case  92: continue;      /* Right Win Key */                  // Still have to handle windows keys
      case  18: LKC(0x38);  /* [ 56] Alt * 2 */

        /* Right Side of Keyboard, organised row by row top-down */
      case  44: EKC(0x137);  /* [ 99] Print_Screen / SysRQ */ /* Only Receive Key Up */ 
      case 145: LKC(0x46);  /* [ 70] Scroll Lock */
      case  19: EKC(0x45);  /* [119] Pause / Break */ /* Fires 17D,19D,19U */

      case  45: EKC(0x52);  /* [110] Insert */
      case  36: EKC(0x47);  /* [102] Home */
      case  33: EKC(0x49);  /* [104] Page Up */

      case  46: EKC(0x53);  /* [111] Delete */ 
      case  35: EKC(0x4f);  /* [107] End */
      case  34: EKC(0x51);  /* [109] Page Down */

      case  38: EKC(0x48);  /* [103] Arrow Up */
      case  37: EKC(0x4b);  /* [105] Arrow Left */
      case  40: EKC(0x50);  /* [108] Arrow Down */
      case  39: EKC(0x4d);  /* [106] Arrow Right */
#undef EKC
#undef LKC
      default:
#ifdef CTRLKEY_HANDLE
        // If ctrl is pressed, same the non-keyboard independent keycode in a temporary variable
        if (adsp_keyboard_data->borc_keys_down[0x1d] == 1)
          adsp_keyboard_data->byc_temp_key = byrl_keycode[0];
#endif
        continue;
        }
#if DEBUG_KEYBOARD
            m_aux_printf( &dsl_output_area_1, "m_proc_mouse_keyboard-l%05d KBD Keydown code in: 0x%d out: 0x%d 0x%d  ",__LINE__,byrl_keycode[0],*achl_oc,*(achl_oc-1) );
#endif   
#if SM_USE_SEND_EVENTS
			if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return -1;
#else
        achl_oc ++;
#endif
        break;
      case 5:/* KEY_UP */
          /* 
          struct KEY_UP (5)
		    {
			    DSD_EVENT_FLAGS event_flags;
			    HASN1_UINT32_BE key_code;
			    HASN1_STRING_UTF8 code;
		    }
          
          Implementation details:
             0...7 | 8....23 | 24....31 | 32...      |
             flags | keycode | code len | code(str)  |

             keycode is always max 16 bit (8/16)
             if code len is 0 no code was provided, use keycode
             client is responsible of NOT sending keypress events if the code is being sent in the corresponding keydown/keyup
          
          */
      case 64+5:
#if !SM_USE_SEND_EVENTS
          if (achl_oc + 2 > achl_oe)
            return -1;                                // Output buffer overflow 
#endif
          achl_ic = m_hasn32u_to_le2( (char*)byrl_keycode, achl_ic+1, achl_ie );    // First input byte DSD_EVENT_FLAGS event_flags is ignored
          if (achl_ic > achl_ie) 
            return -1;

          achl_ic = m_hasn32u_to_int(&iml_codelen, achl_ic, achl_ie); //read the code length
          if (achl_ic > achl_ie) {
            return -1;
          }          
          if (iml_codelen > 0){
            int iml_key = 0;
            achl_ic = m_uicode_to_scancode_hash((char*)byrl_code, achl_ic, achl_ie, iml_codelen, &iml_key); 
            if (achl_ic > achl_ie) {
#if DEBUG_KEYBOARD
                m_aux_printf( &dsl_output_area_1, "m_proc_mouse_keyboard-l%05d KBD KeyUp Unknown Code",__LINE__ );
#endif
                return -1;
            }
              //convert the code to a scancode
            adsp_keyboard_data->borc_direct_keys_down[iml_key] = 0;
				//adsp_keyboard_data->borc_keys_down[INP_SC] = 1;
#if SM_USE_SEND_EVENTS
				dsl_cl_keyb_eve.chc_flags = 0x01;
				if (byrl_code[1] != 0)
                dsl_cl_keyb_eve.chc_flags |= 0x02;
				dsl_cl_keyb_eve.usc_keycode = (unsigned char)byrl_code[0];
				if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return -1;
#else
            *achl_oc = 0x01;
            if (byrl_code[1] != 0)
                *achl_oc |= 0x02;
            *++achl_oc = (unsigned char)byrl_code[0];
            achl_oc++;
#endif
#if DEBUG_KEYBOARD
            m_aux_printf( &dsl_output_area_1, "m_proc_mouse_keyboard-l%05d KBD Keyup Direct code in: %.*s out: 0x%d 0x%d  ",__LINE__,iml_codelen,achl_ic-iml_codelen,byrl_code[0],byrl_code[1] );
#endif
            break;
          }
          //no code found - handle keycode
/*      case 5:                  
        achl_ic = m_hasn32u_to_le2( (char*)byrl_keycode, achl_ic+1, achl_ie );      // First input byte DSD_EVENT_FLAGS event_flags is ignored

        if (achl_ic > achl_ie) 
          return -1;*/
        if (byrl_keycode[1]) 
          return -1;                          // KeyCode > 255 (Unknown)

        switch (byrl_keycode[0]) {
#if SM_USE_SEND_EVENTS
          // Check Buffer Overflow & Send KeyUp event.
#define LKC(INP_SC) adsp_keyboard_data->borc_keys_down[INP_SC] = 0; \
  dsl_cl_keyb_eve.chc_flags = 0x01;\
  dsl_cl_keyb_eve.usc_keycode = (unsigned char)INP_SC; \
  break;
          // Check Buffer Overflow & Send KeyUp event with extended keycode.
#define EKC(INP_SC) adsp_keyboard_data->borc_keys_down[INP_SC] = 0; \
  dsl_cl_keyb_eve.chc_flags = 0x03;\
  dsl_cl_keyb_eve.usc_keycode = (unsigned char)INP_SC; \
  break;
          // Check Buffer Overflow & Send KeyDown and KeyUp events in exceptional cases.
#define DKC(INP_SC) adsp_keyboard_data->borc_keys_down[INP_SC] = 0; \
  dsl_cl_keyb_eve.chc_flags = 0x02;\
  dsl_cl_keyb_eve.usc_keycode = (unsigned char)INP_SC; \
  if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve)) \
		return -1; \
  dsl_cl_keyb_eve.chc_flags = 0x03;\
  dsl_cl_keyb_eve.usc_keycode = (unsigned char)INP_SC; \
  (*aimp_keyboard_mouse)++;\
  break;
#else
          // Check Buffer Overflow & Send KeyUp event.
#define LKC(INP_SC) adsp_keyboard_data->borc_keys_down[INP_SC] = 0; \
  if (achl_oc + 2 > achl_oe)\
  return -1;\
  *achl_oc = 0x01;\
  *++achl_oc = (unsigned char)INP_SC; \
  break;
          // Check Buffer Overflow & Send KeyUp event with extended keycode.
#define EKC(INP_SC) adsp_keyboard_data->borc_keys_down[INP_SC] = 0; \
  if (achl_oc + 2 > achl_oe)\
  return -1;\
  *achl_oc = 0x01;\
  *achl_oc |= 0x02;\
  *++achl_oc = (unsigned char)INP_SC; \
  break;
          // Check Buffer Overflow & Send KeyDown and KeyUp events in exceptional cases.
#define DKC(INP_SC) adsp_keyboard_data->borc_keys_down[INP_SC] = 0; \
  if (achl_oc + 4 > achl_oe)\
  return -1;\
  *achl_oc = 0x02;\
  *++achl_oc = (unsigned char)INP_SC;\
  *++achl_oc = 0x03;\
  *++achl_oc = (unsigned char)INP_SC;\
  (*aimp_keyboard_mouse)++;\
  break;
#endif
          /* Left Side of Keyboard, organised row by row top-down */
      case  27: LKC(0x01);  /* [  1] ESC */
      case 112: LKC(0x3b);  /* [ 59] F1 */
      case 113: LKC(0x3c);  /* [ 60] F2 */
      case 114: LKC(0x3d);  /* [ 61] F3 */
      case 115: LKC(0x3e);  /* [ 62] F4 */
      case 116: LKC(0x3f);  /* [ 63] F5 */
      case 117: LKC(0x40);  /* [ 64] F6 */
      case 118: LKC(0x41);  /* [ 65] F7 */
      case 119: LKC(0x42);  /* [ 66] F8 */
      case 120: LKC(0x43);  /* [ 67] F9 */
      case 121: LKC(0x44);  /* [ 68] F10 */
      case 122: LKC(0x57);  /* [ 87] F11 */
      case 123: LKC(0x58);  /* [ 88] F12 */

      case   8: LKC(0x0e);  /* [ 14] Backspace */

      case   9: LKC(0x0f);  /* [ 15] Tab */
      case  13: LKC(0x1c);  /* [ 28] Return */

      case  20: continue;  /* [ 58] Caps Lock */                  // Caps Lock event is not sent to prevent erraneous state changes

      case  16: LKC(0x2a);  /* [ 42] Shift * 2 */

      case  17: LKC(0x1d);  /* [ 29] Ctrl * 2 */
      case  91: continue;      /* Left Win Key */                   // Still have to handle windows keys
      case  92: continue;      /* Right Win Key */                   // Still have to handle windows keys
      case  18: LKC(0x38);  /* [ 56] Alt * 2 */

        /* Right Side of Keyboard, organised row by row top-down */
      case  44: DKC(0x137);  /* [ 99] Print_Screen / SysRQ */             // Only KeyUp is received so 2 events are generated
      case 145: LKC(0x46);  /* [ 70] Scroll Lock */
      case  19: EKC(0x45);  /* [119] Pause / Break */

      case  45: EKC(0x52);  /* [110] Insert */
      case  36: EKC(0x47);  /* [102] Home */
      case  33: EKC(0x49);  /* [104] Page Up */

      case  46: EKC(0x53);  /* [111] Delete */ 
      case  35: EKC(0x4f);  /* [107] End */
      case  34: EKC(0x51);  /* [109] Page Down */

      case  38: EKC(0x48);  /* [103] Arrow Up */
      case  37: EKC(0x4b);  /* [105] Arrow Left */
      case  40: EKC(0x50);  /* [108] Arrow Down */
      case  39: EKC(0x4d);  /* [106] Arrow Right */
#undef EKC
#undef LKC
      default:
#ifdef CTRLKEY_HANDLE
        if (byrl_keycode[0] == adsp_keyboard_data->byc_temp_key) {
          adsp_keyboard_data->byc_temp_key = 0;

          // Convert to Unicode
          if (byrl_keycode[0] > 0x5A || byrl_keycode[0] < 0x41) 
            uml_ucode =  0;
          else
            uml_ucode =  byrl_keycode[0] + 32; 

          if (uml_ucode > 0xFFFF) 
            return -1;

          // Translate unicode to scancodes and modifiers in respective keyboard layout.
          iml_ret = m_map_unicode_to_scancode(adsp_keyboard_data, (wchar_t)uml_ucode);

          // Error occurred.
          if (iml_ret < 0) 
            return -1;

			 switch(iml_ret) {
			 case 0: // No mapping found
            if (uml_ucode > 0xFFFF)  /* UUUU but we have only 2 byte for output. What to do? Are Surrogate-4byte-sequences allowed? */
              return -1;
#if SM_USE_SEND_EVENTS
				dsl_cl_keyb_eve.chc_flags = 0x00;
				dsl_cl_keyb_eve.usc_keycode = (unsigned short)uml_ucode;
				if(!adsp_keyboard_data->amc_send_unicode_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return -1;
#else
            if (achl_oc + 3 > achl_oe) // Check buffer overflow
              return -1;
            *achl_oc = 0x80; // eventHeader: FASTPATH_INPUT_EVENT_UNICODE << 5  

            *++achl_oc = (unsigned char)uml_ucode;
            *++achl_oc = uml_ucode >> 8;
            achl_oc++;
#endif
            break;
			 case 1:
#if SM_USE_SEND_EVENTS
				 if(!m_send_keyboard_data(adsp_aux, adsp_keyboard_data, aimp_keyboard_mouse, TRUE)) // Buffer overflows are checked in function
					 return -1;
#else
				 achl_oc = m_send_keyboard_data(adsp_keyboard_data, achl_oc, achl_oe, aimp_keyboard_mouse, TRUE); // Buffer overflows are checked in function
				 if (achl_oc == NULL)
						return -1;
#endif
				 break;
			 case 2:
#if SM_USE_SEND_EVENTS
				 if(!m_send_keyboard_data(adsp_aux, adsp_keyboard_data, aimp_keyboard_mouse, FALSE)) // Buffer overflows are checked in function
					 return -1;
#else
				 achl_oc = m_send_keyboard_data(adsp_keyboard_data, achl_oc, achl_oe, aimp_keyboard_mouse, FALSE); // Buffer overflows are checked in function
				 if (achl_oc == NULL)
						return -1;
#endif
				 break;
			 default:
				 return -1;
			 }
          continue;
        } 
#endif
        continue;
#undef DKC
        }
#if DEBUG_KEYBOARD
            m_aux_printf( &dsl_output_area_1, "m_proc_mouse_keyboard-l%05d KBD Keyup code in: 0x%d out: 0x%d 0x%d  ",__LINE__,byrl_keycode[0],*achl_oc,*(achl_oc-1) );
#endif
#if SM_USE_SEND_EVENTS
			if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return -1;
#else
        achl_oc++;
#endif
        break;
      case 6:                  /* KEY_PRESSED */
#ifdef CTRLKEY_HANDLE  
        adsp_keyboard_data->byc_temp_key = 0;
#endif
#if !SM_USE_SEND_EVENTS
		  if (achl_oc + 3 > achl_oe)
          return -1;                                   // Output buffer overflow 
#endif
        achl_ic = m_hasn32u_to_le2( (char*)byrl_keycode, achl_ic+1, achl_ie );

        // Handling discrepency in events between Mozilla and Chrome when it comes to the keyPresses of some keyboard independant keys.
        // The Enter key is particularly problematic since Chrome considers a character key whilst Mozilla does not.
        if (*achl_ic == 0 || *achl_ic == 0x0d){ 
          achl_ic++;
          continue;
        }

        if (achl_ic >= achl_ie) 
          return -1;

        // parse unicode, up to 5 bytes input 
        achl_ie_local = (achl_ic+5 < achl_ie) ? achl_ic+5 : achl_ie;
        uml_ucode = 0;
        while (achl_ic < achl_ie_local) {  

          if( (signed char)(*achl_ic) >= 0 ) 
            break;

          uml_ucode |= (*achl_ic & 0x7F);
          uml_ucode <<= 7;
          ++achl_ic;

          if (achl_ic >= achl_ie_local) 
            return -1;
        }

        uml_ucode |= *(achl_ic++); 

        if (uml_ucode > 0xFFFF) 
          return -1;

        // Translate unicode to scancodes and modifiers in respective keyboard layout.
        iml_ret = m_map_unicode_to_scancode(adsp_keyboard_data, (wchar_t)uml_ucode);

        // Error occurred.
        if (iml_ret < 0) 
          return -1;
#if SM_USE_SEND_EVENTS
		  switch(iml_ret) {
		  case 0:
          if (uml_ucode > 0xFFFF)  /* UUUU but we have only 2 byte for output. What to do? Are Surrogate-4byte-sequences allowed? */
            return -1;
				dsl_cl_keyb_eve.chc_flags = 0x00;
				dsl_cl_keyb_eve.usc_keycode = (unsigned short)uml_ucode;
				if(!adsp_keyboard_data->amc_send_unicode_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return -1;
				break;
		  case 1:
		  case 2:
#if SM_USE_SEND_EVENTS
				 if(!m_send_keyboard_data(adsp_aux, adsp_keyboard_data, aimp_keyboard_mouse, FALSE)) // Buffer overflows are checked in function
					 return -1;
#else
			   achl_oc = m_send_keyboard_data(adsp_keyboard_data, achl_oc, achl_oe, aimp_keyboard_mouse, FALSE); // Buffer overflows are checked in function
				 if (achl_oc == NULL)
					return -1;
#endif
			   break;
		  default:
			  return FALSE;
		  }
#else
        // No mapping found 
        else if (iml_ret == 0) {
          *achl_oc = 0x80; // eventHeader: FASTPATH_INPUT_EVENT_UNICODE << 5  
          if (uml_ucode > 0xFFFF)  /* UUUU but we have only 2 byte for output. What to do? Are Surrogate-4byte-sequences allowed? */
            return -1;

          *++achl_oc = (unsigned char)uml_ucode;
          *++achl_oc = uml_ucode >> 8;
          achl_oc++;
          break;
        } else if (iml_ret == 1 || iml_ret == 2) {
          achl_oc = m_send_keyboard_data(adsp_keyboard_data, achl_oc, achl_oe, aimp_keyboard_mouse, FALSE); // Buffer overflows are checked in function
          if (achl_oc == NULL)
            return -1;
        } else {
          return -1;
        }
#endif
        continue;

        /////////////////////////////////////////////////////////////////////////////////

      case 7: {
#if SM_USE_SEND_EVENTS
			unsigned int unl_ret;
			achl_ic = m_hasn32u_to_int2( &unl_ret, achl_ic, achl_ie );
			if (achl_ic == NULL)
				 return -1;
			if (unl_ret > 0xffff)
				 return -1;
			dsl_cl_keyb_eve.chc_flags = 0x00;
			dsl_cl_keyb_eve.usc_keycode = (unsigned short)unl_ret;
			if(!adsp_keyboard_data->amc_send_unicode_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
				return -1;
#else
        char byrl_unicode[2];
        achl_ic = m_hasn32u_to_le2( byrl_unicode, achl_ic, achl_ie );
        if (achl_ic > achl_ie)
          return -1;
        if (achl_oc + 3 > achl_oe)
          return -1;  /* output buffer would overflow */
        *achl_oc++ = 0x04 << 5;  /* eventHeader: FASTPATH_INPUT_EVENT_SCANCODE << 5 is 0x00. if keyup, add FASTPATH_INPUT_KBDFLAGS_RELEASE << 0 */
        *achl_oc++ = byrl_unicode[0];
        *achl_oc++ = byrl_unicode[1];
#endif
#if DEBUG_KEYBOARD
        m_aux_printf( &dsl_output_area_1, "m_proc_mouse_keyboard-l%05d KBD Unicode Direct code: 0x%d 0x%d  ",__LINE__,byrl_unicode[0],byrl_unicode[1] );
#endif

        break;
              }

      case 8: {
        // Send KeyUp event.

        achl_ic++;

        /* Release all pressed keys */
        int inl1;
        for (inl1 = 0; inl1 < IM_NUM_KEYS; inl1++) {
          if (adsp_keyboard_data->borc_keys_down[inl1] == 1) {
            adsp_keyboard_data->borc_keys_down[inl1] = 0;
#if !SM_USE_SEND_EVENTS
            if (achl_oc + 2 > achl_oe) { // Output buffer overflow
              return -1;
            }
#endif
            if (inl1 < 0x45) {
#if SM_USE_SEND_EVENTS
					dsl_cl_keyb_eve.chc_flags = 0x01;
					dsl_cl_keyb_eve.usc_keycode = (unsigned char)inl1;
					if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
						return -1;
#else
					*achl_oc = 0x01;
              *++achl_oc = (unsigned char)inl1;
              achl_oc++;
#endif
              (*aimp_keyboard_mouse)++;
            } else {
#if SM_USE_SEND_EVENTS
					dsl_cl_keyb_eve.chc_flags = 0x03;
					dsl_cl_keyb_eve.usc_keycode = (unsigned char)inl1;
					if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
						return -1;
#else
              *achl_oc = 0x01;
              *achl_oc |= 0x02;
              *++achl_oc = (unsigned char)inl1;
              achl_oc++;
#endif
              (*aimp_keyboard_mouse)++;
            }
          }
        }
        for (inl1 = 0; inl1 < MAX_HASH_VALUE; inl1++) {
			  if(adsp_keyboard_data->borc_direct_keys_down[inl1] == 0)
				  continue;
           adsp_keyboard_data->borc_direct_keys_down[inl1] = 0;
#if !SM_USE_SEND_EVENTS
            if (achl_oc + 2 > achl_oe) { // Output buffer overflow
              return -1;
            }
#endif
            int iml_val = (wordlist[inl1]).im_val;
#if SM_USE_SEND_EVENTS
				dsl_cl_keyb_eve.chc_flags = 0x01;
            if (((iml_val >> 8) & 0xFF) != 0)
                dsl_cl_keyb_eve.chc_flags |= 0x02;
				dsl_cl_keyb_eve.usc_keycode = (unsigned char)(iml_val & 0xFF);
				if(!adsp_keyboard_data->amc_send_keyboard_event(adsp_aux, adsp_keyboard_data, &dsl_cl_keyb_eve))
					return -1;
#else
				*achl_oc = 0x01;
            if (((iml_val >> 8) & 0xFF) != 0)
                *achl_oc |= 0x02;
            *++achl_oc = (unsigned char)(iml_val & 0xFF);
            achl_oc++;        
#endif
            (*aimp_keyboard_mouse)++;
        }
        continue;
              }
#if CV_TOUCH_REDIR
      case 9: {        /* TOUCH_START: Contains a list of fingers that have made contact with the touch surface during this touchstart event. */
        unsigned long long ulll_curr_time;
        adsp_aux->amc_aux(adsp_aux->vpc_userfld,
          DEF_AUX_GET_T_MSEC,
          &ulll_curr_time, sizeof(unsigned long long));                               // Get time in milliseconds
        ulll_curr_time *= 1000;                                                                             // convert to microseconds (approximation)

        if (achl_ic + 2 > achl_ie) // Flags (1), TouchCount (1)
          return -1; // Error: Insufficient input

        unsigned char ucl_flags = *(achl_ic++);
        unsigned char ucl_touch_count = *(achl_ic++);
        struct dsd_input_touch_frame *adsl_touch_frame = &adsp_input_ex->dsl_active_touch_frame;

        if (adsp_input_ex->ullc_prev_frame_time == 0) {
          adsl_touch_frame->ullc_frame_offset = 0;
          adsp_aux->amc_aux(adsp_aux->vpc_userfld,
            DEF_AUX_GET_T_MSEC,
            &adsp_input_ex->ullc_prev_frame_time, sizeof(unsigned long long));// Get time in milliseconds
          adsp_input_ex->ullc_prev_frame_time *= 1000; // convert to microseconds (approximation)
        } else {
          adsl_touch_frame->ullc_frame_offset = ulll_curr_time - adsp_input_ex->ullc_prev_frame_time;
          adsp_input_ex->ullc_prev_frame_time = ulll_curr_time;
        }

        struct dsd_input_touch_contact *adsl_contact;
        unsigned char ucc_contact_id;

        // Iterate over all the active frame's touches and set them to update
        for (int inl1 = 0; inl1 < DVC_INPUT_MAX_CONTACTS; inl1++) {
          // Check if active, If not, skip.
          if (adsl_touch_frame->dsrc_touch_contacts[inl1].boc_active != TRUE)
            continue;

          adsl_contact = &adsl_touch_frame->dsrc_touch_contacts[inl1];

          adsl_contact->umc_contact_flags = DVC_INPUT_CONTACT_FLAG_UPDATE | 
            DVC_INPUT_CONTACT_FLAG_INRANGE | 
            DVC_INPUT_CONTACT_FLAG_INCONTACT; 
        }

        // Iterate over all the event's touches and create new ones in the active frame
        for (int inl_id = 0; inl_id < ucl_touch_count; inl_id++) {      
          if (achl_ic + 1 > achl_ie) // ContactId(1)
            return -1; // Error: Insufficient input

          ucc_contact_id = *(achl_ic++);

          // Check if contact id is over max
          if (ucc_contact_id > DVC_INPUT_MAX_CONTACTS)
            return -1;

          adsl_contact = &adsl_touch_frame->dsrc_touch_contacts[ucc_contact_id];

          adsl_contact->boc_active = TRUE;
          adsl_contact->ucc_contact_id = ucc_contact_id;

          achl_ic = m_read_hasn1_sint32_be(achl_ic, achl_ie, &adsl_contact->ilc_x_coord);
          if (achl_ic == 0)
            return -1; // Error
          achl_ic = m_read_hasn1_sint32_be(achl_ic, achl_ie, &adsl_contact->ilc_y_coord);
          if (achl_ic == 0)
            return -1; // Error

          adsl_contact->umc_contact_flags = DVC_INPUT_CONTACT_FLAG_DOWN | 
            DVC_INPUT_CONTACT_FLAG_INRANGE | 
            DVC_INPUT_CONTACT_FLAG_INCONTACT; 

          adsl_contact->usc_fields_present_flag = 0;


        }


        adsl_touch_frame->usc_contact_count += ucl_touch_count;
#if DEBUG_TOUCH
      m_aux_printf( &dsl_output_area_1, "m_proc_mouse_keyboard-l%05d-W TOUCH_START: active count: %d contact count:%d, at %d:%d flags:%d",
          __LINE__ ,adsl_touch_frame->usc_active_count,adsl_touch_frame->usc_contact_count,
          adsl_touch_frame->dsrc_touch_contacts[0].ilc_x_coord,adsl_touch_frame->dsrc_touch_contacts[0].ilc_y_coord,adsl_touch_frame->dsrc_touch_contacts[0].umc_contact_flags);
#endif
			*aimp_touch_data_out = m_send_rdpinput_touch_event(adsp_input_ex, &dsl_output_area_1, adsl_touch_frame, adsp_touch_fifo_out);
		 	if (*aimp_touch_data_out <=0) {
				// error occured
				return -1;
			}
        continue;
              }
      case 10: {         /* TOUCH_MOVE: Contains a list of fingers that have moved during this touchmove event. */
        unsigned long long ulll_curr_time; // Get time in milliseconds
        adsp_aux->amc_aux(adsp_aux->vpc_userfld,
          DEF_AUX_GET_T_MSEC,
          &ulll_curr_time, sizeof(unsigned long long));
        ulll_curr_time *= 1000; // convert to microseconds (approximation)
        if (achl_ic + 2 > achl_ie) // Flags (1), TouchCount (1)
          return -1; // Error: Insufficient input

        unsigned char ucl_flags = *(achl_ic++);
        unsigned char ucl_touch_count = *(achl_ic++);
        struct dsd_input_touch_frame *adsl_touch_frame = &adsp_input_ex->dsl_active_touch_frame;

        if (adsp_input_ex->ullc_prev_frame_time == 0) {
          adsl_touch_frame->ullc_frame_offset = 0;
          adsp_input_ex->ullc_prev_frame_time;// = GetTickCount() * 1000;
          adsp_aux->amc_aux(adsp_aux->vpc_userfld,
            DEF_AUX_GET_T_MSEC,
            &adsp_input_ex->ullc_prev_frame_time, sizeof(unsigned long long)); // Get time in milliseconds
          adsp_input_ex->ullc_prev_frame_time *= 1000; // convert to microseconds (approximation)
        } else {
          adsl_touch_frame->ullc_frame_offset = ulll_curr_time - adsp_input_ex->ullc_prev_frame_time;
          adsp_input_ex->ullc_prev_frame_time = ulll_curr_time;
        }

        struct dsd_input_touch_contact *adsl_contact;
        unsigned char ucc_contact_id;

        // Iterate over all the active frame's touches and set them to update
        for (int inl1 = 0; inl1 < DVC_INPUT_MAX_CONTACTS; inl1++) {
          // Check if active, If not, skip.
          if (adsl_touch_frame->dsrc_touch_contacts[inl1].boc_active != TRUE)
            continue;

          adsl_contact = &adsl_touch_frame->dsrc_touch_contacts[inl1];

          adsl_contact->umc_contact_flags = DVC_INPUT_CONTACT_FLAG_UPDATE | 
            DVC_INPUT_CONTACT_FLAG_INRANGE | 
            DVC_INPUT_CONTACT_FLAG_INCONTACT; 
        }

        for (int inl1 = 0; inl1 < ucl_touch_count; inl1++) {

          if (achl_ic + 1 > achl_ie) // ContactId(1)
            return -1; // Error: Insufficient input

          ucc_contact_id = *(achl_ic++);

          // Check if contact id is over max
          if (ucc_contact_id > DVC_INPUT_MAX_CONTACTS)
            return -1;

          adsl_contact = &adsl_touch_frame->dsrc_touch_contacts[ucc_contact_id];

          // Should already be active from touch down
          if (adsl_contact->boc_active == FALSE)
            return -1;

          adsl_contact->ucc_contact_id = ucc_contact_id;
          achl_ic = m_read_hasn1_sint32_be(achl_ic, achl_ie, &adsl_contact->ilc_x_coord);
          if (achl_ic == 0)
            return -1; // Error
          achl_ic = m_read_hasn1_sint32_be(achl_ic, achl_ie, &adsl_contact->ilc_y_coord);
          if (achl_ic == 0)
            return -1; // Error
          adsl_contact->umc_contact_flags = DVC_INPUT_CONTACT_FLAG_UPDATE | 
            DVC_INPUT_CONTACT_FLAG_INRANGE | 
            DVC_INPUT_CONTACT_FLAG_INCONTACT;

          adsl_contact->usc_fields_present_flag = 0;

        }
#if DEBUG_TOUCH
      m_aux_printf( &dsl_output_area_1, "m_proc_mouse_keyboard-l%05d-W TOUCH_MOVE: active count: %d contact count:%d, at %d:%d flags:%d",
          __LINE__ ,adsl_touch_frame->usc_active_count,adsl_touch_frame->usc_contact_count,
          adsl_touch_frame->dsrc_touch_contacts[0].ilc_x_coord,adsl_touch_frame->dsrc_touch_contacts[0].ilc_y_coord,adsl_touch_frame->dsrc_touch_contacts[0].umc_contact_flags);
#endif


        *aimp_touch_data_out = m_send_rdpinput_touch_event(adsp_input_ex, &dsl_output_area_1, adsl_touch_frame, adsp_touch_fifo_out);
		if (*aimp_touch_data_out <=0) {
		   // error occured
		   return -1;
	   	}

        continue;
               }
      case 11: {         /* TOUCH_END: Contains a list of fingers that have just been removed from the touch surface during this touchend event. */
        unsigned long long ulll_curr_time; // Get time in milliseconds
        adsp_aux->amc_aux(adsp_aux->vpc_userfld,
          DEF_AUX_GET_T_MSEC,
          &ulll_curr_time, sizeof(unsigned long long));  
        ulll_curr_time *= 1000; // convert to microseconds (approximation)
        if (achl_ic + 2 > achl_ie) // Flags (1), TouchCount (1)
          return -1; // Error: Insufficient input

        unsigned char ucl_flags = *(achl_ic++);
        unsigned char ucl_touch_count = *(achl_ic++);
        struct dsd_input_touch_frame *adsl_touch_frame = &adsp_input_ex->dsl_active_touch_frame;

        if (adsp_input_ex->ullc_prev_frame_time == 0) {
          adsl_touch_frame->ullc_frame_offset = 0;
          adsp_aux->amc_aux(adsp_aux->vpc_userfld,
            DEF_AUX_GET_T_MSEC,
            &adsp_input_ex->ullc_prev_frame_time, sizeof(unsigned long long)); // Get time in milliseconds
          adsp_input_ex->ullc_prev_frame_time *= 1000; // convert to microseconds (approximation)
        } else {
          adsl_touch_frame->ullc_frame_offset = ulll_curr_time - adsp_input_ex->ullc_prev_frame_time;
          adsp_input_ex->ullc_prev_frame_time = ulll_curr_time;
        }

        struct dsd_input_touch_contact *adsl_contact;
        unsigned char ucc_contact_id;

        // Iterate over all the active frame's touches and set them to update
        for (int inl1 = 0; inl1 < DVC_INPUT_MAX_CONTACTS; inl1++) {
          // Check if active, If not, skip.
          if (adsl_touch_frame->dsrc_touch_contacts[inl1].boc_active != TRUE)
            continue;

          adsl_contact = &adsl_touch_frame->dsrc_touch_contacts[inl1];

          adsl_contact->umc_contact_flags = DVC_INPUT_CONTACT_FLAG_UPDATE | 
            DVC_INPUT_CONTACT_FLAG_INRANGE | 
            DVC_INPUT_CONTACT_FLAG_INCONTACT; 
        }

        for (int inl1 = 0; inl1 < ucl_touch_count; inl1++) {

          if (achl_ic + 1 > achl_ie) // ContactId(1)
            return -1; // Error: Insufficient input

          ucc_contact_id = *(achl_ic++);

          // Check if contact id is over max
          if (ucc_contact_id > DVC_INPUT_MAX_CONTACTS)
            return -1;

          adsl_contact = &adsl_touch_frame->dsrc_touch_contacts[ucc_contact_id];

          // Should already be active from touch down
          if (adsl_contact->boc_active == FALSE)
            return -1;

          adsl_contact->ucc_contact_id = ucc_contact_id;
          achl_ic = m_read_hasn1_sint32_be(achl_ic, achl_ie, &adsl_contact->ilc_x_coord);
          if (achl_ic == 0)
            return -1; // Error
          achl_ic = m_read_hasn1_sint32_be(achl_ic, achl_ie, &adsl_contact->ilc_y_coord);
          if (achl_ic == 0)
            return -1; // Error
          adsl_contact->umc_contact_flags = DVC_INPUT_CONTACT_FLAG_UP;

          adsl_contact->usc_fields_present_flag = 0;

        }
#if DEBUG_TOUCH
      m_aux_printf( &dsl_output_area_1, "m_proc_mouse_keyboard-l%05d-W TOUCH_END:  active count: %d contact count:%d, at %d:%d flags:%d",
          __LINE__ , adsl_touch_frame->usc_active_count,adsl_touch_frame->usc_contact_count,
          adsl_touch_frame->dsrc_touch_contacts[0].ilc_x_coord,adsl_touch_frame->dsrc_touch_contacts[0].ilc_y_coord,adsl_touch_frame->dsrc_touch_contacts[0].umc_contact_flags);
#endif

        *aimp_touch_data_out = m_send_rdpinput_touch_event(adsp_input_ex, &dsl_output_area_1, adsl_touch_frame, adsp_touch_fifo_out);
		if (*aimp_touch_data_out <=0) {
		   // error occured
		   return -1;
	   	}
        adsl_touch_frame->usc_contact_count -= ucl_touch_count;

        continue;
               }    
      case 12: {         /* TOUCH_CANCEL */
        unsigned long long ulll_curr_time; // Get time in milliseconds
        adsp_aux->amc_aux(adsp_aux->vpc_userfld,
          DEF_AUX_GET_T_MSEC,
          &ulll_curr_time, sizeof(unsigned long long));
        ulll_curr_time *= 1000; // convert to microseconds (approximation)
        if (achl_ic + 2 > achl_ie) // Flags (1), TouchCount (1)
          return -1; // Error: Insufficient input

        unsigned char ucl_flags = *(achl_ic++);
        unsigned char ucl_touch_count = *(achl_ic++);
        struct dsd_input_touch_frame *adsl_touch_frame = &adsp_input_ex->dsl_active_touch_frame;

        if (adsp_input_ex->ullc_prev_frame_time == 0) {
          adsl_touch_frame->ullc_frame_offset = 0;
          adsp_aux->amc_aux(adsp_aux->vpc_userfld,
            DEF_AUX_GET_T_MSEC,
            &adsp_input_ex->ullc_prev_frame_time, sizeof(unsigned long long)); // Get time in milliseconds
          adsp_input_ex->ullc_prev_frame_time *= 1000; // convert to microseconds (approximation)
        } else {
          adsl_touch_frame->ullc_frame_offset = ulll_curr_time - adsp_input_ex->ullc_prev_frame_time;
          adsp_input_ex->ullc_prev_frame_time = ulll_curr_time;
        }

        struct dsd_input_touch_contact *adsl_contact;
        unsigned char ucc_contact_id;

        // Iterate over all the active frame's touches and set them to update
        for (int inl1 = 0; inl1 < DVC_INPUT_MAX_CONTACTS; inl1++) {
          // Check if active, If not, skip.
          if (adsl_touch_frame->dsrc_touch_contacts[inl1].boc_active != TRUE)
            continue;

          adsl_contact = &adsl_touch_frame->dsrc_touch_contacts[inl1];

          adsl_contact->umc_contact_flags = DVC_INPUT_CONTACT_FLAG_UPDATE | 
            DVC_INPUT_CONTACT_FLAG_INRANGE | 
            DVC_INPUT_CONTACT_FLAG_INCONTACT; 
        }

        for (int inl1 = 0; inl1 < ucl_touch_count; inl1++) {

          if (achl_ic + 1 > achl_ie) // ContactId(1)
            return -1; // Error: Insufficient input

          ucc_contact_id = *(achl_ic++);

          // Check if contact id is over max
          if (ucc_contact_id > DVC_INPUT_MAX_CONTACTS)
            return -1;

          adsl_contact = &adsl_touch_frame->dsrc_touch_contacts[ucc_contact_id];

          // Should already be active from touch down
          if (adsl_contact->boc_active == FALSE)
            return -1;

          adsl_contact->ucc_contact_id = ucc_contact_id;
          achl_ic = m_read_hasn1_sint32_be(achl_ic, achl_ie, &adsl_contact->ilc_x_coord);
          if (achl_ic == 0)
            return -1; // Error
          achl_ic = m_read_hasn1_sint32_be(achl_ic, achl_ie, &adsl_contact->ilc_y_coord);
          if (achl_ic == 0)
            return -1; // Error

          adsl_contact->umc_contact_flags = DVC_INPUT_CONTACT_FLAG_UP | DVC_INPUT_CONTACT_FLAG_CANCELED;

          adsl_contact->usc_fields_present_flag = 0;
        }


        *aimp_touch_data_out = m_send_rdpinput_touch_event(adsp_input_ex, &dsl_output_area_1, adsl_touch_frame, adsp_touch_fifo_out);
		if (*aimp_touch_data_out <=0) {
		   // error occured
		   return -1;
	   	}
        adsl_touch_frame->usc_contact_count -= ucl_touch_count;
        #if DEBUG_TOUCH
      m_aux_printf( &dsl_output_area_1, "m_proc_mouse_keyboard-l%05d-W TOUCH_CANCEL:  active count: %d contact count:%d, at %d:%d flags:%d",
          __LINE__ , adsl_touch_frame->usc_active_count,adsl_touch_frame->usc_contact_count,
          adsl_touch_frame->dsrc_touch_contacts[0].ilc_x_coord,adsl_touch_frame->dsrc_touch_contacts[0].ilc_y_coord,adsl_touch_frame->dsrc_touch_contacts[0].umc_contact_flags);
#endif

        continue;
               }  
#endif /* CV_TOUCH_REDIR */
      default:
        return -1;             /* protocol error */
      }
      (*aimp_keyboard_mouse)++;   /* increase counter */
    }
#if SM_USE_SEND_EVENTS
	 return adsp_keyboard_data->achc_out_cur - achl_out_start;
#else
    return achl_oc - achp_out;
#endif
} /* end m_proc_mouse_keyboard */
