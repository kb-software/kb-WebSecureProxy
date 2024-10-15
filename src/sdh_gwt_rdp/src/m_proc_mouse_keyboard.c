#include <hob-sdh-gwt-rdp-1.h>

#define DISCARD_KEYPRESSED
//#define DEBUG_20131111/**/
/*#define DEBUG_20140130*/

/* helper function: reads a value from a unsigned "HASN1" field to
   unsigned 16-bit little endian and returns pointer to after the
   bytes read in, if no input buffer overflow or numeric overflow
   is detected. Else returns achp_in_end+1. */
/* UUUU it is inefficient to read the keycode with this, because that cannot be so big that a 3rd input byte comes */
char* m_hasn32u_to_le2( char* achp_out, char* achp_in, char* achp_in_end ) {
  if( achp_in >= achp_in_end ) return achp_in_end+1;
  if( (signed char)(*achp_in) < 0 ) {  /* two- or three-byte input */
    if( achp_in+1 >= achp_in_end ) return achp_in_end+1;
    if( (signed char)(*(achp_in+1)) < 0 ) {  /* three-byte input */
      if(    (achp_in+2 > achp_in_end )   /* input buffer ended */
          || ( (signed char)(*(achp_in+2)) < 0 )  /* more input bytes */
          || (*achp_in & 0xFC)             /* number too big */
        ) return achp_in_end+1;
      *achp_out = *(achp_in+2) | (unsigned char)(*(achp_in+1) << 7);
      *(achp_out+1) = ((*(achp_in+1) & 0x7E) >> 1) | (unsigned char)(*achp_in << 6);
      return achp_in+3;
    } else {  /* two-byte input */
      *achp_out = *(achp_in+1) | (unsigned char)(*achp_in << 7);
      *(achp_out+1) = (*(achp_in) & 0x7F) >> 1;
      return achp_in+2;
    }
  } else {    /* one-byte input */
    *achp_out = *achp_in;
    *(achp_out+1) = 0;
    return achp_in+1;
  }
}

/* transforms userinput data
   from the format sent by the HOB-HTML5-client
   given in Mr. Rettners WebTermProtocol.txt
   to the format used within fastpath RDP events
   given in MS-RDPBCGR 2.2.8.1.2.2.*

   @return -1 on error, else count of bytes written to achp_out
*/
int m_proc_mouse_keyboard( char *achp_out, int imp_len_out,
                           int *aimp_keyboard_mouse,
                           char *achp_inp, int imp_len_inp ) {
  char *achl_ic = achp_inp;                /* current input pointer */
  char *achl_ie = achp_inp + imp_len_inp;  /* end of input-buffer */
  char *achl_oc = achp_out;                /* current output pointer */
  char *achl_oe = achp_out + imp_len_out;  /* end of output-buffer */
  char *achl_ie_local;                     /* helper variable */
  unsigned char byrl_keycode[2];
  unsigned int uml_ucode;
  int          iml_wheelmove;

  while (achl_ic < achl_ie) {  /* still data to process present */
    switch (*achl_ic++) {      /* client_command */
      /* although we are using fastpath output format here, the pointerFlags are documented
         with the slowpath variant in 2.2.8.1.1.3.1.1.3  Mouse Event (TS_POINTER_EVENT) */
      case 0:                  /* MOUSE_MOVE */
        if (achl_oc + 7 > achl_oe)
          return -1;  /* output buffer would overflow */
        *(achl_oc++) = 0x20; /* eventHeader: FASTPATH_INPUT_EVENT_MOUSE << 5 */
        *(achl_oc++) = 0; /* pointerFlags LSB */
        *(achl_oc++) = 0x08; /* pointerFlags MSB: PTRFLAGS_MOVE >> 8 */
        /* first input byte DSD_EVENT_FLAGS event_flags is ignored */
        achl_ic = m_hasn32u_to_le2( achl_oc, achl_ic+1, achl_ie );  /* pos_x */ 
        if (achl_ic >= achl_ie) return -1;
        achl_oc += 2;
        achl_ic = m_hasn32u_to_le2( achl_oc, achl_ic, achl_ie );  /* pos_y */ 
        if (achl_ic > achl_ie) return -1;
        achl_oc += 2;
        break;
      case 1:                  /* MOUSE_DOWN */
      case 2:                  /* MOUSE_UP */
        if (achl_oc + 7 > achl_oe)
          return -1;  /* output buffer would overflow */
        *achl_oc = 0x20; /* eventHeader: FASTPATH_INPUT_EVENT_MOUSE << 5 */
        *(achl_oc+1) = 0; /* pointerFlags LSB */
        *(achl_oc+2) = *(achl_ic-1) << 7; /* pointerFlags MSB: if mousedown, PTRFLAGS_DOWN >> 8 */
        /* first input byte DSD_EVENT_FLAGS event_flags is ignored */
        achl_ic = m_hasn32u_to_le2( achl_oc+3, achl_ic+1, achl_ie );  /* pos_x */ 
        if (achl_ic >= achl_ie) return -1;
        achl_ic = m_hasn32u_to_le2( achl_oc+5, achl_ic, achl_ie );  /* pos_y */ 
        if (achl_ic >= achl_ie) return -1;
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
        achl_oc += 7;
        break;
      case 3:                  /* MOUSE_WHEEL */
#ifdef DEBUG_20140130
        printf("\n\n");
#endif
        if (achl_oc + 7 > achl_oe)
          return -1;  /* output buffer would overflow */
        *achl_oc = 0x20; /* eventHeader: FASTPATH_INPUT_EVENT_MOUSE << 5 */
        *(achl_oc+2) = 0x02; /* pointerFlags MSB: PTRFLAGS_WHEEL >> 8 */
        /* first input byte DSD_EVENT_FLAGS event_flags is ignored */
        achl_ic = m_hasn32u_to_le2( achl_oc+3, achl_ic+1, achl_ie );  /* pos_x */ 
        if (achl_ic >= achl_ie) return -1;
        achl_ic = m_hasn32u_to_le2( achl_oc+5, achl_ic, achl_ie );  /* pos_y */ 
        if (achl_ic >= achl_ie) return -1;
        /* read wheel data (parse HASN1_SINT32_BE delta_y), we can store 9 bits in WheelRotationMask and a signbit */
        if( (signed char)(*achl_ic) < 0 ) {  /* two-byte input */
          iml_wheelmove = (*achl_ic & 0x7F) << 6;
          ++achl_ic;
          if (achl_ic >= achl_ie) return -1;
          if( (signed char)(*achl_ic) < 0 ) return -1;  /* numeric overflow */
          iml_wheelmove |= *achl_ic >> 1;
          if (*achl_ic & 1) {  /* negative direction */
            if (iml_wheelmove > 0x1FE) return -1;  /* numeric overflow (UUUU or use max/min?) */
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
            if (iml_wheelmove > 0x1FF) return -1;  /* numeric overflow (UUUU or use max?) */
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
        break;
      case 4:                  /* KEY_DOWN */
      case 5:                  /* KEY_UP */
        if (achl_oc + 2 > achl_oe)
          return -1;  /* output buffer would overflow */
        *achl_oc = *(achl_ic-1) & 0x01;  /* eventHeader: FASTPATH_INPUT_EVENT_SCANCODE << 5 is 0x00. if keyup, add FASTPATH_INPUT_KBDFLAGS_RELEASE << 0 */
        /* first input byte DSD_EVENT_FLAGS event_flags is ignored */
        achl_ic = m_hasn32u_to_le2( byrl_keycode, achl_ic+1, achl_ie );
#ifdef DEBUG_20131111
        printf("m_proc_mouse_keyboard(): keycode 0x%X%02X\n", byrl_keycode[1], byrl_keycode[0]);
#endif
        if (achl_ic > achl_ie) return -1;
        if (byrl_keycode[1]) return -1;  /* keycodes over 255 unknown */
        switch (byrl_keycode[0]) {
#define LKC(INP_SC) *++achl_oc = (unsigned char)INP_SC;  \
                break;
#define EKC(INP_SC) *achl_oc |= 0x02;  /* add FASTPATH_INPUT_KBDFLAGS_EXTENDED << 0 to eventHeader */ \
                LKC(INP_SC); /* (cutting the scancode to 8 bits) */
          case  27: LKC(0x01);  /* [  1] ESC */
          case 112: LKC(0x3b);  /* [ 59] F1 */
          case 113: LKC(0x3c);  /* [ 60] Firefox-& Googlebrowser-code for F2 */
          case 114: LKC(0x3d);  /* [ 61] F3 */
          case 115: LKC(0x3e);  /* [ 62] Firefox-& Googlebrowser-code for F4 */
          case 116: LKC(0x3f);  /* [ 63] Firefox-& Googlebrowser-code for F5 */
          case 117: LKC(0x40);  /* [ 64] F6 */
          case 118: LKC(0x41);  /* [ 65] F7 */
          case 119: LKC(0x42);  /* [ 66] F8 */
          case 120: LKC(0x43);  /* [ 67] probably F9 */
          case 121: LKC(0x44);  /* [ 68] F10 */
          case 122: LKC(0x57);  /* [ 87] F11 */
          case 123: LKC(0x58);  /* [ 88] F12 */

          /*case  54: LKC(0x29);  /* [ 41] ^ / ° */
          case 160: LKC(0x29);  /* [ 41] Firefox-code for ^ / ° */
          /*case 192: LKC(0x29);  /* [ 41]  Safari-code for ^ / ° */
          case 220: LKC(0x29);  /* Googlebrowser-code for ^ / ° */
          case  49: LKC(0x02);  /* [  2] 1 / ! */
          case  50: LKC(0x03);  /* [  3] 2 / " */
          case  51: LKC(0x04);  /* [  4] 3 / § */
          case  52: LKC(0x05);  /* [  5] 4 / $ */
          case  53: LKC(0x06);  /* [  6] 5 / % */
          case  54: LKC(0x07);  /* [  7] 6 / & */
          case  55: LKC(0x08);  /* [  8] 7 / / / { */
          case  56: LKC(0x09);  /* [  9] 8 / ( / [ */
          case  57: LKC(0x0a);  /* [ 10] 9 / ) / ] */
          case  48: LKC(0x0b);  /* [ 11] 0 / = / } */
          /* case : LKC(0x0c);  /* [ 12] &szlig; / ? / \ */
          case  63: LKC(0x0c);  /* [ 12] Firefox-code for &szlig; / ? */
          /*case 189: LKC(0x35);  /* [ 12]  Safari-code for  - / _ / &szlig; / ? */
          case 219: LKC(0x0c);  /* Googlebrowser-code for &szlig; / ? */
          /* case : LKC(0x0d);  /* [ 13] ' / ` */
          /* case 192: LKC(0x0d);  /* [ 13] Firefox-code for ´ / ` */
          /* case 187: LKC(0x1b);  /* [ 13]  Safari-code for + / * / ´ / ` */
          case 221: LKC(0x0d);  /* Googlebrowser-code for ´ / ` */
          case   8: LKC(0x0e);  /* [ 14] DEL */

          case   9: LKC(0x0f);  /* [ 15] TAB */
          case  81: LKC(0x10);  /* [ 16] q / Q / @ */
          case  87: LKC(0x11);  /* [ 17] w */
          case  69: LKC(0x12);  /* [ 18] e / E / U+20AC */
          case  82: LKC(0x13);  /* [ 19] r */
          case  84: LKC(0x14);  /* [ 20] t */
          case  90: LKC(0x15);  /* [ 21] z */
          case  85: LKC(0x16);  /* [ 22] u */
          case  73: LKC(0x17);  /* [ 23] i */
          case  79: LKC(0x18);  /* [ 24] o */
          case  80: LKC(0x19);  /* [ 25] p */
          /* case : LKC(0x1a);  /* [ 26] ü */
          /* case 219: LKC(0x1a);  /* [ 26]   Safari-code for ü */
          case 186: LKC(0x1a);  /* Googlebrowser-code for ü */
          case  61: LKC(0x1b);  /* [ 27] + / * / ~ */
          case 171: LKC(0x1b);  /* [ 27] Firefox-code for + / * */
		  case 187: LKC(0x1b);  /* Googlebrowser-code for + / * */
          /* case : LKC(0x1c);  /* [ 28] Return */
          case  13: LKC(0x1c);  /* Firefox-& Googlebrowser-code for Return */

          case  20: LKC(0x3a);  /* [ 58] capslock */
          case  65: LKC(0x1e);  /* [ 30] a */
          case  83: LKC(0x1f);  /* [ 31] s */
          case  68: LKC(0x20);  /* [ 32] d */
          case  70: LKC(0x21);  /* [ 33] f */
          case  71: LKC(0x22);  /* [ 34] g */
          case  72: LKC(0x23);  /* [ 35] h */
          case  74: LKC(0x24);  /* [ 36] j */
          case  75: LKC(0x25);  /* [ 37] k */
          case  76: LKC(0x26);  /* [ 38] l */
          /* case : LKC(0x27);  /* [ 39] ö */
          /* case 186: LKC(0x27);  /* [ 39]   Safari-code for ö */
          case 192: LKC(0x27);  /* Googlebrowser-code for ö */
          /* case : LKC(0x28);  /* [ 40] ä */
          case 222: LKC(0x28);  /* Googlebrowser-code for ä */
          /* case  51: LKC(0x2b);  /* [ 43] # / ' */
          case 163: LKC(0x2b);  /* [ 43] Firefox-code for # / ' */
          /* case 220: LKC(0x2b);  /* [ 43]  Safari-code for # / ' */
          case 191: LKC(0x2b);  /* Googlebrowser-code for # / ' */

          case  16: LKC(0x2a);  /* [ 42] left_Shift */
          /*case 188: LKC(0x56);  /* [ 86] < / > / | */
          /*case 188: LKC(0x56);  /* [ 86] Safari-code for , / ; / < / > */
          case  60: LKC(0x56);  /* [ 86] Firefox-code for < / > */
          case 226: LKC(0x56);  /* Googlebrowser-code for < / > */
          case  89: LKC(0x2c);  /* [ 44] y */
          case  88: LKC(0x2d);  /* [ 45] x */
          case  67: LKC(0x2e);  /* [ 46] c */
          case  86: LKC(0x2f);  /* [ 47] v */
          case  66: LKC(0x30);  /* [ 48] b */
          case  78: LKC(0x31);  /* [ 49] n */
          case  77: LKC(0x32);  /* [ 50] m */
          case 188: LKC(0x33);  /* [ 51] , / ; */
          case 190: LKC(0x34);  /* [ 52] . / : */
          /*case 109: LKC(0x35);  /* [ 53] - / _ */
          case 173: LKC(0x35);  /* [ 53] Firefox-code for - / _ */
          case 189: LKC(0x35);  /* Googlebrowser-code for - / _ */
          /*case 16: LKC(0x36);  /* [ 54] right_Shift */

          case  17: LKC(0x1d);  /* [ 29] left_Control */
          /* case : EKC(0x5b);  /* [125] left_Windows */
          case  18: LKC(0x38);  /* [ 56] Alt */
          case  32: LKC(0x39);  /* [ 57] " " */
          /* case : EKC(0x38);  /* [100] AltGr UUUU seems to make a Ctrl and a Alt */
          /* case : EKC(0x5c);  /* [126] right_Windows */
          case  91: EKC(0x5c);  /* Windowskey on MS-screenkbd, left propellerkey in Safari */
          case  93: EKC(0x5d);  /* [127] Windows95menu, right propellerkey in Safari */
          /* case  17: EKC(0x1d);  /* [ 97] right_Control */

          case  44: EKC(0x37);  /* UUUU seems to make two events: 0xE0 0x2A 0xE0 0x37 (at keyup set bit7 in both non-0xE0 bytes) */  /* [ 99] Print_Screen/SysRQ */
          case 145: LKC(0x46);  /* [ 70] Scroll_Lock */
          case  19: EKC(0x45);  /* UUUU seems to make two events, one of them even "more" extended than usual: 0xE1 0x1D 0x45 (at keyup set bit7 in middle and last byte) */  /* [119] Break */

          case  45: EKC(0x52);  /* [110] Einfg */
          case  46: EKC(0x53);  /* [111] Entf */
          case  36: EKC(0x47);  /* [102] Pos1 */
          case  35: EKC(0x4f);  /* [107] Ende */
          case  33: EKC(0x49);  /* [104] PgUp */
          case  34: EKC(0x51);  /* [109] PgDn */

          case  38: EKC(0x48);  /* [103] arrow_up */
          case  37: EKC(0x4b);  /* [105] arrow_left */
          case  40: EKC(0x50);  /* [108] arrow_down */
          case  39: EKC(0x4d);  /* [106] arrow_right */

          case 144: LKC(0x45); /* [ 69] Num_Lock */
          case 111: EKC(0x35); /* [ 98] KP_/ */
          case 106: LKC(0x37); /* [ 55] KP_* */

          case 103: LKC(0x47); /* [ 71] KP_7 */
          case 104: LKC(0x48); /* [ 72] KP_8 */
          case 105: LKC(0x49); /* [ 73] KP_9 */
          case 109: LKC(0x4a); /* [ 74] KP_- */

          case 100: LKC(0x4b); /* [ 75] KP_4 */
          case 101: LKC(0x4c); /* [ 76] KP_5 */
          case 102: LKC(0x4d); /* [ 77] KP_6 */
          case 107: LKC(0x4e); /* [ 78] KP_+ */

          case  97: LKC(0x4f); /* [ 79] KP_1 */
          case  98: LKC(0x50); /* [ 80] KP_2 */
          case  99: LKC(0x51); /* [ 81] KP_3 */
          /* case :_EKC(0x1c); /* [ 96] KP_Enter */

          case  96: LKC(0x52); /* [ 82] KP_0 */
          case 108: LKC(0x53); /* [ 83] KP_, */
          case 110: LKC(0x53); /* [ 83] Firefox-code for KP_,, UUUU seems to make more */
#undef EKC
#undef LKC
          default:
            return -1;  /* UUUU what to do? */
        }
        /* UUU some special keys (SysRq and Break) will need two output events (do not forget &aimp_keyboard_mouse ++; */
        achl_oc ++;
        break;
      case 6:                  /* KEY_PRESSED */
#ifndef DISCARD_KEYPRESSED
        if (achl_oc + 3 > achl_oe)
          return -1;  /* output buffer would overflow */
        *achl_oc = 0x80; /* eventHeader: FASTPATH_INPUT_EVENT_UNICODE << 5  */
        /* UUUU when should we set 0x1, FASTPATH_INPUT_KBDFLAGS_RELEASE << 0? Do we need this event anyway? */
#endif
        /* first byte DSD_EVENT_FLAGS event_flags is ignored */
        /* keycode parsed for length, but ignored */
        achl_ic = m_hasn32u_to_le2( byrl_keycode, achl_ic+1, achl_ie );
        if (achl_ic >= achl_ie) return -1;
        /* parse unicode, up to 5 bytes input */
        achl_ie_local = (achl_ic+5 < achl_ie) ? achl_ic+5 : achl_ie;
        uml_ucode = 0;
        while (achl_ic < achl_ie_local) {  /* parse "HASN1" with value possibly bigger than 16 bit */
          if( (signed char)(*achl_ic) >= 0 ) break;
          uml_ucode |= (*achl_ic & 0x7F);
          uml_ucode <<= 7;
          ++achl_ic;
          if (achl_ic >= achl_ie_local) return -1;
        }
        uml_ucode |= *(achl_ic++);  /* the last byte (that which has Bit 7 unset) */
#ifndef DISCARD_KEYPRESSED
        if (uml_ucode > 0xFFFF)  /* UUUU but we have only 2 byte for output. What to do? Are Surrogate-4byte-sequences allowed? */
          return -1;
        *++achl_oc = (unsigned char)uml_ucode;
        *++achl_oc = uml_ucode >> 8;
        break;
#else
        continue;  /* skip counting, go up looking for next event */
#endif
	  case 7: {
	    char byrl_unicode[2];
		achl_ic = m_hasn32u_to_le2( byrl_unicode, achl_ic, achl_ie );
        if (achl_ic > achl_ie)
			return -1;
		if (achl_oc + 3 > achl_oe)
          return -1;  /* output buffer would overflow */
        *achl_oc++ = 0x04 << 5;  /* eventHeader: FASTPATH_INPUT_EVENT_SCANCODE << 5 is 0x00. if keyup, add FASTPATH_INPUT_KBDFLAGS_RELEASE << 0 */
        *achl_oc++ = byrl_unicode[0];
        *achl_oc++ = byrl_unicode[1];
		break;
	  }

/* FOCUS_EVENT */
	  case 8: {
#define LKC(INP_SC) *achl_oc = 0x01;\
			    *++achl_oc = (unsigned char)INP_SC;\
				achl_oc++;

		achl_ic++;
		LKC(0x38);  /* On focus lost, sent Alt KEY_UP event to untoggle*/
		LKC(0x1d);  /* On focus lost, sent Ctrl KEY_UP event to untoggle*/
		LKC(0x2a);  /* On focus lost, sent Shift KEY_UP event to untoggle*/
		(*aimp_keyboard_mouse)+= 2;
		
#undef LKC
		break;
	  }

      default:
        return -1;             /* protocol error */
    }
    (*aimp_keyboard_mouse)++;   /* increase counter */
  }
  
  return achl_oc - achp_out;
} /* end m_proc_mouse_keyboard */

