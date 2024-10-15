/*
  file hob-tab-ascii-ansi-1.h
  replaces hltabaw2.h
  variable names changed from gr_850_to_819 to ucrg_tab_850_to_819
  and from gr_819_to_850 to ucrg_tab_819_to_850
  and from EXT_GR_850_TO_819 to HL_EXT_TAB_850_TO_819
  23.01.09 KB
  added tables for conversion to and from codepage 437 ("OEM")
  31.03.11 WS
  added tables for conversion to and from singlebyte-windows-codepages
  added compressed data for making tables for CJK-windows-codepages
  24.04.12 WS
  added tables for conversion to and from ISO-8859-codepages
  28.08.12 WS
  removed all tables except the oldest two (now found in xslunic1.cpp)
  06.08.13 WS
*/
/** @addtogroup unicode
* @{
* @file
* This header contains data for conversion between character encodings.
* They are direct 256-Byte codepoint-to-codepoint lookup-tables.
*
* If more than one file includes it for the same program, define the
* preprocessor symbol HL_EXT_TAB_850_TO_819 (above the include) in
* all except one of them.
* @}
*/
#ifndef HL_EXT_TAB_850_TO_819
/*********************************************************************
***                                                                ***
***                       DOS to ANSI                              ***
***                                                                ***
***                      Conversion table                          ***
***                                                                ***
*********************************************************************/
/** DOS to ANSI Conversion table. Approximately gives ISO-8859-1 codepoints
* when indexed by Codepage-850-codepoints. When a character does not really
* exist in both charsets, there is no invalid content, but some chosen
* replacement. Also some historical special relations are included.
* Bijectivitiy is not fulfilled in the following cases: the values 
* 0x7F, 0x98 and 0xFF appear twice each; 0x1A, 0x92 and 0xA0 appear never.
* From the value gotten with some index X, X can be reconstructed by the
* table ucrg_tab_819_to_850 below, except if X is 0x7F, 0x98 or 0xDA.
*/

unsigned char ucrg_tab_850_to_819[256] = {

/*         0    1    2    3    4    5    6    7     */
         0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,   /*	0	DOS */


/*         8    9    A    B    C    D    E    F     */
         0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,   /*	0       */


/*         0    1    2    3    4    5    6    7     */
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,   /*	1       */


/*         8    9    A    B    C    D    E    F     */
         0x18,0x19,0x1C,0x1B,0x7F,0x1D,0x1E,0x1F,   /*	1       */


/*         0    1    2    3    4    5    6    7     */
         0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,   /*	2		*/


/*         8    9    A    B    C    D    E    F     */
         0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,   /*	2		*/


/*         0    1    2    3    4    5    6    7     */
         0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,   /*	3	DOS */


/*         8    9    A    B    C    D    E    F     */
         0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,   /*	3		*/


/*         0    1    2    3    4    5    6    7     */
         0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,   /*	4		*/


/*         8    9    A    B    C    D    E    F     */
         0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,   /*	4		*/


/*         0    1    2    3    4    5    6    7     */
         0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,   /*	5		*/


/*         8    9    A    B    C    D    E    F     */
         0x58,0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F,   /*	5		*/


/*         0    1    2    3    4    5    6    7     */
         0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,   /*	6	DOS	*/


/*         8    9    A    B    C    D    E    F     */
         0x68,0x69,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F,   /*	6		*/


/*         0    1    2    3    4    5    6    7     */
         0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,   /*	7		*/


/*         8    9    A    B    C    D    E    F     */
         0x78,0x79,0x7A,0x7B,0x7C,0x7D,0x7E,0x7F,   /*	7		*/


/*         0    1    2    3    4    5    6    7     */
         0xC7,0xFC,0xE9,0xE2,0xE4,0xE0,0xE5,0xE7,   /*	8		*/


/*         8    9    A    B    C    D    E    F     */
         0xEA,0xEB,0xE8,0xEF,0xEE,0xEC,0xC4,0xC5,   /*	8		*/


/*         0    1    2    3    4    5    6    7     */
         0xC9,0xE6,0xC6,0xF4,0xF6,0xF2,0xFB,0xF9,   /*	9	DOS	*/


/*         8    9    A    B    C    D    E    F     */
         0xFF,0xD6,0xDC,0xF8,0xA3,0xD8,0xD7,0x9F,   /*	9		*/


/*         0    1    2    3    4    5    6    7     */
         0xE1,0xED,0xF3,0xFA,0xF1,0xD1,0xAA,0xBA,   /*	A		*/


/*         8    9    A    B    C    D    E    F     */
         0xBF,0xAE,0xAC,0xBD,0xBC,0xA1,0xAB,0xBB,   /*	A		*/


/*         0    1    2    3    4    5    6    7     */
         0x9B,0x9C,0x9D,0x90,0x97,0xC1,0xC2,0xC0,   /*	B	 	*/


/*         8    9    A    B    C    D    E    F     */
         0xA9,0x87,0x80,0x83,0x85,0xA2,0xA5,0x93,   /*	B		*/


/*         0    1    2    3    4    5    6    7     */
         0x94,0x99,0x98,0x96,0x91,0x9A,0xE3,0xC3,   /*	C	DOS	*/


/*         8    9    A    B    C    D    E    F     */
         0x84,0x82,0x89,0x88,0x86,0x81,0x8A,0xA4,   /*	C		*/


/*         0    1    2    3    4    5    6    7     */
         0xF0,0xD0,0xCA,0xCB,0xC8,0x9E,0xCD,0xCE,   /*	D		*/


/*         8    9    A    B    C    D    E    F     */
         0xCF,0x95,0x98,0x8D,0x8C,0xA6,0xCC,0x8B,   /*	D		*/


/*         0    1    2    3    4    5    6    7     */
         0xD3,0xDF,0xD4,0xD2,0xF5,0xD5,0xB5,0xFE,   /*	E		*/


/*         8    9    A    B    C    D    E    F     */
         0xDE,0xDA,0xDB,0xD9,0xFD,0xDD,0xAF,0xB4,   /*	E		*/


/*         0    1    2    3    4    5    6    7     */
         0xAD,0xB1,0x8F,0xBE,0xB6,0xA7,0xF7,0xB8,   /*	F	 	*/


/*         8    9    A    B    C    D    E    F     */
         0xB0,0xA8,0xB7,0xB9,0xB3,0xB2,0x8E,0xFF    /*	F		*/

};

/*********************************************************************
***                                                                ***
***                       ANSI to DOS                              ***
***                                                                ***
***                      Conversion table                          ***
***                                                                ***
*********************************************************************/
/** ANSI to DOS Conversion table. Approximately gives Codepage-850-codepoints
* when indexed by ISO-8859-1 codepoints. When a character does not really
* exist in both charsets, there is no invalid content, but some chosen
* replacement. Also some historical special relations are included.
* Bijectivitiy is almost fulfilled, just 0xFF appears twice and 0x98 never.
* From the value gotten with some index X, X can be reconstructed by the
* table ucrg_tab_850_to_819 above, except if X is 0x1A, 0x92 or 0xA0.
*/

unsigned char ucrg_tab_819_to_850[256] = {


/*         0    1    2    3    4    5    6    7     */
         0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,   /*	0	ANSI	*/


/*         8    9    A    B    C    D    E    F     */
         0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,   /*	0			*/


/*         0    1    2    3    4    5    6    7     */
         0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,   /*	1			*/


/*         8    9    A    B    C    D    E    F     */
         0x18,0x19,0x7F,0x1B,0x1A,0x1D,0x1E,0x1F,   /*	1			*/


/*         0    1    2    3    4    5    6    7     */
         0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,   /*	2			*/


/*         8    9    A    B    C    D    E    F     */
         0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F,   /*	2			*/


/*         0    1    2    3    4    5    6    7     */
         0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,   /*	3	ANSI	*/


/*         8    9    A    B    C    D    E    F     */
         0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F,   /*	3			*/


/*         0    1    2    3    4    5    6    7     */
         0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,   /*	4			*/


/*         8    9    A    B    C    D    E    F     */
         0x48,0x49,0x4A,0x4B,0x4C,0x4D,0x4E,0x4F,   /*	4			*/


/*         0    1    2    3    4    5    6    7     */
         0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,   /*	5			*/


/*         8    9    A    B    C    D    E    F     */
         0x58,0x59,0x5A,0x5B,0x5C,0x5D,0x5E,0x5F,   /*	5			*/


/*         0    1    2    3    4    5    6    7     */
         0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,   /*	6	ANSI	*/


/*         8    9    A    B    C    D    E    F     */
         0x68,0x69,0x6A,0x6B,0x6C,0x6D,0x6E,0x6F,   /*	6			*/


/*         0    1    2    3    4    5    6    7     */
         0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,   /*	7			*/


/*         8    9    A    B    C    D    E    F     */
         0x78,0x79,0x7A,0x7B,0x7C,0x7D,0x7E,0x1C,   /*	7			*/


/*         0    1    2    3    4    5    6    7     */
         0xBA,0xCD,0xC9,0xBB,0xC8,0xBC,0xCC,0xB9,   /*	8			*/


/*         8    9    A    B    C    D    E    F     */
         0xCB,0xCA,0xCE,0xDF,0xDC,0xDB,0xFE,0xF2,   /*	8			*/


/*         0    1    2    3    4    5    6    7     */
         0xB3,0xC4,0xDA,0xBF,0xC0,0xD9,0xC3,0xB4,   /*	9	ANSI	*/


/*         8    9    A    B    C    D    E    F     */
         0xC2,0xC1,0xC5,0xB0,0xB1,0xB2,0xD5,0x9F,   /*	9			*/


/*         0    1    2    3    4    5    6    7     */
         0xFF,0xAD,0xBD,0x9C,0xCF,0xBE,0xDD,0xF5,   /*	A			*/


/*         8    9    A    B    C    D    E    F     */
         0xF9,0xB8,0xA6,0xAE,0xAA,0xF0,0xA9,0xEE,   /*	A			*/


/*         0    1    2    3    4    5    6    7     */
         0xF8,0xF1,0xFD,0xFC,0xEF,0xE6,0xF4,0xFA,   /*	B			*/


/*         8    9    A    B    C    D    E    F     */
         0xF7,0xFB,0xA7,0xAF,0xAC,0xAB,0xF3,0xA8,   /*	B			*/


/*         0    1    2    3    4    5    6    7     */
         0xB7,0xB5,0xB6,0xC7,0x8E,0x8F,0x92,0x80,   /*	C	ANSI	*/


/*         8    9    A    B    C    D    E    F     */
         0xD4,0x90,0xD2,0xD3,0xDE,0xD6,0xD7,0xD8,   /*	C			*/


/*         0    1    2    3    4    5    6    7     */
         0xD1,0xA5,0xE3,0xE0,0xE2,0xE5,0x99,0x9E,   /*	D			*/


/*         8    9    A    B    C    D    E    F     */
         0x9D,0xEB,0xE9,0xEA,0x9A,0xED,0xE8,0xE1,   /*	D		 	*/


/*         0    1    2    3    4    5    6    7     */
         0x85,0xA0,0x83,0xC6,0x84,0x86,0x91,0x87,   /*	E			*/


/*         8    9    A    B    C    D    E    F     */
         0x8A,0x82,0x88,0x89,0x8D,0xA1,0x8C,0x8B,   /*	E			*/


/*         0    1    2    3    4    5    6    7     */
         0xD0,0xA4,0x95,0xA2,0x93,0xE4,0x94,0xF6,   /*	F			*/


/*         8    9    A    B    C    D    E    F     */
         0x9B,0x97,0xA3,0x96,0x81,0xEC,0xE7,0xFF    /*	F			*/

};

#else
extern unsigned char ucrg_tab_850_to_819[256];
extern unsigned char ucrg_tab_819_to_850[256];
/* now static within xslunic1.cpp:
extern unsigned char ucrg_tab_850_to_437[256];
extern unsigned char ucrg_tab_437_to_850[256];
extern unsigned short usrg_tab_437_to_uni[256];
extern unsigned short usrg_tab_874_to_uni[256];
extern unsigned short usrg_tab_1250_to_uni[256];
extern unsigned short usrg_tab_1251_to_uni[256];
extern unsigned short usrg_tab_1252_to_uni[256];
extern unsigned short usrg_tab_1253_to_uni[256];
extern unsigned short usrg_tab_1254_to_uni[256];
extern unsigned short usrg_tab_1255_to_uni[256];
extern unsigned short usrg_tab_1256_to_uni[256];
extern unsigned short usrg_tab_1257_to_uni[256];
extern unsigned short usrg_tab_1258_to_uni[256];
extern unsigned short usrg_tab_i02_to_uni[256];
extern unsigned short usrg_tab_i03_to_uni[256];
extern unsigned short usrg_tab_i04_to_uni[256];
extern unsigned short usrg_tab_i05_to_uni[256];
extern unsigned short usrg_tab_i06_to_uni[256];
extern unsigned short usrg_tab_i07_to_uni[256];
extern unsigned short usrg_tab_i08_to_uni[256];
extern unsigned short usrg_tab_i09_to_uni[256];
extern unsigned short usrg_tab_i10_to_uni[256];
extern unsigned short usrg_tab_i11_to_uni[256];
extern unsigned short usrg_tab_i13_to_uni[256];
extern unsigned short usrg_tab_i14_to_uni[256];
extern unsigned short usrg_tab_i15_to_uni[256];
extern unsigned short usrg_tab_i16_to_uni[256];
extern unsigned int unrg_tabindex_uni_to_437[66];
extern unsigned int unrg_tabindex_uni_to_874[18];
extern unsigned int unrg_tabindex_uni_to_1250[34];
extern unsigned int unrg_tabindex_uni_to_1251[18];
extern unsigned int unrg_tabindex_uni_to_1252[34];
extern unsigned int unrg_tabindex_uni_to_1253[18];
extern unsigned int unrg_tabindex_uni_to_1254[34];
extern unsigned int unrg_tabindex_uni_to_1255[34];
extern unsigned int unrg_tabindex_uni_to_1256[34];
extern unsigned int unrg_tabindex_uni_to_1257[34];
extern unsigned int unrg_tabindex_uni_to_1258[34];
extern unsigned int unrg_tabindex_uni_to_i02[18];
extern unsigned int unrg_tabindex_uni_to_i03[18];
extern unsigned int unrg_tabindex_uni_to_i04[18];
extern unsigned int unrg_tabindex_uni_to_i05[8];
extern unsigned int unrg_tabindex_uni_to_i06[12];
extern unsigned int unrg_tabindex_uni_to_i07[12];
extern unsigned int unrg_tabindex_uni_to_i08[12];
extern unsigned int unrg_tabindex_uni_to_i09[12];
extern unsigned int unrg_tabindex_uni_to_i10[18];
extern unsigned int unrg_tabindex_uni_to_i11[12];
extern unsigned int unrg_tabindex_uni_to_i13[18];
extern unsigned int unrg_tabindex_uni_to_i14[24];
extern unsigned int unrg_tabindex_uni_to_i15[12];
extern unsigned int unrg_tabindex_uni_to_i16[24];
extern unsigned char ucrg_tabparts_uni_to_437[280];
extern unsigned char ucrg_tabparts_uni_to_874[99];
extern unsigned char ucrg_tabparts_uni_to_1250[187];
extern unsigned char ucrg_tabparts_uni_to_1251[159];
extern unsigned char ucrg_tabparts_uni_to_1252[124];
extern unsigned char ucrg_tabparts_uni_to_1253[131];
extern unsigned char ucrg_tabparts_uni_to_1254[129];
extern unsigned char ucrg_tabparts_uni_to_1255[165];
extern unsigned char ucrg_tabparts_uni_to_1256[226];
extern unsigned char ucrg_tabparts_uni_to_1257[200];
extern unsigned char ucrg_tabparts_uni_to_1258[149];
extern unsigned char ucrg_tabparts_uni_to_i02[173];
extern unsigned char ucrg_tabparts_uni_to_i03[125];
extern unsigned char ucrg_tabparts_uni_to_i04[186];
extern unsigned char ucrg_tabparts_uni_to_i05[110];
extern unsigned char ucrg_tabparts_uni_to_i06[63];
extern unsigned char ucrg_tabparts_uni_to_i07[115];
extern unsigned char ucrg_tabparts_uni_to_i08[118];
extern unsigned char ucrg_tabparts_uni_to_i09[102];
extern unsigned char ucrg_tabparts_uni_to_i10[169];
extern unsigned char ucrg_tabparts_uni_to_i11[88];
extern unsigned char ucrg_tabparts_uni_to_i13[187];
extern unsigned char ucrg_tabparts_uni_to_i14[141];
extern unsigned char ucrg_tabparts_uni_to_i15[108];
extern unsigned char ucrg_tabparts_uni_to_i16[144];
extern unsigned char ucrg_huff_cp932[181];
extern unsigned char ucrg_holes_cp932[43];
extern unsigned char ucrg_code_cp932[10041];
extern unsigned char ucrg_huff_cp936[218];
extern unsigned char ucrg_holes_cp936[43];
extern unsigned char ucrg_code_cp936[9746];
extern unsigned char ucrg_huff_cp949[211];
extern unsigned char ucrg_holes_cp949[36];
extern unsigned char ucrg_code_cp949[9886];
extern unsigned char ucrg_huff_cp950[67];
extern unsigned char ucrg_holes_cp950[7];
extern unsigned char ucrg_code_cp950[12996];
*/
#endif
