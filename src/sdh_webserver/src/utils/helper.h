#ifndef __HELPER_H
#define __HELPER_H

#if defined WIN32 || defined WIN64
#include <windows.h>
#include <tchar.h>
#else
#include <sys/types.h>
#include <errno.h>
#include <hob-unix01.h>
#endif

#include <types_defines.h>

#ifndef HL_WCHAR
#define HL_WCHAR unsigned short int
#endif

#if !defined WIN32 && !defined WIN64
#define LPBYTE char*
#endif

//#define SEPARATE_IN_OUT



//----------------------------------------------------------------------
// BASE 64 Encoder-Table (00h-3Fh)
//----------------------------------------------------------------------
   static const BYTE BET[] =
   {
//           0            1            2            3
     (BYTE) 0x41, (BYTE) 0x42, (BYTE) 0x43, (BYTE) 0x44,  // 00h-03h
//          'A'          'B'          'C'          'D'
//
//           4            5            6            7
     (BYTE) 0x45, (BYTE) 0x46, (BYTE) 0x47, (BYTE) 0x48,  // 04h-07h
//          'E'          'F'          'G'          'H'
//
//           8            9            A            B
     (BYTE) 0x49, (BYTE) 0x4A, (BYTE) 0x4B, (BYTE) 0x4C,  // 08h-0Bh
//          'I'          'J'          'K'          'L'
//
//           C            D            E            F
     (BYTE) 0x4D, (BYTE) 0x4E, (BYTE) 0x4F, (BYTE) 0x50,  // 0Ch-0Fh
//          'M'          'N'          'O'          'P'
//
//           0            1            2            3
     (BYTE) 0x51, (BYTE) 0x52, (BYTE) 0x53, (BYTE) 0x54,  // 10h-13h
//          'Q'          'R'          'S'          'T'
//
//           4            5            6            7
     (BYTE) 0x55, (BYTE) 0x56, (BYTE) 0x57, (BYTE) 0x58,  // 14h-17h
//          'U'          'V'          'W'          'X'
//
//           8            9            A            B
     (BYTE) 0x59, (BYTE) 0x5A, (BYTE) 0x61, (BYTE) 0x62,  // 18h-1Bh
//          'Y'          'Z'          'a'          'b'
//
//           C            D            E            F
     (BYTE) 0x63, (BYTE) 0x64, (BYTE) 0x65, (BYTE) 0x66,  // 1Ch-1Fh
//          'c'          'd'          'e'          'f'
//
//           0            1            2            3
     (BYTE) 0x67, (BYTE) 0x68, (BYTE) 0x69, (BYTE) 0x6A,  // 20h-23h
//          'g'          'h'          'i'          'j'
//
//           4            5            6            7
     (BYTE) 0x6B, (BYTE) 0x6C, (BYTE) 0x6D, (BYTE) 0x6E,  // 24h-27h
//          'k'          'l'          'm'          'n'
//
//           8            9            A            B
     (BYTE) 0x6F, (BYTE) 0x70, (BYTE) 0x71, (BYTE) 0x72,  // 28h-2Bh
//          'o'          'p'          'q'          'r'
//
//           C            D            E            F
     (BYTE) 0x73, (BYTE) 0x74, (BYTE) 0x75, (BYTE) 0x76,  // 2Ch-2Fh
//          's'          't'          'u'          'v'
//
//           0            1            2            3
     (BYTE) 0x77, (BYTE) 0x78, (BYTE) 0x79, (BYTE) 0x7A,  // 30h-33h
//          'w'          'x'          'y'          'z'
//
//           4            5            6            7
     (BYTE) 0x30, (BYTE) 0x31, (BYTE) 0x32, (BYTE) 0x33,  // 34h-37h
//          '0'          '1'          '2'          '3'
//
//           8            9            A            B
     (BYTE) 0x34, (BYTE) 0x35, (BYTE) 0x36, (BYTE) 0x37,  // 38h-3Bh
//          '4'          '5'          '6'          '7'
//
//           C            D            E            F
     (BYTE) 0x38, (BYTE) 0x39, (BYTE) 0x2B, (BYTE) 0x2F,  // 3Ch-3Fh
//          '8'          '9'           +            /
   };


//----------------------------------------------------------------------
// BASE 64 Decoder-Table (20h-7Fh),
// Invalid Codes = 0FFh, Padding-Code = 0FEh
//----------------------------------------------------------------------
   static const BYTE BDT[] = 
   {
//           0            1            2            3
     (BYTE) 0xFF, (BYTE) 0xFF, (BYTE) 0xFF, (BYTE) 0xFF,  // 20h-23h
//          SPC           !            "            #
//
//           4            5            6            7
     (BYTE) 0xFF, (BYTE) 0xFF, (BYTE) 0xFF, (BYTE) 0xFF,  // 24h-27h
//           $            %            &            '
//
//           8            9            A            B
     (BYTE) 0xFF, (BYTE) 0xFF, (BYTE) 0xFF, (BYTE) 0x3E,  // 28h-2Bh
//           (            )            *            +
//
//           C            D            E            F
     (BYTE) 0xFF, (BYTE) 0xFF, (BYTE) 0xFF, (BYTE) 0x3F,  // 2Ch-2Fh
//           ,            -            .            /
//
//           0            1            2            3
     (BYTE) 0x34, (BYTE) 0x35, (BYTE) 0x36, (BYTE) 0x37,  // 30h-33h
//          '0'          '1'          '2'          '3'
//
//           4            5            6            7
     (BYTE) 0x38, (BYTE) 0x39, (BYTE) 0x3A, (BYTE) 0x3B,  // 34h-37h
//          '4'          '5'          '6'          '7'
//
//           8            9            A            B
     (BYTE) 0x3C, (BYTE) 0x3D, (BYTE) 0xFF, (BYTE) 0xFF,  // 38h-3Bh
//          '8'          '9'           :            ; 
//
//           C            D            E            F
     (BYTE) 0xFF, (BYTE) 0xFE, (BYTE) 0xFF, (BYTE) 0xFF,  // 3Ch-3Fh
//           <            =            >            ?
//
//           0            1            2            3
     (BYTE) 0xFF, (BYTE) 0x00, (BYTE) 0x01, (BYTE) 0x02,  // 40h-43h
//           @           'A'          'B'          'C'
//
//           4            5            6            7
     (BYTE) 0x03, (BYTE) 0x04, (BYTE) 0x05, (BYTE) 0x06,  // 44h-47h
//          'D'          'E'          'F'          'G'
//
//           8            9            A            B
     (BYTE) 0x07, (BYTE) 0x08, (BYTE) 0x09, (BYTE) 0x0A,  // 48h-4Bh
//          'H'          'I'          'J'          'K'
//
//           C            D            E            F
     (BYTE) 0x0B, (BYTE) 0x0C, (BYTE) 0x0D, (BYTE) 0x0E,  // 4Ch-4Fh
//          'L'          'M'          'N'          'O'
//
//           0            1            2            3
     (BYTE) 0x0F, (BYTE) 0x10, (BYTE) 0x11, (BYTE) 0x12,  // 50h-53h
//          'P'          'Q'          'R'          'S'
//
//           4            5            6            7
     (BYTE) 0x13, (BYTE) 0x14, (BYTE) 0x15, (BYTE) 0x16,  // 54h-57h
//          'T'          'U'          'V'          'W'
//
//           8            9            A            B
     (BYTE) 0x17, (BYTE) 0x18, (BYTE) 0x19, (BYTE) 0xFF,  // 58h-5Bh
//          'X'          'Y'          'Z'           [
//
//           C            D            E            F
     (BYTE) 0xFF, (BYTE) 0xFF, (BYTE) 0xFF, (BYTE) 0xFF,  // 5Ch-5Fh
//           \            ]            ^            _
//
//           0            1            2            3
     (BYTE) 0xFF, (BYTE) 0x1A, (BYTE) 0x1B, (BYTE) 0x1C,  // 60h-63h
//           `           'a'          'b'          'c'
//
//           4            5            6            7
     (BYTE) 0x1D, (BYTE) 0x1E, (BYTE) 0x1F, (BYTE) 0x20,  // 64h-67h
//          'd'          'e'          'f'          'g'
//
//           8            9            A            B
     (BYTE) 0x21, (BYTE) 0x22, (BYTE) 0x23, (BYTE) 0x24,  // 68h-6Bh
//          'h'          'i'          'j'          'k'
//
//           C            D            E            F
     (BYTE) 0x25, (BYTE) 0x26, (BYTE) 0x27, (BYTE) 0x28,  // 6Ch-6Fh
//          'l'          'm'          'n'          'o'
//
//           0            1            2            3
     (BYTE) 0x29, (BYTE) 0x2A, (BYTE) 0x2B, (BYTE) 0x2C,  // 70h-73h
//          'p'          'q'          'r'          's'
//
//           4            5            6            7
     (BYTE) 0x2D, (BYTE) 0x2E, (BYTE) 0x2F, (BYTE) 0x30,  // 74h-77h
//          't'          'u'          'v'          'w'
//
//           8            9            A            B
     (BYTE) 0x31, (BYTE) 0x32, (BYTE) 0x33, (BYTE) 0xFF,  // 78h-7Bh
//          'x'          'y'          'z'           {
//
//           C            D            E            F
     (BYTE) 0xFF, (BYTE) 0xFF, (BYTE) 0xFF, (BYTE) 0xFF  // 7Ch-7Fh
//           |            }            ~           DEL
   };

class ds_session; //forward-definition!!

/*! \brief Helper class
 *
 * @ingroup webserver
 *
 * several helper methods
*/
class helper
{
public:
    helper(void);
    ~helper(void);

    // // setup the struct dsd_hl_clib_1, by which this class communicates with WSP
    void m_init( ds_session* adsl_session );

    static unsigned int ConHTBa(const BYTE pbySrcBuf[], int nSrcLen,int nDstAllocLen, PBYTE pbyDstBuf, PINT pnDstLen);
    int m_mac_to_bytes(char *s, char* ach_dest, int in_len_dest);
    char m_2char_to_bytes(char *s);

    int m_tokenize(const dsd_const_string& ahstr_source, const dsd_const_string& rdsp_sep, ds_hvector_btype<dsd_const_string>* ads_v_tokens,
                   bool bo_trim_tokens, bool bo_find_only_first_sep, bool bo_delimeter_must_exist);

    bool AUrps1(const char* pchPwInput, const char* pchUserNm, int nDstAllocLen, char* pchOutput, PINT pnDstLen); // JF 26.03.09
	 static void m_to_lowercase_hex_string(const void* avop_src, int nSrcLen, void* avop_dst);
	 static void m_to_uppercase_hex_string(const void* avop_src, int nSrcLen, void* avop_dst);
private:
    ds_session* ads_session;

    int  ConBTHe(BYTE pbySrcBuf[], int nSrcLen, int nDstAllocLen, PBYTE pbyDstBuf, PINT pnDstLen);
    void m_dump_plain_text(const BYTE* lpData, int nLen, FILE* fTrace);
    unsigned int glUsHa32(const char pchUInput[]); // JF 26.03.09
    unsigned int dlhsHa32(LPCSTR pchInput, int nLen); // JF 26.03.09
    ////BOOL AUrps2(PTCHAR pchPwInput, PTCHAR pchUserNm, int nDstAllocLen, PTCHAR pchPwOutput, PINT pnDstLen);
};

#endif
