#include <types_defines.h>
#include <sys/timeb.h>
#include <time.h>
#include <sstream>
#include <rdvpn_globals.h>

#include "../ds_session.h"

// order is important; why ????
#ifdef HL_UNIX
    #include <stdarg.h>
    #ifndef HOB_XSLUNIC1_H
        #define HOB_XSLUNIC1_H
        #include <hob-xslunic1.h>
    #endif // HOB_XSLUNIC1_H
    #include "helper.h"
    #include "../sdh_web_server.h"
#else
    #include "../sdh_web_server.h"
    #include "helper.h"
#endif


helper::helper(void)
{
}

helper::~helper(void)
{
}

/*! \brief Class initializer function
 *
 * @ingroup webserver
 *
 * setup the struct dsd_hl_clib_1, by which this class communicates with WSP
*/
void helper::m_init( ds_session* adsl_session )
{
    ads_session = adsl_session;
}



void helper::m_dump_plain_text(const BYTE* lpData, int nLen, FILE* fTrace)
{
    if (fTrace != NULL) {
        fprintf(fTrace, "%.*s\n", nLen, lpData); // JF 15.05.07: printing of lpData will be terminated at the first 0x00 inside lpData !!!
    }
}

/*! \brief Convert Hex to Base64
 *
 * @ingroup webserver
 *
 * Subroutine ConHTBa (ConvertHexToBase64) converts given hex-values 
 * buffer to base64 formatted ASCII lines in destination buffer.
 *
 * Input Parameters:    BYTE    pbySrcBuf[]    Base of Input buffer
 *                      int        nSrcLen        Length of data
 *                      PBYTE    pbyDstBuf      Array for Output Buffer
 *                      int        nDstAllocLen   Length of allocated Output Buffer
 *                      int        pnDstLen[]     Length of relevant data in Output Buffer
 *
 * Returns: true = o.k., false = input erraneous
*/
unsigned int helper::ConHTBa(const BYTE pbySrcBuf[], int nSrcLen,
                     int nDstAllocLen, PBYTE pbyDstBuf, PINT pnDstLen)
{
   int nSrcIndex = 0;
   int nDstIndex = 0;
   int nBufLen;
   BYTE c1,c2;

   if ((pbySrcBuf == NULL) || (nSrcLen <= 0) || (nDstAllocLen <= 0))
      return false;
   if ((pbyDstBuf == NULL) || (pnDstLen == NULL))
      return false;

   // Calculate required destination buffer size
   nBufLen = (((nSrcLen + 2) / 3) * 4);  // bytes after conversion
   if (nDstAllocLen < nBufLen)
      return false;

   // Convert 3 Input bytes (or less) to 4 output bytes
   do
   {
     if (nSrcLen >= 3)  // full triple present
     {
       c1 = pbySrcBuf[nSrcIndex++];  // get 1st byte
       c2 = (BYTE)((c1 & 0x03) << 4);  // save 2 LSB bits at top-2
       pbyDstBuf[nDstIndex++] = BET[(c1 >> 2) & 0x3F];  // convert 6 Bits
       c1 = pbySrcBuf[nSrcIndex++];  // get 2nd byte
       c2 |= (BYTE)((c1 >> 4) & 0x0F);  // extract top 4 bits
       pbyDstBuf[nDstIndex++] = BET[c2];  // convert 6 Bits
       c2 = (BYTE)((c1 & 0x0F) << 2);  // save 4 bits at top-2
       c1 = pbySrcBuf[nSrcIndex++];  // get 3rd byte
       c2 |= (BYTE)((c1 >> 6) & 0x03);  // extract top 2 bits
       pbyDstBuf[nDstIndex++] = BET[c2];  // convert 6 bits
       pbyDstBuf[nDstIndex++] = BET[c1 & 0x3F];  // convert remaining bits
       nSrcLen -= 3;
     }
     else  // end of data, remaining bytes
     {
       c1 = pbySrcBuf[nSrcIndex++];  // get 1st byte
       c2 = (BYTE)((c1 & 0x03) << 4);  // save 2 LSB bits at top-2
       pbyDstBuf[nDstIndex++] = BET[(c1 >> 2) & 0x3F];  // convert 6 bits
       nSrcLen--;
       if (nSrcLen == 0)  // data exhausted
       {
         pbyDstBuf[nDstIndex++] = BET[c2];  // convert 2 + 4 padding bits
         pbyDstBuf[nDstIndex++] = 0x3D;  // append padding character
         pbyDstBuf[nDstIndex++] = 0x3D;  // append padding character
       }
       else
       {
         c1 = pbySrcBuf[nSrcIndex++];  // get 2nd byte
         c2 |= (BYTE)((c1 >> 4) & 0x0F);  // extract top 4 bits
         pbyDstBuf[nDstIndex++] = BET[c2];  // convert 6 Bits
         c2 = (BYTE)((c1 & 0x0F) << 2);  // save 4 bits at top-2
         pbyDstBuf[nDstIndex++] = BET[c2];  // convert 4 + 2 padding bits
         pbyDstBuf[nDstIndex++] = 0x3D;  // append padding character
         nSrcLen--;
       }
     }
   }
   while (nSrcLen != 0);

   // Set return length value, report true destination length
   pnDstLen[0] = nDstIndex;
   return true;
}


//===================================================================
// Subroutine ConBTHe (ConvertBase64ToHex) converts input data
// in B64 format to hex data.
//
// Input Parameters:    BYTE  pbySrcBuf[]    Base of Input buffer
//                      int   nSrcLen        Length of data
//                      PBYTE pbyDstBuf      Array for Output Buffer
//                      int   nDstAllocLen   Length of allocated Output Buffer
//                      int   pnDstLen[]     Length of relevant data in Output Buffer
//
// Returns: int Status    > 0 : o.k. (=^= pnDstLen[0])
//                      == 0 : no input
//                      == -912 : input erraneous
//                      == -913 : wrong input length
//                      == -914 : invalid characters
//                      == -915 : wrong trailing characters
//                      == -916 : allocated buffer too short
//===================================================================
int helper::ConBTHe(BYTE pbySrcBuf[], int nSrcLen,
                    int nDstAllocLen, PBYTE pbyDstBuf,
                    PINT pnDstLen)
{
   BYTE c1;  // NOTE: M U S T be of type BYTE !!
   BYTE c2;
   int nSrcOffset = 0;
   int nDstIndex = 0;
   int nActByteIdx;
   BYTE pbyActBuf[4];

   // check for valid length (must be multiple of 4)
   if ((pbySrcBuf == NULL) || (nSrcLen <= 0) || (nDstAllocLen <= 0))
     return 0;
   if ((pbyDstBuf == NULL) || (pnDstLen == NULL))
      return (-912);
   if ((nSrcLen & 0x03) != 0)
      return (-913);

   // Calculate required destination buffer size
   nActByteIdx = (((nSrcLen + 7) / 4) * 3);  // bytes after conversion + reserved space
   if (nDstAllocLen < nActByteIdx)
      return (-916);

   // Process all data quads
   nActByteIdx = 0;
   do
   {
     c1 = pbySrcBuf[nSrcOffset++];  // get source character
     if ((c1 < 0x20) || (c1 > 0x7F))  // check if basically valid
        c1 = (BYTE)0xFF;  // set invalid
     else
        c1 = BDT[c1 - 0x20];  // convert, check
     nSrcLen--;
     // check for Invalid Base64 Characters
     if (c1 == (BYTE)0xFF)  // invalid character
        return (-914);

     // check for Padding Base64 Character ('=')
     if (c1 == (BYTE)0xFE)  // padding character
     {
       if ((nSrcLen > 1) ||  // (1) must be in last 2 chars
           ((nSrcLen == 1) &&  // (2) 2 Characters left:
            ((pbySrcBuf[nSrcOffset] != 0x3D) ||  // (2a)  last must be padding 
             ((pbyActBuf[1] & 0x0F) != 0))) ||  // (2b) low 4 bits must be zero
           ((nSrcLen == 0) &&  // (3) 1 Character left: 
            ((pbyActBuf[2] & 0x03) != 0)))  // (3a) low 2 bits must be zero
          return (-915);
       c1 = pbyActBuf[1];  // get 2nd byte (always pres.)
       pbyDstBuf[nDstIndex++] = (BYTE)((pbyActBuf[0] << 2) |  // get 1st byte
                                       (c1 >> 4));  // insert 2 bits from 2nd
       if (nSrcLen == 0)  // 1 byte Padding, 16 Bits out
       {
         c2 = pbyActBuf[2];  // get 3rd byte
         c1 <<= 4;  // get 4 LSB Bits from 2nd
         pbyDstBuf[nDstIndex++] = (BYTE)(c1 | (c2 >> 2));  // insert 4 Bits from 3rd
       }
       break;
     }
     // Standard Base64 Character, buffer, check if Quad present
     pbyActBuf[nActByteIdx++] = c1;  // save byte
     if (nActByteIdx == 4)// Quad present, process !
     {
       c1 = pbyActBuf[1];            // get 2nd byte
       pbyDstBuf[nDstIndex++] = (BYTE)((pbyActBuf[0] << 2) |  // get 1st byte
                                    (c1 >> 4));  // insert 2 bits from 2nd
       c2 = pbyActBuf[2];  // get 3rd byte
       c1 <<= 4;  // get 4 LSB Bits from 2nd
       pbyDstBuf[nDstIndex++] = (BYTE)(c1 | (c2 >> 2));  // insert 4 Bits from 3rd
       c1 = pbyActBuf[3];  // get 4th byte
       pbyDstBuf[nDstIndex++] = (BYTE) (c1 | (c2 << 6));  // insert top 2 bits
       nActByteIdx = 0;  // reset index
     }
   }
   while(nSrcLen != 0);  // for all bytes

   // Set return length value, report true destination length
   pnDstLen[0] = nDstIndex;
   return (nDstIndex);
}

/*! \brief Encrpytion function
 *
 * @ingroup webserver
 *
 * Subroutine AUrps1 (encrypt) encrypts a given character buffer
 * using a second character string for the key generation
 * to base64 formatted ASCII text in destination buffer.
 *
 * Input Parameters:    cchar*  pchPwInput    Base of Input buffer
 *                      cchar*  pchUserNm     Key generation buffer (user name)
 *                      int     nDstAllocLen  Size of allocated buffer
 *                      char*   pchOutput     Pointer to preallocated Output Buffer
 *                      PINT    pnDstLen      Number of valid characters in Output Buffer
 *
 * Minimum length of nDstAllocLen should be (((length of pchPwInput) + 2) << 2)
 *
 * Returns: true = o.k., false = input erraneous
*/
bool helper::AUrps1(const char* pchPwInput, const char* pchUserNm,
                    int nDstAllocLen, char* pchOutput, PINT pnDstLen)
{
   size_t ni, nj;
   int nHa;
   short shCh;
   PBYTE pbyAr;
   BYTE pbyHa[4];

   if ((pchPwInput == NULL) || (pchUserNm == NULL) ||
       (pchOutput == NULL) || (pnDstLen == NULL))
      return false;
   if (nDstAllocLen <= 0)
      return false;
   nj = strlen((LPCSTR)(&pchPwInput[0]));
   ni = strlen((LPCSTR)(&pchUserNm[0]));
   if ((ni <= 0) || (nj <= 0))
      return false;

   size_t in_len_buf = (nj << 1) * sizeof(BYTE);
   // pbyAr = (BYTE *)malloc(in_len_buf);
   pbyAr = (PBYTE)ads_session->ads_wsp_helper->m_cb_get_memory( in_len_buf, false );
   if ( pbyAr == NULL ) {
       return false;
   }

   // convert to byte array by rotating 3 bits
   for (ni = 0; ni < nj; ni++)
   {
     shCh = (short)(((short)pchPwInput[ni]) & 0xFF);
     pbyAr[ni << 1] = (BYTE)(((shCh << 5) & 0xE0) |
                             ((shCh >> 11) & 0x1F));
     pbyAr[(ni << 1) + 1] = (BYTE)(shCh >> 3);
   }
   nHa = glUsHa32((const char *)pchUserNm);  // get the hash from the user name

   for (ni = 0; ni < 4; ni++)
      pbyHa[ni] = (BYTE)((nHa >> (ni << 3)) & 0xFF);
   nj = (nj << 1);
   for (ni = 0; ni < nj; ni++)
      pbyAr[ni] ^= pbyHa[ni & 0x03];  // do the encryption

   pnDstLen[0] = 0;  // do the base64 encoding
   if (ConHTBa(pbyAr, (int)nj, nDstAllocLen, (PBYTE)(&pchOutput[0]), pnDstLen) == FALSE)
   {
       //free((void *)pbyAr);
       ads_session->ads_wsp_helper->m_cb_free_memory( pbyAr );
       return false;
   }
   //free((void *)pbyAr);
    ads_session->ads_wsp_helper->m_cb_free_memory( pbyAr );

   return true;
}


//===================================================================
// Subroutine glUsHa32 generates a hash value from a given input 
// character buffer using an initialization buffer and multiple
// input character replication. The output is a 32-bit hash value.
//
// Input Parameters:    char[]   pchUInput   Base of Input buffer (user name)
//
// Returns: 32-bit integer, 0: if input erraneous
//===================================================================
unsigned int helper::glUsHa32(const char pchUInput[])
{
   int ni, nj, nHa;
   char* pchUserOk = NULL;
   char* pchHaInput;
   const char pchHaDefInp[24] =
                         {'A', 'z', 'B', 'y', 'C', 'x', 'D', 'w',
                          'E', 'v', 'F', 'u', 'G', 't', 'H', 's',
                          'I', 'r', 'J', 'q', 'K', 'p', 'L', 'o'
                         };

   if (pchUInput == NULL)
      return 0;
   if (pchUInput[0] == '\0')
      return 0;

   size_t nLen = strlen((LPCSTR)(&pchUInput[0]));
   //pchUserOk = (char *)malloc(nLen * sizeof(char));
   size_t in_len_buf = nLen * sizeof(char);
   pchUserOk = ads_session->ads_wsp_helper->m_cb_get_memory( in_len_buf, false );
   if ( pchUserOk == NULL ) {
       return 0;
   }

   if (pchUserOk == NULL)
      return 0;

   for (ni = 0, nHa = 0; ni < (int)nLen; ni++)
   {
     if ((pchUInput[ni] > (char)0x20) && (pchUInput[ni] < (char)0x7F))
     {
       pchUserOk[nHa] = (char)tolower((int)pchUInput[ni]);
       nHa++;
     }
   }
   nLen = (sizeof(pchHaDefInp) / sizeof(char));
   //pchHaInput = (char *)malloc((nLen + 1) * sizeof(char));
   size_t in_len_buf_input = (nLen + 1) * sizeof(char);
   pchHaInput = ads_session->ads_wsp_helper->m_cb_get_memory( in_len_buf_input, false );
   if ( pchHaInput == NULL ) {
       return 0;
   }

   if (nHa > 0)
   {
     ni = 0;
     while (ni < (int)nLen)
     {
       nj = 0;
       while ((nj < nHa) && (ni < (int)nLen))
       {
         pchHaInput[ni] = (char)(pchHaDefInp[ni] ^ pchUserOk[nj]);
         if (pchHaInput[ni] == '\0')
            pchHaInput[ni] = pchUserOk[nj];
         ni++;
         nj++;
       }
     }
   }
   else
   {
     for (ni = 0; ni < (int)nLen; ni++)
        pchHaInput[ni] = pchHaDefInp[ni];
   }
   pchHaInput[nLen] = '\0';
   //free((void *)pchUserOk);
   ads_session->ads_wsp_helper->m_cb_free_memory( pchUserOk );
   nHa = dlhsHa32((LPCSTR)(&pchHaInput[0]), (int)nLen);
   //free((void *)pchHaInput);
   ads_session->ads_wsp_helper->m_cb_free_memory( pchHaInput );
   return (nHa);
}


//===================================================================
// Subroutine dlhsHa32 generates a hash value from a given input 
// character buffer using a very short and quite effective algorithm.
// The output is formed by a 32-bit hash value.
//
// Input Parameters:    char[]   pchUInput   Base of Input buffer
//
// Returns: 32-bit integer, 0: if input erraneous
//===================================================================
unsigned int helper::dlhsHa32(LPCSTR pchInput, int nLen)
{
   signed int ns, n1;
   unsigned int n2, r3, v4;
   unsigned int rt = 0;

   if (pchInput == NULL)
      return 0;
   if (*pchInput == '\0')
      return 0;

   n1 = 0;
   n2 = 0x100;
   while (n1 < nLen)
   {
     v4 = (n2 | ((unsigned int)(((int)(*pchInput)) & 0x00FF)));
     pchInput++;
     n2 += 0x100;
     r3 = (((v4 >> 2) ^ v4) & 0x0F);
     rt = ((rt << r3) | (rt >> (32 - r3)));
     rt ^= (v4 * v4);
     n1++;
   }
   ns = (signed int)rt;
   v4 = (((unsigned int)(ns >> 16)) ^ rt);

   return (v4);
}

/*! \brief Mac to Byte converter
 *
 * @ingroup webserver
 *
 * method expects format "00-50-8B-63-3B-38" (separator can be another char!!)
*/
int helper::m_mac_to_bytes(char *s, char* ach_dest, int in_len_dest) {
    for(int i = 0; i < 6; i++) {
        if (i > in_len_dest-1) {
            return -1;
        }
        ach_dest[i] = m_2char_to_bytes(&s[i*2+i]);
    }

    return 0;
}

/*! \brief Char to byte converter
 *
 * @ingroup webserver
*/
char helper::m_2char_to_bytes(char *s) {
    char ch = 0;
    for (int k = 0; k < 2; k++) {
        ch = ch << 4;
        if((s[k] >= '0') && (s[k] <= '9')) {
            ch += s[k] - '0';
        }
        else if ((s[k] >= 'a') && (s[k] <= 'f')) {
            ch += s[k] - 'a' + 10;
        }
        else if ((s[k] >= 'A') && (s[k] <= 'F')) {
            ch += s[k] - 'A' + 10;
        }
        else {
            ch = 0;
        }
    }

    return ch;
}

/*! \brief Split string to tokens
 *
 * @ingroup webserver
 *
 * split a string into tokens, which are returned inside a string[]
*/
int helper::m_tokenize(const dsd_const_string& ahstr_source, const dsd_const_string& rdsp_sep, ds_hvector_btype<dsd_const_string>* ads_v_tokens,
                                       bool bo_trim_tokens, bool bo_find_only_first_sep, bool bo_delimeter_must_exist)
{
    int in_a = 0, in_e = 0;
    dsd_const_string hstr_temp("");

    int in_pos_del = ahstr_source.m_find_first_of(rdsp_sep, in_a);
    if ( (bo_delimeter_must_exist) && (in_pos_del == -1) ) { // no delimeter found!!
        return -1;
    }

    // when the delimeter is the first character -> we must return an empty string at first position !!
    if (in_pos_del == 0) {
        // e.g. problem when splitting for '?' with ?gclid=CKa8qLO71ZECFR5FZwodMxOMZQ/
        ads_v_tokens->m_add("");
        in_a = 1;

        if (bo_find_only_first_sep) {
            dsd_const_string hstr = ahstr_source.m_substring(in_a);
            if (bo_trim_tokens) {
                hstr.m_trim(" ");
            }
            ads_v_tokens->m_add(hstr);
            return ads_v_tokens->m_size();
        }
    }

    while ( (in_a = ahstr_source.m_find_first_not_of(rdsp_sep, in_a)) != -1) {
        in_e = ahstr_source.m_find_first_of(rdsp_sep, in_a);
        if (in_e != -1) {
            hstr_temp = ahstr_source.m_substr(in_a, in_e-in_a);
            if (bo_trim_tokens) {
                hstr_temp.m_trim(" ");
            }
            ads_v_tokens->m_add(hstr_temp);
            in_a = in_e + 1;
            if (bo_find_only_first_sep) { // we shall stop tokenizing, when we found the first delimeter
                hstr_temp = ahstr_source.m_substring(in_a);
                if (bo_trim_tokens) {
                    hstr_temp.m_trim(" ");
                }
                ads_v_tokens->m_add(hstr_temp);
                break;
            }
        }
        else {
            hstr_temp = ahstr_source.m_substring(in_a);
            if (bo_trim_tokens) {
                hstr_temp.m_trim(" ");
            }
            ads_v_tokens->m_add(hstr_temp);
            break;
        }
    }

    return ads_v_tokens->m_size();
}

static const char CHRG_TO_HEX_LC[] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
};

static const char CHRG_TO_HEX_UC[] = {
	'0', '1', '2', '3', '4', '5', '6', '7',
	'8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

static void m_to_hex_string(const void* avop_src, int nSrcLen, void* avop_dst, const char (&rchp_tab)[16]) {
	const unsigned char* aucl_src = (const unsigned char* )avop_src;
	char* achl_dst = (char* )avop_dst;
	for(int a=0; a<nSrcLen; a++) {
		unsigned char ucl_v = aucl_src[a];
		achl_dst[a<<1] = rchp_tab[(ucl_v>>4)&0xf];
		achl_dst[(a<<1)+1] = rchp_tab[ucl_v&0xf];
	}
}

void helper::m_to_lowercase_hex_string(const void* avop_src, int nSrcLen, void* avop_dst)
{
	m_to_hex_string(avop_src, nSrcLen, avop_dst, CHRG_TO_HEX_LC);
}

void helper::m_to_uppercase_hex_string(const void* avop_src, int nSrcLen, void* avop_dst)
{
	m_to_hex_string(avop_src, nSrcLen, avop_dst, CHRG_TO_HEX_UC);
}
