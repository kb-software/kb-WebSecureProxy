#define XH_INTERFACE

//*********************************************************************
//
// The Original (at least Output compatible) MPPC Compressor
//
//*********************************************************************
#if defined JAVA
package hob.mppc;
#endif

#define __MPPC_COMPRESSOR__
//#include "MPPC-BT.h"
//#include "MPPC-BM.h"
#include <basetype.h>
#include <basemacs.h>

#if defined __DEBUG_CHECK__
#include <printf.h>
#endif


#if !defined JAVA
#include <stdio.h>
#ifndef HL_FREEBSD
#include <malloc.h>
#else
#include <stdlib.h>
#endif
#include <memory.h>
#endif

//#include "../hmem/memfunc.h"
#include "memfunc.h"
#include "mppccmp.h"


#if defined JAVA
class mppccmpr {
#endif

//----------------------------------------------------------------
// Include the (Program Generated) Hash Table(s) here
// The Hash Tables are constructed from a Hash Base (0x9CCF93)
// and its multiples from 0 to 255
//
// NOTE:
// Only the first Table (containing all the multiples) is needed,
// the remaining two tables just speed up calculation and can
// easily be derived drom the first table by shifting each element
// left 8 respective 16 Bits (both modulo 2**32)
// --> have been removed !!!
//----------------------------------------------------------------
#include "mppchtab.h"

#if defined JAVA
PRIVATE STATIC BIT32PTR HashTab1 = NULL;

//=================================================================
// Load the Hash Lookup Table from the String Array
//
// Input Parameters:	none
// Returns: int Status: 0 - o.k. else Error occured
//==================================================================
PUBLIC STATIC int MPPC_LoadHashLookupTab()
{
  int SrcIndex = 0;
  int DstIndex = 0;
  int Count = MPPC_HASH_LOOKUP_TABLE_SIZE;
  BIT32 Element;

  if(HashTab1 != NULL)
    return(0);
  //--------------------------------------------------------
  // Allocate the Hash Lookup Table
  //--------------------------------------------------------
  HashTab1 = new int[MPPC_HASH_LOOKUP_TABLE_SIZE];
  if(HashTab1 == NULL)
    return(-1);
  //--------------------------------------------------------
  // Get the Words from the String, combine and put to table
  //--------------------------------------------------------
  do
  {
    Element = ((BIT32) HashTabStr.charAt(SrcIndex) & 0xFFFF) |
              (((BIT32) HashTabStr.charAt(SrcIndex+1) & 0xFFFF) << 16);
    SrcIndex+= 2;
    HashTab1[DstIndex++] = Element;
    Count--;
  }while(Count != 0);
  return(0);
}  
#endif // JAVA

//=================================================================
// Free a dictionary Structure and its Components
//
// Input Parameters:	DICTSTRU_PTR pDictStruc		Structure Pointer
//			BOOL pMemProc(int,void*,int)	Memory Procedure
// Returns: nothing
//==================================================================
PUBLIC STATIC void FAST MPPC_FreeDict(HMEM_CTX_DEF
				      DICTSTRU_PTR pDictStruc)
{
  if(pDictStruc != NULL)
  {
    //----------------------------------------------------
    // Free the Buffers if allocated
    //----------------------------------------------------
#if defined C600 && !defined XH_INTERFACE
    if(DICTSTRU_pDictBuf(pDictStruc) != NULL)
    {
      hfree(DICTSTRU_pDictBuf(pDictStruc));
      DICTSTRU_pDictBuf(pDictStruc) = NULL;
    }
    if(DICTSTRU_pHashTab(pDictStruc) != NULL)
    {
      hfree(DICTSTRU_pHashTab(pDictStruc));
      DICTSTRU_pHashTab(pDictStruc) = NULL;
    }
#else // !defined C600
    FREE_ARRAYEX(HMEM_CTX_REF,DICTSTRU_pDictBuf(pDictStruc));
    FREE_ARRAYEX(HMEM_CTX_REF,DICTSTRU_pHashTab(pDictStruc));
#endif
    //----------------------------------------------------
    // Free the Structure
    //----------------------------------------------------
    FREE_ARRAY(HMEM_CTX_REF,pDictStruc);
  }
}
//=================================================================
// Allocate the MPPC Control Structure, initialize the Elements
//
// Input Parameters:	BIT32 DictSize		Size for Dictionary (in Bytes)
//			BIT32 HashTabSize	Size for Hash Table (in Words),
//						or 0 if no Hashtable used
//						(for DECODER only !!)
//
// Returns: DICTSTRU_PTR pDictStru or NULL in case of an Error
//==================================================================
PUBLIC STATIC DICTSTRU_PTR FAST MPPC_AllocDict(HMEM_CTX_DEF
		BIT32 DictSize, BIT32 HashTabSize)
{
  DICTSTRU_PTR pDictStruc = NULL;

#if !defined JAVA && defined C600 && !defined XH_INTERFACE
  BIT8  _huge * pDictBuf = NULL;
  BIT16 _huge * pHashTab = NULL;
#else
  BIT8PTR pDictBuf  = NULL;
  BIT16PTR pHashTab = NULL;
#endif

  //----------------------------------------------------
  // Allocate the buffers
  //----------------------------------------------------
#if defined C600 && !defined XH_INTERFACE
  if((pDictBuf = halloc(DictSize,1)) == NULL)
    return(NULL);
  if(HashTabSize != 0)
  {
    if((pHashTab = halloc(HashTabSize,2)) == NULL)
    {
      hfree(pDictBuf);
      return(NULL);
    }
  }
#else // not C600
  if((pDictBuf = BIT8_ARRAY_ALLOCEX(HMEM_CTX_REF,DictSize)) == NULL)
    return(NULL);

  if(HashTabSize != 0)
  {
    if((pHashTab = BIT16_ARRAY_ALLOCEX(HMEM_CTX_REF,HashTabSize)) == NULL)
    {
      FREE_ARRAYEX(HMEM_CTX_REF,pDictBuf);
      return(NULL);
    }
  }
#endif // C600
  //----------------------------------------------------
  // Allocate the Dictionary Structure
  //----------------------------------------------------
#if !defined JAVA
  pDictStruc = (DICTSTRU_PTR)
    ((void *) BIT8_ARRAY_ALLOC(HMEM_CTX_REF,sizeof(DICTSTRU)));
#else
  pDictStruc = new DICTSTRU();
#endif
  if(pDictStruc == NULL)
  {
#if defined C600 && !defined XH_INTERFACE
    hfree(pDictBuf);
    if(pHashTab != NULL)
      hfree(pHashTab);
#else // not C600
    FREE_ARRAYEX(HMEM_CTX_REF,pDictBuf);
    FREE_ARRAYEX(HMEM_CTX_REF,pHashTab);
#endif // C600
    return(NULL);
  }
  //----------------------------------------------------
  // Initialize the Dictionary Structure
  //----------------------------------------------------
  DICTSTRU_pDictBuf(pDictStruc)		= pDictBuf;
  DICTSTRU_pHashTab(pDictStruc)		= pHashTab;
  DICTSTRU_MaxDictIndex(pDictStruc)	= 0;
  DICTSTRU_CurrDictIndex(pDictStruc)	= 0;
  DICTSTRU_DictSize(pDictStruc)		= DictSize;
  DICTSTRU_HashTabSize(pDictStruc)	= HashTabSize;
  DICTSTRU_FlagsSave(pDictStruc)	= 0;
  return(pDictStruc);
}
//=================================================================
// Initialze/Reinitialize MPPC Structure/Buffers
//
// Input Parameters:	DICTSTRU_PTR pDictStruc
//			int	     MaxDictIndClearFlag 0 - dont clear
//			int	     CurrDictIndSetMode	 0 - set Zero,
//							   else set Top+1
// Returns: Nothing
//==================================================================
PUBLIC STATIC void FAST MPPC_DictStrucInit(DICTSTRU_PTR pDictStruc,
					   int MaxDictIndClearFlag,
					   int CurrDictIndSetMode)
{
  BIT32 Index;
  BIT8PTR  pDictBuf;
  BIT16PTR pHashTab;

  if(pDictStruc == NULL)
    return;
  //------------------------------------------------------
  // Clear Dictionary if allocated
  //------------------------------------------------------
  if((pDictBuf = DICTSTRU_pDictBuf(pDictStruc)) != NULL)
  {
    Index = DICTSTRU_DictSize(pDictStruc);
#if !defined JAVA && !defined C600
    memset(pDictBuf,0,Index);
#else
    do{Index--;pDictBuf[Index] = 0;}while(Index != 0);
#endif
  }    
  //------------------------------------------------------
  // Clear Hash Table if allocated
  //------------------------------------------------------
  if((pHashTab = DICTSTRU_pHashTab(pDictStruc)) != NULL)
  {
    Index = DICTSTRU_HashTabSize(pDictStruc);
#if !defined JAVA && !defined C600
    memset(pHashTab,0,Index*2);
#else
    do{Index--;pHashTab[Index] = 0;}while(Index != 0);
#endif
  }    
  //------------------------------------------------------
  // Clear MaxDictIndex if requested
  //------------------------------------------------------
  if(MaxDictIndClearFlag != 0)
    DICTSTRU_MaxDictIndex(pDictStruc) = 0;
  //------------------------------------------------------
  // Set CurrentDictIndex either to 0 or Max+1(?)
  //------------------------------------------------------
  if(CurrDictIndSetMode == 0)
    DICTSTRU_CurrDictIndex(pDictStruc) = 0;
  else
    DICTSTRU_CurrDictIndex(pDictStruc) =
     (int) DICTSTRU_DictSize(pDictStruc) + 1;
}
//=================================================================
// MPPC Compressor
// NOTE: Must Implement Check for Destination Buffer Overrun !!!!
// ----- This must be done inside the compression loop...
//
//
// Input Parameters:	BIT8PTR SrcBuf		Source Buffer
//			int	SrcOff		Start of Data
//			int	SrcLen		Length of Data
//			BIT8PTR pDstBuf		Destination Buffer
//			int	DstOff		Start of output
//			INTPTR  pDstLen		IN:  Length of Output Buffer
//						OUT: Length of Data on Buffer
//			DICTSTRU_PTR pDictStruc	Dictionary Structure
//
// Returns: int Compress Status:
//		if BIT5 == 0:
//		   - Data not compressible, Dictionary/HashTable Cleared,
//		   - all other bits should be ignored
//		else: (BIT5 == 1)
//                 - Data compressed, other bits signal specific action:
//		     Bit 7: 1 - Clear Dictionary, reset pointer to 0
//		     Bit 6: 1 - reset dictionary pointer to 0 (not with clear)
//		     Bit 4: 0 - unknown
//		     Bit 3-0: Dictionary buffer size:
//			      0x00 - use small dictionary (8K)
//			      0x01 - use large dictionary (64K) 
//			      0x02..0xFF unknown
//==================================================================
PUBLIC STATIC int FAST MPPC_Compress(
		BIT8PTR SrcBuf, int SrcOff, int SrcLen,
		BIT8PTR DstBuf, int DstOff, int pDstLen[],
		DICTSTRU_PTR pDictStruc)
{

  BIT8 Byte0, Byte1, Byte2;			// the current observed bytes

  REGISTER int FreeBitCnt = 16;
  REGISTER BIT16 BitAccu  = 0;


  int SrcIndex = SrcOff;
  int MaxSrcIndex  = SrcIndex + SrcLen - 1;
  int LastSrcIndex = SrcIndex + SrcLen - 3;
  int DstIndex     = DstOff;
  int MaxDstIndex  = DstIndex + pDstLen[0] - 1;

  int CurrDictIndex = (int) DICTSTRU_CurrDictIndex(pDictStruc);
  int MaxDictIndex  = DICTSTRU_MaxDictIndex(pDictStruc);
  int DictSize      = (int) DICTSTRU_DictSize(pDictStruc);
  int HashTabMask   = (int) DICTSTRU_HashTabSize(pDictStruc)-1;
  int OffsetMask; 
  int MatchIndex;
  int Offset;
  int MatchLen;

  int Retcode = 0;
  int Index;
  int FlushFlag = 0;
  int LargeDictFlag = 0;

  BIT8PTR  pDictBuf = DICTSTRU_pDictBuf(pDictStruc);
  BIT16PTR pHashTab = DICTSTRU_pHashTab(pDictStruc);

  BIT32 HashValue;
  //-------------------------------------------------------------
  // Preset the Compression Flags's Dictionary Size Bits (3..0)
  //-------------------------------------------------------------
  if(DictSize != MPPC_SMALL_DICT_SIZE)
  {
    Retcode = MPPC_LARGE_DICT_FLAG;
    LargeDictFlag = 1;
  }
  //-------------------------------------------------------------
  // Check if Message must be moved to Start of Dictionary
  //-------------------------------------------------------------
  OffsetMask = DictSize-1;
  Index = SrcLen + CurrDictIndex;
  if((Index == 0) || (Index > DictSize-2))
  {
    Retcode |= MPPC_RESET_PTR_BIT;
    CurrDictIndex = 0;
  }
  //-------------------------------------------------------------
  // Check if enough Data for Compression loop
  //-------------------------------------------------------------
  if(SrcLen > 3)
  {
    //--------------------------------------------------------------
    // The Compression Loop, takes into account: 3 Bytes from source
    //--------------------------------------------------------------
    for(;;)
    {
      //-----------------------------------------------------------
      // Load Next 3 bytes, but ONLY skip the current byte !!
      //-----------------------------------------------------------
      Byte0 = SrcBuf[SrcIndex];			// fetch a byte to compare
      pDictBuf[CurrDictIndex] = Byte0;		// save this byte
      SrcIndex++;					// advance to next
      CurrDictIndex++;				// dto.
      Byte1 = SrcBuf[SrcIndex];			// get next byte to follow
      Byte2 = SrcBuf[SrcIndex+1];			// dto. at nextpos + 1
      //-----------------------------------------------------------
      // Calculate the hash value of the current bytes via table, get
      // associated matching position, get the Offset
      //-----------------------------------------------------------
      HashValue =
        ((HashTab1[(int) Byte0 & 0xFF] +
         (HashTab1[(int) Byte1 & 0xFF] << 8) +
         (HashTab1[(int) Byte2 & 0xFF] << 16)) >> 12) & HashTabMask;

      MatchIndex = (int) pHashTab[HashValue] & 0xFFFF;
      Offset = CurrDictIndex - MatchIndex;
      //-----------------------------------------------------------
      // Replace Hash Index if Match Offset != 1
      //-----------------------------------------------------------
      if(Offset != 1)
        pHashTab[HashValue] = (BIT16) CurrDictIndex;
      //-----------------------------------------------------------
      // Check if MaxDictIndex can be increased
      //-----------------------------------------------------------
      if(CurrDictIndex > MaxDictIndex)
        MaxDictIndex = CurrDictIndex;
      //-----------------------------------------------------------
      // Check if there is a match >= 3)
      //-----------------------------------------------------------
      if((MatchIndex != 0) &&			// is not usable
         (Byte0 == pDictBuf[MatchIndex-1]) &&	// check for fake hash
         (Byte1 == pDictBuf[MatchIndex]) &&
         (Byte2 == pDictBuf[MatchIndex+1]) &&
         (Offset != 1) &&				// not same as before
         (MatchIndex != CurrDictIndex) &&		// dto.
         (MatchIndex + 1 < MaxDictIndex))		// inside Dictionary
      {
        //-----------------------------------------------------
        // A match of at least 3 Bytes has been found, is Token
        // check if match can be enlarged
        //-----------------------------------------------------
        Offset &= OffsetMask;			// Wrap around negatives
        SrcIndex += 2;				// skip matched source bytes
        MatchIndex += 2;				// dto. for Dictionary
        MatchLen = 3;
        pDictBuf[CurrDictIndex++] = Byte1;		// copy the next byte
        pDictBuf[CurrDictIndex++] = Byte2;		// dto.
        if(SrcBuf[SrcIndex] == pDictBuf[MatchIndex]) // possible to Enlarge
        {
          //-------------------------------------------------
          // At least next byte matches, try more to match
          //-------------------------------------------------
          for(;;)
          {
            if((SrcIndex >= MaxSrcIndex) ||	// end of source
               (MatchIndex >= MaxDictIndex))	// end of Dictionary
              break;
            pDictBuf[CurrDictIndex++] = SrcBuf[SrcIndex++]; // copy byte
            MatchIndex++;
            MatchLen++;
            if(SrcBuf[SrcIndex] != pDictBuf[MatchIndex]) // end of match
              break;
          }          
        }
        //--------------------------------------------------------
        // Encode a Token (i.e. Offset / Length Pair), first check
        // enough Space [for longest Token encoding] on Destination
        // Buffer
        //--------------------------------------------------------
        if((DstIndex + MPPC_MAX_TOKEN_BYTES) > MaxDstIndex)
        {
          FlushFlag = 1;
          break;
        }
        //--------------------------------------------------------
        // 1. Check which Offset Encoding is to be used
        //--------------------------------------------------------
        if(LargeDictFlag == 0)		// Offsets for SMALL Dictionary
        {        
          //---------------------------------------------------------
          // 1.1.1 Encode Offset for Small Dictionary (10/12/16 Bits)
          //       * All cases checked
          //---------------------------------------------------------
          if(Offset < 64)		// is a short offset (10 bit)
          {
            Offset |= 0x3C0;		// 10 Bit, Encoding: 11 11xx xxxx
            FreeBitCnt -= 10;		// reduce by needed Bits
          }
          else if(Offset < 320)
          {
            Offset += 0xDC0;		// 12 Bit, Encoding: 1110 xxxx xxxx
            FreeBitCnt -= 12;		// reduce by needed Bits
          }
          else
          {
            Offset += 0xBEC0;		// 16 Bit, Coding:110x xxxx xxxxxxxx
            FreeBitCnt -= 16;		// reduce by needed Bits
          }
        }
        else					// LARGE Dictionary Mode
        {
          //------------------------------------------------------------
          // 1.2.1 Encode Offset for Large Dictionary (11/13/15/19 Bits)
          //       * All cases except 19 bit, FreeBitCnt <= 3, checked 
          //------------------------------------------------------------
          if(Offset < 64)		// is a short offset (11 bit)
          {
            Offset |= 0x7C0;		// 11 Bit, Encoding: 111 11xx xxxx
            FreeBitCnt -= 11;		// reduce by needed Bits
          }
          else if(Offset < 320)		// is a medium offset (13 bit)
          {
            Offset += 0x1DC0;		// 13 Bit, Encoding: 1 1110 xxxx xxxx
            FreeBitCnt -= 13;		// reduce by needed Bits
          }
          else if(Offset < 2368)	// is a large offset (15 bit)
          {
            Offset += 0x6EC0;		// 15 Bit, Coding:111 0xxx xxxxxxxx
            FreeBitCnt -= 15;		// reduce by needed Bits
          }
          else				// is a very large offset (19 bit)
          {				// -> requires special treatment !
            Offset -= 2368;		// 19 Bit, Coding:110 xxxxxxxx xxxxxxxx
            FreeBitCnt -= 3;		// need 3 leader Bits
            if(FreeBitCnt <= 0)		// must make room for bits
            {
              FreeBitCnt += 8;
              BitAccu |= (0x06 << FreeBitCnt);
              DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);	// save high
              BitAccu <<= 8;				// clear LSB
            }
            else			// enough space for bits
              BitAccu |= (0x06 << FreeBitCnt);
            FreeBitCnt -= 16;		// reduce by needed Bits for offset
          }
        }
        //---------------------------------------------------------
        // 1.2. Output the Offset (for 19 bit the remaining bits)
        //	* all cases testet
        //---------------------------------------------------------
        if(FreeBitCnt <= 0)		// must make room for high bits
        {
          FreeBitCnt += 8;
          if(FreeBitCnt < 0)		// still not enough space !
          {
            DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          BitAccu |= (((Offset >> 8) & 0xFF) << FreeBitCnt);
          DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);	// save high
          BitAccu <<= 8;				// clear LSB
        }
        BitAccu |= (Offset << FreeBitCnt);		// insert low bits
        DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);	// save high
        BitAccu <<= 8;					// clear LSB
        FreeBitCnt += 8;

        if(FreeBitCnt < 8)			// is a FAULT! (but handle...)
        {
#if defined __DEBUG_CHECK__
          PRINT("Past Offset generate, Bitakku overflow 1!\n");
#endif
          DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);	// save high
          BitAccu <<= 8;				// clear LSB
          FreeBitCnt += 8;
        }
        //--------------------------------------------------------
        // 2. Encode MatchLength
        // NOTE: lengths 3..31 are treated SPECIAL
        // from here we have at least 8 free bits available !
        //--------------------------------------------------------
        if(MatchLen == 3)			// special mode, 1 Bit
        {
          //------------------------------------------------------
          // Length: 3,  Encoding: 0, Total: 1 Bit
	  //		 * all cases tested, 8..16 free bits
          //------------------------------------------------------
          FreeBitCnt--;				// reduce by needed length
          if(FreeBitCnt <= 8)			// must free space
          {
            DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);	// save high
            BitAccu = 0;			// clear
            FreeBitCnt += 8;
          }
        }
        else if(MatchLen < 8)
        {
          //------------------------------------------------------
          // Length: 4..7,  Encoding: 10xx, Total: 4 Bit
          //		    * all cases tested, 8..16 free bits
          //------------------------------------------------------
          MatchLen += 4;			// generate 10xx
          FreeBitCnt -= 4;
          BitAccu |= (MatchLen << FreeBitCnt);
          if(FreeBitCnt <= 8)			// must free space
          {
            DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);	// save high
            BitAccu <<= 8;				// clear
            FreeBitCnt += 8;
          }
        }
        else if(MatchLen < 16)
        {
          //------------------------------------------------------
          // Length: 8..15,  Encoding: 110xxx, Total: 6 Bit
	  //		     * all cases tested, 8..16 free bits
          //------------------------------------------------------
          MatchLen += 0x28;			// generate 110xxx
          FreeBitCnt -= 6;
          BitAccu |= (MatchLen << FreeBitCnt);
          if(FreeBitCnt <= 8)			// must free space
          {
            DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);	// save high
            BitAccu <<= 8;			// clear
            FreeBitCnt += 8;
          }
        }
        else if(MatchLen < 32)			// 16..31, 8 Bit
        {
          //------------------------------------------------------
          // Length: 16..31,  Encoding: 1110xxxx, Total: 8 Bit
	  //		      * tested, 8..16 free bits
          //------------------------------------------------------
          MatchLen += 0xD0;			// generate 1110xxxx
          BitAccu |= (MatchLen << (FreeBitCnt-8));
          DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);	// save high
          BitAccu <<= 8;			// clear
        }
        else if(MatchLen < 64)
        {
          //------------------------------------------------------
          // Length: 32..63,  Encoding: 11110xxxxx, Total: 10 Bit
          //		      * all cases tested, 8..16 free bits
          //------------------------------------------------------
          FreeBitCnt -= 4;			// reduce
          BitAccu |= (0x0F << FreeBitCnt);	// insert header
          if(FreeBitCnt <= 8)
          {
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          FreeBitCnt -= 6;
          BitAccu |= ((MatchLen - 32) << FreeBitCnt);
          if(FreeBitCnt <= 8)
          {
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
        }
        else if(MatchLen < 128)
        {
          //--------------------------------------------------------
          // Length: 64..127,  Encoding: 111110xxxxxx, Total: 12 Bit
          //                   * all cases tested, 8..16 free bits
          //--------------------------------------------------------
          FreeBitCnt -= 5;			// reduce
          BitAccu |= (0x1F << FreeBitCnt);	// insert header
          if(FreeBitCnt <= 8)
          {
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          FreeBitCnt -= 7;
          BitAccu |= ((MatchLen - 64) << FreeBitCnt);
          if(FreeBitCnt <= 8)
          {
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
        }
        else if(MatchLen < 256)
        {
          //-----------------------------------------------------------
          // Length: 128..255,  Encoding: 1111110xxxxxxx, Total: 14 Bit
	  //			* all cases tested, 8..16 free bits
          //-----------------------------------------------------------
          FreeBitCnt -= 6;			// reduce
          BitAccu |= (0x3F << FreeBitCnt);	// insert header
          if(FreeBitCnt <= 8)
          {
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          BitAccu |= ((MatchLen - 128) << (FreeBitCnt-8));
          DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
          BitAccu <<= 8;
        }
        else if(MatchLen < 512)
        {
          //-------------------------------------------------------------
          // Length: 256..511,  Encoding: 11111110xxxxxxxx, Total: 16 Bit
	  //			* all cases tested, 8..16 free bits
          //-------------------------------------------------------------
          MatchLen &= 0xFF;
          FreeBitCnt -= 7;			// reduce
          BitAccu |= (0x7F << FreeBitCnt);	// insert header
          if(FreeBitCnt <= 8)
          {
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }

          if(FreeBitCnt > 9)
          {
            FreeBitCnt -= 9;
            BitAccu |= (MatchLen << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          else						// at least 9 bits free
          {
            BitAccu |= MatchLen;
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            DstBuf[DstIndex++] = (BIT8) BitAccu;		// save
            BitAccu = 0;
            FreeBitCnt = 16;
          }
        }
        else if(MatchLen < 1024)
        {
          //----------------------------------------------------------------
          // Length: 512..1023,  Encoding: 111111110xxxxxxxxx, Total: 18 Bit
	  //			* all cases tested, 8..16 free bits
          //----------------------------------------------------------------
          MatchLen &= 0x1FF;
          BitAccu |= (0xFF << (FreeBitCnt-8));	// insert header
          DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
          BitAccu <<= 8;
          if(FreeBitCnt > 10)
          {
            FreeBitCnt -= 10;
            BitAccu |= (MatchLen << FreeBitCnt);
          }
          else						// at least 8 free!
          {
            FreeBitCnt -= 2;				// 2 bits
            BitAccu |= (((MatchLen >> 8) & 0xFF) << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;

            BitAccu |= ((MatchLen & 0xFF) << FreeBitCnt);
          }
          DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
          BitAccu <<= 8;
          FreeBitCnt += 8;
        }
        else if(MatchLen < 2048)
        {
          //-----------------------------------------------------------------
          // Length: 1024..2047,Encoding: 1111111110xxxxxxxxxx, Total: 20 Bit
	  //			* all cases tested, 8..16 free bits
          //-----------------------------------------------------------------
          MatchLen &= 0x3FF;
          if(FreeBitCnt < 9)			// not enough for header, ==8
          {
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          FreeBitCnt -= 9;
          BitAccu |= (0x1FF << FreeBitCnt);
          DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
          BitAccu <<= 8;
          FreeBitCnt += 8;


          if(FreeBitCnt > 11)			// more than 11 Bits...
          {
            FreeBitCnt -= 11;
            BitAccu |= (MatchLen << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          else if(FreeBitCnt == 11)		// exactly 11 Bits
          {
            BitAccu |= MatchLen;
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);
            DstBuf[DstIndex++] = (BIT8) BitAccu;
            BitAccu = 0;
            FreeBitCnt = 16;
          }
          else					// less than 11 Bits, >= 8
          {
            BitAccu |= (MatchLen >> (11-FreeBitCnt));	// get high bits
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);
            DstBuf[DstIndex++] = (BIT8) BitAccu;
            FreeBitCnt = 16-(11-FreeBitCnt);
            BitAccu = (BIT16) (MatchLen << FreeBitCnt);
          }
        }
        else if(MatchLen < 4096)
        {
          //-------------------------------------------------------------------
          // Length: 2048..4095,Encoding: 11111111110xxxxxxxxxxx, Total: 22 Bit
	  //			* all cases tested, 8..16 free bits
          //-------------------------------------------------------------------
          MatchLen &= 0x7FF;
          if(FreeBitCnt > 10)			// enough for header
          {
            FreeBitCnt -= 10;
            BitAccu |= (0x3FF << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          else					// less/same as 10 Bit, >= 8
          {
            FreeBitCnt -= 2;

            BitAccu |= (3 << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;

            BitAccu |= (0xFF << (FreeBitCnt));
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }


          if(FreeBitCnt > 12)			// more than 12 Bits...
          {
            FreeBitCnt -= 12;
            BitAccu |= (MatchLen << FreeBitCnt);
          }
          else					// less/equal 12 Bits, >= 8
          {
            FreeBitCnt -= 4;

            BitAccu |= (((MatchLen >> 8) & 0xFF) << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;

            BitAccu |= ((MatchLen & 0xFF) << FreeBitCnt);
          }
          DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
          BitAccu <<= 8;
          FreeBitCnt += 8;
        }
        else if(MatchLen < 8192)
        {
          //-------------------------------------------------------------------
          // Length: 4096..8191,Enc.: 111111111110xxxxxxxxxxxx, Total: 24 Bit
	  //			* all cases tested, 8..16 free bits
          //-------------------------------------------------------------------
          MatchLen &= 0xFFF;
          if(FreeBitCnt > 11)			// enough for header
          {
            FreeBitCnt -= 11;
            BitAccu |= (0x7FF << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          else if(FreeBitCnt == 11)		// exact match
          {
            BitAccu |= 0x7FF;
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            DstBuf[DstIndex++] = (BIT8) BitAccu;		// save
            BitAccu = 0;
            FreeBitCnt = 16;
          }
          else					// less than 11, >= 8
          {
            BitAccu |= (0x7FF >> (11 - FreeBitCnt));	// get high bits
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            DstBuf[DstIndex++] = (BIT8) BitAccu;		// save
            FreeBitCnt += 5;
            BitAccu = (BIT16) (0x7FF << FreeBitCnt);
          }
  
          if(FreeBitCnt > 13)			// enough for length Bits
          {
            FreeBitCnt -= 13;
            BitAccu |= (MatchLen << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          else					// less/same than 13, >= 8
          {
            FreeBitCnt -= 5;
   
            BitAccu |= (((MatchLen >> 8) & 0xFF) << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
     
            BitAccu |= ((MatchLen & 0xFF) << (FreeBitCnt-8));
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
          }
        }
        else if(MatchLen < 16384)
        {
          //-------------------------------------------------------------------
          // Length: 8192..16383,Enc.: 1111111111110xxxxxxxxxxxxx, Tot.: 26 Bit
	  //			* all cases tested, 8..16 free bits
          //-------------------------------------------------------------------
          MatchLen &= 0x1FFF;
          if(FreeBitCnt > 12)			// enough for header
          {
            FreeBitCnt -= 12;
            BitAccu |= (0xFFF << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          else if(FreeBitCnt == 12)		// exact match
          {
            BitAccu |= 0xFFF;
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            DstBuf[DstIndex++] = (BIT8) BitAccu;		// save
            BitAccu = 0;
            FreeBitCnt = 16;
          }
          else					// less than 12, >= 8
          {
            BitAccu |= (0xFFF >> (12 - FreeBitCnt));	// get high bits
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            DstBuf[DstIndex++] = (BIT8) BitAccu;		// save
            FreeBitCnt += 4;
            BitAccu = (BIT16) (0xFFF << FreeBitCnt);
          }
  
          if(FreeBitCnt > 14)			// enough for length Bits
          {
            FreeBitCnt -= 14;
            BitAccu |= (MatchLen << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          else					// less/same than 14, >= 8
          {
            FreeBitCnt -= 6;
   
            BitAccu |= (((MatchLen >> 8) & 0xFF) << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
     
            BitAccu |= ((MatchLen & 0xFF) << (FreeBitCnt-8));
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
          }
        }
        else if(MatchLen < 32768)
        {
          //-------------------------------------------------------------------
          // Len: 16384..32767,Enc.: 11111111111110xxxxxxxxxxxxxx, Tot.: 28 Bit
	  //			* all cases tested, 8..16 free bits
          //-------------------------------------------------------------------
          MatchLen &= 0x3FFF;
          if(FreeBitCnt > 13)			// enough for header
          {
            FreeBitCnt -= 13;
            BitAccu |= (0x1FFF << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          else if(FreeBitCnt == 13)		// exact match
          {
            BitAccu |= 0x1FFF;
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            DstBuf[DstIndex++] = (BIT8) BitAccu;		// save
            BitAccu = 0;
            FreeBitCnt = 16;
          }
          else					// less than 13, >= 8
          {
            BitAccu |= (0x1FFF >> (13 - FreeBitCnt));	// get high bits
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            DstBuf[DstIndex++] = (BIT8) BitAccu;		// save
            FreeBitCnt += 3;
            BitAccu = (BIT16) (0x1FFF << FreeBitCnt);
          }
  
          if(FreeBitCnt > 15)			// enough for length Bits
          {
            FreeBitCnt -= 15;
            BitAccu |= (MatchLen << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          else					// less/same than 15, >= 8
          {
            FreeBitCnt -= 7;
   
            BitAccu |= (((MatchLen >> 8) & 0xFF) << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
     
            BitAccu |= ((MatchLen & 0xFF) << (FreeBitCnt-8));
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
          }
        }
        else
        {
          //-----------------------------------------------------------------
          // Length:>=32768, Enc: 111111111111110xxxxxxxxxxxxxxx, Total: 30 Bit
	  //			* all cases tested, 8..16 free bits
          //-----------------------------------------------------------------
          MatchLen &= 0x07FFF;
          if(FreeBitCnt > 15)			// enough for header
          {
            FreeBitCnt -= 15;
            BitAccu |= (0x7FFE << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          else if(FreeBitCnt == 15)		// exact match
          {
            BitAccu |= 0x7FFE;
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            DstBuf[DstIndex++] = (BIT8) BitAccu;		// save
            BitAccu = 0;
            FreeBitCnt = 16;
          }
          else					// less than 15, >= 8
          {
            BitAccu |= (0x7FFE >> (15 - FreeBitCnt));	// get high bits
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            DstBuf[DstIndex++] = (BIT8) BitAccu;		// save
            FreeBitCnt += 1;
            BitAccu = (BIT16) (0x7FFE << FreeBitCnt);
          }
  
          if(FreeBitCnt > 15)			// enough for length Bits
          {
            FreeBitCnt -= 15;
            BitAccu |= (MatchLen << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          else					// less/same than 15
          {
            FreeBitCnt -= 7;
   
            BitAccu |= (((MatchLen >> 8) & 0xFF) << FreeBitCnt);
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
            FreeBitCnt += 8;
     
            BitAccu |= ((MatchLen & 0xFF) << (FreeBitCnt-8));
            DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
            BitAccu <<= 8;
          }
        }
      }
      else
      {    
        //------------------------------------------------------------
        // No proper match found, output as a Literal, if enough space
        //------------------------------------------------------------
        if((DstIndex + MPPC_MAX_LITERAL_BYTES) > MaxDstIndex)
        {
          FlushFlag = 1;
          break;
        }

        if((Byte0 & 0x80) == 0)			// Bit 7 is zero
        {
          //-----------------------------------------------------
          // Short Literal Encoding: 0xxxxxxx, 8 Bit
	  // * all cases tested, 0..16 free bits
          //-----------------------------------------------------
          if(FreeBitCnt < 8)
          {
            DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
          BitAccu |= (((BIT16) Byte0 & 0xFF) << (FreeBitCnt - 8));
          DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
          BitAccu <<= 8;
        }
        else
        {
          //-----------------------------------------------------
          // Long Literal Encoding: 10xxxxxxx, 9 Bit
	  // * all cases tested, 0..16 free bits
          //-----------------------------------------------------
          Byte0 &= 0x7F;			// clear Bit 7
          if(FreeBitCnt < 9)			// not enough bits free
          {
            DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);
            BitAccu <<= 8;
            FreeBitCnt += 8;
            if(FreeBitCnt < 9)			// still not enough
            {
              DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);
              BitAccu <<= 8;
              FreeBitCnt += 8;
            }
          }
          BitAccu |= (((int) Byte0 | 0x100) << (FreeBitCnt-9));
          DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);	// write 8 Bit
          BitAccu <<= 8;
          FreeBitCnt--;				// but still a bit less !
        }
      }
      //--------------------------------------------------------
      // Check if processing loop is to be continued...
      //--------------------------------------------------------
      if(SrcIndex >= LastSrcIndex)		// is exhausted
        break;
    } // Compress FOR Loop
  } // Compression IF
  //----------------------------------------------------------
  // Check if remaining bytes in source
  //----------------------------------------------------------
  if((SrcIndex < MaxSrcIndex+1) && (FlushFlag == 0))	// more bytes present
  {
    for(;;)
    {
      Byte0 = SrcBuf[SrcIndex++];			// get byte
      pDictBuf[CurrDictIndex++] = Byte0;		// save to dict.
      //------------------------------------------------------
      // Encode as literal, check for Destination buffer space
      //------------------------------------------------------
      if((DstIndex + MPPC_MAX_LITERAL_BYTES) > MaxDstIndex)
      {
        FlushFlag = 1;
        break;
      }

      if((Byte0 & 0x80) == 0)			// Bit 7 is zero
      {
        //-----------------------------------------------------
        // Short Literal Encoding: 0xxxxxxx, 8 Bit
	// * all cases tested, 0..16 free bits
        //-----------------------------------------------------
        if(FreeBitCnt < 8)
        {
          DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);
          BitAccu <<= 8;
          FreeBitCnt += 8;
        }
        BitAccu |= (((BIT16) Byte0 & 0xFF) << (FreeBitCnt - 8));
        DstBuf[DstIndex++] = (BIT8) (BitAccu >>8);	// save
        BitAccu <<= 8;
      }
      else
      {
        //-----------------------------------------------------
        // Long Literal Encoding: 10xxxxxxx, 9 Bit
	// * all cases tested, 0..16 free bits
        //-----------------------------------------------------
        Byte0 &= 0x7F;
        if(FreeBitCnt < 9)			// not enough bits free
        {
          DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);
          BitAccu <<= 8;
          FreeBitCnt += 8;
          if(FreeBitCnt < 9)			// still not enough
          {
            DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);
            BitAccu <<= 8;
            FreeBitCnt += 8;
          }
        }
        BitAccu |= (((int) Byte0 | 0x100) << (FreeBitCnt-9));
        DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);	// write 8 Bit
        BitAccu <<= 8;
        FreeBitCnt--;				// but still a bit less !
      }
      if(SrcIndex > MaxSrcIndex)
        break;
    } // literal out FOR
  }
  //------------------------------------------------------
  // Check if remaining Bits in Bitaccu
  // tested o.k.
  //------------------------------------------------------
  if((FreeBitCnt != 16) && (FlushFlag == 0))
    DstBuf[DstIndex++] = (BIT8) (BitAccu >> 8);

  DICTSTRU_CurrDictIndex(pDictStruc) = CurrDictIndex;
  DICTSTRU_MaxDictIndex(pDictStruc)  = MaxDictIndex;

  //------------------------------------------------------
  // Check if Compressed is smaller/same than source
  //------------------------------------------------------
  if(((DstIndex-DstOff) <= (SrcIndex-SrcOff)) && (FlushFlag == 0))
  {
    Retcode |= MPPC_COMPRESSED_BIT;
    if((DICTSTRU_FlagsSave(pDictStruc) & MPPC_DICT_CLEARED_BIT) != 0)
    {
      DICTSTRU_FlagsSave(pDictStruc) &= (~MPPC_DICT_CLEARED_BIT);
      Retcode |= MPPC_DICT_CLEARED_BIT;		// Signal Dictionary Cleared
      Retcode &=  (~MPPC_RESET_PTR_BIT);	// implizit pointer reset
    }
  }
  else
  {
    //------------------------------------------------------  
    // is a BAD compress result (enlarged), clear Dict./Hash
    // NOTE: As this is UNCOMPRESSED, the other flags would be
    // ----- ignored -> save in structure for next turn !!!
    //------------------------------------------------------  
    MPPC_DictStrucInit(pDictStruc,0,1);
    DICTSTRU_FlagsSave(pDictStruc) |= MPPC_DICT_CLEARED_BIT;
    Retcode = 0;				// uncompressed anyway...
//    Retcode |= MPPC_DICT_CLEARED_BIT;		// Signal Dictionary Cleared
//    Retcode &=  (~MPPC_RESET_PTR_BIT);		// implizit pointer reset
    return(Retcode);
  }
  pDstLen[0]        = DstIndex;
  return(Retcode);
}

#if defined JAVA
}
#endif
