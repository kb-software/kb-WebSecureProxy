#if defined JAVA
package hob.mppc;
#endif

//#include <stdio.h>	// TEST TEST TEST

#define __MPPC_DECOMPRESS__
//******************************************************
//
// MPPC Decompression Routine
// Version 2.0., includes large (64KB) Dictionary mode
// 2001/05/30
//******************************************************
//
// For a Description of Compression / Decompression Process
// see RFC2118
//
#include "mppccmp.h"

#if defined JAVA
public class MPPCDECOMPinst {
#endif

//========================================================
// Decompressor Subroutine, small (8kB) and large (64kB)
// Dictionary modes (RDP V5.0).
//
// NOTE: 1. The Output Buffer will  n e v e r  be allocated; it is either
// -----    the Input buffer (in case of non compressed) or portion of
//	    the Dictionary buffer
//	 2. The Dictionary buffer must have the appropriate size
//	    when large Dictionary (64K-1 bytes) is used, no
//	    checking on size is done !!
//
// Input Parameters:	BIT8	 SrcBuf[]	Input Data
//			BIT32	 SrcOff		Start of Data
//			BIT32	 SrcLen		Length of Data
//			BIT8	 CmprFlags	Compression Control Flags
//			BIT8	 DictBuf[]	Dictionary/Output Buffer
//			BIT32PTR pActDictIndex	Current Index in use
//			BIT8PTR	 pDstBuf[]	Output Buffer
//			BIT32PTR pDstOff	Start of Output Data
//			BIT32PTR pDstLen	Length of Output Data
//
// Return value: int Status		0 - o.k., else error occured
//
//========================================================
PUBLIC STATIC int MPPCDecompress(BIT8 SrcBuf[], BIT32 SrcOff, BIT32 SrcLen,
			BIT8 CmprFlags, BIT8 DictBuf[], BIT32 pActDictIndex[],
			BIT8PTR pDstBuf[], BIT32 pDstOff[], BIT32 pDstLen[])
{
  BIT8 LargeDictFlag;
  int BitCount = 0;
  int Count;

  BIT32 SrcIndex;
  BIT32 DictIndex;
  BIT32 DictStartIndex;
  BIT32 MatchLen;
  BIT32 Offset;

  BIT32	DictSize;
  BIT32 BitBuf = 0;
  //-----------------------------------------------
  // Check Parameters
  //-----------------------------------------------
  if((SrcBuf == NULL) || (DictBuf == NULL) || (pActDictIndex == NULL) ||
     (pDstBuf == NULL) || (pDstOff == NULL) || (pDstLen == NULL))
    return(-1);
  //===============================================
  // 1. Process Compressionflags
  //===============================================
  //-----------------------------------------------
  // 1a. Check if compressed at all
  //-----------------------------------------------
  if((CmprFlags & MPPC_COMPRESSED_BIT) == 0)	// uncompressed case
  {
    pDstBuf[0] = SrcBuf;			// Out = In
    pDstOff[0] = SrcOff;			// dto.
    pDstLen[0] = SrcLen;			// dto.
    return(0);
  }
  //------------------------------------------------------------
  // 1b. Compressed, Get Dictionary Size used, check Buffer Flag
  //------------------------------------------------------------
  LargeDictFlag = (BIT8) (CmprFlags & MPPC_DICTSIZE_MASK); // isolate Bit 3..0
  if(LargeDictFlag > 1)				// out of range, 0 or 1 !!
    return(-11);
  if(LargeDictFlag == 0)			// is small Dictionary
    DictSize = MPPC_SMALL_DICT_SIZE;		// 2000h
  else
    DictSize = MPPC_LARGE_DICT_SIZE;		// 10000h

  pDstBuf[0] = DictBuf;				// must be from Dictionary
  pDstOff[0] = 0;				// assume start at Zero
  pDstLen[0] = 0;				// no size  
  //------------------------------------------------------------
  // 1c. Check if Dictionary has to be reinitialized
  //------------------------------------------------------------
  if((CmprFlags & MPPC_DICT_CLEARED_BIT) != 0)	// must clear dictionary
  {
    DictIndex = DictSize;			// get size in bytes
#ifndef JAVA
    memset(DictBuf,0,(int) DictIndex);	// clear all (incl. Index)
#else
    do{DictIndex--;DictBuf[DictIndex] = 0;}while(DictIndex != 0);
#endif // JAVA
    pActDictIndex[0] = 0;
  }
  //------------------------------------------------------------
  // 1d. Check if Current Dictionary Index should be reset
  //------------------------------------------------------------
  if((CmprFlags & MPPC_RESET_PTR_BIT) != 0)	// reset index to start
    pActDictIndex[0] = 0;
  //-------------------------------------------------------------------
  // 2. Get current Dictionary Write Index, save, check for
  //    Source Data Zero length
  //------------------------------------------------------------
  DictIndex = pActDictIndex[0];
  DictStartIndex = DictIndex;
  pDstOff[0] = DictStartIndex;		// set Start of Data
  if(SrcLen == 0)			// no data in, no data out !
    return(0);
  //------------------------------------------------------------
  // 3. Decompression Loop
  //------------------------------------------------------------
  for(;;)
  {
    //-----------------------------------------------
    // 3.0. Refill the Bit Buffer if empty
    //-----------------------------------------------
    if(BitCount == 0)				// empty bitbuffer
    {
      if(SrcLen == 0)				// no more Source Data
        break;
      BitBuf = ((BIT32) SrcBuf[SrcOff++] & 0xFF) << 24;	// get Bits
      SrcLen--;
      BitCount = 8;
    }
    //-------------------------------------------------
    // 3.1. Get Top Bit to Check for Literal (Bit == 0)
    //-------------------------------------------------
    if((BitBuf & 0x80000000) == 0) 		// is a 7-Bit Literal
    {
      if(BitCount < 8)				// must fill Bit-Buffer
      {
        if(SrcLen == 0)				// no data, if not all zero,err
        {
          if(BitBuf != 0)			// still bits, error !
            return(-2);        
          else					// empty, exit
            break;
        }
        BitBuf |=				// more data, collect
          ((BIT32) SrcBuf[SrcOff++] & 0xFF) << (24-BitCount); // fill buffer
        SrcLen--;
        BitCount += 8;
      }
      if(DictIndex >= DictSize)			// already Full !
        return(-100);
      DictBuf[DictIndex++] = (BYTE) ((BitBuf >> 24) & 0x7F);//save Byte,B7 = 0
      BitBuf <<= 8;				// remove bits
      BitCount -= 8;				// reduce count
      continue;					// to outer FOR loop      
    }
    //-------------------------------------------------------
    // 3.2. Top Bit is  n o t  zero, check if it is a literal
    //-------------------------------------------------------
    BitBuf <<= 1;				// remove bit
    BitCount --;
    if(BitCount == 0)				// must refill    
    {
      if(SrcLen == 0)				// no data, error !
        return(-3);
      BitBuf = ((BIT32) SrcBuf[SrcOff++] & 0xFF) << 24;	// get bits
      SrcLen --;
      BitCount = 8;
    }
    if((BitBuf & 0x80000000) == 0)		// is an 8 Bit literal
    {
      if(BitCount < 8)				// must have 8 bits
      {
        if(SrcLen == 0)				// no more data, error !
          return(-4);
        BitBuf |=
           ((BIT32) SrcBuf[SrcOff++] & 0xFF) << (24-BitCount); // insert bits
        SrcLen--;
        BitCount += 8;
      }
      if(DictIndex >= DictSize)			// already Full !
        return(-100);
      DictBuf[DictIndex++] = (BYTE) ((BitBuf >> 24) | 0x80); //store 7 Bit,B7=1
      BitBuf <<= 8;				// remove bits
      BitCount -= 8;				// reduce count
      continue;					// to outer FOR loop      
    }
    //--------------------------------------------------------
    // 3.3. Had a Bit-Combination of 11, is an Offset Encoding
    //--------------------------------------------------------
    BitBuf <<= 1;				// remove bit
    BitCount--;
    if(BitCount < 2)				// need at last 2 Bits
    {
      if(SrcLen == 0)				// no more data, error !
        return(-5);
      BitBuf |=
        ((BIT32) SrcBuf[SrcOff++] & 0xFF) << (24-BitCount); // fill buffer
      SrcLen--;
      BitCount += 8;
    }
    //---------------------------------------------------------------
    // 3.3.1. Decode Offset Encoding:
    //
    // a) Small Dictionary (8KB)
    // (11) 11  xxxxxx 		  - 6  Bit direct Offset,
    // (11) 10  xxxxxxxx	  - 8  Bit Offset, rel. Start at 64
    // (11) 0   xxxxxxxx xxxxx	  - 13 Bit Offset, rel. Start at 320
    //---------------------------------------------------------------
    if(LargeDictFlag == 0)
    {
      switch((BitBuf >> 30) & 0x03)		// Distribute by lead bits
      {
        case 3:					// (11) 11xxxxxx 6 Bit offset
          if(BitCount < 8)			// must reload
          {
            if(SrcLen == 0)			// no more data, error !
              return(-6);				// Offset Error
            BitBuf |=
              ((BIT32) SrcBuf[SrcOff++] & 0xFF) << (24-BitCount); // fill buffer
            SrcLen--;
            BitCount += 8;
          }
          Offset = (BitBuf >> 24) & 0x3F;	// get the 6-Bit Offset
          BitBuf <<= 8;				// remove bits
          BitCount -= 8;
          break;				// get the count next

        case 2:					// (11) 10xxxxxxxx 8 Bit offset
          BitBuf <<= 2;				// remove bits
	  BitCount -= 2;
          if(BitCount < 8)			// must reload
          {
            if(SrcLen == 0)			// no more data, error !
              return(-6);			// Offset Error
            BitBuf |=
               ((BIT32) SrcBuf[SrcOff++] & 0xFF) << (24-BitCount); // fill buffer
            SrcLen--;
            BitCount += 8;
          }
          Offset = ((BitBuf >> 24) & 0xFF) + 64;// get 8-Bit Offset + Base
          BitBuf <<= 8;				// remove bits
          BitCount -= 8;
          break;				// get the count next
        
        default:				// (11) 0xxxxxxxxxxxxx 13 Bit
          while(BitCount < 14)			// need 1 or 2 Bytes
          {
            if(SrcLen == 0)			// no more data, error !
              return(-6);			// Offset Error
            BitBuf |=
              ((BIT32) SrcBuf[SrcOff++] & 0xFF) << (24-BitCount);// fill buffer
            SrcLen--;
            BitCount += 8;
          }
          Offset = (BitBuf >> 18) + 320;	//get 13-Bit Off. + Base
						// Note that Bit 31 was zero !!

          BitBuf <<= 14;			// remove bits
          BitCount -= 14;
          break;				// get the count next
      } // Offset Switch
    }
    else					// large Dictionary
    {
      //---------------------------------------------------------------
      // b) Large Dictionary (64KB)
      // (11) 111 xxxxxx 	    - 6  Bit direct Offset,
      // (11) 110 xxxxxxxx	    - 8  Bit Offset, rel. Start at 64
      // (11) 10  xxxxxxxx xxx	    - 11 Bit Offset, rel. Start at 320
      // (11) 0   xxxxxxxx xxxxxxxx - 16 Bit Offset, rel. Start at 2368
      //---------------------------------------------------------------
      switch((BitBuf >> 30) & 0x03)		// Distribute by lead bits
      {
        case 3:					// (11) 11 1xxxxxx   6 Bit Off.
          					// (11) 11 0xxxxxxxx 8 Bit Off.
          BitBuf <<= 2;				// remove next 2 leader bits
          BitCount -= 2;

          if(BitCount < 1)			// must reload
          {
            if(SrcLen == 0)			// no more data, error !
              return(-6);				// Offset Error
            BitBuf |=
              ((BIT32) SrcBuf[SrcOff++] & 0xFF) << (24-BitCount); // fill buffer
            SrcLen--;
            BitCount += 8;
          }
          if((BitBuf & 0x80000000) != 0)	// (11) 11 1xxxxxx 6 Bit Offset
          {
            if(BitCount < 7)			// must have 6+1 bits
            {
              if(SrcLen == 0)			// no more data, error !
                return(-4);
              BitBuf |=
               ((BIT32) SrcBuf[SrcOff++] & 0xFF) << (24-BitCount); // insert bits
              SrcLen--;
              BitCount += 8;
            }
            Offset = (BitBuf >> 25) & 0x3F;	// get the 6-Bit Offset
            BitBuf <<= 7;			// remove bits
            BitCount -= 7;
            break;				// get the count next
          }
          else    				// (11) 11 0xxxxxxxx 8 Bit Offset 
          {
            if(BitCount < 9)			// must reload
            {
              if(SrcLen == 0)			// no more data, error !
                return(-6);			// Offset Error
              BitBuf |=
                ((BIT32) SrcBuf[SrcOff++] & 0xFF) << (24-BitCount);// fill buffer
              SrcLen--;
              BitCount += 8;
            }
            Offset = (BitBuf >> 23) + 64;	//get 8-Bit Off. + Base
                                                // NOTE: Bit31 was zero !
            BitBuf <<= 9;			// remove bits
            BitCount -= 9;
            break;				// get the count next
          }

        case 2:					// (11) 10 xxxxxxxxxxx 11 Bit
          BitBuf <<= 2;				// remove next 2 leader bits
	  BitCount -= 2;
          while(BitCount < 11)			// must reload
          {
            if(SrcLen == 0)			// no more data, error !
              return(-6);			// Offset Error
            BitBuf |=
               ((BIT32) SrcBuf[SrcOff++] & 0xFF) << (24-BitCount); // fill buffer
            SrcLen--;
            BitCount += 8;
          }
          Offset = ((BitBuf >> 21) & 0x7FF) + 320;// get 11-Bit Offset + Base
          BitBuf <<= 11;			// remove bits
          BitCount -= 11;
          break;				// get the count next
        
        default:				// (11) 0xxxxxxxxxxxxxxxx 16Bit
          while(BitCount < 17)			// need 1 or 2 Bytes
          {
            if(SrcLen == 0)			// no more data, error !
              return(-6);			// Offset Error
            BitBuf |=
              ((BIT32) SrcBuf[SrcOff++] & 0xFF) << (24-BitCount);// fill buffer
            SrcLen--;
            BitCount += 8;
          }
          Offset = (BIT32) (BitBuf >> 15) + 2368;//get 16-Bit Off. + Base
						// Note that Bit 31 was zero !!

          BitBuf <<= 17;			// remove bits
          BitCount -= 17;
          break;				// get the count next
      } // Offset Switch
    }

    //-------------------------------------------------------------------
    // 3.3.2. Get the Length of Match Encoding
    //
    // a) Both Small and Large Dictionary
    // 0			      -     3
    // 10xx			      -	    4 + xx	        (   4 ..   7)
    // 110xxx			      -	    8 + xxx	        (   8 ..  15)
    // 1110xxxx			      -	   16 + xxxx	        (  16 ..  31)
    // 11110xxxxx		      -	   32 + xxxxx	        (  32 ..  63)
    // 111110xxxxxx		      -	   64 + xxxxxx	        (  64 .. 127)
    // 1111110xxxxxxx		      -	  128 + xxxxxxx	        ( 128 .. 255)
    // 11111110xxxxxxxx		      -	  256 + xxxxxxxx        ( 256 .. 511)
    // 111111110xxxxxxxxx	      -	  512 + xxxxxxxxx       ( 512 ..1023)
    // 1111111110xxxxxxxxxx	      -	 1024 + xxxxxxxxxx      (1024 .. 2047)
    // 11111111110xxxxxxxxxxx	      -	 2048 + xxxxxxxxxxx     (2048 .. 4095)
    // 111111111110xxxxxxxxxxxx       -	 4096 + xxxxxxxxxxxx    (4096 .. 8191)
    //
    // b) Additional for Large Dictionary
    // 1111111111110xxxxxxxxxxxxx -	 8192 + xxxxxxxxxxxxx   (8192 ..16383)
    // 11111111111110xxxxxxxxxxxxxx -	16384 + xxxxxxxxxxxxxx  (16384..32767)
    // 111111111111110xxxxxxxxxxxxxxx -	32768 + xxxxxxxxxxxxxxx (32768..65535)
    //
    //---------------------------------------------------------------
    if(BitCount == 0)				// need at least one bit
    {
      if(SrcLen == 0)				// no more Data, error !
        return(-7);				// match length error
      BitBuf = ((BIT32) SrcBuf[SrcOff++] & 0xFF) << 24;	// get new bits
      BitCount = 8;
      SrcLen--;
    }
    //--------------------------------------------------------
    // 3.3.2.1 Check if Matchlength is the minimal value...
    //--------------------------------------------------------
    if((BitBuf & 0x80000000) == 0)		// minimal length case
    {
      MatchLen = 3;				// set length
      BitBuf <<= 1;				// remove Bit
      BitCount --;
    }
    //------------------------------------------------------------
    // 3.3.2.2 Long Match-Length decoding, 1st bit is '1',
    // count number of consecutive 1 bits till 0 bit found,
    // max. 11 consecutive 1 bits allowed for Small Dictionary,
    // max. 14 consecutive 1 bits allowed for Large Dictionary,
    // then 0 bit must follow
    //------------------------------------------------------------
    else					// had 1st '1' bit, max.10 more
    {
      if(LargeDictFlag != 0)
        Count = 14;				// Large, max 14 '1' Bits allowed
      else
        Count = 11;				// Small, max 11 '1' Bits allowed
      MatchLen = Count + 2;			// max. needed bits
      do
      {
        BitBuf <<= 1;				// remove Bit
        BitCount --;
        if(BitCount == 0)			// must reload
        {
          if(SrcLen == 0)			// no more data, error !
            return(-7);				// match length error
           BitBuf = ((BIT32) SrcBuf[SrcOff++] & 0xFF) << 24;// get next data
	   SrcLen--;
           BitCount = 8;
        }
        if((BitBuf & 0x80000000) == 0)		// found delimiter
          break;
        Count--;
      }while(Count != 0);

      if(Count == 0)				// too many '1' bits !!
        return(-8);
      //------------------------------------------------------
      // Zero Bit found, remove bit, get needed following bits
      //------------------------------------------------------
      MatchLen -= Count;          		// get number of needed bits
      BitBuf <<= 1;      			// remove Zero Bit
      BitCount --;
      while(BitCount < (int) MatchLen)
      {
        if(SrcLen == 0)			// no more data, error !
          return(-8);
        BitBuf |= 
	  ((BIT32) SrcBuf[SrcOff++] & 0xFF) << (24-BitCount); // get Data
        SrcLen--;
        BitCount += 8;			// increment counter
      }
      //------------------------------------------------------
      // Decode the (loaded bits) into Match-Length
      //------------------------------------------------------
      Count = (int) MatchLen;			// save Bit Count for add.

      MatchLen =  (((BitBuf >> (32-Count)) & // get the length bits 
                  (~(0xFFFFFFFF << Count))) |	// remove leader bits (!)
	          ((BIT32) 1 << Count));	// add the Base

      BitBuf <<= Count;				// remove bits
      BitCount -= Count;			// dto.
    } // else long Matchlen 
    //------------------------------------------------------------
    // 3.3.3 Copy Data from Current Dictionary Index - Offset for
    //       Matchlength to Current Dictionary Index, obey Wrap
    //	     Around of Source !!.
    //	     NOTE: 1) There is NO Wrap around for Destination !
    //       ----- 2) Wrapped Source Start + MatchLen may not Wrap !
    //------------------------------------------------------------
    if((DictIndex + MatchLen) > DictSize) // check if inside buffer
      return(-9);
    SrcIndex = DictIndex - Offset;		// Start of Copy
    if(SrcIndex < 0)				// we have a WRAP around !
    {
      SrcIndex += DictSize;		// wrap the Bufferpointer
      if(SrcIndex + MatchLen > DictSize)	// is illegal ??
        return(-10);
    }

    // NOTE: Can't do Array Copy here as Source and Destination
    // ----- may overlap !!

//    Count = MatchLen;

//    fprintf(stdout,"Copy now, Start: 0x%08lX, Len: 0x%08lX, Dest: 0x%08lX\n",
//		SrcIndex,MatchLen, DictIndex);
    do
    {
      DictBuf[DictIndex++] = DictBuf[SrcIndex++];
      MatchLen--;
    }while(MatchLen != 0);
//    BIT8_ARRAY_COPY(DictBuf,SrcIndex,DictBuf,DictIndex,MatchLen);
//    DictIndex += MatchLen;
    continue;
  } // Decompresion loop
  //------------------------------------------------------------
  // Set Output Buffer, offset and length
  //------------------------------------------------------------
  pActDictIndex[0] = DictIndex;
  pDstBuf[0] = DictBuf;
  pDstOff[0] = DictStartIndex;		// Start of Data
  pDstLen[0] = DictIndex - DictStartIndex;
  return(0);
}

#ifdef JAVA
}
#endif
