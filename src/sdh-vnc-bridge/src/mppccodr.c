#define XH_INTERFACE 

//***************************************************************
// The MPPC Compressor / Decompressor, adhering to the
// UCDRDEF1.H defined DCDRFIELD structure calling convention (Version1)
// or hob-cdrdef1.h (Version2)
// NOTE: Can only be compiled for C/C++
// -----
//
// Date: 09.07.2001	Version 0	G.O.
// Date: 22.10.2004	Version 1	G.O. with memory manager
// Date: 13.12.2006	Version 2	G.O. with new XH Interface
//
//***************************************************************
#if !defined XH_MPPC_INTF_VERSION
#error XH_MPPC_INTF_VERSION not defined, STOP!
#endif

#include "mppccmp.h"
#include "mcdrdef.h"
#include <memory.h>


//===============================================================
// Memory manager initial size information callback
//
// Input parameters: HMEMINFO * pMemInfoStruc
// Returns: int Status, 0 - o.k., else error occured
//===============================================================
PRIVATE STATIC int DCDRInfoCallback(HMEMINFO * pMemInfoStruc)
{
  if(pMemInfoStruc == NULL)
    return(-1);

  if(pMemInfoStruc->InfoStrucSize != sizeof(HMEMINFO))
    return(-2);

  //------------------------------------------------------------
  // Setup desired managed buffer block sizes 
  // Note: at the moment minimal size is 32 !!
  //------------------------------------------------------------
  pMemInfoStruc->InitialByte16BlockCount = 32;
  pMemInfoStruc->InitialByte32BlockCount = 32;
  pMemInfoStruc->InitialByte64BlockCount = 32;
  pMemInfoStruc->InitialByte256BlockCount = 32;
  pMemInfoStruc->InitialByte512BlockCount = 32;
  return(0);
}




//===============================================================
// Reallocate a Buffer through helper Interface
// NOTE: Data above present data are NOT cleared !!
// -----
//
// Input Parameters:	DCDRFIELD *dcdf		Calling Structure
//			BIT8PTR   pBuf		Input Buffer
//			BIT32	  DataLen	Current length of Data
//			BIT32	  NewSize	Required length of Buffer
//			BIT8PPTR  ppNewBuf	New allocated buffer/old one
// Returns: int Status, 0 - o.k., else allocation failed/Parameter Error
//================================================================
PRIVATE STATIC int ReallocBuffer(HMEM_CTX_DEF
	 BIT8PTR pBuf, BIT32 DataLen, BIT32 NewSize, BIT8PPTR ppNewBuf)
{
  BIT8PTR pNewBuf;
  //----------------------------------------------------------
  // Check Parameters first (remove later)
  //----------------------------------------------------------
  if((pBuf == NULL) || (ppNewBuf == NULL) ||
     (NewSize <= 0))
    return(-1);
  //----------------------------------------------------------
  // Allocate new buffer through Auxiliary routine
  //----------------------------------------------------------
  ppNewBuf[0] = pBuf;
  if((pNewBuf = BIT8_ARRAY_ALLOC_POOL(HMEM_CTX_REF,(int) NewSize)) == NULL)
    return(-2);
  ppNewBuf[0] = pNewBuf;
  //----------------------------------------------------------
  // Copy Data up to min(NewSize,DataLen) from Old to new
  //----------------------------------------------------------
  if(DataLen >= NewSize)		// is larger, so must limit
    DataLen = NewSize;			// limit to buffer size
  memcpy(pNewBuf,pBuf,(int) DataLen);	// copy data till end
  //----------------------------------------------------------
  // free the old buffer
  //----------------------------------------------------------
  FREE_ARRAY_POOL(HMEM_CTX_REF,pBuf)
  return(0);
}

//===============================================================
// Free Temporary Buffers used for Coder
//
// Input Parameters:	DCDRFIELD *dcdf		Calling Structure
//			ENC_PTR * pEncStru	Coder Structure Pointer
// Returns: Nothing
//================================================================
PRIVATE STATIC void FreeTmpBuffers(HMEM_CTX_DEF ENC_PTR(pEncStru))
{
  if(pEncStru == NULL)
    return;
  //----------------------------------------------------
  // Free temporary Buffers if used, invalidate pointers
  //----------------------------------------------------
  FREE_ARRAY_POOL(HMEM_CTX_REF, ENC_PSRC_GATHER_BUF(pEncStru));
  FREE_ARRAY_POOL(HMEM_CTX_REF, ENC_PTMP_DSTBUF(pEncStru));
}
//===============================================================
// Re-Initialize the Dictionary, clear the in use Flag
//
// Input Parameters:	ENC_PTR * pEncStru	Coder Structure Pointer
// Returns: Nothing
//================================================================
PRIVATE STATIC void ReInitDictionary(ENC_PTR(pEncStru))
{
  if((pEncStru == NULL) || (ENC_PDICT_STRU(pEncStru) == NULL))
    return;
  MPPC_DICT_STRUC_INIT(MPPCCOMPinst,ENC_PDICT_STRU(pEncStru),0,1);
  ENC_DICT_IN_USE_FLAG(pEncStru) = 0;
}


//===============================================================
// Free Elements of a Coder Control Structure and the Structure itself
//
// Input Parameters:	DCDRFIELD * dcdf	Calling Structure
// Returns: Nothing
//================================================================
PRIVATE STATIC void FreeCoderCtrlStruc(HMEM_CTX_DEF DCDRFIELD *dcdf)
{
  ENC_PTR(pEncStru);
#if defined XH_INTERFACE
  ds__hmem TmpMemCtxStruc;
#endif

  pEncStru = (ENC_PTR_REF) dcdf->aext;
  if(pEncStru == NULL)
    return;

#if defined XH_INTERFACE
  memcpy(&TmpMemCtxStruc,&ENC_MemCtxStruc(pEncStru),sizeof(ds__hmem));
  if(ENC_pMemCtxStruc(pEncStru) != NULL)
  {
    vp__ctx = &TmpMemCtxStruc;
    ((ds__hmem *) vp__ctx)->in__flags &= (~HMEM_LOCKED_STRUC_FLAG_BIT);	// unlock !
  }
#endif // XH_INTERFACE

  //----------------------------------------------------
  // Free temporary Buffers if used, invalidate pointers
  //----------------------------------------------------
  FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
  //----------------------------------------------------
  // Free the Dictionary/Hashtable Control Structure
  //----------------------------------------------------
  MPPC_FREE_DICT(MPPCCOMPRinst, HMEM_CTX_REF,
		 ENC_PDICT_STRU(pEncStru));
  ENC_PDICT_STRU(pEncStru) = NULL;
  //----------------------------------------------------
  // Free the Control Structure self
  //----------------------------------------------------
  FREE_CARRAY(HMEM_CTX_REF,pEncStru);
  MEMMGR_FREE(HMEM_CTX_REF);		// release management structs

  dcdf->aext = NULL;
}


//===============================================================
// Allocate a new Coder Control Structure and the Dictionary/
// Hashtable (if needed), initialize them with zeros
//
// Input Parameters:	DCDRFIELD * dcdf	Calling Structure
//			int HashTabFlag		0 - no hash Table needed
// Returns: int Status - 0 o.k., else error occured
//================================================================
PRIVATE STATIC int AllocCoderCtrlStruc(HMEM_CTX_DEF
				  DCDRFIELD *dcdf, int HashTabFlag)
{
  int i,j;

  BIT32 Param;
  BIT32 DictSize;
  BIT32 HashTabSize = 0;
  
  ENC_PTR pEncStru;
  DICTSTRU_PTR pDictStruc;

  //-------------------------------------------------
  // Check Parameters specified from Calling Function
  //-------------------------------------------------
  Param = dcdf->ul_param_1;			// get Dictionary Size needed
  if(Param == VAL_SMALL_MPPC_DICT)		// use 8kB dictionary
    DictSize = MPPC_SMALL_DICT_SIZE;
  else if(Param == VAL_LARGE_MPPC_DICT)		// use 64kB dictionary
    DictSize = MPPC_LARGE_DICT_SIZE;
  else						// invalid Dictionary Size
  {
    dcdf->ireturn = DEF_IRET_ERRAU;		// signal Error
    return(-1);
  }
  if(HashTabFlag != 0)				// HAsh Table is required
  {
    HashTabSize = dcdf->ul_param_2;		// get size of Hash Table
    if(HashTabSize < VAL_SMALL_MPPC_HASHTAB)
    {
      dcdf->ireturn = DEF_IRET_ERRAU;		// signal Error
      return(-2);
    }
    //------------------------------------------------------------
    // check if size of Hashtable is a power of 2 (only 1 Bit set)
    //------------------------------------------------------------
    j = 0;
    i = 8 * sizeof (BIT32);
    Param = HashTabSize;
    do
    {
      if((Param & 0x01) != 0)			// found a set bit
      {
        if(j != 0)
          break;
        j = 1;
      }
      Param >>= 1;
      i--;
    }while(i != 0);
    if(i != 0)
    {
      dcdf->ireturn = DEF_IRET_ERRAU;		// signal Error
      return(-3);
    }
  }
  //-----------------------------------------------------
  // Allocate the Main Control Structure
  //-----------------------------------------------------
  if((pEncStru = (ENC_PTR)
       ((void *) BIT8_ARRAY_CALLOC(HMEM_CTX_REF,1,sizeof(MPENC)))) == NULL)
  {
    dcdf->ireturn = DEF_IRET_ERRAU;		// signal Error
    return(-4);
  }
//  memset(pEncStru,0,sizeof(MPENC));		// clear all

#if defined XH_INTERFACE
  //-----------------------------------------------------
  // Get a copy of the memory context structure
  //-----------------------------------------------------
  memcpy(&ENC_MemCtxStruc(pEncStru),vp__ctx,sizeof(ds__hmem));
  ENC_pMemCtxStruc(pEncStru) = &ENC_MemCtxStruc(pEncStru);

#endif // XH_INTERFACE

  //--------------------------------------------------------
  // Allocate the Dictionary and Hashtable Control Structure
  //--------------------------------------------------------
  pDictStruc = MPPC_ALLOC_DICT(MPPCCOMPinst, HMEM_CTX_REF,
			       DictSize,HashTabSize);
  if(pDictStruc == NULL)
  {
    FREE_CARRAY(HMEM_CTX_REF,pEncStru);
    dcdf->ireturn = DEF_IRET_ERRAU;		// signal Error
    return(-5);
  }
  ENC_PDICT_STRU(pEncStru) = pDictStruc;	// set Dictionary pointer

  MPPC_DICT_STRUC_INIT(MPPCCOMPinst,pDictStruc,1,0);

  dcdf->aext = (void *) pEncStru;
  return(0);
}      


//===============================================================
// Compressor Standard Mode Processing
//
// Input Parameters:	DCDRFIELD * dcdf	Calling Structure
//			ENC_PTR	* pEncStru	Coder Control Structure
// Returns: int Status - 0 o.k., else error occured
//================================================================
PRIVATE STATIC int DistributeCompressMode(HMEM_CTX_DEF
			DCDRFIELD * dcdf, ENC_PTR pEncStru)
{

  BIT8PTR pCompressSrcBuf;
  BIT8PTR pTmpDstBuf = NULL;

  BIT32 SrcDataLen;
  BIT32 DstBufLen;

  BIT32 MaxDictSize;
  BIT32 TmpBufSize;

  BIT32 StoredDataLen;
  BIT32 NewSrcDataLen;
  BIT32 CompressSrcDataLen;

  int Retcode;
  //----------------------------------------------------
  // Fetch the current active State and Src/DstBuf-Length,
  // check if valid (End Pointer >= Start Pointer)
  //----------------------------------------------------
  SrcDataLen = (int) (dcdf->ainpe - dcdf->ainpa);// get length input data
  DstBufLen  = (int) (dcdf->aoute - dcdf->aouta);// get length output buffer

  if((SrcDataLen < 0) || (DstBufLen < 0))
  {
    FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
    ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK; // Restart
    dcdf->ireturn = DEF_IRET_ERRAU;
    return(-1);
  }    
  //----------------------------------------------------
  // Distribute by current state
  //----------------------------------------------------
  switch(ENC_SUBSTATE(pEncStru))
  {
    //==================================================
    // A) Waiting for Source data to be presented
    //==================================================
    case WAIT_FIRST_SOURCE_BLOCK:
      dcdf->bo_sr_flush = FALSE;		// assume not all data yet
      //------------------------------------------------
      // Check if data are present on input at all
      //------------------------------------------------
      if(SrcDataLen  == 0)			// call with empty source...
      {
        if(dcdf->bo_mp_flush == FALSE)		// but more seems to come
          return(0);
        dcdf->ireturn = DEF_IRET_ERRAU;		// is an error (0 data)
        return(-2);
      }
      //------------------------------------------------
      // Data arrived, first check size
      //------------------------------------------------
      MaxDictSize = DICTSTRU_DictSize(ENC_PDICT_STRU(pEncStru))-2;
      if(SrcDataLen >= MaxDictSize)
      {
        dcdf->ireturn = DEF_IRET_OVERFLOW;
        return(-3);
      }
      //------------------------------------------------
      // Check if all data are present now
      //------------------------------------------------
      if(dcdf->bo_mp_flush == TRUE)		// all data present !!
      {
        pCompressSrcBuf    = (BIT8PTR) dcdf->ainpa;// set source of data
        CompressSrcDataLen = SrcDataLen;	// set length
        break;
      }
      //---------------------------------------------------------------
      // only first portion of Record received, must buffer data now...
      // 1. Allocate Buffer of at least 8kB up to 64kB in 4k Increments
      //---------------------------------------------------------------
      TmpBufSize = MIN_GATHER_BUF_SIZE;
      if(SrcDataLen >= TmpBufSize)	// above minimum
      {
        TmpBufSize =
          ((((SrcDataLen - MIN_GATHER_BUF_SIZE) + GATHER_BUF_INCREMENT) /
            GATHER_BUF_INCREMENT) * GATHER_BUF_INCREMENT)
           + MIN_GATHER_BUF_SIZE;
      }
      if((pTmpDstBuf = BIT8_ARRAY_ALLOC_POOL(HMEM_CTX_REF,
					     (int) TmpBufSize)) == NULL)
      {
        dcdf->ireturn = DEF_IRET_ERRAU;		// allocate failure
        return(-4);
      }
      //---------------------------------------------------------------
      // 2. Copy Data to buffer, save sizes and length
      //---------------------------------------------------------------
      memcpy(pTmpDstBuf,dcdf->ainpa,(int) SrcDataLen);	// copy data
      dcdf->ainpa = dcdf->ainpe;			// empty source
      ENC_PSRC_GATHER_BUF(pEncStru) = pTmpDstBuf;	// save buffer ptr
      ENC_SRC_GATHER_BUFSIZE(pEncStru) = TmpBufSize;	// save buffer size
      ENC_SRC_GATHER_DATALEN(pEncStru) = SrcDataLen;	// save data length
      //---------------------------------------------------------------
      // 3. Set continue State
      //---------------------------------------------------------------
      ENC_SUBSTATE(pEncStru) = WAIT_MORE_SOURCE_BLOCKS;
      return(0);

    //==================================================
    // B) Waiting for more Source data to be presented
    //==================================================
    case WAIT_MORE_SOURCE_BLOCKS:
      dcdf->bo_sr_flush = FALSE;		// assume not all data yet
      StoredDataLen = ENC_SRC_GATHER_DATALEN(pEncStru);
      //------------------------------------------------
      // Check if data are present on input at all
      //------------------------------------------------
      if(SrcDataLen  == 0)			// call with empty source...
      {
        if(dcdf->bo_mp_flush == FALSE)		// but more seems to come
          return(0);
        pCompressSrcBuf    = ENC_PSRC_GATHER_BUF(pEncStru);	// set source of data
        CompressSrcDataLen = StoredDataLen;	// set length
        break;					// now all data present !
      }
      //------------------------------------------------------
      // more data present, check total length first
      //------------------------------------------------------
      NewSrcDataLen = SrcDataLen + StoredDataLen;
      MaxDictSize = DICTSTRU_DictSize(ENC_PDICT_STRU(pEncStru))-2;
      if(NewSrcDataLen >= MaxDictSize)
      {
        FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
        ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK;
        dcdf->ireturn = DEF_IRET_OVERFLOW;
        return(-3);
      }
      //---------------------------------------------------------
      // copy new data to buffer if enough space, else reallocate
      //---------------------------------------------------------
      TmpBufSize = ENC_SRC_GATHER_BUFSIZE(pEncStru);
      if(NewSrcDataLen <= TmpBufSize)
      {
        //-------------------------------------------------------
        // Data fit into buffer, so copy, check if last block
        //-------------------------------------------------------
        memcpy(ENC_PSRC_GATHER_BUF(pEncStru)+StoredDataLen,
               dcdf->ainpa,(int) SrcDataLen);
        dcdf->ainpa = dcdf->ainpe;
        ENC_SRC_GATHER_DATALEN(pEncStru) = NewSrcDataLen;
        if(dcdf->bo_mp_flush == FALSE)		// not yet last data block...
          return(0);
        pCompressSrcBuf    = ENC_PSRC_GATHER_BUF(pEncStru);	// set source of data
        CompressSrcDataLen = NewSrcDataLen;	// set length
        break;					// all data present now
      }
      else
      {
        pTmpDstBuf = ENC_PSRC_GATHER_BUF(pEncStru);
        //---------------------------------------------------------
        // Data don't fit into buffer, must reallocate,check how...
        //---------------------------------------------------------
        if(dcdf->bo_mp_flush == TRUE)		// is last block
        {
          //----------------------------------------------------------
          // Is last data block for record, allocate as long as needed
          //----------------------------------------------------------
          Retcode = ReallocBuffer(HMEM_CTX_REF1
				  pTmpDstBuf, StoredDataLen,
                                  NewSrcDataLen, &pTmpDstBuf);
          ENC_PSRC_GATHER_BUF(pEncStru)    = pTmpDstBuf; // set new/old
          ENC_SRC_GATHER_BUFSIZE(pEncStru) = NewSrcDataLen; 
          if(Retcode != 0)
          {
            FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
            ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK;
            dcdf->ireturn = DEF_IRET_ERRAU;
            return(-4);
          }
          memcpy(pTmpDstBuf+StoredDataLen,dcdf->ainpa,(int) SrcDataLen);
          dcdf->ainpa = dcdf->ainpe;
          ENC_SRC_GATHER_DATALEN(pEncStru) = NewSrcDataLen;
          pCompressSrcBuf    = pTmpDstBuf;	// set source of data
          CompressSrcDataLen = NewSrcDataLen;	// set length
          break;				// all data gathered
        }
        else					// not yet last block...
        {
          //----------------------------------------------------------
          // Is not last data block for record, allocate in increments
          //----------------------------------------------------------
          TmpBufSize =
            ((((NewSrcDataLen - MIN_GATHER_BUF_SIZE) + GATHER_BUF_INCREMENT) /
            GATHER_BUF_INCREMENT) * GATHER_BUF_INCREMENT)
            + MIN_GATHER_BUF_SIZE;

          Retcode = ReallocBuffer(HMEM_CTX_REF1
				  pTmpDstBuf, StoredDataLen,
                                  TmpBufSize, &pTmpDstBuf);
          ENC_PSRC_GATHER_BUF(pEncStru)    = pTmpDstBuf; // set new/old
          ENC_SRC_GATHER_BUFSIZE(pEncStru) = TmpBufSize; 
          if(Retcode != 0)
          {
            FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
            ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK;
            dcdf->ireturn = DEF_IRET_ERRAU;
            return(-4);
          }
          memcpy(pTmpDstBuf+StoredDataLen,dcdf->ainpa,(int) SrcDataLen);
          dcdf->ainpa = dcdf->ainpe;
          ENC_SRC_GATHER_DATALEN(pEncStru) = NewSrcDataLen;
          return(0);					// wait for more data
        }
      }
    //==================================================
    // C) Waiting for first Destination buffer
    //==================================================
    case WAIT_FIRST_DSTBUF_BLOCK:
      dcdf->bo_compressed = TRUE;		// always "compressed" mode
      dcdf->bo_sr_flush   = FALSE;		// not complete yet
      if(DstBufLen == 0)			// still no buffer given
        return(0);
      //----------------------------------------------------------
      // Output at least the Compression Flags
      //----------------------------------------------------------
      *(dcdf->aouta) = ENC_COMPRESS_FLAGS(pEncStru);
      dcdf->aouta++;
      DstBufLen--;
      if(DstBufLen == 0)			// buffer filled
      {
        ENC_SUBSTATE(pEncStru) = WAIT_MORE_DSTBUF_BLOCKS; // next state
        return(0);
      }
      //----------------------------------------------------------
      // More Data can be transfered, transfer as much as possible
      //----------------------------------------------------------
      SrcDataLen = ENC_CMPR_OUT_DATALEN(pEncStru);
      if(SrcDataLen <= DstBufLen)
      {
        //--------------------------------------------------------
        // All Data fit into Destination buffer, copy
        //--------------------------------------------------------
        pCompressSrcBuf = ENC_PCMPR_OUTBUF(pEncStru);	// get Source
        memcpy(dcdf->aouta,pCompressSrcBuf,(int) SrcDataLen); // copy data
        dcdf->aouta += SrcDataLen;			// advance pointer
        //-----------------------------------------------------------
        // Free used buffers, take care of Single Source Record Mode!
        //-----------------------------------------------------------
        if(ENC_PSRC_GATHER_BUF(pEncStru) == NULL)	// direct from Input
          dcdf->ainpa = dcdf->ainpe;			// 'free' buffer
        FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
        ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK; // next state
        dcdf->bo_sr_flush   = TRUE;			// now complete
      }
      else
      {
        //--------------------------------------------
        // Not all data fit into destination buffer...
        //--------------------------------------------
        SrcDataLen = DstBufLen;				// limit length
        pCompressSrcBuf = ENC_PCMPR_OUTBUF(pEncStru);	// get Source
        memcpy(dcdf->aouta,pCompressSrcBuf,(int) SrcDataLen);	// copy data
        dcdf->aouta += SrcDataLen;			// advance pointer
        ENC_CMPR_OUT_DATALEN(pEncStru) -= SrcDataLen;	// reduce length
        ENC_CMPR_OUT_DATA_INDEX(pEncStru) = SrcDataLen;	// advance Index
        ENC_SUBSTATE(pEncStru) = WAIT_MORE_DSTBUF_BLOCKS;   // next state
      }
      return(0);
    //==================================================
    // D) Waiting for more Destination buffers
    //==================================================
    case WAIT_MORE_DSTBUF_BLOCKS:
      dcdf->bo_compressed = TRUE;		// always "compressed" mode
      dcdf->bo_sr_flush   = FALSE;		// not complete yet
      if(DstBufLen == 0)			// no buffer given
        return(0);

      SrcDataLen = ENC_CMPR_OUT_DATALEN(pEncStru);
      if(SrcDataLen <= DstBufLen)
      {
        //--------------------------------------------------------
        // All Data fit into Destination buffer, copy
        //--------------------------------------------------------
        pCompressSrcBuf = ENC_PCMPR_OUTBUF(pEncStru);	// get Source
        memcpy(dcdf->aouta,				// copy data
               pCompressSrcBuf+ENC_CMPR_OUT_DATA_INDEX(pEncStru),
	       (int) SrcDataLen);
        dcdf->aouta += SrcDataLen;			// advance pointer
        //-----------------------------------------------------------
        // Free used buffers, take care of Single Source Record Mode!
        //-----------------------------------------------------------
        if(ENC_PSRC_GATHER_BUF(pEncStru) == NULL)	// direct from Input
          dcdf->ainpa = dcdf->ainpe;			// 'free' buffer
        FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
        ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK; // next state
        dcdf->bo_sr_flush   = TRUE;			// now complete
      }
      else
      {
        //--------------------------------------------
        // Not all data fit into destination buffer...
        //--------------------------------------------
        SrcDataLen = DstBufLen;				// limit length
        pCompressSrcBuf = ENC_PCMPR_OUTBUF(pEncStru);	// get Source
        memcpy(dcdf->aouta,				// copy data
               pCompressSrcBuf+ENC_CMPR_OUT_DATA_INDEX(pEncStru),
	       (int) SrcDataLen);
        dcdf->aouta += SrcDataLen;			// advance pointer
        ENC_CMPR_OUT_DATALEN(pEncStru) -= SrcDataLen;	// reduce length
        ENC_CMPR_OUT_DATA_INDEX(pEncStru) += SrcDataLen;// advance Index
      }
      return(0);

    //===========================================================
    // E) Unrecognized substate (should not happen, remove later)
    //===========================================================
    default:
      FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
      ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK;
      dcdf->ireturn = DEF_IRET_ERRAU;
      return(-99);
  } // switch
  //--------------------------------------------------------------
  // All source data are present, check if to send as uncompressed
  // NOTE: don't touch Dictionary in this case !!!
  //--------------------------------------------------------------
  ENC_CMPR_OUT_DATA_INDEX(pEncStru) = 0;	// set start index zero
  if(CompressSrcDataLen < VAL_DATALEN_LOW_LIMIT)
  {
    //--------------------------------------------------------
    // Send direct from Source (either direct or buffered),
    // don't touch Dictionary State
    //--------------------------------------------------------
    ENC_PCMPR_OUTBUF(pEncStru) = pCompressSrcBuf;	 // Copy from Source
    ENC_CMPR_OUT_DATALEN(pEncStru) = CompressSrcDataLen; // set the length    
    ENC_COMPRESS_FLAGS(pEncStru) = 0;		// not compressed !!
  }
  else
  {
    //--------------------------------------------------------
    // Allocate buffer for Compression Output, compress
    //--------------------------------------------------------
    if((pTmpDstBuf = BIT8_ARRAY_ALLOC_POOL(HMEM_CTX_REF,
				           (int) CompressSrcDataLen)) == NULL)
    {
      FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
      ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK;
      dcdf->ireturn = DEF_IRET_ERRAU;
      return(-5);
    }
    ENC_PTMP_DSTBUF(pEncStru) = pTmpDstBuf;	// save buffer
    TmpBufSize = CompressSrcDataLen;		// set length for Compress
    //-------------------------------------------------------------
    // Compress Source Data now
    // NOTE: don't touch Dictionary in this case !!!
    //-------------------------------------------------------------
    Retcode = MPPC_COMPRESS(MPPCCOMPinst,
			    pCompressSrcBuf, 0, (int) CompressSrcDataLen,
                            pTmpDstBuf, 0, (int *) &TmpBufSize,
                            ENC_PDICT_STRU(pEncStru));
    //-------------------------------------------------------------
    // Check if uncompressed Data length is smaller than compressed
    //-------------------------------------------------------------
//    if((Retcode & MPPC_DICT_CLEARED_BIT) != 0)	 // -> uncompressed is smaller
    if((Retcode & MPPC_COMPRESSED_BIT) == 0)	// not compressible
    {
      //--------------------------------------------------------
      // Uncompressed Data is smaller than compressed, copy from
      // Source (either direct or buffered), free Destination buffer,
      // save Dictionary Cleared Condition
      //--------------------------------------------------------
      ENC_PCMPR_OUTBUF(pEncStru) = pCompressSrcBuf;	 // Copy from Source
      ENC_CMPR_OUT_DATALEN(pEncStru) = CompressSrcDataLen; // set the length

      FREE_ARRAY_POOL(HMEM_CTX_REF,ENC_PTMP_DSTBUF(pEncStru)); // free buffer
//      ENC_PTMP_DSTBUF(pEncStru) = NULL;

      ENC_DICT_IN_USE_FLAG(pEncStru) = 0;	// dictionary was cleared
      ENC_COMPRESS_FLAGS(pEncStru) = 0;		// not compressed
    }
    else					// compressed is smaller
    {
      //--------------------------------------------------------
      // Compressed Data is smaller than uncompressed, copy from
      // Allocated Destination Buffer, free the source now
      //--------------------------------------------------------
      ENC_PCMPR_OUTBUF(pEncStru) = pTmpDstBuf;	 // Copy from Destination
      ENC_CMPR_OUT_DATALEN(pEncStru) = TmpBufSize; // set the length    
      if(ENC_PSRC_GATHER_BUF(pEncStru) != NULL)	 // free Source Gather buffer
      {
        FREE_ARRAY_POOL(HMEM_CTX_REF,ENC_PSRC_GATHER_BUF(pEncStru));
//      ENC_PSRC_GATHER_BUF(pEncStru) = NULL;	// invalidate pointer
      }        
      else					 // free the direct source
        dcdf->ainpa = dcdf->ainpe;
      if(ENC_DICT_IN_USE_FLAG(pEncStru) == 0)	// Dictionary was not in use
      {
        Retcode |= MPPC_DICT_CLEARED_BIT;	// Signal clear Dict.
        Retcode &= (~MPPC_RESET_PTR_BIT);	// Pointer is reset automatic
        ENC_DICT_IN_USE_FLAG(pEncStru) = 1;	// now is used
      }
      ENC_COMPRESS_FLAGS(pEncStru) = (BIT8) Retcode;	// set the flags
    }
  }
  //-------------------------------------------------------------------------
  // Data are ready for Transfer to Destination buffer, check State of Buffer
  //-------------------------------------------------------------------------
  dcdf->bo_compressed = TRUE;			// always "compressed" mode
  dcdf->bo_sr_flush   = FALSE;			// not complete
  ENC_SUBSTATE(pEncStru) = WAIT_FIRST_DSTBUF_BLOCK; // next state
  if(DstBufLen == 0)				// no buffer given
    return(0);
  //----------------------------------------------------------
  // Output at least the Compression Flags
  //----------------------------------------------------------
  *(dcdf->aouta) = ENC_COMPRESS_FLAGS(pEncStru);
  dcdf->aouta++;
  DstBufLen--;
  if(DstBufLen == 0)				// buffer filled
  {
    ENC_SUBSTATE(pEncStru) = WAIT_MORE_DSTBUF_BLOCKS; // next state
    return(0);
  }
  //----------------------------------------------------------
  // More Data can be transfered, transfer as much as possible
  //----------------------------------------------------------
  SrcDataLen = ENC_CMPR_OUT_DATALEN(pEncStru);
  if(SrcDataLen <= DstBufLen)
  {
    //--------------------------------------------------------
    // All Data fit into Destination buffer, copy
    //--------------------------------------------------------
    pCompressSrcBuf = ENC_PCMPR_OUTBUF(pEncStru);	// get Source
    memcpy(dcdf->aouta,pCompressSrcBuf,(int) SrcDataLen);// copy data
    dcdf->aouta += SrcDataLen;				// advance pointer
    //-----------------------------------------------------------
    // Free used buffers, take care of Single Source Record Mode!
    //-----------------------------------------------------------
    if(ENC_PSRC_GATHER_BUF(pEncStru) == NULL)		// direct from Input
      dcdf->ainpa = dcdf->ainpe;			// 'free' buffer
    FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
    ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK; // next state
    dcdf->bo_sr_flush   = TRUE;				// now complete
    return(0);
  }
  else
  {
    //--------------------------------------------------------
    // Not all data fit into destination buffer...
    //--------------------------------------------------------
    SrcDataLen = DstBufLen;				// limit length
    pCompressSrcBuf = ENC_PCMPR_OUTBUF(pEncStru);	// get Source
    memcpy(dcdf->aouta,pCompressSrcBuf,(int) SrcDataLen);// copy data
    dcdf->aouta += SrcDataLen;				// advance pointer
    ENC_CMPR_OUT_DATALEN(pEncStru) -= SrcDataLen;	// reduce length
    ENC_CMPR_OUT_DATA_INDEX(pEncStru) = SrcDataLen;	// advance Index
    ENC_SUBSTATE(pEncStru) = WAIT_MORE_DSTBUF_BLOCKS;   // next state
    return(0);
  }
}

//===============================================================
// MPPC-Compressor Function CDRENC / m_cdr_enc
//
// Input Parameters:	DCDRFIELD * dcdf	The Calling Structure
// Returns: Nothing (Returncode placed in Structure)
//===============================================================
#if XH_MPPC_INTF_VERSION < 200
PUBLIC STATIC void CDRENC(DCDRFIELD * dcdf)
#else
PUBLIC STATIC void m_cdr_enc(DCDRFIELD * dcdf)
#endif
{
  int Retcode;

  ENC_PTR pEncStru;

  ds__hmem TmpMemCtxStruc;
  HMEM_CTX_DEF1;

  LOAD_HMEM_CTX_PTR(NULL);

  //---------------------------------------------------
  // Distribute by Calling Function Mode
  //---------------------------------------------------
  if(dcdf == NULL)				// primary sanity check
    return;

  if(dcdf->uaux == NULL)			// ALLOC/FREE sanity check !!!
  {
    dcdf->ireturn = DEF_IRET_ERRAU;		// signal Error
    return;
  }

  //--------------------------------------------------------
  // Fetch general parameters, set default returncode
  //--------------------------------------------------------
  pEncStru = (ENC_PTR) dcdf->aext;		// get controlling structure
  dcdf->ireturn = DEF_IRET_NORMAL;		// assume o.k.
  //--------------------------------------------------------
  // Distribute by Function type requested
  //--------------------------------------------------------
  switch(dcdf->ifunc)
  {
    //-------------------------------------------------------
    // Initialization requested, check if already initialized
    //-------------------------------------------------------
    case DEF_IFUNC_START:
      if(pEncStru != NULL)			// is already initialized
      {
        dcdf->ireturn = DEF_IRET_ERRAU;		// signal Error
        return;
      }
      //----------------------------------------------------
      // Allocate the Structures required
      //----------------------------------------------------
      dcdf->ul_save_mp_needed = 0;		// no additional buffer needed

      memset(&TmpMemCtxStruc,0,sizeof(TmpMemCtxStruc));

      TmpMemCtxStruc.in__struc_size       = sizeof(ds__hmem);
      TmpMemCtxStruc.in__flags		  = HMEM_STRUC_LOCAL_FLAG_BIT;
      TmpMemCtxStruc.pMemSizeInfoCallback = DCDRInfoCallback;
//      TmpMemCtxStruc.pHmemDesc            = NULL;
#if XH_MPPC_INTF_VERSION < 200
//      TmpMemCtxStruc.in__aux_up_version   = 0;
//      TmpMemCtxStruc.vp__context          = NULL;
      TmpMemCtxStruc.am__aux1             = dcdf->uaux;
//      TmpMemCtxStruc.am__aux2             = NULL;
#else
      TmpMemCtxStruc.in__aux_up_version   = 1;
      TmpMemCtxStruc.vp__context          = dcdf->vpc_userfld;
//      TmpMemCtxStruc.am__aux1             = NULL;
      TmpMemCtxStruc.am__aux2             = dcdf->uaux;
#endif

      LOAD_HMEM_CTX_PTR(&TmpMemCtxStruc);	// get correct context !!

      if(AllocCoderCtrlStruc(HMEM_CTX_REF1
			     dcdf, 1) == 0)	// allocate Structure / Buffs.
        dcdf->ifunc = DEF_IFUNC_CONT;		// without error
      else
        dcdf->ireturn = DEF_IRET_ERRAU;		// signal error
      return;

    //----------------------------------------------------------
    // Continue Mode requested, check if initialized
    //----------------------------------------------------------
    case DEF_IFUNC_CONT:
      if(pEncStru == NULL)			// is NOT initialized
      {
        dcdf->ireturn = DEF_IRET_ERRAU;		// signal Error
        return;
      }
#if XH_MPPC_INTF_VERSION >= 200
      ENC_pMemCtxStruc(pEncStru)->vp__context = dcdf->vpc_userfld;
#endif

      LOAD_HMEM_CTX_PTR(ENC_pMemCtxStruc(pEncStru));

      Retcode = DistributeCompressMode(HMEM_CTX_REF1 dcdf, pEncStru);
      return;

    //----------------------------------------------------------
    // Dictionary Reset Requested, check state
    //----------------------------------------------------------
    case DEF_IFUNC_RESET:
      if(pEncStru == NULL)			// is NOT initialized
      {
        dcdf->ireturn = DEF_IRET_ERRAU;		// signal Error
        return;
      }
#if XH_MPPC_INTF_VERSION >= 200
      ENC_pMemCtxStruc(pEncStru)->vp__context = dcdf->vpc_userfld;
#endif
      LOAD_HMEM_CTX_PTR(ENC_pMemCtxStruc(pEncStru));

      if(ENC_SUBSTATE(pEncStru) != WAIT_FIRST_SOURCE_BLOCK)
      {
        FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
        ReInitDictionary(pEncStru);
        dcdf->ireturn = DEF_IRET_ERRAU;
        ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK;
        return;
      }
      ReInitDictionary(pEncStru);
      return;

    //----------------------------------------------------------
    // End of Processing requested, free all regardless of state
    //----------------------------------------------------------
    case DEF_IFUNC_END:
      if(pEncStru == NULL)		// SHOULD NOT HAPPEN !!!
      {
        memset(&TmpMemCtxStruc,0,sizeof(TmpMemCtxStruc));

        TmpMemCtxStruc.in__struc_size       = sizeof(ds__hmem);
        TmpMemCtxStruc.in__flags	    = HMEM_STRUC_LOCAL_FLAG_BIT;
        TmpMemCtxStruc.pMemSizeInfoCallback = DCDRInfoCallback;
//        TmpMemCtxStruc.pHmemDesc            = NULL;
#if XH_MPPC_INTF_VERSION < 200
//        TmpMemCtxStruc.in__aux_up_version   = 0;
//        TmpMemCtxStruc.vp__context          = NULL;
        TmpMemCtxStruc.am__aux1             = dcdf->uaux;
//        TmpMemCtxStruc.am__aux2             = NULL;
#else
        TmpMemCtxStruc.in__aux_up_version   = 1;
        TmpMemCtxStruc.vp__context          = dcdf->vpc_userfld;
//        TmpMemCtxStruc.am__aux1             = NULL;
        TmpMemCtxStruc.am__aux2             = dcdf->uaux;
#endif

        LOAD_HMEM_CTX_PTR(&TmpMemCtxStruc);	// get correct context !!
      }
      else
      {
#if XH_MPPC_INTF_VERSION >= 200
        ENC_pMemCtxStruc(pEncStru)->vp__context = dcdf->vpc_userfld;
#endif
        LOAD_HMEM_CTX_PTR(ENC_pMemCtxStruc(pEncStru));
      }

      FreeCoderCtrlStruc(HMEM_CTX_REF1 dcdf);
      dcdf->ireturn = DEF_IRET_END;
      return;

    //---------------------------------------------
    // Invalid Fucntion Code received, signal Error
    //---------------------------------------------
    default:
      dcdf->ireturn = DEF_IRET_ERRAU;
      return;
  }  
}

//===============================================================
// Decompressor Standard Mode Processing
//
// Input Parameters:	DCDRFIELD * dcdf	Calling Structure
//			ENC_PTR	* pEncStru	Decoder Control Structure
// Returns: int Status - 0 o.k., else error occured
//================================================================
PRIVATE STATIC int DistributeDecompressMode(HMEM_CTX_DEF
		DCDRFIELD * dcdf, ENC_PTR pEncStru)
{
  BIT8PTR pDecompressSrcBuf;
  BIT8PTR pTmpDstBuf;

  BIT8  CmprFlags;

  BIT32 SrcDataLen;
  BIT32 DstBufLen;

  BIT32 MaxDictSize;
  BIT32 TmpBufSize;

  BIT32 StoredDataLen;
  BIT32 NewSrcDataLen;
  BIT32 DecompressSrcDataLen;

  int Retcode;
  int LargeDictFlag;

  DICTSTRU_PTR pDictStru;

  //----------------------------------------------------
  // Fetch the current active State and Src/DstBuf-Length,
  // check if valid (End Pointer >= Start Pointer)
  //----------------------------------------------------
  SrcDataLen = (int) (dcdf->ainpe - dcdf->ainpa);// get length input data
  DstBufLen  = (int) (dcdf->aoute - dcdf->aouta);// get length output buffer

  if((SrcDataLen < 0) || (DstBufLen < 0))
  {
    FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
    ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK; // Restart
    dcdf->ireturn = DEF_IRET_ERRAU;
    return(-1);
  }    
  //----------------------------------------------------
  // Distribute by current state
  //----------------------------------------------------
  switch(ENC_SUBSTATE(pEncStru))
  {
    //==================================================
    // A) Waiting for Source data to be presented
    //==================================================
    case WAIT_FIRST_SOURCE_BLOCK:
      dcdf->bo_sr_flush = FALSE;		// assume not all data yet
      //------------------------------------------------
      // Check if data are present on input at all
      //------------------------------------------------
      if(SrcDataLen  == 0)			// call with empty source...
      {
        if(dcdf->bo_mp_flush == FALSE)		// but more seems to come
          return(0);
        dcdf->ireturn = DEF_IRET_ERRAU;		// is an error (0 data)
        return(-2);
      }
      //------------------------------------------------
      // Data arrived, first check size
      //------------------------------------------------
      MaxDictSize = DICTSTRU_DictSize(ENC_PDICT_STRU(pEncStru))-2;
      if(SrcDataLen >= MaxDictSize)
      {
        dcdf->ireturn = DEF_IRET_OVERFLOW;
        return(-3);
      }
      //------------------------------------------------
      // Check if all data are present now
      //------------------------------------------------
      if(dcdf->bo_mp_flush == TRUE)		// all data present !!
      {
        pDecompressSrcBuf    = (BIT8PTR) dcdf->ainpa;	// set source of data
        DecompressSrcDataLen = SrcDataLen;	// set length
        break;
      }
      //---------------------------------------------------------------
      // only first portion of Record received, must buffer data now...
      // 1. Allocate Buffer of at least 8kB up to 64kB in 4k Increments
      //---------------------------------------------------------------
      TmpBufSize = MIN_GATHER_BUF_SIZE;
      if(SrcDataLen >= TmpBufSize)	// above minimum
      {
        TmpBufSize =
          ((((SrcDataLen - MIN_GATHER_BUF_SIZE) + GATHER_BUF_INCREMENT) /
            GATHER_BUF_INCREMENT) * GATHER_BUF_INCREMENT)
           + MIN_GATHER_BUF_SIZE;
      }
      if((pTmpDstBuf = BIT8_ARRAY_ALLOC_POOL(HMEM_CTX_REF,
				             (int) TmpBufSize)) == NULL)
      {
        dcdf->ireturn = DEF_IRET_ERRAU;		// allocate failure
        return(-4);
      }
      //---------------------------------------------------------------
      // 2. Copy Data to buffer, save sizes and length
      //---------------------------------------------------------------
      memcpy(pTmpDstBuf,dcdf->ainpa,(int) SrcDataLen);	// copy data
      dcdf->ainpa = dcdf->ainpe;			// empty source
      ENC_PSRC_GATHER_BUF(pEncStru) = pTmpDstBuf;	// save buffer ptr
      ENC_SRC_GATHER_BUFSIZE(pEncStru) = TmpBufSize;	// save buffer size
      ENC_SRC_GATHER_DATALEN(pEncStru) = SrcDataLen;	// save data length
      //---------------------------------------------------------------
      // 3. Set continue State
      //---------------------------------------------------------------
      ENC_SUBSTATE(pEncStru) = WAIT_MORE_SOURCE_BLOCKS;
      return(0);

    //==================================================
    // B) Waiting for more Source data to be presented
    //==================================================
    case WAIT_MORE_SOURCE_BLOCKS:
      dcdf->bo_sr_flush = FALSE;		// assume not all data yet
      StoredDataLen = ENC_SRC_GATHER_DATALEN(pEncStru);
      //------------------------------------------------
      // Check if data are present on input at all
      //------------------------------------------------
      if(SrcDataLen  == 0)			// call with empty source...
      {
        if(dcdf->bo_mp_flush == FALSE)		// but more seems to come
          return(0);
        pDecompressSrcBuf  = ENC_PSRC_GATHER_BUF(pEncStru);// set source of data
        DecompressSrcDataLen = StoredDataLen;	// set length
        break;					// now all data present !
      }
      //------------------------------------------------------
      // more data present, check total length first
      //------------------------------------------------------
      NewSrcDataLen = SrcDataLen + StoredDataLen;
      MaxDictSize = DICTSTRU_DictSize(ENC_PDICT_STRU(pEncStru))-2;
      if(NewSrcDataLen >= MaxDictSize)
      {
        FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
        ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK;
        dcdf->ireturn = DEF_IRET_OVERFLOW;
        return(-3);
      }
      //---------------------------------------------------------
      // copy new data to buffer if enough space, else reallocate
      //---------------------------------------------------------
      TmpBufSize = ENC_SRC_GATHER_BUFSIZE(pEncStru);
      if(NewSrcDataLen <= TmpBufSize)
      {
        //-------------------------------------------------------
        // Data fit into buffer, so copy, check if last block
        //-------------------------------------------------------
        memcpy(ENC_PSRC_GATHER_BUF(pEncStru)+StoredDataLen,
               dcdf->ainpa,(int) SrcDataLen);
        dcdf->ainpa = dcdf->ainpe;
        ENC_SRC_GATHER_DATALEN(pEncStru) = NewSrcDataLen;
        if(dcdf->bo_mp_flush == FALSE)		// not yet last data block...
          return(0);
        pDecompressSrcBuf    = ENC_PSRC_GATHER_BUF(pEncStru);	// set source of data
        DecompressSrcDataLen = NewSrcDataLen;	// set length
        break;					// all data present now
      }
      else
      {
        pTmpDstBuf = ENC_PSRC_GATHER_BUF(pEncStru);
        //---------------------------------------------------------
        // Data don't fit into buffer, must reallocate,check how...
        //---------------------------------------------------------
        if(dcdf->bo_mp_flush == TRUE)		// is last block
        {
          //----------------------------------------------------------
          // Is last data block for record, allocate as long as needed
          //----------------------------------------------------------
          Retcode = ReallocBuffer(HMEM_CTX_REF1
				  pTmpDstBuf, StoredDataLen,
                                  NewSrcDataLen, &pTmpDstBuf);
          ENC_PSRC_GATHER_BUF(pEncStru)    = pTmpDstBuf; // set new/old
          ENC_SRC_GATHER_BUFSIZE(pEncStru) = NewSrcDataLen; 
          if(Retcode != 0)
          {
            FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
            ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK;
            dcdf->ireturn = DEF_IRET_ERRAU;
            return(-4);
          }
          memcpy(pTmpDstBuf+StoredDataLen,dcdf->ainpa,(int) SrcDataLen);
          dcdf->ainpa = dcdf->ainpe;
          ENC_SRC_GATHER_DATALEN(pEncStru) = NewSrcDataLen;
          pDecompressSrcBuf    = pTmpDstBuf;	// set source of data
          DecompressSrcDataLen = NewSrcDataLen;	// set length
          break;				// all data gathered
        }
        else					// not yet last block...
        {
          //----------------------------------------------------------
          // Is not last data block for record, allocate in increments
          //----------------------------------------------------------
          TmpBufSize =
            ((((NewSrcDataLen - MIN_GATHER_BUF_SIZE) + GATHER_BUF_INCREMENT) /
            GATHER_BUF_INCREMENT) * GATHER_BUF_INCREMENT)
            + MIN_GATHER_BUF_SIZE;

          Retcode = ReallocBuffer(HMEM_CTX_REF1
				  pTmpDstBuf, StoredDataLen,
                                  TmpBufSize, &pTmpDstBuf);
          ENC_PSRC_GATHER_BUF(pEncStru)    = pTmpDstBuf; // set new/old
          ENC_SRC_GATHER_BUFSIZE(pEncStru) = TmpBufSize; 
          if(Retcode != 0)
          {
            FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
            ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK;
            dcdf->ireturn = DEF_IRET_ERRAU;
            return(-4);
          }
          memcpy(pTmpDstBuf+StoredDataLen,dcdf->ainpa,(int) SrcDataLen);
          dcdf->ainpa = dcdf->ainpe;
          ENC_SRC_GATHER_DATALEN(pEncStru) = NewSrcDataLen;
          return(0);					// wait for more data
        }
      }
    //==================================================
    // C) Waiting for first Destination buffer
    //==================================================
    case WAIT_FIRST_DSTBUF_BLOCK:
      dcdf->bo_sr_flush   = FALSE;		// not complete yet
      if(DstBufLen == 0)			// still no buffer given
        return(0);
      //----------------------------------------------------------
      // Data can be transfered, transfer as much as possible
      //----------------------------------------------------------
      SrcDataLen = ENC_CMPR_OUT_DATALEN(pEncStru);
      if(SrcDataLen <= DstBufLen)
      {
        //--------------------------------------------------------
        // All Data fit into Destination buffer, copy
        //--------------------------------------------------------
        pDecompressSrcBuf = ENC_PCMPR_OUTBUF(pEncStru);	// get Source
        memcpy(dcdf->aouta,
               pDecompressSrcBuf + ENC_CMPR_OUT_DATA_INDEX(pEncStru),
	       (int) SrcDataLen);			// copy data
        dcdf->aouta += SrcDataLen;			// advance pointer
        //-----------------------------------------------------------
        // Free Source buffer, take care of Single Source Record Mode!
        //-----------------------------------------------------------
        if(ENC_PSRC_GATHER_BUF(pEncStru) != NULL)	// direct from Input
        {
          FREE_ARRAY_POOL(HMEM_CTX_REF,ENC_PSRC_GATHER_BUF(pEncStru));
//        ENC_PSRC_GATHER_BUF(pEncStru) = NULL;	// invalidate pointer
        }        
        else
          dcdf->ainpa = dcdf->ainpe;			// 'free' buffer
        ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK; // next state
        dcdf->bo_sr_flush   = TRUE;			// now complete
      }
      else
      {
        //--------------------------------------------
        // Not all data fit into destination buffer...
        //--------------------------------------------
        SrcDataLen = DstBufLen;				// limit length
        pDecompressSrcBuf = ENC_PCMPR_OUTBUF(pEncStru);	// get Source
        memcpy(dcdf->aouta,
               pDecompressSrcBuf + ENC_CMPR_OUT_DATA_INDEX(pEncStru),
	       (int) SrcDataLen);			// copy data
        dcdf->aouta += SrcDataLen;			// advance pointer
        ENC_CMPR_OUT_DATALEN(pEncStru)    -= SrcDataLen;// reduce length
        ENC_CMPR_OUT_DATA_INDEX(pEncStru) += SrcDataLen;// advance Index
        ENC_SUBSTATE(pEncStru) = WAIT_MORE_DSTBUF_BLOCKS;   // next state
      }
      return(0);
    //==================================================
    // D) Waiting for more Destination buffers
    //==================================================
    case WAIT_MORE_DSTBUF_BLOCKS:
      dcdf->bo_sr_flush   = FALSE;		// not complete yet
      if(DstBufLen == 0)			// no buffer given
        return(0);

      SrcDataLen = ENC_CMPR_OUT_DATALEN(pEncStru);
      if(SrcDataLen <= DstBufLen)
      {
        //--------------------------------------------------------
        // All Data fit into Destination buffer, copy
        //--------------------------------------------------------
        pDecompressSrcBuf = ENC_PCMPR_OUTBUF(pEncStru);	// get Source
        memcpy(dcdf->aouta,				// copy data
               pDecompressSrcBuf+ENC_CMPR_OUT_DATA_INDEX(pEncStru),
	       (int) SrcDataLen);
        dcdf->aouta += SrcDataLen;			// advance pointer
        //-----------------------------------------------------------
        // Free used buffers, take care of Single Source Record Mode!
        //-----------------------------------------------------------
        if(ENC_PSRC_GATHER_BUF(pEncStru) != NULL)	// direct from Input
        {
          FREE_ARRAY_POOL(HMEM_CTX_REF,ENC_PSRC_GATHER_BUF(pEncStru));
//          ENC_PSRC_GATHER_BUF(pEncStru) = NULL;	// invalidate pointer
        }        
        else
          dcdf->ainpa = dcdf->ainpe;			// 'free' buffer
        ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK; // next state
        dcdf->bo_sr_flush   = TRUE;			// now complete
      }
      else
      {
        //--------------------------------------------
        // Not all data fit into destination buffer...
        //--------------------------------------------
        SrcDataLen = DstBufLen;				// limit length
        pDecompressSrcBuf = ENC_PCMPR_OUTBUF(pEncStru);	// get Source
        memcpy(dcdf->aouta,				// copy data
               pDecompressSrcBuf+ENC_CMPR_OUT_DATA_INDEX(pEncStru),
	       (int) SrcDataLen);
        dcdf->aouta += SrcDataLen;			// advance pointer
        ENC_CMPR_OUT_DATALEN(pEncStru)    -= SrcDataLen;// reduce length
        ENC_CMPR_OUT_DATA_INDEX(pEncStru) += SrcDataLen;// advance Index
      }
      return(0);

    //===========================================================
    // E) Unrecognized substate (should not happen, remove later)
    //===========================================================
    default:
      FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
      ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK;
      dcdf->ireturn = DEF_IRET_ERRAU;
      return(-99);
  } // switch
  //----------------------------------------------------------------------
  // All source data are present, extract the Compression Flags (1st byte)
  // check if valid Dictionary size (only when compressed)
  // NOTE: When Large dictionary given, both modes supported, else
  // ----- only small dictionary mode supported
  //--------------------------------------------------------------
  CmprFlags = *pDecompressSrcBuf;		// get the Flags
  DecompressSrcDataLen--;
  MaxDictSize = DICTSTRU_DictSize(ENC_PDICT_STRU(pEncStru));
  if((CmprFlags & MPPC_COMPRESSED_BIT) != 0)
  {
    LargeDictFlag = (int) (CmprFlags & MPPC_DICTSIZE_MASK);
// Was wrong, Large dictionary supports both modes !
//    if((LargeDictFlag > 1) ||			// is invalid anyway
//     ((LargeDictFlag == 0) && (MaxDictSize != MPPC_SMALL_DICT_SIZE)) ||
//       ((LargeDictFlag != 0) && (MaxDictSize != MPPC_LARGE_DICT_SIZE)))
    if((LargeDictFlag > 1) ||			// is invalid anyway
       ((LargeDictFlag != 0) && (MaxDictSize < MPPC_LARGE_DICT_SIZE)))
    {
      FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
      ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK;
      dcdf->ireturn = DEF_IRET_INVDA;
      return(-5);
    }
  }
  //-----------------------------------------------------
  // Decompress the Input Data now according to the Flags
  // NOTE: No Destination Buffer has to be allocated, as
  // ----- the Dictionary serves as output buffer in the
  //       compressed case
  //-----------------------------------------------------
  if((CmprFlags & MPPC_COMPRESSED_BIT) == 0)
  {
    //---------------------------------------------------
    // Data are uncompressed, save buffer for output
    //---------------------------------------------------
    ENC_PCMPR_OUTBUF(pEncStru) = pDecompressSrcBuf;	 // Copy from Source
    ENC_CMPR_OUT_DATALEN(pEncStru) = DecompressSrcDataLen; // set the length
    ENC_CMPR_OUT_DATA_INDEX(pEncStru) = 1;	// set start index past Flags
    if(DecompressSrcDataLen == 0)			// handle Strange Case
    {
      if(ENC_PSRC_GATHER_BUF(pEncStru) != NULL)	 // free Source Gather buffer
      {
        FREE_ARRAY_POOL(HMEM_CTX_REF,ENC_PSRC_GATHER_BUF(pEncStru));
//        ENC_PSRC_GATHER_BUF(pEncStru) = NULL;	// invalidate pointer
      }        
      else					 // free the direct source
        dcdf->ainpa = dcdf->ainpe;

      ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK;
      dcdf->bo_sr_flush   = TRUE;		// signal all data processed
      return(0);
    }
  }
  else
  {
    //--------------------------------------------------------
    // Decompress the Data
    //--------------------------------------------------------
    pDictStru = ENC_PDICT_STRU(pEncStru);	// get Dictionary
    Retcode = MPPC_DECOMPR(MPPCDECOMPinst,
			   pDecompressSrcBuf, 1, DecompressSrcDataLen,
			   CmprFlags,DICTSTRU_pDictBuf(pDictStru),
			   &DICTSTRU_CurrDictIndex(pDictStru),
			   &pTmpDstBuf, &SrcDataLen, &TmpBufSize);
    if(Retcode != 0)
    {
      FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
      ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK;
      dcdf->ireturn = DEF_IRET_INVDA;
      return(-6);
    }
    //-----------------------------------------------------------
    // Free the Source buffer, Decompressed comes from Dictionary
    //-----------------------------------------------------------
    if(ENC_PSRC_GATHER_BUF(pEncStru) != NULL)	 // free Source Gather buffer
    {
      FREE_ARRAY_POOL(HMEM_CTX_REF,ENC_PSRC_GATHER_BUF(pEncStru));
//      ENC_PSRC_GATHER_BUF(pEncStru) = NULL;	// invalidate pointer
    }        
    else					 // free the direct source
      dcdf->ainpa = dcdf->ainpe;
    //-----------------------------------------------------------
    // Setup the copy buffer, handle Strange case (Zero data)
    //-----------------------------------------------------------
    ENC_PCMPR_OUTBUF(pEncStru) = pTmpDstBuf;	 // Copy from Dictionary
    ENC_CMPR_OUT_DATALEN(pEncStru) = TmpBufSize; // set the length
    ENC_CMPR_OUT_DATA_INDEX(pEncStru) = SrcDataLen; // save Start Index
  
    if(TmpBufSize == 0)				 // handle Strange Case
    {
      ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK;
      dcdf->bo_sr_flush   = TRUE;		// signal all data processed
      return(0);
    }
  }
  //===================================================
  // Data are ready for Transfer to Destination buffer,
  // check State of Buffer
  //===================================================
  dcdf->bo_sr_flush   = FALSE;			// not complete
  ENC_SUBSTATE(pEncStru) = WAIT_FIRST_DSTBUF_BLOCK; // next state
  if(DstBufLen == 0)				// no buffer given
    return(0);
  //----------------------------------------------------------
  // Data can be transfered, transfer as much as possible
  //----------------------------------------------------------
  SrcDataLen = ENC_CMPR_OUT_DATALEN(pEncStru);
  if(SrcDataLen <= DstBufLen)
  {
    //--------------------------------------------------------
    // All Data fit into Destination buffer, copy
    //--------------------------------------------------------
    pDecompressSrcBuf = ENC_PCMPR_OUTBUF(pEncStru);	// get Source
    memcpy(dcdf->aouta,					// copy data
           pDecompressSrcBuf+ENC_CMPR_OUT_DATA_INDEX(pEncStru),
	   (int) SrcDataLen);
    dcdf->aouta += SrcDataLen;				// advance pointer
    //-----------------------------------------------------------
    // Free Source buffer, take care of Single Source Record Mode!
    //-----------------------------------------------------------
    if(ENC_PSRC_GATHER_BUF(pEncStru) != NULL)	 // free Source Gather buffer
    {
      FREE_ARRAY_POOL(HMEM_CTX_REF,ENC_PSRC_GATHER_BUF(pEncStru));
//      ENC_PSRC_GATHER_BUF(pEncStru) = NULL;	// invalidate pointer
    }        
    else					 // free the direct source
      dcdf->ainpa = dcdf->ainpe;
    ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK; // next state
    dcdf->bo_sr_flush   = TRUE;				// now complete
    return(0);
  }
  else
  {
    //--------------------------------------------------------
    // Not all data fit into destination buffer...
    //--------------------------------------------------------
    SrcDataLen = DstBufLen;				// limit length
    pDecompressSrcBuf = ENC_PCMPR_OUTBUF(pEncStru);	// get Source
    memcpy(dcdf->aouta,					// copy data
           pDecompressSrcBuf+ENC_CMPR_OUT_DATA_INDEX(pEncStru),
	   (int) SrcDataLen);
    dcdf->aouta += SrcDataLen;				// advance pointer
    ENC_CMPR_OUT_DATALEN(pEncStru)    -= SrcDataLen;	// reduce length
    ENC_CMPR_OUT_DATA_INDEX(pEncStru) += SrcDataLen;	// advance Index
    ENC_SUBSTATE(pEncStru) = WAIT_MORE_DSTBUF_BLOCKS;   // next state
    return(0);
  }
}

//===============================================================
// MPPC-Decompressor Function CDRDEC / m_cdr_dec
//
// Input Parameters:	DCDRFIELD * dcdf	The Calling Structure
// Returns: Nothing (Returncode placed in Structure)
//===============================================================
#if XH_MPPC_INTF_VERSION < 200
PUBLIC STATIC void CDRDEC(DCDRFIELD * dcdf)
#else
PUBLIC STATIC void m_cdr_dec(DCDRFIELD * dcdf)
#endif
{
  int Retcode;

  ENC_PTR pEncStru;

  ds__hmem TmpMemCtxStruc;
  HMEM_CTX_DEF1;

  LOAD_HMEM_CTX_PTR(NULL);
  //---------------------------------------------------
  // Distribute by Calling Function Mode
  //---------------------------------------------------
  if(dcdf == NULL)				// primary sanity check
    return;

  if(dcdf->uaux == NULL)			// ALLOC/FREE sanity check !!!
  {
    dcdf->ireturn = DEF_IRET_ERRAU;		// signal Error
    return;
  }
  //--------------------------------------------------------
  // Fetch general parameters, set default returncode
  //--------------------------------------------------------
  pEncStru = (ENC_PTR) dcdf->aext;		// get controlling structure
  dcdf->ireturn = DEF_IRET_NORMAL;		// assume o.k.
  //--------------------------------------------------------
  // Distribute by Function type requested
  //--------------------------------------------------------
  switch(dcdf->ifunc)
  {
    //-------------------------------------------------------
    // Initialization requested, check if already initialized
    //-------------------------------------------------------
    case DEF_IFUNC_START:
      if(pEncStru != NULL)			// is already initialized
      {
        dcdf->ireturn = DEF_IRET_ERRAU;		// signal Error
        return;
      }
      //----------------------------------------------------
      // Allocate the Structures required
      //----------------------------------------------------
      dcdf->ul_save_mp_needed = 0;		// no additional buffer needed

      memset(&TmpMemCtxStruc,0,sizeof(TmpMemCtxStruc));

      TmpMemCtxStruc.in__struc_size       = sizeof(ds__hmem);
      TmpMemCtxStruc.in__flags		  = HMEM_STRUC_LOCAL_FLAG_BIT;
      TmpMemCtxStruc.pMemSizeInfoCallback = DCDRInfoCallback;
//      TmpMemCtxStruc.pHmemDesc            = NULL;

#if XH_MPPC_INTF_VERSION < 200
//      TmpMemCtxStruc.in__aux_up_version   = 0;
//      TmpMemCtxStruc.vp__context          = NULL;
      TmpMemCtxStruc.am__aux1             = dcdf->uaux;
//      TmpMemCtxStruc.am__aux2             = NULL;
#else
      TmpMemCtxStruc.in__aux_up_version   = 1;
      TmpMemCtxStruc.vp__context          = dcdf->vpc_userfld;
//      TmpMemCtxStruc.am__aux1             = NULL;
      TmpMemCtxStruc.am__aux2             = dcdf->uaux;
#endif


      LOAD_HMEM_CTX_PTR(&TmpMemCtxStruc);	// get correct context !!

      if(AllocCoderCtrlStruc(HMEM_CTX_REF1
			     dcdf, 0) == 0)	// allocate Structure / Buffs.
      {
        dcdf->ifunc = DEF_IFUNC_CONT;		// without error
      }
      else
      {
        dcdf->ireturn = DEF_IRET_ERRAU;		// signal error
      }
      return;

    //----------------------------------------------------------
    // Continue Mode requested, check if initialized
    //----------------------------------------------------------
    case DEF_IFUNC_CONT:
      if(pEncStru == NULL)			// is NOT initialized
      {
        dcdf->ireturn = DEF_IRET_ERRAU;		// signal Error
        return;
      }
#if XH_MPPC_INTF_VERSION >= 200
      ENC_pMemCtxStruc(pEncStru)->vp__context = dcdf->vpc_userfld;
#endif
      LOAD_HMEM_CTX_PTR(ENC_pMemCtxStruc(pEncStru));

      Retcode = DistributeDecompressMode(HMEM_CTX_REF1 dcdf, pEncStru);
      return;

    //----------------------------------------------------------
    // Dictionary Reset Requested, check state
    //----------------------------------------------------------
    case DEF_IFUNC_RESET:
      if(pEncStru == NULL)			// is NOT initialized
      {
        dcdf->ireturn = DEF_IRET_ERRAU;		// signal Error
        return;
      }
#if XH_MPPC_INTF_VERSION >= 200
      ENC_pMemCtxStruc(pEncStru)->vp__context = dcdf->vpc_userfld;
#endif
      LOAD_HMEM_CTX_PTR(ENC_pMemCtxStruc(pEncStru));

      if(ENC_SUBSTATE(pEncStru) != WAIT_FIRST_SOURCE_BLOCK)
      {
        FreeTmpBuffers(HMEM_CTX_REF1 pEncStru);
        ReInitDictionary(pEncStru);
        dcdf->ireturn = DEF_IRET_ERRAU;
        ENC_SUBSTATE(pEncStru) = WAIT_FIRST_SOURCE_BLOCK;
        return;
      }
      ReInitDictionary(pEncStru);
      return;

    //----------------------------------------------------------
    // End of Processing requested, free all regardless of state
    //----------------------------------------------------------
    case DEF_IFUNC_END:
      if(pEncStru == NULL)		// SHOULD NOT HAPPEN !!!
      {
        memset(&TmpMemCtxStruc,0,sizeof(TmpMemCtxStruc));

        TmpMemCtxStruc.in__struc_size       = sizeof(ds__hmem);
        TmpMemCtxStruc.in__flags	    = HMEM_STRUC_LOCAL_FLAG_BIT;
        TmpMemCtxStruc.pMemSizeInfoCallback = DCDRInfoCallback;
//        TmpMemCtxStruc.pHmemDesc            = NULL;
#if XH_MPPC_INTF_VERSION < 200
//        TmpMemCtxStruc.in__aux_up_version   = 0;
//        TmpMemCtxStruc.vp__context          = NULL;
        TmpMemCtxStruc.am__aux1             = dcdf->uaux;
//        TmpMemCtxStruc.am__aux2             = NULL;
#else
        TmpMemCtxStruc.in__aux_up_version   = 1;
        TmpMemCtxStruc.vp__context          = dcdf->vpc_userfld;
//        TmpMemCtxStruc.am__aux1             = NULL;
        TmpMemCtxStruc.am__aux2             = dcdf->uaux;
#endif

        LOAD_HMEM_CTX_PTR(&TmpMemCtxStruc);	// get correct context !!
      }
      else
      {
#if XH_MPPC_INTF_VERSION >= 200
        ENC_pMemCtxStruc(pEncStru)->vp__context = dcdf->vpc_userfld;
#endif
        LOAD_HMEM_CTX_PTR(ENC_pMemCtxStruc(pEncStru));
      }

      FreeCoderCtrlStruc(HMEM_CTX_REF1 dcdf);
      dcdf->ireturn = DEF_IRET_END;
      return;

    //---------------------------------------------
    // Invalid Fucntion Code received, signal Error
    //---------------------------------------------
    default:
      dcdf->ireturn = DEF_IRET_ERRAU;
      return;
  }  
}
