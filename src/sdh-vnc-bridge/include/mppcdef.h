#if !defined __MPPCDEF_HDR__
#define __MPPC_DEF_HDR__


//-------------------------------------------------------------
// Definitions needed for Hashtable and Dictionary size control
// for the MPPC Coder (Compression, Decompression)
//
// Parameter1 is used for the Dictionary size selection:
// - small Dictionary, supported by all RDP versions
// - large Dictionary, supported since RDP V5 as far as known,
//		       must have been negotiated
//
// Parameter2 is used for the Hashtable size (in WORDs [16bit])
// - may be chosen arbitrarily within general limits
//-------------------------------------------------------------

// IDs for Dictionary size
#define	MPPC_SMALL_DICT_SIZE_ID	0		// size 8K
#define	MPPC_LARGE_DICT_SIZE_ID	1		// size 64K

// Suggested values for the Hashtable size (Words a 16 Bit)
#define	MPPC_SMALL_HASHTAB_SIZE	8192L		// size 16K
#define	MPPC_LARGE_HASHTAB_SIZE	32768L		// size 32K



#endif // !defined __MPPCDEF_HDR__
