#ifndef __HOB_ENCRYPT_HEADER__
#define __HOB_ENCRYPT_HEADER__
/**
* @file
* This is the header for the general HOB cryptographic module.
*/

// general defines
#if defined WIN32
#define	FAST	_fastcall
#else
#define	FAST
#endif

#if !defined BOOL
#define BOOL int
#endif



//==============================================================
// MD2
//==============================================================

//--------------------------------------------------------------
// MD2 constants
//--------------------------------------------------------------
#define MD2_DIGEST_LEN	16		// Number of digest bytes
#define	MD2_ARRAY_SIZE	81		// State Array Size

//--------------------------------------------------------------
// Externals
//--------------------------------------------------------------
#ifdef __cplusplus
extern"C"{
#endif

extern void FAST MD2_Init(int * MD2_Array);
extern void FAST MD2_Update(int * MD2_Array, char * data,
                            int offset, int len);
extern void FAST MD2_Final(int * MD2_Array, char * Digest,int Offset);

#ifdef __cplusplus
}
#endif


//==============================================================
// MD4
//==============================================================

//----------------------------------
// Constants
//----------------------------------
#define MD4_DIGEST_LEN	16		// Number of digest bytes
#define	MD4_ARRAY_SIZE	24		// State Array Size (integers)

/*--------------------------------------------------------------*/
/* Externals							*/
/*--------------------------------------------------------------*/
#ifdef __cplusplus
extern"C"{
#endif

extern void FAST MD4_Init(int * MD4_Array);
extern void FAST MD4_Update(int * MD4_Array, char * data,
                            int offset, int len);
extern void FAST MD4_Final(int * MD5_Array, char * Digest,int Offset);
extern char * FAST MD4(char * data, int len, char * Digest);
#ifdef __cplusplus
}
#endif

//==============================================================
// MD5
//==============================================================

//--------------------------------------------------------------
// Constants
//--------------------------------------------------------------
#define MD5_DIGEST_LEN	16		// Number of digest bytes
#define MD5_ARRAY_SIZE	24		// State Array Size (integers)

//-------------------------------------------------------------
// Externals
//-------------------------------------------------------------
#ifdef __cplusplus
extern"C"{
#endif

extern void FAST MD5_Init(int * MD5_Array);
extern void FAST MD5_Update(int * MD5_Array, char * data,
                            int offset, int len);
extern void FAST MD5_Final(int * MD5_Array, char * Digest,int Offset);
#ifdef __cplusplus
}
#endif


//==============================================================
// SHA-1/SHA-256/384/512
//==============================================================

//-----------------------------------------------------
// Constants
//-----------------------------------------------------
#define SHA_DIGEST_LEN	20		// digest length
#define SHA_ARRAY_SIZE	24		// size of state array (integers)

#define	SHA256_ARRAY_SIZE	27
#define	SHA384_ARRAY_SIZE	27
#define	SHA512_ARRAY_SIZE	27

#define	SHA256_DIGEST_LEN	32
#define	SHA384_DIGEST_LEN	48
#define	SHA512_DIGEST_LEN	64

//--------------------------------------------------------------------
// Externals
//--------------------------------------------------------------------
#ifdef __cplusplus
extern"C"{
#endif

extern void FAST SHA1_Init(int * SHA_Array);
extern void FAST SHA1_Update(int * SHA_Array,
                             char * data, int Offset, int len);
extern void FAST SHA1_Final(int * SHA_Array, char * Digest, int Offset);


extern void FAST SHA256_Init(int * SHA_Array);
extern void FAST SHA384_Init(long long * SHA_Array);
extern void FAST SHA512_Init(long long * SHA_Array);
extern void FAST SHA256_Update(int * SHA_Array,
                               char * data, int Offset, int len);
extern void FAST SHA384_512_Update(long long * SHA_Array,
                                   char * data, int Offset, int len);
extern void FAST SHA256_Final(int * SHA_Array, char * Digest, int Offset);
extern void FAST SHA384_Final(long long * SHA_Array, char * Digest, int Offset);
extern void FAST SHA512_Final(long long * SHA_Array, char * Digest, int Offset);

#ifdef __cplusplus
}
#endif


//==============================================================
// Ripemd
//==============================================================

//-----------------------------------------------------
// Constants
//-----------------------------------------------------
#define RMD160_DIGEST_LEN	20
#define	RPMD_ARRAY_SIZE	24		// state array size (integers)

//-----------------------------------------------------
// Externals
//-----------------------------------------------------
#if defined __cplusplus
extern"C"{
#endif

extern void FAST RMD160_Init(int * RPMD_Array);
extern void FAST RMD160_Update(int * RPMD_Array,
                            char * data, int Offset, int len);
extern void FAST RMD160_Final(int * RPMD_Array, char * Digest, int Offset);

#if defined __cplusplus
}
#endif

//==============================================================
// HMAC
//==============================================================

//-------------------------------------------------------
// Constants for the Hashes
//-------------------------------------------------------
#define	HMAC_MD5_ID	0
#define	HMAC_SHA1_ID	1
#define	HMAC_RMD160_ID	2
#define  HMAC_SHA256_ID 3

#define	HMAC_MAX_DIGEST_LEN		SHA256_DIGEST_LEN	// SHA-256 is largest
#define	HMAC_MAX_HASH_ARRAY_SIZE	SHA256_ARRAY_SIZE	// SHA-256 is largest

#define	HMAC_BLOCK_LEN	64


#ifndef DEF_HL_STR_G_I_1
#define DEF_HL_STR_G_I_1

// gather input data
struct dsd_gather_i_1
{
  struct dsd_gather_i_1 *adsc_next;          // next in chain
  char *                achc_ginp_cur;       // current position
  char *                achc_ginp_end;       // end of input data
};

#endif

//-----------------------------------------------------
// Externals
//-----------------------------------------------------
#if defined __cplusplus
extern"C"{
#endif

extern int FAST GenHMAC(char * pKeyData, int KeyDataOff,
	int KeyDataLen, char * pHashData, int HashDataOff, int HashDataLen,
	int HashType, char * pDstBuf, int DstOff, int * pDstLen);

extern int FAST GenHMACGath(char * pKeyData, int KeyDataOff, int KeyDataLen,
	   struct dsd_gather_i_1* ads_gath, int HashType, char * pDstBuf,
	   int DstOff, int * pDstLen);

#if defined __cplusplus
}
#endif


//==============================================================
// RC2
//==============================================================

//-----------------------------------
// Constants
//-----------------------------------
#define RC2_ENCRYPT	1
#define RC2_DECRYPT	0

#define RC2_BLOCK	8
#define RC2_KEY_LENGTH	16

#define	RC2_MAX_KEY_WORDS 64		//  64 * 16 Bit = 1024 Bit
#define	RC2_MAX_KEY_BYTES 128		// 128 *  8 Bit = 1024 Bit

//---------------------------------------------------------------
// Externals
//---------------------------------------------------------------
#ifdef __cplusplus
extern"C" {
#endif

extern void FAST RC2_SetKey(short * Key, char * data, int len,int bits);
extern void FAST RC2_cbc_encdecrypt(char * in, int InpOffset,
				    char * out, int OutpOffset,
                                    int length, short * key,
                                    char * iv, int mode);

#ifdef __cplusplus
}
#endif

//==============================================================
// RC4
//==============================================================

//-----------------------------------
// Constants
//-----------------------------------
#define RC4_STATE_SIZE	258			// total size


//----------------------------------------------------------
// Externals
//----------------------------------------------------------
#if defined __cplusplus
extern "C" {
#endif

extern void FAST RC4_SetKey(char * state, char * data,
			    int Offset, int len);
extern void FAST RC4(char * indata, int InpOffset,
		     int len, char * outdata, int OutpOffset,
		     char * state);
extern void FAST m_rc4_singlepass(char * byrp_indata, int imp_inpoffset,
		     int imp_inplen, char * byrp_key, int imp_keyoffset,
		     int imp_keylen, char * byrp_outdata,int imp_outpoffset);
#if defined __cplusplus
}
#endif


//==============================================================
// DES
//==============================================================

//-------------------------------------------------------
// Constants
//-------------------------------------------------------
#define SP_BOX_LEN	64			// 64 longs a 32 Bit
#define	DES_ENCRYPT	0			// do DES encryption
#define	DES_DECRYPT	1			// do DES decryption
#define	DES_KEY_BYTES	8			// number of Key Bytes
#define	DES_SUBKEY_ARRAY_SIZE	32		// 32 longs a 32 Bit
#define	DES_BLOCK_SIZE	8			// 8 bytes

//------------------------------------------------------
// Externals
//------------------------------------------------------
#ifdef __cplusplus
extern "C" {
#endif

extern void DES_encrypt_decrypt(unsigned int * data,
                                unsigned int * SubKeyTab,
                                int mode);

extern void GenDESSubKeys(unsigned char * DesKey, unsigned int * SubKeyTab);


extern void DES_cbc_encrypt_decrypt(unsigned char * input,
				    unsigned char * output,
                                    unsigned int * DES_SubkeyTab,
                                    int BlkCnt,
                                    unsigned char * IVector,
                                    int mode);


extern void DES_ecb_encrypt_decrypt(unsigned char * input,
				    unsigned char * output,
                                    unsigned int * DES_SubkeyTab,
                                    int BlkCnt,
                                    int mode);

extern void DES_encrypt3(unsigned int * data,
			 unsigned int * SubKeyTab1,
			 unsigned int * SubKeyTab2,
                         unsigned int * SubKeyTab3);

extern void DES_decrypt3(unsigned int * data,
			 unsigned int * SubKeyTab1,
			 unsigned int * SubKeyTab2,
			 unsigned int * SubKeyTab3);

extern void DES3_ede_cbc_encrypt_decrypt(unsigned char * input,
					 unsigned char * output,
                                         unsigned int * DES_SubkeyTab1,
                                         unsigned int * DES_SubkeyTab2,
                                         unsigned int * DES_SubkeyTab3,
                                         int BlkCnt,
                                         unsigned char * IVector,
                                         int mode);

#ifdef __cplusplus
}
#endif


//==============================================================
// AES
//==============================================================
//#define	USE_CPU_AES

//-----------------------------------------------------------
// Preprocessing macro definitions
//-----------------------------------------------------------
#if defined USE_CPU_AES

#if (defined LINUX_X86CPU || defined LINUX_X64CPU || defined WIN32 || defined WIN64) && (!defined _M_IA64 && !defined WINCE)
#define	HAVE_AES_CPU_ASSEMBLER
#endif

#if (defined WIN32 || defined WIN64) && !defined _M_IA64 && !defined WINCE
#define	HAVE_AES_CPU
#endif

#if defined LINUX_X86CPU || defined LINUX_X64CPU || defined SOLARIS_X64CPU
#define	HAVE_AES_CPU
#endif

#endif // USE_CPU_AES

//-----------------------------------------------------------
// Align macro
//-----------------------------------------------------------
#if !defined (ALIGN16)
# if defined (__GNUC__)
#  define ALIGN16 __attribute__ ( (aligned (16)))
# elif defined WIN32 || defined WIN64
#  define ALIGN16 __declspec (align (16))
# else
#  define ALIGN16
# endif
#endif

//-----------------------------------------------------------
// Constants
//-----------------------------------------------------------
#define	AES_ENCRYPT	0
#define	AES_DECRYPT	1

#define	AES_BLOCK_SIZE	16		// Block size in Bytes
#define	AES_NB		4		// Block size in DWORDs
#define	AES_NK_MIN	4		// min. keysize in DWORDs
#define	AES_NK_MID	6		// mid. keysize in DWORDs
#define	AES_NK_MAX	8		// max. keysize in DWORDs
#define	AES_NR_MIN	(AES_NK_MIN + 6) // min. Rounds
#define	AES_NR_MAX	(AES_NK_MAX + 6) // max. Rounds

#define	AES_MX_VAL	0x11B		// reduction polynom
#define	AES_MX_VAL_LSB	0x1B		// dto. LSB only


//---------------------------------------------------
// Key structure for new/old routines
//---------------------------------------------------
typedef struct ds_aes_key_t {
  ALIGN16 unsigned char byr_key[15*16];	// key array
  int im_flags;				// flags
  char byr_alignfill[16];		// filler
} ds_aes_key;

#define	AES_KEY_ARRAY_SIZE_BIT32  (64+4)	// total size of structure


#define	USE_CPU_AES_FLAG	0x01	// use AES from x86/64 CPU
#define  CHECK_CPU_AES_FLAG  0x02  // check, if any CPU AES support is available

//-----------------------------------------------------------
// Macros
//-----------------------------------------------------------

#if !defined HAVE_AES_CPU
#define	m_aes_set_encrypt_key(a,b,c) m_gen_aes_encrypt_keys(a,b,c)
#define	m_aes_set_decrypt_key(a,b,c) m_gen_aes_decrypt_keys(a,b,c)

#define	m_aes_cbc_encrypt(a,b,c,d,e,f) AES_Fast_cbc_encrypt(a,b,c,d,e,f)
#define	m_aes_cbc_decrypt(a,b,c,d,e,f) AES_Fast_cbc_decrypt(a,b,c,d,e,f)
#define	m_aes_ecb_encrypt(a,b,c,d,e) AES_Fast_ecb_encrypt(a,b,c,d,e)
#define	m_aes_ecb_decrypt(a,b,c,d,e) AES_Fast_ecb_decrypt(a,b,c,d,e)
#endif // !defined HAVE_AES_CPU


//-----------------------------------------------------------
// Externals
//-----------------------------------------------------------
#if defined __cplusplus
extern "C" {
#endif // C++


extern void m_aes_cfb8_encrypt(unsigned char * abyp_input,
		                  unsigned char * abyp_output,
		                  ds_aes_key * adsp_key,
		                  unsigned int ump_byte_count,
		                  unsigned char * abyp_iv,
		                  int imp_rounds);

extern void m_aes_cfb8_decrypt(unsigned char * abyp_input,
		                  unsigned char * abyp_output,
		                  ds_aes_key * adsp_key,
		                  unsigned int ump_byte_count,
		                  unsigned char * abyp_iv,
		                  int imp_rounds);

extern int m_gen_aes_encrypt_keys(unsigned char * AesKey, int AesKeyLen,
			          ds_aes_key * pEncKeyStruc);

extern int m_gen_aes_decrypt_keys(unsigned char * AesKey, int AesKeyLen,
			          ds_aes_key * pDecKeyStruc);

extern void FAST AES_Fast_cbc_encrypt(unsigned char * input,
		                      unsigned char * output,
                                      ds_aes_key * pEncKeyStruc,
                                      int BlkCnt,
                                      unsigned char * IVector,
		                      int Rounds);

extern void FAST AES_Fast_cbc_decrypt(unsigned char * input,
			              unsigned char * output,
                                      ds_aes_key * pDecKeyStruc,
                                      int BlkCnt,
                                      unsigned char * IVector,
			              int Rounds);

extern void FAST AES_Fast_ecb_encrypt(unsigned char * input,
		                      unsigned char * output,
                                      ds_aes_key * pEncKeyStruc,
                                      int BlkCnt,
		                      int Rounds);

extern void FAST AES_Fast_ecb_decrypt(unsigned char * input,
		                      unsigned char * output,
                                      ds_aes_key * pDecKeyStruc,
                                      int BlkCnt,
		                      int Rounds);


#if defined HAVE_AES_CPU
extern int m_check_cpu_support_aes(void);
extern void m_aes_cbc_cpu_encrypt(const unsigned char * abyp_in,
		                  unsigned char * abyp_out,
		                  unsigned char * abyp_key,
		                  unsigned int ump_blkcount,
		                  unsigned char * abyp_ivec,
		                  int imp_number_of_rounds);

extern void m_aes_cbc_cpu_decrypt(const unsigned char * abyp_in,
		                  unsigned char * abyp_out,
		                  unsigned char * abyp_key,
		                  unsigned int ump_blkcount,
		                  unsigned char * abyp_ivec,
		                  int imp_number_of_rounds);

extern void m_aes_ecb_cpu_encrypt(const unsigned char * abyp_in,
		                  unsigned char * abyp_out,
		                  unsigned char * abyp_key,
		                  unsigned int ump_blkcount,
		                  int imp_number_of_rounds);

extern void m_aes_ecb_cpu_decrypt(const unsigned char * abyp_in,
		                  unsigned char * abyp_out,
		                  unsigned char * abyp_key,
		                  unsigned int ump_blkcount,
		                  int imp_number_of_rounds);

extern void m_aes_ctr_cpu_encrypt(const unsigned char * abyp_in,
		                  unsigned char * abyp_out,
		                  const unsigned char * abyp_ivec,
		                  const unsigned char * abyp_nonce,
		                  unsigned int ump_blockcnt,
		                  const unsigned char * abyp_key,
		                  int imp_number_of_rounds);


extern void m_aes_128_cpu_key_expansion(const unsigned char * abyp_userkey,
			                unsigned char * abyp_key);

extern void m_aes_192_cpu_key_expansion(const unsigned char * abyp_userkey,
			                unsigned char * abyp_key);

extern void m_aes_256_cpu_key_expansion(const unsigned char * abyp_userkey,
			                unsigned char * abyp_key);


extern void m_aes_cpu_set_encrypt_key(const unsigned char * abyp_userkey,
			              const int imp_dwords,
			              ds_aes_key * adsp_key);

extern void m_aes_cpu_set_decrypt_key(const unsigned char * abyp_userkey,
			              const int imp_dwords,
				      ds_aes_key * adsp_key);


extern void m_aes_set_encrypt_key(unsigned char * abyp_userkey,
			          int imp_dwords,
			          ds_aes_key * adsp_keytab);

extern void m_aes_set_decrypt_key(unsigned char * abyp_userkey,
			          int imp_dwords,
			          ds_aes_key * adsp_keytab);

extern void m_aes_cbc_encrypt(unsigned char * abyp_input,
		              unsigned char * abyp_output,
		              ds_aes_key * adsp_key,
           		      unsigned int ump_blkcount,
		              unsigned char * abyp_iv,
		              int imp_rounds);

extern void m_aes_cbc_decrypt(unsigned char * abyp_input,
		              unsigned char * abyp_output,
		              ds_aes_key * adsp_key,
		              unsigned int ump_blkcount,
		              unsigned char * abyp_iv,
		              int imp_rounds);

extern void m_aes_ecb_encrypt(unsigned char * abyp_input,
		              unsigned char * abyp_output,
		              ds_aes_key * adsp_key,
           		      unsigned int ump_blkcount,
		              int imp_rounds);

extern void m_aes_ecb_decrypt(unsigned char * abyp_input,
		              unsigned char * abyp_output,
		              ds_aes_key * adsp_key,
		              unsigned int ump_blkcount,
		              int imp_rounds);

extern void m_aes_cpu_revert_key(unsigned char * adsp_key,
			         unsigned char * adsp_rev_key,
				 int imp_rounds);

#endif // HAVE_AES_CPU


#if defined WIN_EM64T_ASSEMBLER

extern int FAST GenAESEncryptKeys(unsigned char * AesKey, int Offset,
			          int AesKeyLen, unsigned int * EncKeyTab);

extern int FAST GenAESDecryptKeys(unsigned char * AesKey, int Offset,
		                  int AesKeyLen, unsigned int * DecKeyTab);

#endif //defined WIN_EM64T_ASSEMBLER


#if defined __cplusplus
}
#endif // C++

//==============================================================
// Memory manager for Largenumber System/RSA/DSA
//==============================================================
#if defined __cplusplus
extern "C" {
#endif

//---------------------------------------------------------
// Memory preallocation info structure
// Used with the Callback function (if supplied)
//---------------------------------------------------------
typedef struct HMEMINFO_t {
  int	InfoStrucSize;			// for versioning
  int	InitialByte16BlockCount;	// number of 16  Byte blocks to use
  int	InitialByte32BlockCount;	// number of 32  Byte blocks to use
  int	InitialByte64BlockCount;	// number of 64  Byte blocks to use
  int	InitialByte256BlockCount;	// number of 256 Byte blocks to use
  int	InitialByte512BlockCount;	// number of 512 Byte blocks to use
  int	InitialPoolSize;		// initial pool buffer size
  int   InitialPoolCount;		// initial pool count
} HMEMINFO;

//-------------------------------------------------------------
// memory context structure
//-------------------------------------------------------------
typedef struct ds__hmem_t {
        int     in__struc_size;         // for version control
	int	in__flags;		// control flags
	int	in__aux_up_version;	// 0 - V1, 1 - V2
	int	(* pMemSizeInfoCallback)(struct HMEMINFO_t *); // info callback/NULL
	struct HMEMDESC_t * pHmemDesc;	// internal memory manager desc.
        void * vp__context;             // context for allocation function
        BOOL (* am__aux1)(int in__funct,
                          void * vp__p_mem,
                          int  in__size);  // allocation / free function (old)
        BOOL (* am__aux2)(void * vp__p_ctx,
                          int in__funct,
                          void * vp__p_mem,
                          int  in__size);  // allocation / free function (new)
} ds__hmem;
//--------------------------------------------------------------
// External definitions
//--------------------------------------------------------------
extern void FAST HMemMgrFree(ds__hmem * vp__ctx);
extern void FAST m__hpoolfree(ds__hmem * vp__ctx, void * ach_ppool_mem);
extern char * FAST m__hpoolmalloc(ds__hmem * vp__ctx, int in__memory_size);
extern void FAST MemStatistics(ds__hmem * vp__ctx);
extern void * m__hextmalloc(ds__hmem * ads__p_hmem_struc,
                            int in__memory_size);
extern void * m__hextmalloc_glbl(ds__hmem * ads__p_hmem_struc,
                                 int in__memory_size);
extern void * m__hextcalloc(ds__hmem * ads__p_hmem_struc,
			    int in__element_cnt, int in__element_size);
extern void * m__hextcalloc_glbl(ds__hmem * ads__p_hmem_struc,
			         int in__element_cnt, int in__element_size);
extern void m__hextfree(ds__hmem * ads__p_hmem_struc,
			void * vp__p_mem);
extern void m__hextfree_glbl(ds__hmem * ads__p_hmem_struc,
			     void * vp__p_mem);
extern void * m__hmalloc(ds__hmem * ads__p_hmem_struc,
                         int in__memory_size);
extern void * m__hcalloc(ds__hmem * ads__p_hmem_struc,
		         int in__element_cnt, int in__element_size);
extern void m__hfree(ds__hmem * ads__p_hmem_struc,void * vp__p_mem);

extern ds__hmem * FAST AllocFillMemCtxStruc(int InterfaceMode);


#if defined __cplusplus
}
#endif

//-------------------------------------------------------
// Macros for memory allocation
//-------------------------------------------------------
#if !defined XH_INTERFACE
#define	HMEM_CTX_DEF
#define	HMEM_CTX_DEF1
#define	HMEM_CTX_REF
#define	HMEM_CTX_REF1
#define	LOAD_HMEM_CTX_PTR(a)

#define BIT8_ARRAY_ALLOC(Ctx,Size)		(char *) malloc(Size)
#define BIT8_ARRAY_ALLOCEX(Ctx,Size)   		(char *) malloc(Size)
#define BIT8_ARRAY_ALLOCEX_GLBL(Ctx,Size)	(char *) malloc(Size)
#define	BIT8_ARRAY_ALLOC_POOL(Ctx,Size)		(char *) malloc(Size)
#define BIT8_ARRAY_CALLOC(Ctx,Cnt,Size)		(char *) calloc(Cnt,Size)
#define BIT8_ARRAY_CALLOCEX(Ctx,Cnt,Size)	(char *) calloc(Cnt,Size)
#define BIT8_ARRAY_CALLOCEX_GLBL(Ctx,Cnt,Size)	(char *) calloc(Cnt,Size)
#define BIT16_ARRAY_ALLOC(Ctx,Size)		(short *) malloc((Size)*2)
#define BIT16_ARRAY_ALLOCEX(Ctx,Size)		(short *) malloc((Size)*2)
#define	BIT16_ARRAY_ALLOC_POOL(Ctx,Size)	(short *) malloc((Size)*2)
#define BIT32_ARRAY_ALLOC(Ctx,Size)		(int *) malloc((Size)*4)
#define INT_ARRAY_ALLOC(Ctx,Size)       (int *) malloc((Size)*sizeof(int))
#define INT_ARRAY_ALLOCEX(Ctx,Size)     (int *) malloc((Size)*sizeof(int))
#else // XH_INTERFACE

#define	HMEM_CTX_DEF ds__hmem * vp__ctx,
#define	HMEM_CTX_DEF1 ds__hmem * vp__ctx

#define	HMEM_CTX_REF vp__ctx
#define	HMEM_CTX_REF1 vp__ctx,
#define	LOAD_HMEM_CTX_PTR(a)	vp__ctx = a

#define BIT8_ARRAY_ALLOC(Ctx,Size)	  (char *) m__hmalloc(Ctx,Size)
#define BIT8_ARRAY_ALLOCEX(Ctx,Size)      (char *) m__hextmalloc(Ctx,Size)
#define BIT8_ARRAY_ALLOCEX_GLBL(Ctx,Size) (char *) m__hextmalloc_glbl(Ctx,Size)
#define	BIT8_ARRAY_ALLOC_POOL(Ctx,Size)	  (char *) m__hpoolmalloc(Ctx,Size)
#define BIT8_ARRAY_CALLOC(Ctx,Cnt,Size)	  (char *) m__hcalloc(Ctx,Cnt,Size)
#define BIT8_ARRAY_CALLOCEX(Ctx,Cnt,Size) (char *) m__hextcalloc(Ctx,Cnt,Size)
#define BIT8_ARRAY_CALLOCEX_GLBL(Ctx,Cnt,Size) (char *) m__hextcalloc_glbl(Ctx,Cnt,Size)
#define BIT16_ARRAY_ALLOC(Ctx,Size)	  (short *) m__hmalloc(Ctx,(Size)*2)
#define BIT16_ARRAY_ALLOCEX(Ctx,Size)	  (short *) m__hextmalloc(Ctx,(Size)*2)
#define BIT16_ARRAY_ALLOC_POOL(Ctx,Size)  (short *) m__hpoolmalloc(Ctx,(Size)*2)
#define BIT32_ARRAY_ALLOC(Ctx,Size)	  (int *) m__hmalloc(Ctx,(Size)*4)
#define INT_ARRAY_ALLOC(Ctx,Size) \
          (int *) m__hmalloc(Ctx,(Size)*sizeof(int))
#define INT_ARRAY_ALLOCEX(Ctx,Size) \
          (int *) m__hextmalloc(Ctx,(Size)*sizeof(int))
#endif // XH_INTERFACE
//--------------------------------------------------------
// Macros for freeing allocated arrays
//--------------------------------------------------------
#if !defined XH_INTERFACE
#define	FREE_ARRAY(ctx,a)      if((a) != 0) {free(a);a = 0;}
#define	FREE_ARRAYEX(ctx,a)    if((a) != 0) {free(a);a = 0;}
#define	FREE_ARRAYEX_GLBL(ctx,a) if((a) != 0) {free(a);a = 0;}
#define	FREE_ARRAY_POOL(ctx,a) if((a) != 0) {free(a);a = 0;}
#define	FREE_CARRAY(ctx,a)     if((a) != 0) {free(a);a = 0;}
#define	FREE_CARRAYEX(ctx,a)   if((a) != 0) {free(a);a = 0;}
#define	MEMMGR_FREE(ctx)
#else
#define	FREE_ARRAY(ctx,a)      if((a) != 0) {m__hfree(ctx,a);a = 0;}
#define	FREE_ARRAYEX(ctx,a)    if((a) != 0) {m__hextfree(ctx,a);a = 0;}
#define	FREE_ARRAYEX_GLBL(ctx,a) if((a) != 0) {m__hextfree_glbl(ctx,a);a = 0;}
#define	FREE_ARRAY_POOL(ctx,a) if((a) != 0) {m__hpoolfree(ctx,a);a = 0;}
#define	FREE_CARRAY(ctx,a)     if((a) != 0) {m__hfree(ctx,a);a = 0;}
#define	FREE_CARRAYEX(ctx,a)   if((a) != 0) {m__hextfree(ctx,a);a = 0;}
#define	MEMMGR_FREE(ctx)     HMemMgrFree(ctx);
#endif // XH_INTERFACE

//==============================================================
// Random generator
//==============================================================
//----------------------------------------------
// Externals
//----------------------------------------------
#if defined __cplusplus
extern "C" {
#endif

extern int FAST SecGetSystemTimeUTC(void);
extern int FAST SecDrbgInit(HMEM_CTX_DEF1);
extern int FAST SecDrbgRandBytes(HMEM_CTX_DEF
				 char * pOutData,int OutOff,
				 int OutLen);

extern int FAST SecDrbgRandBytes_Test(char * pDstBuf,int DstOff, int DstLen);

extern int m_secdrbg_randbytes(char * abyrp_dstbuf,int imp_dstlen);


#if defined __cplusplus
}
#endif
//==============================================================
// Large number system
//==============================================================

#if defined __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------
// 32Bit Large Number structure and the Element type
// NOTE: we do not use a sign anymore (all is unsigned !!)
//---------------------------------------------------------------
typedef struct WLNUM_t {
  int AllocSize;			// number of Elements (BIT32)
  int UsedSize;				// Index of actual last used Element
  int * lpEl;				// pointer to array of alloc. Elements
}WLNUM;

//---------------------------------------------------------------
// WLargenumber Work-Context Structure
//---------------------------------------------------------------
typedef struct WLNUM_CTX_t {
  int	AllocedNumCnt;			// size of Workspace
  int	NextFreeIndex;			// Index of next available element
  WLNUM ** pWLnumArr;			// Array of WLNUM Structures
} WLNUM_CTX;

//---------------------------------------------------------------
// Montgomery Context Structure
//---------------------------------------------------------------
typedef struct MONT_CTX_t {
  WLNUM *	pModN;			// Modulus n saver
  WLNUM *	pRSquare;		// Associated r**2 (mod n)
  WLNUM *	pTmpLnum;		// temporary number for processing
  WLNUM *	pTmpMontLnum;		// temporary number for processing
  int	sLen;				// element count of r
  int	Ni0;				// inverse of n[0]
} MONT_CTX;


// Comparison codes

#define	WLNUM_1ST_GT_2ND	1	// 1st is > 2nd
#define	WLNUM_1ST_EQ_2ND	0	// 1st is same as 2nd
#define	WLNUM_1ST_LT_2ND	-1	// 1st is < 2nd


//===========================================
// Global Returncodes
//===========================================
#define	LNUM_OP_OK		0	// operation o.k.

//===============================================
// Specific Returncodes, range from -600 ... -619
//===============================================
//-------------------------------------------
// Returncodes from all the functions
//-------------------------------------------
#define	LNUM_OP_NULL_PTR	-600	// no structure Pointer (NULL)
#define	LNUM_OP_ALLOC_ERR	-601	// Element/Struct alloc error
#define	LNUM_OP_ZERO_DIV	-602	// Division by zero
#define	LNUM_OP_RECIP_ERR	-603	// Reciprocal error
#define LNUM_OP_NO_INVERSE	-604	// Inverse mod. not declared
#define LNUM_OP_ZERO_SIZE	-605	// invalid bitcount/bytecount
#define LNUM_OP_INVALID_PRIME	-606	// a prime <> 2 is even, etc.

#define	LNUM_OP_INVALID_MONT_MODULUS	-607	// montgomery modulus even/0

#define	LNUM_OP_PARAM_ERR	-610
#define	LNUM_OP_CTX_FULL	-611

//---------------------------------------------------------
// Externals
//---------------------------------------------------------
extern int FAST HardGetByteCntWLnumElem(int WElement);
extern int FAST HardGetBitCntWLnumElem(int WElement);
extern void FAST ClearWLnumElements(WLNUM * pWLnum);
extern int FAST GetBitCntWLnum(WLNUM * pNum);
extern int FAST GetByteCntWLnum(WLNUM * pNum);
extern int FAST UcompWLnum(WLNUM * pU, WLNUM * pV);
extern int FAST IsZeroWLnum(WLNUM * pU);
extern int FAST IsOneWLnum(WLNUM * pU);

extern WLNUM * FAST AllocNewWLnum(HMEM_CTX_DEF int Size);
extern void FAST FreeWLnum(HMEM_CTX_DEF WLNUM * pWLnum);
extern void FAST ClearFreeWLnum(HMEM_CTX_DEF WLNUM * pWLnum);
extern int FAST AllocWLnumElements(HMEM_CTX_DEF WLNUM * pWLnum, int NewSize);
extern void FAST FreeWLnumContext(HMEM_CTX_DEF WLNUM_CTX * pCtx);
extern WLNUM_CTX * FAST AllocWLnumContext(HMEM_CTX_DEF
					 int NumCnt,int ElementSize);
extern int FAST GetWLnumFromContext(HMEM_CTX_DEF
			WLNUM_CTX * pCtx, int ElementSize,
			WLNUM ** ppWLnum);
extern WLNUM * FAST GetWLnumPtrFromContext(HMEM_CTX_DEF
			WLNUM_CTX * pCtx, int ElementSize);
extern void FAST ReleaseWLnumsFromContext(
			WLNUM_CTX * pCtx, int WLnumCnt);

extern int FAST CopyWLnum(HMEM_CTX_DEF WLNUM * pDst, WLNUM * pSrc);
extern int FAST LshiftWLnum(HMEM_CTX_DEF
			WLNUM * pR, WLNUM * pU, int sBitcnt);
extern int FAST Lshift1WLnum(HMEM_CTX_DEF WLNUM * pR, WLNUM * pU);
extern int FAST RshiftWLnum(HMEM_CTX_DEF
			WLNUM * pR, WLNUM * pU, int sBitcnt);
extern int FAST Rshift1WLnum(HMEM_CTX_DEF WLNUM * pR, WLNUM * pU);
extern int FAST AddElementWLnumEmul32(HMEM_CTX_DEF
			              WLNUM * pWnumU, int Summand);
extern int FAST AddElementWLnumBit64(HMEM_CTX_DEF
		                     WLNUM * pWnumU, int Summand);
extern int FAST AddWLnum(HMEM_CTX_DEF
			WLNUM * pSum, WLNUM * pU, WLNUM * pV);
extern int FAST AddElementWLnum(HMEM_CTX_DEF WLNUM * pWnumU, int Summand);
extern int FAST SubWLnum(HMEM_CTX_DEF
			WLNUM * pDif, WLNUM * pU, WLNUM * pV);
extern int FAST SubElementWLnum(WLNUM * pWnumU, int Subtrahend);
extern int FAST MulWLnum(HMEM_CTX_DEF
			WLNUM * pProd, WLNUM * pU, WLNUM * pV);
extern int FAST SquareWLnum(HMEM_CTX_DEF WLNUM * pProd, WLNUM * pU);
extern int FAST DivWLnum(HMEM_CTX_DEF
		WLNUM * pQuot, WLNUM * pRem,
		WLNUM * pU, WLNUM * pV, WLNUM_CTX * pCtx);
extern int FAST QuotWLnum(HMEM_CTX_DEF
		WLNUM * pQuot,
		WLNUM * pU, WLNUM * pV, WLNUM_CTX * pCtx);
extern int FAST ModWLnum(HMEM_CTX_DEF
		WLNUM * pRem,
		WLNUM * pU, WLNUM * pV, WLNUM_CTX * pCtx);
extern int FAST MulModWLnum(HMEM_CTX_DEF
		WLNUM * pRem, WLNUM * pU,
		WLNUM * pV, WLNUM * pMod, WLNUM_CTX * pCtx);
extern int FAST ExpModWLnum(HMEM_CTX_DEF
			    WLNUM * pRem, WLNUM * pU, WLNUM * pV,
			    WLNUM * pMod, WLNUM_CTX * pCtx,
			    void callback(int));
extern int FAST GcdWLnum(HMEM_CTX_DEF
			WLNUM * pRes, WLNUM * pU, WLNUM * pV);
extern int FAST InvModWLnum(HMEM_CTX_DEF
		WLNUM * pUinv,
		WLNUM * pU, WLNUM * pMod, WLNUM_CTX * pCtx);
extern int FAST WLnum_bin2wlnum(HMEM_CTX_DEF
			WLNUM * pWLnum, char * pSrcBuf,
			int SrcOffset, int SrcLen);
extern int FAST WLnum_bin2wlnumLe(HMEM_CTX_DEF
			WLNUM * pWLnum, char * pSrcBuf,
			int SrcOffset, int SrcLen);
extern int FAST WLnum_wlnum2bin(
		char * pDstBuf, int DstIndex,
		int * pDstLen, WLNUM * pWLnum, int ZeroFlag);
extern int FAST WLnum_wlnum2binLe(
		char * pDstBuf, int DstIndex,
		int * pDstLen, WLNUM * pWLnum, int ZeroFlag);
extern int FAST WLnum_wlnum2binFill(char * pDstBuf, int DstIndex,
		int * pDstLen, WLNUM * pWLnum, int ReqNumLen);

extern int FAST WLnumRand(HMEM_CTX_DEF
			WLNUM * pRnd, int BitSize,
			int TopFlag, int OddFlag);
extern int FAST ModWordWLnum(WLNUM * pWnumU, short Modulus);
extern int FAST DoEratosthenesWSieve(HMEM_CTX_DEF
			short pPrimesArr[], int MaxNums);
extern int FAST WLnumMillerRabin(HMEM_CTX_DEF
			WLNUM * pWnumN, int CheckCount,
			int * pResult, WLNUM_CTX * pCtx,
			void callback(int));
extern int FAST GenPrimeWLnum(HMEM_CTX_DEF
	 WLNUM * pPrime, int Bits,
         WLNUM * pStep, WLNUM * pRem, int Strong, WLNUM_CTX * pCtx,
         void (*callback)(int));
extern int FAST m_lcm_wlnum(HMEM_CTX_DEF
                                   WLNUM * adsp_u, WLNUM * adsp_v,
                                   WLNUM * adsp_result);
#if defined __cplusplus
}
#endif

//==============================================================
// RSA
//==============================================================
//----------------------------------------------------
// Global Returncodes
//----------------------------------------------------
#define	RSA_OP_OK				 0

//----------------------------------------------------
// Specific Returncodes, Range is -700 ... -799
//----------------------------------------------------
//----------------------------------------------------
// Fast Exponentation Returncodes
//----------------------------------------------------
#define RSA_FAST_EXPMOD_FAILURE			-700

//----------------------------------------------------
// Public Encrypt Returncodes
//----------------------------------------------------
#define RSA_PUBENC_ALLOC_ERR			-710
#define RSA_PUBENC_DATA_TOO_LARGE		-711
#define RSA_PUBENC_KEY_SIZE_TOO_LARGE		-712
#define RSA_PUBENC_RANDOM_GET_FAILURE		-713
#define RSA_PUBENC_LNUM_ALLOC_ERR		-714
#define RSA_PUBENC_BYTES_TO_LNUM_ERR		-715
#define RSA_PUBENC_EXPMOD_ERR			-716
#define RSA_PUBENC_LNUM_TO_BYTES_ERR		-717
//----------------------------------------------------
// Private Encrypt Returncodes
//----------------------------------------------------
#define RSA_PRIVENC_ALLOC_ERR			-720
#define RSA_PRIVENC_SRCDATA_TOO_LARGE		-721
#define RSA_PRIVENC_DSTBUF_TOO_SMALL		-722
#define RSA_PRIVENC_LNUM_ALLOC_ERR		-723
#define RSA_PRIVENC_BYTES_TO_LNUM_ERR		-724
#define RSA_PRIVENC_FAST_EXPMOD_ERR		-725
#define RSA_PRIVENC_EXPMOD_ERR			-726
#define RSA_PRIVENC_LNUM_TO_BYTES_ERR		-727
//----------------------------------------------------
// Public Decrypt Returncodes
//----------------------------------------------------
#define RSA_PUBDEC_ALLOC_ERR			-730
#define RSA_PUBDEC_LNUM_ALLOC_ERR		-731
#define RSA_PUBDEC_BYTES_TO_LNUM_ERR		-732
#define RSA_PUBDEC_SRCDATA_TOO_LARGE		-733
#define RSA_PUBDEC_EXPMOD_ERR			-734
#define RSA_PUBDEC_LNUM_TO_BYTES_ERR		-735
#define RSA_PUBDEC_BLOCKTYPE_NOT_00_01		-736
#define RSA_PUBDEC_NO_DATA_BLOCK_DELIM		-737
#define RSA_PUBDEC_BAD_FF_HEADER		-738
#define RSA_PUBDEC_BAD_PAD_BYTE_COUNT		-739
#define RSA_PUBDEC_DSTBUF_TOO_SMALL		-740
#define	RSA_PUBDEC_BLOCKTYPE_NOT_01		-741	// TLS
//----------------------------------------------------
// Private Decrypt Returncodes
//----------------------------------------------------
#define RSA_PRIVDEC_ALLOC_ERR			-750
#define RSA_PRIVDEC_LNUM_ALLOC_ERR		-751
#define RSA_PRIVDEC_BYTES_TO_LNUM_ERR		-752
#define RSA_PRIVDEC_SRCDATA_TOO_LARGE		-753
#define RSA_PRIVDEC_FAST_EXPMOD_ERR		-754
#define RSA_PRIVDEC_EXPMOD_ERR			-755
#define RSA_PRIVDEC_LNUM_TO_BYTES_ERR		-756
#define RSA_PRIVDEC_BLOCKTYPE_NOT_02		-757
#define RSA_PRIVDEC_NO_DATA_BLOCK_DELIM		-758
#define RSA_PRIVDEC_BAD_PAD_BYTE_COUNT		-759
#define RSA_PRIVDEC_DSTBUF_TOO_SMALL		-760
#define	RSA_PRIVDEC_GET_RAND_ERR		-761
//----------------------------------------------------
// Signature Generate/Verify Returncodes
//----------------------------------------------------
#define	RSA_SIG_PARAMS_MISSING			-770
#define	RSA_SIG_DSTBUF_TOO_SMALL		-771
#define	RSA_SIG_INVALID_SIGNATURE_LEN		-772
#define	RSA_SIG_TMP_ALLOC_ERR			-773
#define	RSA_SIG_UNKNOWN_ALGOR_TYPE		-774
#define RSA_SIG_PRIV_ENCRYPT_ERR		-775
#define RSA_SIG_PUBLIC_DECRYPT_ERR		-776
#define	RSA_SIG_VERIFY_FAILURE			-777

//----------------------------------------------------------
// definitions for signature digests etc.
//----------------------------------------------------------
#define	MD2_WITH_RSA_ALGOR		0
#define	MD5_WITH_RSA_ALGOR		1
#define	SHA1_WITH_RSA_ALGOR		2
#define	RIPEMD160_WITH_RSA_ALGOR	3

#define	RSA_MAX_DIGEST_LEN		20	// from SHA1/RIPEMD

#define RSA_DEFAULT_PUB_EXP		0x010001 // Fermat number F4


#if defined __cplusplus
extern "C" {
#endif

//----------------------------------------------------------
// structure for RSA Public/Private key acording to PKCS1
//----------------------------------------------------------
typedef struct RSA_STRUC_t
{
  int Version;			// Version, is 0
  WLNUM * Modul;		// modulus, n = p * q
  WLNUM * PubExp;		// public exponent e
  WLNUM * PrivExp;		// private exponent d
  WLNUM * Prime_p;		// prime p
  WLNUM * Prime_q;		// prime q
  WLNUM * Dmodpm1;		// d mod(p-1)
  WLNUM * Dmodqm1;		// d mod(q-1)
  WLNUM * Invqmp;		// q**(-1) mod p
} RSA_STRUC;
//------------------------------------------------------------
// Externals
//------------------------------------------------------------
extern int FAST RSA_Size(RSA_STRUC * rsa);
extern int FAST RSA_BitSize(RSA_STRUC * rsa);

extern void FAST RSA_Free(HMEM_CTX_DEF RSA_STRUC * rsa);
extern RSA_STRUC * FAST RSA_New(HMEM_CTX_DEF
				   int nElementcnt,
				   int eElementCnt,
				   int dElementcnt,
				   int pElementcnt,
				   int qElementcnt);

extern int FAST  RSA_PublicEncrypt(HMEM_CTX_DEF
				   char * MsgBuf, int MsgOff,
				   int  MsgLen,
				   char * DstBuf, int DstOff,
				   int * DstLen,
				   RSA_STRUC * rsa, int ZeroFill);

extern int FAST RSA_PrivateEncrypt(HMEM_CTX_DEF
				   char * InpBuf,int InpLen,
                                   char * DstBuf,int DstOffset,
				   int * DstLen,
				   RSA_STRUC * rsa,
				   int ZeroFlag);

extern int FAST RSA_PrivateEncryptEx(HMEM_CTX_DEF
			 	     char * InpBuf, int InpLen,
                                     char * DstBuf, int DstOffset,
				     int * pDstLen,
				     RSA_STRUC * rsa,
				     int ZeroFlag);

extern int FAST RSA_PublicDecrypt(HMEM_CTX_DEF
				  int Buflen, char * InpBuf,
				  int InputOffset,
                                  char * OutpBuf, int * MsgLen ,
                                  RSA_STRUC * rsa);

extern int FAST RSA_PublicDecryptEx(HMEM_CTX_DEF
				  int Buflen, char * InpBuf,
				  int InputOffset,
                                  char * OutpBuf, int * MsgLen ,
                                  RSA_STRUC * rsa, int Flags);

extern int FAST RSA_PrivateDecrypt(HMEM_CTX_DEF
				   char * InpBuf, int InpOff,
				   int Inplen,
                                   char * OutpBuf, int * MsgLen,
                                   RSA_STRUC * rsa);

extern int FAST RSA_sign(HMEM_CTX_DEF
		     int DigestType,
		     char * MessageBuf,
		     int MsgBufOffset, int MessageLen,
		     char * SignatureBuf,
		     int SignatBufOffset, int * SignatureLen,
		     RSA_STRUC * rsa, int mode);

extern int FAST RSA_signEx(HMEM_CTX_DEF
		     int DigestType,
		     char * MessageBuf,
		     int MsgBufOffset, int MessageLen,
		     char * SignatureBuf,
		     int SignatBufOffset, int * SignatureLen,
		     RSA_STRUC * rsa, int mode, int Flags);

extern RSA_STRUC * FAST RSA_GenKey(HMEM_CTX_DEF int bits, int e_value,
             	  	       void (*callback)(int));

extern int FAST m_rsa_crypt_raw_big(HMEM_CTX_DEF
	unsigned char * abyp_rsa_data, int imp_rsa_data_len,
	unsigned char * abyp_rsa_exp,  int imp_rsa_exp_len,
	unsigned char * abyp_rsa_modulus, int imp_rsa_modulus_len,
	unsigned char * abyp_dst_buf, int * aimp_dst_len);

extern int FAST m_rsa_crypt_raw_little(HMEM_CTX_DEF
	unsigned char * abyp_rsa_data, int imp_rsa_data_len,
	unsigned char * abyp_rsa_exp,  int imp_rsa_exp_len,
	unsigned char * abyp_rsa_modulus, int imp_rsa_modulus_len,
	unsigned char * abyp_dst_buf, int * aimp_dst_len);


#ifdef __cplusplus
}
#endif

//==============================================================
// DSA/Diffie Hellman
//==============================================================
//------------------------------------------------
// Global Returncodes
//------------------------------------------------
#define DSA_OP_OK			 0
#define DH_OP_OK			 0
#define DSA_DH_OP_OK			 0	// same as LNUM_OP_OK

#define	DSA_DH_NULL_PTR			-1
#define	DSA_DH_ALLOC_ERR		-3

//------------------------------------------------
// Specific Returncodes, range is -800 ... -899
//------------------------------------------------
//------------------------------------------------------------------
// DSA/DH Key-/Parameter generation/check Returncodes, internal only
//------------------------------------------------------------------
#define DSA_DH_GEN_INV_BITSIZE  	-800

#define DSA_DH_CHK_INV_BITSIZE		-805
#define DSA_DH_CHK_INVALID_PUBVAL	-806

#define DSA_DH_KEY_SIZE_ERR		-810
#define DSA_DH_KEY_PRIV_GEN_ERR		-811
#define DSA_DH_KEY_PUBL_GEN_ERR		-812

//------------------------------------------------
// DSA Key generate Returncodes
//------------------------------------------------
#define DSA_GEN_NULL_PTR_ERR		-820
#define DSA_GEN_INV_BITSIZE_ERR		-821
#define DSA_GEN_ALLOC_ERR		-822

//------------------------------------------------
// DSA Signature generate/verify Returncodes
//------------------------------------------------

#define DSA_SIGN_R_DATA_TOO_LARGE	-830
#define DSA_SIGN_S_DATA_TOO_LARGE	-831
#define DSA_SIGN_DATA_TOO_LARGE		-832
#define DSA_SIGN_LNUM_ERR		-833
#define	DSA_SIGN_BUFFER_TOO_SMALL	-834
#define DSA_SIGN_INVALID_HASH_LEN	-835
#define	DSA_SIGN_R_S_ZERO		-836


#define DSA_VERIFY_SIGNAT_TOO_SMALL	-840
#define DSA_VERIFY_ALLOC_ERR		-841
#define	DSA_VERIFY_INVALID_SIGNAT_DATA	-842
#define DSA_VERIFY_NO_R_VALUE		-843
#define DSA_VERIFY_NO_S_VALUE		-844
#define	DSA_VERIFY_INVALID_SIGNAT	-845
#define DSA_VERIFY_LNUM_ERR		-846
#define DSA_VERIFY_INVALID_HASH_LEN	-847

//------------------------------------------------
// DH Params/Secret generate Returncodes
//------------------------------------------------
#define DH_GEN_NULL_PTR_ERR		-850
#define DH_GEN_INV_BITSIZE		-851
#define DH_GEN_ALLOC_ERR		-852

#define DH_COMPUTE_KEY_INV_DATA		-860
#define DH_COMPUTE_KEY_ALLOC_ERR	-861
#define DH_COMPUTE_KEY_EXPMOD_ERR	-862
#define DH_COMPUTE_KEY_LNUM_TO_BIN_ERR	-863
//-------------------------------------------------------
// Defines
//-------------------------------------------------------
#define DSA_GEN_TYPE		0	// generate DSA parameters
#define DH_GEN_TYPE		1	// generate DH  parameters

#define MIN_DH_DSA_Q_BITS	160

#if defined __cplusplus
extern "C" {
#endif

//-------------------------------------------------------
// DSA/Diffie hellman structures
//-------------------------------------------------------
typedef struct DSA_STRUC_st
{
  WLNUM * p;
  WLNUM * q;
  WLNUM * g;
  WLNUM * y;
  WLNUM * x;
} DSA_STRUC;

typedef struct DH_STRUC_t
{
  WLNUM * p;		// prime p
  WLNUM * q;		// prime q
  WLNUM * g;		// base  g (Generator)
  WLNUM * j;		// subgroup factor j
  WLNUM * PubKey;	// public key
  WLNUM * PrivKey;	// private key
  WLNUM * Seed;		// generation seed
  int PgenCount;	// generation counter
  int PrivLen;		// private Key length
} DH_STRUC;
//----------------------------------------------------------
// Externals
//----------------------------------------------------------
extern void FAST DSA_Free(HMEM_CTX_DEF DSA_STRUC * r);

extern DSA_STRUC * FAST DSA_New(HMEM_CTX_DEF
				  int pElementcnt,
			          int qElementcnt,
			          int gElementcnt,
			          int yElementcnt,
				  int xElementcnt);

extern int FAST DSA_BitSize(DSA_STRUC * dsa);

extern int DSA_SignatMaxLen(DSA_STRUC * dsa);

extern int FAST DSA_Sign(HMEM_CTX_DEF
			 char * msgBuf, int msgOffset, int msgLen,
                         char * sigBuf, int sigOffset, int * sigLen,
                         DSA_STRUC * dsa, WLNUM * kTest, int Mode);

extern int FAST DSA_Verify(HMEM_CTX_DEF
			   char * msgBuf, int msgOffset, int msgLen,
                           char * sigBuf, int sigOffset, int sigLen,
                           DSA_STRUC * dsa, int Mode);

extern int FAST DSA_GenKey(HMEM_CTX_DEF DSA_STRUC * dsa);

extern int FAST DSA_GenParams(HMEM_CTX_DEF int pBits,
			      DSA_STRUC ** pdsa,
			      void CallBack(int));

extern int GenDsaDhParams(HMEM_CTX_DEF
				 int L, int m, int ncheck,
				 int Type,
				 WLNUM * p, WLNUM * q, WLNUM * g,
				 WLNUM * j, WLNUM * Seed, int * Counter,
				 void callback(int));

extern int GenDsaDhKey(HMEM_CTX_DEF
			      int PrivKeyLen, int KeyType, int Mode,
			      WLNUM * p, WLNUM * q, WLNUM * g,
			      WLNUM * y, WLNUM * x,
			      void callback(int));


extern int CheckDsaDhPubValue(HMEM_CTX_DEF
			WLNUM * p, WLNUM * q, WLNUM * y);

extern DH_STRUC * FAST DH_New(HMEM_CTX_DEF
			int pElementcnt,
			int qElementcnt,
			int gElementcnt,
			int yElementcnt,
			int xElementcnt);

extern void FAST DH_Free(HMEM_CTX_DEF DH_STRUC * r);

extern int FAST DH_Size(DH_STRUC * dh);
extern int FAST DH_BitSize(DH_STRUC * dh);
extern int FAST DH_ParamCompare(DH_STRUC * Dh1, DH_STRUC * Dh2);

extern int FAST DH_GenParams(HMEM_CTX_DEF
			     int pBits, int qBits, DH_STRUC ** pdh,
			     void CallBack(int));

extern int FAST DH_GenKey(HMEM_CTX_DEF DH_STRUC *dh,
				   void CallBack(int));

extern int FAST DH_GenSecret(HMEM_CTX_DEF
				    char * pDstBuf[], int pDstLen[],
				    DH_STRUC * dh);

extern int FAST DSA_SignRaw(HMEM_CTX_DEF
		char * pDgstBuf, int DgstOffset,
		int DgstLen, char * pSigBuf, int SigOffset, int * pSigLen,
		DSA_STRUC * dsa, WLNUM * kTest);

extern int FAST DSA_VerifyRaw(HMEM_CTX_DEF
		char * pDgstBuf, int DgstOffset,
		int DgstLen, char * pSigBuf, int SigOffset, int SigLen,
		DSA_STRUC * dsa);

#if defined __cplusplus
}
#endif


#endif	// __HOB_ENCRYPT_HEADER__
