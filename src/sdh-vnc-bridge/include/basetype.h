#if !defined __BASE_TYPES__
#define	__BASE_TYPES__


#if defined WIN32		// MUST COME FIRST !!
#pragma warning(disable:4115)
#include <windows.h>
#pragma warning(default:4115)
#endif


#if 0
// some (new) defines for malta...
#endif

#if defined _SOLARIS && !defined HL_SOLARIS
#define HL_SOLARIS
#endif

#if defined _LINUX && !defined HL_LINUX
#define HL_LINUX
#endif


#if 0
// New defines to map the old ones to the new ones (HL_.....)
// to keep compiling same as before.
#endif

#if defined SOLARIS && !defined HL_SOLARIS
#define HL_SOLARIS
#endif

#if defined AIX && !defined HL_AIX
#define HL_AIX
#endif

#if defined HPUX && !defined HL_HPUX
#define HL_HPUX
#endif

#if defined LINUX && !defined HL_LINUX
#define HL_LINUX
#endif

#if defined FREEBSD && !defined HL_FREEBSD
#define HL_FREEBSD
#endif

#if defined OPENUNIX && !defined HL_OPENUNIX
#define HL_OPENUNIX
#endif




#ifndef FALSE
#define FALSE 0
#endif

#ifndef TRUE
#define TRUE 1
#endif


#if defined WIN32 || defined WIN64

#ifdef NULL 
#undef NULL
#endif


#define	PUBLIC
#define NULL  0
#define	FINAL
#define STATIC
#define PRIVATE		static
#define SYNCHRONIZED
#define SYNCHRONIZED_JAVA
#define	CONST		const

#ifndef __NO_FASTCALL__
#if !defined NOFAST
#define	FAST		_fastcall 
#else
#define	FAST
#endif
#endif

#define REGISTER	register

#define	BIT8	char
#if !defined BYTE
#define BYTE	unsigned char	
#endif
#define BYTEPTR unsigned char *		// wg. C-Compiler
#define	BIT8PTR char *
#define BIT8PPTR char **
#define BIT8PPPTR char ***
#define	INTPTR	int *
#define	INTPPTR	int **
#define	BIT16_MINUS_ONE 0xFFFF

#define STRING		BYTE
#define STRING_PTR	BIT8 *
#define STRING_PPTR	BIT8 **
#define STRING_PPPTR	BIT8 ***
#define STRING_CHAR(Name,Index)	Name[Index]

#define	INT_BITS	32		// int has 32 Bits
#define	INT_MINUS_ONE	0xFFFFFFFF	// - 1

#define	UBIT16	 unsigned short
#define	BIT16	 short
#define BIT16PTR short *
#define	UBIT32	 unsigned int
#define UBIT32PTR unsigned int *
#define	BIT32	 int
#define BIT32PTR int *
#define BIT32PPTR int **

#define	BIT8ARRAY(name,size) BIT8 name[size]
#define	BYTEARRAY(name,size) BYTE name[size]
#define	BIT8PTRARRAY(name,size) BIT8 * name[size]
#define	BIT8PTRARRAYI(name,size) BIT8 * name[size]
#define	BIT8PPTRARRAY(name,size) BIT8 ** name[size]
#define	BIT8PPTRARRAYI(name,size) BIT8 ** name[size]
#define	BIT8ARRAYI(name,size) BIT8 name[size]
#define	BYTEARRAYI(name,size) BYTE name[size]
#define	BIT16ARRAY(name,size) BIT16 name[size]
#define	BIT16ARRAYI(name,size) BIT16 name[size]
#define	BIT32ARRAY(name,size) BIT32 name[size]
#define	BIT32ARRAYI(name,size) BIT32 name[size]
#define	BIT32PTRARRAY(name,size) BIT32 * name[size]
#define	UBIT32ARRAY(name,size) UBIT32 name[size]
#define	UBIT32ARRAYI(name,size) UBIT32 name[size]


#define INTARRAY(name,size) int name[size]
#define INTARRAYI(name,size) int name[size]
#define INTPTRARRAY(name,size) int * name[size]
#define INTPTRARRAYI(name,size) int * name[size]

#define STRINGARRAY(name,size)  BIT8 name [size]
#define STRINGARRAYI(name,size) BIT8 name []
#define STRINGPTR_ARRAY(name,size) BIT8 * name [size]
#define STRINGPTR_ARRAYI(name,size) BIT8 * name [size]
#define STRINGPPTR_ARRAY(name,size) BIT8 ** name [size]
#define STRINGPPTR_ARRAYI(name,size) BIT8 ** name [size]
#define STRINGPPPTR_ARRAY(name,size) BIT8 *** name [size]
#define STRINGPPPTR_ARRAYI(name,size) BIT8 *** name [size]

#endif // WIN32


#if defined HL_SOLARIS || defined HL_AIX || defined HL_HPUX || defined HL_FREEBSD || defined HL_OPENUNIX

#ifdef NULL 
#undef NULL
#endif

#define	PUBLIC
#define NULL  0
#define	FINAL
#define STATIC
#define PRIVATE		static
#define SYNCHRONIZED
#define SYNCHRONIZED_JAVA
#define	CONST		const

#define	FAST
#define REGISTER	register

#define BIT8	char
#define	BIT8PTR char *
#define BIT8PPTR char **
#define BIT8PPPTR char ***
#define BYTE	unsigned char	
#define BYTEPTR unsigned char *		// wg. C-Compiler
#define	INTPTR	int *
#define	INTPPTR	int **
#define	BIT16_MINUS_ONE 0xFFFF

#define STRING		char
#define STRING_PTR	char *
#define STRING_PPTR	char **
#define STRING_PPPTR	char ***
#define STRING_CHAR(Name,Index)	Name[Index]

#define	INT_BITS	32		// int has 32 Bits
#define	INT_MINUS_ONE	0xFFFFFFFF	// - 1

#define	UBIT16	 unsigned short
#define	BIT16	 short
#define BIT16PTR short *
#define	UBIT32	 unsigned int
#define UBIT32PTR unsigned int *
#define	BIT32	 int
#define BIT32PTR int *
#define BIT32PPTR int **


#define	BIT8ARRAY(name,size) BIT8 name[size]
#define	BYTEARRAY(name,size) BYTE name[size]
#define	BIT8PTRARRAY(name,size) BIT8 * name[size]
#define	BIT8PTRARRAYI(name,size) BIT8 * name[size]
#define	BIT8PPTRARRAY(name,size) BIT8 ** name[size]
#define	BIT8PPTRARRAYI(name,size) BIT8 ** name[size]
#define	BIT8ARRAYI(name,size) BIT8 name[size]
#define	BYTEARRAYI(name,size) BYTE name[size]
#define	BIT16ARRAY(name,size) BIT16 name[size]
#define	BIT16ARRAYI(name,size) BIT16 name[size]
#define	BIT32ARRAY(name,size) BIT32 name[size]
#define	BIT32ARRAYI(name,size) BIT32 name[size]
#define	BIT32PTRARRAY(name,size) BIT32 * name[size]
#define	UBIT32ARRAY(name,size) UBIT32 name[size]
#define	UBIT32ARRAYI(name,size) UBIT32 name[size]


#define INTARRAY(name,size) int name[size]
#define INTARRAYI(name,size) int name[size]
#define INTPTRARRAY(name,size) int * name[size]
#define INTPTRARRAYI(name,size) int * name[size]

#define STRINGARRAY(name,size)  BIT8 name [size]
#define STRINGARRAYI(name,size) BIT8 name []
#define STRINGPTR_ARRAY(name,size) BIT8 * name [size]
#define STRINGPTR_ARRAYI(name,size) BIT8 * name [size]
#define STRINGPPTR_ARRAY(name,size) BIT8 ** name [size]
#define STRINGPPTR_ARRAYI(name,size) BIT8 ** name [size]
#define STRINGPPPTR_ARRAY(name,size) BIT8 *** name [size]
#define STRINGPPPTR_ARRAYI(name,size) BIT8 *** name [size]

#endif // SOLARIS


#if defined HL_LINUX

#ifdef NULL 
#undef NULL
#endif

#define	PUBLIC
#define NULL  0
#define	FINAL
#define STATIC
#define PRIVATE		static
#define SYNCHRONIZED
#define SYNCHRONIZED_JAVA
#define	CONST		const

#define	FAST
#define REGISTER	register

#define BIT8	char
#define	BIT8PTR char *
#define BIT8PPTR char **
#define BIT8PPPTR char ***
#define BYTE	unsigned char	
#define BYTEPTR unsigned char *		// wg. C-Compiler
#define	INTPTR	int *
#define	INTPPTR	int **
#define	BIT16_MINUS_ONE 0xFFFF

#define STRING		char
#define STRING_PTR	char *
#define STRING_PPTR	char **
#define STRING_PPPTR	char ***
#define STRING_CHAR(Name,Index)	Name[Index]

#define	INT_BITS	32		// int has 32 Bits
#define	INT_MINUS_ONE	0xFFFFFFFF	// - 1

#define	UBIT16	 unsigned short
#define	BIT16	 short
#define BIT16PTR short *
#define	UBIT32	 unsigned int
#define UBIT32PTR unsigned int *
#define	BIT32	 int
#define BIT32PTR int *
#define BIT32PPTR int **


#define	BIT8ARRAY(name,size) BIT8 name[size]
#define	BYTEARRAY(name,size) BYTE name[size]
#define	BIT8PTRARRAY(name,size) BIT8 * name[size]
#define	BIT8PTRARRAYI(name,size) BIT8 * name[size]
#define	BIT8PPTRARRAY(name,size) BIT8 ** name[size]
#define	BIT8PPTRARRAYI(name,size) BIT8 ** name[size]
#define	BIT8ARRAYI(name,size) BIT8 name[size]
#define	BYTEARRAYI(name,size) BYTE name[size]
#define	BIT16ARRAY(name,size) BIT16 name[size]
#define	BIT16ARRAYI(name,size) BIT16 name[size]
#define	BIT32ARRAY(name,size) BIT32 name[size]
#define	BIT32ARRAYI(name,size) BIT32 name[size]
#define	BIT32PTRARRAY(name,size) BIT32 * name[size]
#define	UBIT32ARRAY(name,size) UBIT32 name[size]
#define	UBIT32ARRAYI(name,size) UBIT32 name[size]


#define INTARRAY(name,size) int name[size]
#define INTARRAYI(name,size) int name[size]
#define INTPTRARRAY(name,size) int * name[size]
#define INTPTRARRAYI(name,size) int * name[size]

#define STRINGARRAY(name,size)  BIT8 name [size]
#define STRINGARRAYI(name,size) BIT8 name []
#define STRINGPTR_ARRAY(name,size) BIT8 * name [size]
#define STRINGPTR_ARRAYI(name,size) BIT8 * name [size]
#define STRINGPPTR_ARRAY(name,size) BIT8 ** name [size]
#define STRINGPPTR_ARRAYI(name,size) BIT8 ** name [size]
#define STRINGPPPTR_ARRAY(name,size) BIT8 *** name [size]
#define STRINGPPPTR_ARRAYI(name,size) BIT8 *** name [size]

#endif // LINUX


#if !defined JAVA
#define	LOCK_CSHARP(a)
#define	END_LOCK_CSHARP
#endif

#if defined JAVA	// JAVA, CSHARP

#if !defined CSHARP
#define	USING_CSHARP(a)
#define	PACKAGE_JAVA(a)		package	a;
#define	IMPORT_JAVA(a)		import	a;
#define	END_PACKAGE_JAVA
#define	FINAL_CLASS		final
#define	METHOD			Method
#define THREAD			Thread
#define	ARRAY_LENGTH(a)		a.length
#define	STRING_BUFFER		StringBuffer
#define	STR_LENGTH(a)		a.length()
#define	STR_SUBSTR1(a,b)	a.substring(b)
#define	STR_SUBSTR2(a,b,c)	a.substring(b,c)
#define	STR_ENDSWITH(a,b)	a.endsWith(b)
#define	STR_INDEXOF1(a,b)	a.indexOf(b)
#define	STR_INDEXOF2(a,b,c)	a.indexOf(b,c)
#define	STR_LASTINDEXOF1(a,b)	a.lastIndexOf(b)
#define	STR_LASTINDEXOF2(a,b,c)	a.lastIndexOf(b,c)
#define	CHAR_AT(a,b)		a.charAt(b)
#define	SYNCHRONIZED_JAVA	synchronized
#define	LOCK_CSHARP(a)
#define	END_LOCK_CSHARP
#define	INPUT_STREAM		InputStream
#define	OUTPUT_STREAM		OutputStream
#define	STD_INPUT_STREAM	FileInputStream
#define	STD_OUTPUT_STREAM	FileOutputStream
#define	FILE_OBJECT		File
#define	FILE_INPUT_STREAM	FileInputStream
#define	FILE_OUTPUT_STREAM	FileOutputStream
#define	RANDOM_ACCESS_FILE	RandomAccessFile
#else // defined CSHARP
#define	USING_CSHARP(a)		using a;
#define	PACKAGE_JAVA(a)		namespace a {
#define	END_PACKAGE_JAVA	}
#define	IMPORT_JAVA(a)
#define	FINAL_CLASS		sealed
#define	METHOD			System.Reflection.MethodInfo
#define THREAD			System.Threading.Thread
#define	ARRAY_LENGTH(a)		a.Length
#define	STRING_BUFFER		System.Text.StringBuilder
#define	STR_LENGTH(a)		a.Length
#define	STR_SUBSTR1(a,b)	a.Substring(b)
#define	STR_SUBSTR2(a,b,c)	a.Substring(b,c)
#define	STR_ENDSWITH(a,b)	a.EndsWith(b)
#define	STR_INDEXOF1(a,b)	a.IndexOf(b)
#define	STR_INDEXOF2(a,b,c)	a.IndexOf(b,c)
#define	STR_LASTINDEXOF1(a,b)	a.LastIndexOf(b)
#define	STR_LASTINDEXOF2(a,b,c)	a.LastIndexOf(b,c)
#define	CHAR_AT(a,b)		a[b]
#define	SYNCHRONIZED_JAVA
#define	LOCK_CSHARP(a)		lock(typeof(a)){
#define	END_LOCK_CSHARP		}
#define	INPUT_STREAM		System.IO.Stream
#define	OUTPUT_STREAM		System.IO.Stream
#define	STD_INPUT_STREAM	System.IO.Stream
#define	STD_OUTPUT_STREAM	System.IO.Stream
#define	FILE_OBJECT		System.IO.File
#define	FILE_INPUT_STREAM	System.IO.FileStream
#define	FILE_OUTPUT_STREAM	System.IO.FileStream
#define	RANDOM_ACCESS_FILE	System.IO.FileStream
#endif // CSHARP

#define NULL null
#define	PUBLIC	public
#define PRIVATE	private

#if !defined CSHARP
#define CONST	final
#else // CSHARP
#define CONST	readonly
#endif

#define STATIC	static
#define SYNCHRONIZED synchronized
#define	FAST
#define REGISTER

#define	BIT8	 byte
#define BIT8PTR  byte[]
#define BIT8PPTR byte[][]
#define BIT8PPPTR byte[][][]
#define	BYTE	 byte
#define BYTEPTR  byte[]

#define	BIT16    short

#if !defined CSHARP
#define	UBIT16	 short
#else
#define	UBIT16	 ushort
#endif

#define BIT16PTR short[]
#define BIT32	 int
#define BIT32PTR int[]
#define BIT32PPTR int[][]
#define UBIT32	 int
#define UBIT32PTR int[]
#define	INTPTR   int[]
#define	INTPPTR  int[][]

#define STRING	 String
#define STRING_PTR String
#define STRING_PPTR	String[]
#define STRING_PPPTR	String[][]


#if !defined JAVA
//#define STRING	 byte
//#define STRING_PTR byte[]
#endif
#define STRING_CHAR(Name,Index)	Name.charAt(Index)


#define	INT_BITS	32		// int has 32 Bits
#define BIT16_MINUS_ONE INT_MINUS_ONE
#define	INT_MINUS_ONE	0xFFFFFFFF	// - 1


#if !defined CSHARP

#define	BIT8ARRAY(name,size) BIT8 name[]=new BIT8[size]
#define	BYTEARRAY(name,size) BIT8 name[]=new BIT8[size]
#define	BIT8PTRARRAY(name,size) BIT8 name[][]=new BIT8[size][]
#define	BIT8PTRARRAYI(name,size) BIT8 name[][]
#define	BIT8PPTRARRAY(name,size) BIT8 name[][][]=new BIT8[size][][]
#define	BIT8PPTRARRAYI(name,size) BIT8 name[][][]
#define	BIT8ARRAYI(name,size) BIT8 name[]
#define	BYTEARRAYI(name,size) BIT8 name[]
#define	BIT16ARRAY(name,size) BIT16 name[]=new BIT16[size]
#define	BIT16ARRAYI(name,size) BIT16 name[]
#define	BIT32ARRAY(name,size) BIT32 name[]=new BIT32[size]
#define	BIT32ARRAYI(name,size) BIT32 name[]
#define	BIT32PTRARRAY(name,size) BIT32 name[][] =new BIT32[size][]
#define	UBIT32ARRAY(name,size) UBIT32 name[]=new UBIT32[size]
#define	UBIT32ARRAYI(name,size) UBIT32 name[]

#define INTARRAY(name,size) int name[] = new int[size]
#define INTARRAYI(name,size) int name[]
#define	INTPTRARRAY(name,size) int name[][]=new int[size][]
#define	INTPTRARRAYI(name,size) int name[][]

#define STRINGARRAY(name,size)  String name
#define STRINGARRAYI(name,size) String name
#define STRINGPTR_ARRAY(name,size) String name[] = new String[size];
#define STRINGPTR_ARRAYI(name,size) String[] name
#define STRINGPPTR_ARRAY(name,size) String name[][] = new String[size][];
#define STRINGPPTR_ARRAYI(name,size) String[][] name
#define STRINGPPPTR_ARRAY(name,size) String name[][][] = new String[size][][];
#define STRINGPPPTR_ARRAYI(name,size) String[][][] name


#else // defined CSHARP


#define	BIT8ARRAY(name,size) BIT8[] name=new BIT8[size]
#define	BYTEARRAY(name,size) BIT8[] name=new BIT8[size]
#define	BIT8PTRARRAY(name,size) BIT8[][] name=new BIT8[size][]
#define	BIT8PTRARRAYI(name,size) BIT8[][] name
#define	BIT8PPTRARRAY(name,size) BIT8[][][] name=new BIT8[size][][]
#define	BIT8PPTRARRAYI(name,size) BIT8[][][] name
#define	BIT8ARRAYI(name,size) BIT8[] name
#define	BYTEARRAYI(name,size) BIT8[] name
#define	BIT16ARRAY(name,size) BIT16[] name=new BIT16[size]
#define	BIT16ARRAYI(name,size) BIT16[] name
#define	BIT32ARRAY(name,size) BIT32[] name=new BIT32[size]
#define	BIT32ARRAYI(name,size) BIT32[] name
#define	BIT32PTRARRAY(name,size) BIT32[][] name =new BIT32[size][]
#define	BIT32ARRAY(name,size) UBIT32 name[]=new UBIT32[size]
#define	BIT32ARRAYI(name,size) UBIT32 name[]

#define INTARRAY(name,size) int[] name = new int[size]
#define INTARRAYI(name,size) int[] name
#define	INTPTRARRAY(name,size) int[][] name=new int[size][]
#define	INTPTRARRAYI(name,size) int[][] name

#define STRINGARRAY(name,size)  String name
#define STRINGARRAYI(name,size) String name
#define STRINGPTR_ARRAY(name,size) String[] name = new String[size];
#define STRINGPTR_ARRAYI(name,size) String[] name
#define STRINGPPTR_ARRAY(name,size) String[][] name = new String[size][];
#define STRINGPPTR_ARRAYI(name,size) String[][] name
#define STRINGPPPTR_ARRAY(name,size) String[][][] name = new String[size][][];
#define STRINGPPPTR_ARRAYI(name,size) String[][][] name

#endif

#endif // JAVA

#endif /*__BASE_TYPES__ */
