#ifndef SDH_PRECOMP_H
#define SDH_PRECOMP_H

#define JF_CORRECT_ALIGNMENT // JF 05.03.07: corrects alignment ONLY FOR PURPOSES OF PRECOMP-IN-WEBSERVERDLL

#define WORK_AS_SDH   // without this define: precompiler will work on files (read in a file and write an output file)
                 // with this define: precompiler will use the passed work area

//#define FOR_WSP_V23 // set this define to enable for WSPv23

#if defined WIN32 || WIN64
    #include <windows.h>
#else
    #include <types_defines.h>
    #include <stdarg.h>  // for va_arg, etc.
#endif


/*+--------------------------------------------------------------------------+*/
/*| System and library header files.                                         |*/
/*+--------------------------------------------------------------------------+*/


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
// JF not needed #include <conio.h>
#include <time.h>

// MJ 05.05.09:
#ifndef _HOB_XSCLIB01_H
    #define _HOB_XSCLIB01_H
    #include <hob-xsclib01.h>
#endif //_HOB_XSCLIB01_H

#define LEN_STACK      65536                /* length stack to store v */
#define LEN_MAC_S        512                /* length macro start      */
#define LEN_MAC_C        512                /* length macro resize     */
#define LINELEN        10000                /* length of line          */
#define CHAR_CR         0X0D                /* carriage-return         */
#define CHAR_LF         0X0A                /* line-feed               */
#define CHAR_EOF        0X1A                /* end-of-file             */
#define CHAR_QUOTE      0X27                /* character quote         */
#define LENSYM            16                /* length of symbol        */

#if defined WIN32 || WIN64
#ifndef WORK_AS_SDH
#define HFILE  HANDLE
#endif // #ifndef WORK_AS_SDH
#define APIRET DWORD
#endif

// ATTENTION: THERE MUST BE AN ALPHABETICAL ORDER
#define DEF_SEC_NO                 13           /* number of symbols       */
#define DEF_SEC_COPYC				0
#define DEF_SEC_DATE				1
#define DEF_SEC_INPFCOU				2
#define DEF_SEC_INPFILN				3
#define DEF_SEC_LINE_A				4            /* $LINE_A line over all   */
#define DEF_SEC_LINE_FI				5            /* $LINE_FI line of this file */
#define DEF_SEC_LINE_O				6            /* $LINE_O line output     */
#define DEF_SEC_PPP_INETA			7			// HOB-PPP-Tunnel: applet-parameter WSP_INETA; address of HOB-PPP-Tunnel
#define DEF_SEC_PPP_L2TP_ARG		8			// HOB-PPP-Tunnel: applet-parameter WSP_L2TP_ARG; string "rasdial ..."
#define DEF_SEC_PPP_LOCALHOST	    9			// HOB-PPP-Tunnel: applet-parameter WSP_L2TP_LOCAL_HOST; string "rasdial ..."
#define DEF_SEC_PPP_SOCKS_MODE	   10			// HOB-PPP-Tunnel: applet-parameter WSP_SOCKS_MODE
#define DEF_SEC_PPP_SYSTEM_PARAMS  11			// HOB-PPP-Tunnel: applet-parameter WSP_SYSTEM_PARAMETER -> [17719]
#define DEF_SEC_PPP_UNIX_PARAMETER 12			// HOB-PPP-Tunnel: applet-parameter WSP_UNIX_PARAMETER


#define DEF_C_MACRO  17
#define DEF_C_MEND   18
#define DEF_C_MEXIT  19
#define DEF_C_MSET   20
#define DEF_C_MDEFT  21
#define DEF_C_RPT    22
#define DEF_C_RPTN   23
#define DEF_C_REND   24
#define DEF_C_REXIT  25

// JF
#define MSG_LEN  2000

class cPrecomp 
{
#ifndef WORK_AS_SDH
HFILE  hfo;                          /* output-file                    */
char   szfni[ MAX_PATH ]; // JF  = "TEST.INP";  /* file-name input      */
char   szfno[ MAX_PATH ]; // JF  = "TEST.OUT";  /* file-name output     */
#endif // #ifndef WORK_AS_SDH

#ifndef WORK_AS_SDH
APIRET rc;                           /* Return code                    */
#endif
unsigned char strlineout[LINELEN+1];
// JF made local: ULONG ulRead;
ULONG ulWrite;
ULONG ulSout;                        /* position output         */
ULONG ul_Sout_save;                  /* position output saved   */
ULONG isavecommand;                  /* save position command   */
short i1;
short i2;
char ch1;
unsigned char strsymbol[LENSYM+1];   /* erkanntes Symbol        */
unsigned char kzout;
  /* 0 = kein, F = File, D = Display, I = Include, T = Text-var. ...   */
  /* A = Arguments for Macro                                           */
unsigned char kzbef1;
unsigned char kzifakt1;
unsigned char kzifakt2;
unsigned char kzifaktu;              /* von Unterprogramm gef.  */
unsigned char ch_symbol_scope;       /* G = global M = macro    */
unsigned char ch_expr_end_search;    /* expression end searched */
unsigned char ch_expr_end_found;     /* expression end found    */
int countif1;
int countif2;
int icountmac1;                      /* count macro-definitions */
int icountrpt1;                      /* count repeat            */
BOOL bcont;                          /* Continue-Zeile          */
long ilinenr; // JF = 0;                    /* Zeilen-Nummer           */
long ins_linenr_out; // JF = 1;             /* line-number output      */
long icopyc; // JF = 0;                     /* Copy-Count              */
/* Symbol suchen */
unsigned char kzsym1;                /* was suchen              */
unsigned char kzsym2;                /* was gefunden            */
ULONG asymtab;                       /* Adresse in Tabelle      */
/* Stack */
ULONG astack;                        /* Adresse freier Bereich  */
ULONG aanfsym;                       /* Anfang der Symbole      */
ULONG aglobsym;                      /* address global symbols  */
ULONG atextende;                     /* Ende der Texte          */
// JF: Attention: after ULONG (must be 8bytes long) the chstack is 8-byte-aligned; otherwise it can be miss-aligned; therefore don't break the order!!
unsigned char chstack[LEN_STACK];

char* ach_empty_string;

typedef struct {
  unsigned char symbol[LENSYM];
  unsigned modebsec :1;                     /* Eintrag geschuetzt      */
  unsigned modebdef :1;                     /* Eintrag definiert       */
  unsigned modebtex :1;                     /* Text                    */
  unsigned modebmac :1;                     /* Macro                   */
  unsigned filler :12;
/*short modet2;*/                           /* Laenge Text             */
  long int modet2;                          /* Laenge Text             */
  union {
    long value;                             /* Wert                    */
    ULONG addr;                             /* Adresse                 */
  } u;
#ifdef JF_CORRECT_ALIGNMENT
  long in_filler1; // JF
#endif
} DSYMBOL;
DSYMBOL wss;

typedef struct {
  long i;
} DLONG;

typedef struct {
  short i;
} DSMALL;

typedef struct {
  unsigned char par;
  unsigned char op;
  unsigned char class1;  // JF class->class1
  unsigned char filler;
  int value;
} DSTOP;

typedef struct {
  unsigned char tifakt1;
} DIFAKT;

/* Tabelle der Input-Files */
typedef struct {
  PVOID next;
#ifndef WORK_AS_SDH
  HFILE hfi;                                /* input-file              */
#endif // #ifndef WORK_AS_SDH
  long  ilnr;                               /* Line-number             */
  short ifil;                               /* Laenge Zeile eingeles.  */
  short ifia;                               /* aktuelle Position       */
  unsigned char *astorinps;                 /* input storage start     */
  unsigned char *astorinpe;                 /* input storage end       */
  unsigned char *astorinpc;                 /* input storage current   */
  int irepcount;                            /* count how many more     */
  unsigned char ch_flag_macro_rpt;          /* read from macro / repea */
  unsigned char strlineinp[LINELEN];
} INFILE;
INFILE *ainf1; // JF = 0;                   /* Anker und aktuell       */
INFILE *ainf2;


/* Befehls-Tabelle */
typedef struct {
  char tname[LENSYM];
  unsigned char tb1;
  unsigned char tb2;
} TABBEF;

TABBEF tabbef[26]; // must be initialized in constructor
////TABBEF tabbef[] = {
////  "INT             ",'0','0',
////  "TEXT            ",'0','0',
////  "HEXA            ",'0','0',
////  "TAB             ",'0','0',
////  "CONT            ",'0','0',
////  "SET             ",'1','0',
////  "DEFT            ",'1','0',
////  "INCLUDE         ",'1','0',
////  "CANCEL          ",'1','0',
////  "DISP            ",'1','0',
////  "ACC             ",'1','0',
////  "IIF             ",'2','0',
////  "IF              ",'2','1',
////  "IFT             ",'2','1',
////  "IFF             ",'2','1',
////  "IFTF            ", '2', '1',
////  "CEND            ", '2', '1',
////  "MACRO           ", '2', '1',
////  "MEND            ", '2', '1',
////  "MEXIT           ", '1', '0',
////  "MSET            ", '1', '0',
////  "MDEFT           ", '1', '0',
////  "RPT             ", '2', '1',
////  "RPTN            ", '2', '1',
////  "REND            ", '2', '1',
////  "REXIT           ", '1', '0' };

short itabbef;


/* Operatoren-Tabelle */
typedef struct {
  unsigned char chop;
  unsigned char class1; // JF class->class1
  short ityp;
} TABOP;
TABOP tabop[8];
//////TABOP tabop[] = {
//////  '+','2',0,
//////  '-','2',0,
//////  '*','4',0,
//////  '/','4',0,
//////  '(','8',1,
//////  ')','1',2,
//////  ',','0',3,
//////  ';','0',3};
short itabop;


/* Condition-Tabelle */
typedef struct {
  char cname[4];
} TABCOND;
TABCOND tabcond[8]; // must be initialized in constructor
//////TABCOND tabcond[] = {
//////  "DEF ",
//////  "NDF ",
//////  "EQ  ",
//////  "NE  ",
//////  "GT  ",
//////  "LT  ",
//////  "GE  ",
//////  "LE  "};


/* table of macro arguments                                            */
typedef struct {
  char aname[8];
} TABMARG;
TABMARG tabmarg[3]; // must be initialized in constructor
//////static TABMARG tabmarg[] = {
//////  "MINT    ",
//////  "MTEXT   ",
//////  "MQUOTE  " };

unsigned char chartab[256];
//////unsigned char chartab[256] = {
//////  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
//////  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
//////  0,0,0,0,'$',0,0,0,0,0,0,0,0,0,0,0,
//////  '0','1','2','3','4','5','6','7','8','9',0,0,0,0,0,0,
//////  0,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,
//////  80,81,82,83,84,85,86,87,88,89,90,0,0,0,0, 0X5F,
//////  0,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,
//////  80,81,82,83,84,85,86,87,88,89,90,0,0,0,0,0,
//////  0,0X9A,0,0,0X8E,0,0,0,0,0,0,0,0,0,0X8E,0,             /* 80 bis 8F */
//////  0,0,0,0,0X99,0,0,0,0,0X99,0X9A,0,0,0,0,0,
//////  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
//////  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
//////  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
//////  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
//////  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
//////  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

// JF
int in_bytes_occupied_wa;
int in_flags;
int in_len_ainf1;
struct dsd_hl_clib_1* ads_trans;
char ch_msg[MSG_LEN];

public:
    cPrecomp(int in_flags_inp = 0);
    int m_hlclib01(struct dsd_hl_clib_1* ads_trans);

    void m_set_ppp_ineta(char* achl_ppp_ineta);
    void m_set_ppp_l2tp_arg(char* achl_ppp_l2tp_arg);
    void m_set_ppp_socks_mode(char* achl_ppp_socks_mode);
    void m_set_ppp_localhost(char* achl_ppp_localhost);
    void m_set_ppp_unix_parameter(char* achl_ppp_unix_parameter);
    void m_set_ppp_system_parameter(char* achl_ppp_system_parameter);

private:
    void ugetdate( void );
    void uinfile( void );
    void upruefend( void );
    void usymbol( void );
    void usymbos( void );
    void usymbsun( void );
    void usymbsut( void );
    BOOL usymbein( void );
    void usymbtab( void );               /* search symbol in table  */
    void usecvalue( void );
    void uzahl( void );
    BOOL uausdr( void );
    BOOL uholif( void );
    BOOL uint( void );
    void uhexa( void );
    BOOL utab( void );
    BOOL utext( void );
    BOOL uset( void );
    BOOL umset( void );
    BOOL udeft( void );
    BOOL umdeft( void );
    BOOL uacc( void );
    BOOL ucmacro( void );                /* command MACRO           */
    BOOL umargs( void );                 /* macro arguments         */
    BOOL usaveSout( void );              /* save previous output    */
    BOOL decstack( int, int );
    BOOL incstack( int, int );

    // JF
    void m_dump_data(unsigned char* lpData, int nLen, FILE* fTrace);
    int m_sdh_printf( char *achptext, ... );
    //__int64 GetMachineCycleCount();

// Ticket[14388]
    char* ach_ppp_ineta;
    char* ach_ppp_l2tp_arg;
    char* ach_ppp_socks_mode;
    char* ach_ppp_localhost;
    char* ach_ppp_unix_parameter; // Ticket[16598]
    char* ach_ppp_system_parameter;
    char* m_get_ppp_ineta();
    char* m_get_ppp_l2tp_arg();
    char* m_get_ppp_socks_mode();
    char* m_get_ppp_localhost();
    char* m_get_ppp_unix_parameter();
    char* m_get_ppp_system_parameter();

};

#endif // SDH_PRECOMP_H
