#ifdef TO_DO_140328
max-download-size
max-upload-size
line numbers
- 09.05.14 -
tested o.k.
extension for XML scan with Xerces
usage for WSP web-filter
#endif
//#define TRACEHL1
#define D_INCL_FC_REGEX
/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: xsl-dash-file-control-01                            |*/
/*| -------------                                                     |*/
/*|  C/C++ subroutine implementing DASH file control                  |*/
/*|  KB 24.07.13                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2013                                   |*/
/*|  Copyright (C) HOB Germany 2014                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

/**
   memory:
   NHASN length of rule
   - no, two bytes big endian
   enum type of rule
   NHASN length bytes with rule
   - no, two bytes big endian
     when 0X8000, wildcard, length zero, no content
   content bytes with rule
   after ied_fct_end (enum type of rule):
   enum access
   after ied_fct_select
   NHASN length of rule
   - no, two bytes big endian

   to-do 10.09.13 KB
   a group needs to contain at least one rule,
   not only <select-condition>
   ---
   syntax: see sample-file-control-02.xml
   ------------------------------------
   to-do 10.09.13 KB
   m_dash_file_control_conf() enlarge and shrink memory
   ied_fct_fn_no_sub                - file name no sub directory follows
   ied_fct_wc_dir                   - wild-card directory names
   ied_fct_wc_file                  - wild-card file name
*/

/**
   Mr. Jira, February 2014:
   maximum-file-size different for upload and download
*/

#include <time.h>
#include <sys/timeb.h>
#include <stdio.h>
#ifndef HL_UNIX
#include <windows.h>
#else
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <fcntl.h>
#include <errno.h>
#include "hob-unix01.h"
#include <stdarg.h>
#endif
#define DEF_HL_INCL_DOM
#define DEF_HL_NO_XERCES
#include <hob-xsclib01.h>
#include <hob-xslunic1.h>
#include <hob-dash-01.h>
#define XML_DOM_DEF_ONLY
#ifdef B140128
#include "hob-xml-dom-parser-01.hpp"
#endif
#include "hob-xml-dom-parser-02.h"

#define LEN_FILE_NAME          1024         /* maximum length of file name */
#define MAX_DIR_STACK          64           /* maximum stack of nested directories */
#define MAX_XML_DOM_STACK      64           /* maximum stack of nested XML / DOM nodes */
#define LEN_MEM_BLOCK          (16 * 1024)  /* length of memory block */
#define MAX_RULES_STACK        32           /* maximum stack of nested rules (select-group) */
#define MAX_GROUP_SELECT       16           /* maximum select in one group */
#define LEN_RULE               1024         /* maximum length of rule */

#define RULE_CHAR_NORMAL       1            /* normal character in rule */
#define RULE_CHAR_WC_1         2            /* wildcard character in rule - last character */
#define RULE_CHAR_WC_2         4            /* wildcard character in rule - before last character */
#define RULE_CHAR_DOT          8            /* after last dot          */

/*+-------------------------------------------------------------------+*/
/*| Function Calls definitions.                                       |*/
/*+-------------------------------------------------------------------+*/

#ifdef D_INCL_FC_REGEX
extern "C" BOOL m_search_regex_exists( const char *achp_search_in, int imp_search_len,
                                       const char *achp_regexp, int imp_len_regexp );
#endif

/*+-------------------------------------------------------------------+*/
/*| Internal function prototypes.                                     |*/
/*+-------------------------------------------------------------------+*/

static BOOL m_get_numeric( HL_LONGLONG *ilp_max_file_size, char *achp_input, int imp_len_input );
static int m_sub_printf( struct dsd_sub_call_1 *adsp_sub_call_1, const char *achptext, ... );
#ifdef TRACEHL1
static void m_sub_console_out( struct dsd_sub_call_1 *adsp_sub_call_1,
                               char *achp_buff, int implength );
#endif

/*+-------------------------------------------------------------------+*/
/*| global used dsects = structures.                                  |*/
/*+-------------------------------------------------------------------+*/

struct dsd_file_ctrl {                      /* file-control management */
   int        imc_stor_len;                 /* length of storage       */
   BOOL       boc_case_sensitive;           /* do parsing case sensitive */
   BOOL       boc_compression;              /* rule with compression   */
   BOOL       boc_file_size;                /* rule with max-file-size */
};

enum ied_file_ctrl_type {                   /* type of file-control    */
#ifdef XYZ1
   ied_fct_end = 0,                         /* end of select rules     */
#endif
   ied_fct_fn_no_sub = 0,                   /* file name no sub directory follows */
   ied_fct_ext_no_sub,                      /* file name extension no sub directory follows */
   ied_fct_fnnd,                            /* file name without dot   */
   ied_fct_dir_any,                         /* directory name in any stage */
   ied_fct_dir_this,                        /* directory name in this stage */
   ied_fct_wc_dir,                          /* wild-card directory names */
   ied_fct_wc_file,                         /* wild-card file name    */
   ied_fct_file_size,                       /* max-file-size          */
   ied_fct_select,                          /* select group           */
#ifdef D_INCL_FC_REGEX
   ied_fct_regex,                           /* select regex           */
   ied_fct_not_regex                        /* select not-regex       */
#endif
};
/**
not used:
ied_fct_end
ied_fct_fn_any_sub
ied_fct_select - is used
*/

struct dsd_sub_call_1 {                     /* structure call subroutine */
   BOOL (* amc_aux) ( void *, int, void *, int );  // Helper routine pointer
   void *     vpc_userfld;                  /* User Field Subroutine   */
};

/*+-------------------------------------------------------------------+*/
/*| Internal used classes.                                            |*/
/*+-------------------------------------------------------------------+*/

/*+-------------------------------------------------------------------+*/
/*| Static global variables and local constants.                      |*/
/*+-------------------------------------------------------------------+*/

#define KW_CONF_RO           0
#define KW_CONF_RW           1
#define KW_CONF_WO           2
#define KW_CONF_DENY         3
#define KW_CONF_EXCL_COMPR   4
#define KW_CONF_MAX_FILE_S   5
#define KW_CONF_SEL_GROUP    6
#define KW_CONF_SEL_COND     7
#define KW_CONF_SEL_NOT_CO   8
#ifdef D_INCL_FC_REGEX
#define KW_CONF_SEL_REGEX    9
#define KW_CONF_SEL_NOT_RE   10
#endif

static const char * achrs_conf_keyword[] = {
   "allow-read-only",
   "allow-read-write",
   "allow-write-only",
   "deny",
   "exclude-compression",
   "max-file-size",
   "select-group",
   "select-condition",
   "select-not-condition",
#ifdef D_INCL_FC_REGEX
   "select-regex",
   "select-not-regex"
#endif
};

#define D_FCT_MASK           0X3F
#define D_FCT_GROUP_LAST     0X40

#ifdef TRACEHL1
static const char chrstrans[]
     = { '0', '1', '2', '3', '4', '5', '6', '7',
         '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
#endif

/*+-------------------------------------------------------------------+*/
/*| Control procedures.                                               |*/
/*+-------------------------------------------------------------------+*/

#define M_CHECK_MEMORY( IMP_P ) \
   if ((achl_out_cur + IMP_P) > ((char *) adsl_file_ctrl + adsl_file_ctrl->imc_stor_len)) {  \
     struct dsd_file_ctrl *adsh_file_ctrl_new;  /* file-control management */                \
     int      imh_len = adsl_file_ctrl->imc_stor_len + LEN_MEM_BLOCK;                        \
     while (TRUE) {                                                                          \
       if (imh_len >= (achl_out_cur + IMP_P - ((char *) adsl_file_ctrl))) break;             \
       imh_len += LEN_MEM_BLOCK;                                                             \
     }                                                                                       \
     bol_rc = dsl_sub_call_1.amc_aux( dsl_sub_call_1.vpc_userfld,                            \
                                      DEF_AUX_MEMGET,                                        \
                                      &adsh_file_ctrl_new,                                   \
                                      imh_len );                                             \
     if (bol_rc == FALSE) {                 /* error occured           */                    \
/*     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;                    */                    \
       return FALSE;                                                                         \
     }                                                                                       \
     memcpy( adsh_file_ctrl_new, adsl_file_ctrl, achl_out_cur - ((char *) adsl_file_ctrl) ); \
     adsh_file_ctrl_new->imc_stor_len = imh_len;  /* length of memory block */               \
     bol_rc = dsl_sub_call_1.amc_aux( dsl_sub_call_1.vpc_userfld,                            \
                                      DEF_AUX_MEMFREE,  /* release a block of memory */      \
                                      &adsl_file_ctrl,                                       \
                                      0 );                                                   \
     if (bol_rc == FALSE) {                 /* error occured           */                    \
/*     adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;                    */                    \
       return FALSE;                                                                         \
     }                                                                                       \
     adsl_file_ctrl = adsh_file_ctrl_new;   /* this is enlarged memory */                    \
   }

extern "C" BOOL m_dash_file_control_conf( struct dsd_dash_fc_dom_conf *adsp_dfcdc ) {
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol_search_select_cond;       /* search select condition */
   BOOL       bol_valid_access;             /* valid access rule found */
   int        iml_cmp;                      /* compare value           */
   int        iml_keyword;                  /* index of keyword        */
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_nesting;                  /* nesting of XML nodes    */
   int        iml_rule_char;                /* parse characters in rule */
   int        iml_rule_save;                /* save rule at dot        */
   int        iml_rule_stack;               /* position in rule stack  */
   int        iml_group_select;             /* position in group select */
   int        iml_start_group_select;       /* start position in group select in this level */
   int        iml_pos_last_select;          /* position of last select in memory */
   enum ied_nodetype iel_nt;                /* DOM node type           */
   HL_LONGLONG ill_max_file_size;           /* <max-file-size>         */
   char       *achl_w1;                     /* working variable        */
   char       *achl_last_dot;               /* position of last dot    */
   char       *achl_start_sub_dir;          /* start of sub directory in rule */
   char       *achl_out_cur;                /* current output          */
   void *     al_node_cur;                  /* current node            */
   void *     al_node_child;                /* child of current node   */
   void *     al_node_start;                /* start node of current level */
   struct dsd_file_ctrl *adsl_file_ctrl;    /* file-control management */
   struct dsd_unicode_string *adsl_ucs_node;  /* node found            */
   struct dsd_unicode_string *adsl_ucs_value;  /* value retrieved      */
   struct dsd_unicode_string dsl_ucs_l;     /* working variable        */
   struct dsd_sub_call_1 dsl_sub_call_1;    /* structure call subroutine */
   int        imrl_rule_start[ MAX_RULES_STACK ];  /* maximum stack of nested rules (select-group) */
   BOOL       borl_rule_set[ MAX_RULES_STACK ];  /* valid rule found   */
   int        imrl_group_select[ MAX_RULES_STACK ];  /* last group select in array */
   void *     vprl_node_group_select[ MAX_GROUP_SELECT ];  /* select in all groups */
   void *     vprl_xml_n[ MAX_XML_DOM_STACK ];  /* XML / DOM nesting   */
   char       byrl_rule[ LEN_RULE ];        /* maximum length of rule  */

   dsl_sub_call_1.amc_aux = adsp_dfcdc->amc_aux;  /* auxiliary subroutine */
   dsl_sub_call_1.vpc_userfld = adsp_dfcdc->vpc_userfld;  /* User Field Subroutine */
   al_node_cur = adsp_dfcdc->amc_call_dom( adsp_dfcdc->vpc_userfld, adsp_dfcdc->vpc_node_conf, ied_hlcldom_get_first_child );  /* getFirstChild() */
   iml_nesting = 0;                         /* nesting of XML nodes    */
   iml_rule_stack = 0;                      /* position in rule stack  */
   iml_group_select = 0;                    /* position in group select */
   iml_start_group_select = 0;              /* start position in group select in this level */
   dsl_ucs_l.imc_len_str = -1;
   dsl_ucs_l.iec_chs_str = ied_chs_utf_8;   /* Unicode UTF-8           */
   iml_keyword = -1;                        /* index of keyword - no keyword found yet */
   bol_rc = dsl_sub_call_1.amc_aux( dsl_sub_call_1.vpc_userfld,
                                    DEF_AUX_MEMGET,
                                    &adsl_file_ctrl,
                                    LEN_MEM_BLOCK );
   if (bol_rc == FALSE) {                   /* error occured           */
//   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return FALSE;
   }
   memset( adsl_file_ctrl, 0, sizeof(struct dsd_file_ctrl) );  /* file-control management */
   adsl_file_ctrl->imc_stor_len = LEN_MEM_BLOCK;  /* length of memory block */
   achl_out_cur = (char *) (adsl_file_ctrl + 1);  /* current output    */
#ifdef TRACEHL1
   m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-T start adsl_file_ctrl=%p achl_out_cur=%p.",
                 __LINE__, adsl_file_ctrl, achl_out_cur );
#endif
   bol_search_select_cond = FALSE;          /* search select condition */
   bol_valid_access = FALSE;                /* valid access rule found */
   al_node_start = al_node_cur;             /* for compiler only       */

   p_node_00:                               /* search node             */
   iel_nt = (enum ied_nodetype) ((long long int) adsp_dfcdc->amc_call_dom( adsp_dfcdc->vpc_userfld, al_node_cur, ied_hlcldom_get_node_type ));  /* getNodeType() */
   switch (iel_nt) {                        /* type of node            */
     case ied_nt_node:
       goto p_node_40;                      /* found node              */
     case ied_nt_text:
       goto p_node_20;                      /* found text              */
   }
   al_node_cur = adsp_dfcdc->amc_call_dom( adsp_dfcdc->vpc_userfld, al_node_cur, ied_hlcldom_get_next_sibling );  /* getNextSibling() */
   if (al_node_cur) {                       /* node found              */
     goto p_node_00;                        /* search node             */
   }
// missing error
   return FALSE;

   p_node_20:                               /* search value            */
   if (   (bol_search_select_cond)          /* search select condition */
#ifndef D_INCL_FC_REGEX
       && (iml_keyword != KW_CONF_SEL_COND)
       && (iml_keyword != KW_CONF_SEL_NOT_CO)) {
#ifdef FORKEDIT
   }
#endif
#endif
#ifdef D_INCL_FC_REGEX
       && (iml_keyword != KW_CONF_SEL_COND)
       && (iml_keyword != KW_CONF_SEL_NOT_CO)
       && (iml_keyword != KW_CONF_SEL_REGEX)
       && (iml_keyword != KW_CONF_SEL_NOT_RE)) {
#endif
     goto p_node_60;                        /* node processed          */
   }
   adsl_ucs_value = (struct dsd_unicode_string *) adsp_dfcdc->amc_call_dom( adsp_dfcdc->vpc_userfld, al_node_cur, ied_hlcldom_get_node_value );  /* getNodeValue() */
   iml1 = m_cpy_vx_ucs( byrl_rule, sizeof(byrl_rule), ied_chs_utf_8,  /* Unicode UTF-8 */
                        adsl_ucs_value );
// missing error
   achl_w1 = byrl_rule;
   while (achl_w1 < (byrl_rule + iml1)) {
     if (*achl_w1 > 0X20) break;            /* valid character found   */
     achl_w1++;                             /* increment address       */
   }
   if (achl_w1 >= (byrl_rule + iml1)) {
     if (   (iml_keyword >= 0)
         && (iml_keyword != KW_CONF_SEL_GROUP)) {
       m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W found text \"%.*(u8)s\" invalid",
                     __LINE__, iml1, byrl_rule );
     }
     goto p_node_60;                        /* node processed          */
   }
   if (   (iml_keyword < 0)
       || (iml_keyword == KW_CONF_SEL_GROUP)) {
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W found text \"%.*(u8)s\" keyword invalid or invalid <select-group>",
                   __LINE__, iml1, byrl_rule );
     goto p_node_60;                        /* node processed          */
   }
   if (iml_keyword == KW_CONF_MAX_FILE_S) {
     iml_keyword = -1;                      /* index of keyword - no keyword found yet */
     iml2 = iml1;                           /* get length              */
     if (   (iml2 > 0)
         && (   (byrl_rule[ iml2 - 1 ] == 'B')
             || (byrl_rule[ iml2 - 1 ] == 'b'))) {
       iml2--;                              /* remove bytes at the end */
     }
     bol_rc = m_get_numeric( &ill_max_file_size, byrl_rule, iml2 );
     if (bol_rc == FALSE) {                 /* not valid number        */
       m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W <max-file-size> \"%.*(u8)s\" invalid number",
                     __LINE__, iml1, byrl_rule );
       goto p_node_60;                      /* node processed          */
     }
     /* check how many bytes needed for file-size                      */
     iml1 = sizeof(HL_LONGLONG);            /* set index               */
     do {
       if ((ill_max_file_size >> ((iml1 - 1) << 3)) != 0) break;
       iml1--;                              /* decrement index         */
     } while (iml1 > 0);
     iml2 = 1 + iml1;                       /* length of rule          */
     M_CHECK_MEMORY( 2 + iml1 )             /* check if memory big enough */
     *achl_out_cur++ = (unsigned char) (iml2 >> 8);  /* high value byte of length */
     *achl_out_cur++ = (unsigned char) iml2;  /* low value byte of length */
     *achl_out_cur++ = (unsigned char) ied_fct_file_size;  /* max-file-size */
     do {
       iml1--;                              /* decrement index         */
       *achl_out_cur++ = (unsigned char) (ill_max_file_size >> (iml1 << 3));
     } while (iml1 > 0);
     adsl_file_ctrl->boc_file_size = TRUE;  /* rule with max-file-size */
     iml1 = iml_rule_stack;                 /* position in stack       */
     while (iml1 > 0) {                     /* loop to set rules valid */
       iml1--;                              /* decrement index         */
       borl_rule_set[ iml1 ] = TRUE;        /* valid rule found        */
     }
     goto p_node_60;                        /* node processed          */
#ifdef D_INCL_FC_REGEX
   } else if (   (iml_keyword == KW_CONF_SEL_REGEX)
              || (iml_keyword == KW_CONF_SEL_NOT_RE)) {
     iml2 = 1 + iml1;                       /* length of rule          */
     M_CHECK_MEMORY( 2 + iml1 )             /* check if memory big enough */
     *achl_out_cur++ = (unsigned char) (iml2 >> 8);  /* high value byte of length */
     *achl_out_cur++ = (unsigned char) iml2;  /* low value byte of length */
     iml_pos_last_select = achl_out_cur - ((char *) adsl_file_ctrl);  /* position of last select in memory */
     *achl_out_cur = (unsigned char) ied_fct_regex;  /* select regex   */
     if (iml_keyword == KW_CONF_SEL_NOT_RE) {
       *achl_out_cur = (unsigned char) ied_fct_not_regex;  /* select not-regex */
     }
     achl_out_cur++;
     memcpy( achl_out_cur, byrl_rule, iml1 );
     achl_out_cur += iml1;
     iml_keyword = -1;                      /* index of keyword - no keyword found yet */
     goto p_node_60;                        /* node processed          */
#endif
   }
   achl_w1 = byrl_rule;
   while (achl_w1 < (byrl_rule + iml1)) {
     if (*achl_w1 != '/') break;            /* not slash found         */
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W rule \"%.*(u8)s\" invalid slash at start",
                   __LINE__, iml1, byrl_rule );
     achl_w1++;                             /* increment address       */
   }
   imrl_rule_start[ iml_rule_stack ] = achl_out_cur - ((char *) adsl_file_ctrl);  /* start of rule */
#ifdef TRACEHL1
   m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-T iml_rule_stack=%d imrl_rule_start[ iml_rule_stack ]=%X.",
                 __LINE__, iml_rule_stack, imrl_rule_start[ iml_rule_stack ] );
#endif
   M_CHECK_MEMORY( 2 + LEN_RULE )           /* check if memory big enough */
   achl_out_cur += 2;                       /* current output, space for length */
   iml_pos_last_select = achl_out_cur - ((char *) adsl_file_ctrl);  /* position of last select in memory */
   achl_last_dot = NULL;                    /* position of last dot    */

   p_rules_00:                              /* process rules           */
   achl_start_sub_dir = achl_w1;            /* start of sub directory in rule */
   iml_rule_char = 0;                       /* parse characters in rule */
   if (achl_last_dot) {                     /* position of last dot    */
     iml_rule_char = RULE_CHAR_DOT;         /* after last dot          */
     achl_last_dot = NULL;                  /* position of last dot    */
   }
   iml_rule_save = 0;                       /* save rule at dot        */

   p_rules_20:                              /* process character of rule */
   switch (*achl_w1) {                      /* depends on character    */
     case '/':                              /* slash - separate sub directories */
       achl_last_dot = NULL;                /* position of last dot    */
       iml_rule_char |= iml_rule_save;      /* apply saved rule at dot */
       goto p_rules_40;                     /* slash found - next sub directory */
     case '*':                              /* asterisk - wildcard     */
       if (iml_rule_char & RULE_CHAR_WC_2) {  /* wildcard character in rule - before last character */
         m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W found *** - shortened to **", __LINE__ );
       }
       if (iml_rule_char & RULE_CHAR_WC_1) {  /* wildcard character in rule - last character */
         if (iml_rule_char & RULE_CHAR_DOT) {  /* after last dot       */
           m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W found .** - not valid", __LINE__ );
           iml_rule_char &= -1 - RULE_CHAR_WC_2;  /* reset wildcard    */
           break;
         }
         if (iml_rule_char & RULE_CHAR_NORMAL) {  /* normal character in rule */
           m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W found x** - not valid", __LINE__ );
           iml_rule_char &= -1 - RULE_CHAR_WC_2;  /* reset wildcard    */
           break;
         }
         iml_rule_char |= RULE_CHAR_WC_2;   /* wildcard character in rule - before last character */
         break;
       }
       iml_rule_char |= RULE_CHAR_WC_1;     /* wildcard character in rule - last character */
       break;
     case '.':                              /* dot                     */
       achl_last_dot = achl_w1;             /* position of last dot    */
       iml_rule_save |= iml_rule_char;      /* save rule at dot        */
       iml_rule_char = 0;                   /* parse characters in rule */
       break;
     default:                               /* other character         */
       if (iml_rule_char & RULE_CHAR_WC_2) {  /* wildcard character in rule - before last character */
         m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W found **x - not valid", __LINE__ );
       }
       iml_rule_char |= RULE_CHAR_NORMAL;   /* normal character in rule */
       iml_rule_char &= -1 - RULE_CHAR_WC_1 - RULE_CHAR_WC_2;  /* reset wildcard */
       break;
   }
   achl_w1++;                               /* increment address       */
   if (achl_w1 < (byrl_rule + iml1)) {      /* not yet at end          */
     goto p_rules_20;                       /* process character of rule */
   }

   if (achl_last_dot) {                     /* position of last dot    */
     if (achl_w1 < (byrl_rule + iml1)) {    /* not yet at end          */
       m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W . found in rule but not yet end of rule - not valid", __LINE__ );
// 13.05.14 KB error
       goto p_rules_80;                     /* end of rules reached    */
     }
     achl_w1 = achl_last_dot;               /* process only till dot   */
     iml_rule_char = iml_rule_save;         /* save rule at dot        */
   }

   p_rules_40:                              /* slash found - next sub directory */
   iml2 = achl_w1 - achl_start_sub_dir;     /* number of character in sub directory in rule */
   if (iml_rule_char & RULE_CHAR_WC_2) {    /* only two dots           */
     *achl_out_cur++ = (unsigned char) ied_fct_dir_any;  /* directory name in any stage */
     goto p_rules_60;                       /* output of rule done - next sub directory */
   }
   if (iml_rule_char & RULE_CHAR_DOT) {     /* after last dot          */
     *achl_out_cur++ = (unsigned char) ied_fct_ext_no_sub;  /* file name extension no sub directory follows */
     *achl_out_cur++ = (unsigned char) (iml2 >> 8);  /* high value byte of length */
     *achl_out_cur++ = (unsigned char) iml2;  /* low value byte of length */
     memcpy( achl_out_cur, achl_start_sub_dir, iml2 );
     achl_out_cur += iml2;
     goto p_rules_60;                       /* output of rule done - next sub directory */
   }
   if (achl_w1 < (byrl_rule + iml1)) {      /* not yet at end          */
     *achl_out_cur = (unsigned char) ied_fct_dir_this;  /* directory name in this stage */
     if (achl_last_dot) {                   /* position of last dot    */
       *achl_out_cur = (unsigned char) ied_fct_fnnd;  /* file name without dot */
     }
     achl_out_cur++;                        /* after command           */
     if (   (iml2 == 1)                     /* only wildcard           */
         && (*achl_start_sub_dir == '*')) {  /* only wildcard          */
       *achl_out_cur++ = (unsigned char) 0X80;  /* high value byte of length - wildcard */
       *achl_out_cur++ = 0;                 /* low value byte of length */
       goto p_rules_60;                     /* output of rule done - next sub directory */
     }
     *achl_out_cur++ = (unsigned char) (iml2 >> 8);  /* high value byte of length */
     *achl_out_cur++ = (unsigned char) iml2;  /* low value byte of length */
     memcpy( achl_out_cur, achl_start_sub_dir, iml2 );
     achl_out_cur += iml2;
     goto p_rules_60;                       /* output of rule done - next sub directory */
   }
   *achl_out_cur++ = (unsigned char) ied_fct_fn_no_sub;  /* file name no sub directory follows */
   *achl_out_cur++ = (unsigned char) (iml2 >> 8);  /* high value byte of length */
   *achl_out_cur++ = (unsigned char) iml2;  /* low value byte of length */
   memcpy( achl_out_cur, achl_start_sub_dir, iml2 );
   achl_out_cur += iml2;

   p_rules_60:                              /* output of rule done - next sub directory */
   if (achl_w1 < (byrl_rule + iml1)) {      /* not yet at end          */
     achl_w1++;                             /* after slash             */
     if (achl_w1 < (byrl_rule + iml1)) {    /* not yet at end          */
       goto p_rules_00;                     /* process rules           */
     }
     if ((achl_w1 - 1 ) != achl_last_dot) {
       m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W rule \"%.*(u8)s\" invalid slash at end",
                     __LINE__, iml1, byrl_rule );
     } else {
       *achl_out_cur++ = (unsigned char) ied_fct_ext_no_sub;  /* file name extension no sub directory follows */
       *achl_out_cur++ = (unsigned char) 0;  /* high value byte of length */
       *achl_out_cur++ = (unsigned char) 0;  /* low value byte of length */
     }
   }

   p_rules_80:                              /* output of rule done - end of rule */
   *achl_out_cur++ = (unsigned char) iml_keyword;  /* index of keyword */
   if (   (iml_keyword == KW_CONF_RO)
       || (iml_keyword == KW_CONF_RW)
       || (iml_keyword == KW_CONF_WO)) {
     bol_valid_access = TRUE;               /* valid access rule found */
   }
   achl_w1 = ((char *) adsl_file_ctrl) + imrl_rule_start[ iml_rule_stack ];  /* start of rule */
   iml1 = achl_out_cur - (achl_w1 + 2);     /* length of rule set      */
#ifdef TRACEHL1
   m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-T p_rules_80: iml_rule_stack=%d achl_out_cur=%p achl_w1=%p iml1=%d iml_keyword=%d bol_search_select_cond=%d.",
                 __LINE__, iml_rule_stack, achl_out_cur, achl_w1, iml1, iml_keyword, bol_search_select_cond );
#endif
   *(achl_w1 + 0) = (unsigned char) (iml1 >> 8);  /* high value byte of length */
   *(achl_w1 + 1) = (unsigned char) iml1;   /* low value byte of length */
   if (iml_keyword == KW_CONF_EXCL_COMPR) {
     adsl_file_ctrl->boc_compression = TRUE;  /* rule with compression */
   }
   if (bol_search_select_cond == FALSE) {   /* search select condition */
     iml1 = iml_rule_stack;                 /* position in stack       */
     while (iml1 > 0) {                     /* loop to set rules valid */
       iml1--;                              /* decrement index         */
       borl_rule_set[ iml1 ] = TRUE;        /* valid rule found        */
     }
   }
   iml_keyword = -1;                        /* index of keyword - no keyword found yet */
   goto p_node_60;                          /* node processed          */

   p_node_40:                               /* found node              */
#ifdef TRACEHL1
   m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-T p_node_40: bol_search_select_cond=%d iml_nesting=%d iml_rule_stack=%d al_node_cur=%p.",
                 __LINE__, bol_search_select_cond, iml_nesting, iml_rule_stack, al_node_cur, iml_rule_stack );
#endif
   if (bol_search_select_cond == FALSE) {   /* not search select condition */
     iml1 = iml_start_group_select;         /* start position in group select in this level */
     while (iml1 < iml_group_select) {      /* position in group select */
       if (al_node_cur == vprl_node_group_select[ iml1 ]) {  /* select in one group */
         goto p_node_60;                    /* node processed          */
       }
       iml1++;                              /* increment index         */
     }
   }
   if (al_node_start == NULL) {             /* start node of current level */
     al_node_start = al_node_cur;           /* start node of current level */
   }
   adsl_ucs_node = (struct dsd_unicode_string *) adsp_dfcdc->amc_call_dom( adsp_dfcdc->vpc_userfld, al_node_cur, ied_hlcldom_get_node_name );  /* getNodeName() */
#ifdef TRACEHL1
   m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-T p_node_40: found node \"%.*s\"",
                 __LINE__, adsl_ucs_node->imc_len_str, adsl_ucs_node->ac_str );
#endif
   iml_keyword = sizeof(achrs_conf_keyword) / sizeof(achrs_conf_keyword[0]) - 1;
   do {
     dsl_ucs_l.ac_str = (void *) achrs_conf_keyword[ iml_keyword ];
     bol_rc = m_cmp_ucs_ucs( &iml_cmp, adsl_ucs_node, &dsl_ucs_l );
     if ((bol_rc) && (iml_cmp == 0)) break;  /* strings do compare     */
     iml_keyword--;                         /* decrement index         */
   } while (iml_keyword >= 0);
#ifndef D_INCL_FC_REGEX
   if (   (iml_keyword == KW_CONF_SEL_COND)
       || (iml_keyword == KW_CONF_SEL_NOT_CO)) {
#ifdef FORKEDIT
   }
#endif
#endif
#ifdef D_INCL_FC_REGEX
   if (   (iml_keyword == KW_CONF_SEL_COND)
       || (iml_keyword == KW_CONF_SEL_NOT_CO)
       || (iml_keyword == KW_CONF_SEL_REGEX)
       || (iml_keyword == KW_CONF_SEL_NOT_RE)) {
#endif
     if (bol_search_select_cond) {          /* search select condition */
#ifdef TRACEHL1
       m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-T bol_search_select_cond iml_keyword=%d iml_rule_stack=%d al_node_cur=%p.",
                     __LINE__, iml_keyword, iml_rule_stack, al_node_cur );
#endif
#ifdef B131214
       vprl_node_select_cond[ iml_rule_stack + 1 ] = al_node_cur;  /* select condition found */
#endif
       vprl_node_group_select[ iml_group_select++ ] = al_node_cur;  /* select condition found */
     }
   } else {
     if (bol_search_select_cond) {          /* search select condition */
       goto p_node_60;                      /* node processed          */
     }
   }
   al_node_child = adsp_dfcdc->amc_call_dom( adsp_dfcdc->vpc_userfld, al_node_cur, ied_hlcldom_get_first_child );  /* getFirstChild() */
   if (al_node_child == NULL) {
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W no child to node found", __LINE__ );
// missing error
     return FALSE;
   }
   if (iml_nesting >= MAX_XML_DOM_STACK) {  /* maximum stack of nested XML / DOM nodes */
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W nesting of <select-group> too deep", __LINE__ );
// missing error
     return FALSE;
   }
   vprl_xml_n[ iml_nesting++ ] = al_node_cur;
   if (iml_keyword == KW_CONF_SEL_GROUP) {
     bol_search_select_cond = TRUE;         /* search select condition */
     imrl_rule_start[ iml_rule_stack ] = achl_out_cur - ((char *) adsl_file_ctrl);  /* start of rule / select group */
#ifdef TRACEHL1
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-T iml_rule_stack=%d imrl_rule_start[ iml_rule_stack ]=%X.",
                   __LINE__, iml_rule_stack, imrl_rule_start[ iml_rule_stack ] );
#endif
     imrl_group_select[ iml_rule_stack ] = iml_group_select;  /* last group select in array */
     borl_rule_set[ iml_rule_stack ] = FALSE;  /* not yet valid rule found */
     iml_rule_stack++;                      /* position in rule stack  */
     if (iml_rule_stack >= MAX_RULES_STACK) {  /* maximum stack of nested rules (select-group) */
       m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W nesting of <select-group> too deep",
                     __LINE__ );
       return FALSE;
     }
     al_node_start = NULL;                  /* start node of current level */
     iml_pos_last_select = 0;               /* position of last select in memory */
     iml_start_group_select = iml_group_select;  /* start position in group select in this level */
     M_CHECK_MEMORY( 2 + LEN_RULE )         /* check if memory big enough */
     achl_out_cur += 2;                     /* current output, space for length */
     *achl_out_cur++ = (unsigned char) ied_fct_select;  /* select group */
#ifdef TRACEHL1
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-T iml_keyword == KW_CONF_SEL_GROUP iml_rule_stack=%d.",
                   __LINE__, iml_rule_stack );
#endif
   }
   al_node_cur = al_node_child;             /* continue with child     */
   goto p_node_00;                          /* search node             */

   p_node_60:                               /* node processed          */
   al_node_cur = adsp_dfcdc->amc_call_dom( adsp_dfcdc->vpc_userfld, al_node_cur, ied_hlcldom_get_next_sibling );  /* getNextSibling() */
   if (al_node_cur) {                       /* node found              */
     goto p_node_00;                        /* search node             */
   }
#ifdef TRACEHL1
   m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-T p_node_60: bol_search_select_cond=%d iml_nesting=%d iml_rule_stack=%d.",
                 __LINE__, bol_search_select_cond, iml_nesting, iml_rule_stack );
#endif
   while (   (iml_rule_stack == iml_nesting)  /* current stage condition */
          && (bol_search_select_cond)) {    /* search select condition */
     if (iml_pos_last_select == 0) {        /* position of last select in memory */
       m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W found <select-group> but no select",
                     __LINE__ );
       break;
     }
     *((char *) adsl_file_ctrl + iml_pos_last_select) |= D_FCT_GROUP_LAST;  /* position of last select in memory */
     al_node_cur = al_node_start;           /* start node of current level */
     iml_keyword = -1;                      /* index of keyword - no keyword found yet */
#ifdef TRACEHL1
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-T bol_search_select_cond iml_rule_stack=%d achl_out_cur=%p.",
                   __LINE__, iml_rule_stack, achl_out_cur );
#endif
     bol_search_select_cond = FALSE;        /* search select condition */
     goto p_node_40;                        /* found node              */
   }
   if (iml_nesting <= 0) {
     goto p_node_80;                        /* end of XML rules        */
   }
   al_node_cur = vprl_xml_n[ --iml_nesting ];
   if (iml_rule_stack <= iml_nesting) {     /* position in rule stack  */
     goto p_node_60;                        /* node processed          */
   }
   achl_w1 = ((char *) adsl_file_ctrl) + imrl_rule_start[ --iml_rule_stack ];  /* start of rule */
   if (borl_rule_set[ iml_rule_stack ] == FALSE) {  /* no valid rule found */
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W found <select-group> but no rule",
                   __LINE__ );
     achl_out_cur = achl_w1;                /* delete from memory      */
   } else {
     iml1 = achl_out_cur - (achl_w1 + 2);   /* length of rule set      */
#ifdef TRACEHL1
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-T p_node_60: iml_rule_stack=%d achl_out_cur=%p achl_w1=%p iml1=%d.",
                   __LINE__, iml_rule_stack, achl_out_cur, achl_w1, iml1 );
#endif
     *(achl_w1 + 0) = (unsigned char) (iml1 >> 8);  /* high value byte of length */
     *(achl_w1 + 1) = (unsigned char) iml1;  /* low value byte of length */
   }
   iml_start_group_select = 0;              /* start position in group select in this level */
   if (iml_rule_stack > 0) {                /* not first level         */
     iml_start_group_select = imrl_group_select[ iml_rule_stack - 1 ];  /* last group select in array */
   }
   iml_group_select = imrl_group_select[ iml_rule_stack ];  /* position in group select */
   goto p_node_60;                          /* node processed          */

   p_node_80:                               /* end of XML rules        */
   if (bol_valid_access == FALSE) {         /* valid access rule found */
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W no valid access rule found",
                   __LINE__ );
     return FALSE;
   }
   adsl_file_ctrl->imc_stor_len = achl_out_cur - ((char *) adsl_file_ctrl);  /* length of memory block */
   *adsp_dfcdc->aac_conf = adsl_file_ctrl;  /* return data from conf   */
#ifdef TRACEHL1
   m_sub_console_out( &dsl_sub_call_1, (char *) adsl_file_ctrl, adsl_file_ctrl->imc_stor_len );
#endif
   return TRUE;                             /* all done                */
} /* end m_dash_file_control_conf()                                    */

extern "C" BOOL m_dash_file_control_execute( struct dsd_dash_fc_execute *adsp_dfcexe ) {
   BOOL       bol_rc;                       /* return code             */
   BOOL       bol_file_rule;                /* rule for file access set */
   BOOL       bol_compression;              /* rule with compression   */
   BOOL       bol_file_size;                /* rule with max-file-size */
   BOOL       bol_any_dir;                  /* any directory stages    */
   int        iml1, iml2, iml3;             /* working variables       */
   int        iml_cmp;                      /* compare value           */
   int        iml_no_dir;                   /* number of sub directories */
   int        iml_dot;                      /* position after dot      */
   int        iml_rule_len;                 /* length of rule          */
   int        iml_rule_stack;               /* position in rule stack  */
   int        iml_pos_fn;                   /* position in file name   */
   char       *achl_w1, *achl_w2;           /* working variables       */
   char       *achl_rule_cur;               /* current position in rules */
   char       *achl_rule_next;              /* next rule position      */
   char       *achl_rule_end;               /* end of rules            */
   char       *achl_rule_this;              /* end of this rule        */
   char       *achl_rule_start;             /* start of this rule      */
   struct dsd_file_ctrl *adsl_file_ctrl;    /* file-control management */
   char *     achrl_rule_end[ MAX_RULES_STACK ];  /* maximum stack of nested rules (select-group) */
   struct dsd_unicode_string dsl_ucs_filename;  /* file name           */
   struct dsd_sub_call_1 dsl_sub_call_1;    /* structure call subroutine */
   unsigned short int usrl_dir[ MAX_DIR_STACK ];
   char       byrl_file_name[ LEN_FILE_NAME ];

   dsl_sub_call_1.amc_aux = adsp_dfcexe->amc_aux;  /* auxiliary subroutine */
   dsl_sub_call_1.vpc_userfld = adsp_dfcexe->vpc_userfld;  /* User Field Subroutine */
   adsp_dfcexe->iec_dac = ied_dac_deny;     /* access denied           */
   adsp_dfcexe->boc_exclude_compression = FALSE;  /* <exclude-compression> */
   adsp_dfcexe->ilc_max_file_size = 0;      /* clear <max-file-size>   */
   dsl_ucs_filename = adsp_dfcexe->dsc_ucs_filename;  /* file name     */
   if (dsl_ucs_filename.iec_chs_str == ied_chs_utf_8) {  /* Unicode UTF-8 */
     if (dsl_ucs_filename.imc_len_str < 0) {  /* zero-terminted        */
       dsl_ucs_filename.imc_len_str = strlen( (char *) dsl_ucs_filename.ac_str );
     }
   } else {
     dsl_ucs_filename.imc_len_str = m_cpy_uc_vx_ucs( byrl_file_name, sizeof(byrl_file_name), ied_chs_utf_8,  /* Unicode UTF-8 */
                                                     &dsl_ucs_filename );
     dsl_ucs_filename.ac_str = byrl_file_name;  /* file name in stack  */
     dsl_ucs_filename.iec_chs_str = ied_chs_utf_8;  /* Unicode UTF-8   */
   }
   if (dsl_ucs_filename.imc_len_str <= 0) {  /* invalid length         */
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W execute file-name \"%(ucs)s\" invalid",
                   __LINE__, &adsp_dfcexe->dsc_ucs_filename );
// to-do 31.07.13 KB error message
     return FALSE;
   }
   iml_dot = 0;                             /* position after dot      */
   iml_no_dir = 0;                          /* number of sub directories */
   achl_w1 = (char *) dsl_ucs_filename.ac_str;  /* start of file name  */

   p_dir_00:                                /* search file delimiters  */
   achl_w2 = (char *) memchr( achl_w1,
                              adsp_dfcexe->chc_file_delimiter,
                              ((char *) dsl_ucs_filename.ac_str + dsl_ucs_filename.imc_len_str) - achl_w1 );
   if (achl_w2 == NULL) {                   /* no more sub directory   */
     goto p_dir_40;                         /* end of sub directories  */
   }
   if (iml_no_dir >= MAX_DIR_STACK) {       /* too many sub directories */
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W execute file-name too many sub-directories \"%(ucs)s\"",
                   __LINE__, &dsl_ucs_filename );
// to-do 31.07.13 KB error message
     return FALSE;
   }
   usrl_dir[ iml_no_dir++ ] = achl_w2 - ((char *) dsl_ucs_filename.ac_str);
   achl_w1 = achl_w2 + 1;                   /* after this sub directory */
   if (achl_w1 < ((char *) dsl_ucs_filename.ac_str + dsl_ucs_filename.imc_len_str)) {
     goto p_dir_00;                         /* search file delimiters  */
   }
   goto p_dir_60;                           /* end of searching for dot */

   p_dir_40:                                /* end of sub directories  */
   achl_w2 = (char *) memchr( achl_w1,
                              '.',
                              ((char *) dsl_ucs_filename.ac_str + dsl_ucs_filename.imc_len_str) - achl_w1 );
   if (achl_w2) {                           /* dot found               */
     achl_w1 = achl_w2 + 1;                 /* after this dot          */
     iml_dot = achl_w1 - ((char *) dsl_ucs_filename.ac_str);  /* position after dot */
     if (iml_dot < dsl_ucs_filename.imc_len_str) {
       goto p_dir_40;                       /* continue search for dot */
     }
   }

   p_dir_60:                                /* end of searching for dot */
   adsl_file_ctrl = (struct dsd_file_ctrl *) adsp_dfcexe->ac_conf;  /* configuration */
   if (adsl_file_ctrl->imc_stor_len <= 0) {  /* no rules               */
     return TRUE;                           /* all done                */
   }
   bol_file_rule = FALSE;                   /* rule for file access set */
   bol_compression = adsl_file_ctrl->boc_compression;  /* rule with compression */
   bol_file_size = adsl_file_ctrl->boc_file_size;  /* rule with max-file-size */
   iml_rule_stack = 0;                      /* position in rule stack  */
   achl_rule_cur = (char *) (adsl_file_ctrl + 1);  /* current position in rules */
   achl_rule_end = (char *) adsl_file_ctrl + adsl_file_ctrl->imc_stor_len;  /* end of rules */


   p_rule_00:                               /* start processing rules  */
   iml_rule_len                             /* length of rule          */
     = (*((unsigned char *) achl_rule_cur + 0) << 8)
         | *((unsigned char *) achl_rule_cur + 1);
   achl_rule_cur += 2;                      /* after length            */
   achl_rule_next = achl_rule_cur + iml_rule_len;  /* next rule position */
// file-size and regex
   achl_rule_this = achl_rule_next - 1;     /* end of this rule        */
   iml_pos_fn = 0;                          /* position in file name   */
   bol_any_dir = FALSE;                     /* any directory stages    */
   achl_rule_start = achl_rule_cur;         /* start of this rule      */

   p_rule_20:                               /* process part of rule    */
   switch ((enum ied_file_ctrl_type) (*achl_rule_cur & D_FCT_MASK)) {
//   case ied_fct_end:                      /* end of select rules     */
     case ied_fct_fn_no_sub:                /* file name no sub directory follows */
       goto p_rule_fn_no_sub_00;            /* file name no sub directory follows */
     case ied_fct_ext_no_sub:               /* file name extension no sub directory follows */
       goto p_rule_ext_no_sub_00;           /* file name extension no sub directory */
     case ied_fct_fnnd:                     /* file name without dot   */
       goto p_rule_file_00;                 /* file name in last stage */
     case ied_fct_dir_any:                  /* directory name in any stage */
       bol_any_dir = TRUE;                  /* any directory stages    */
       iml1 = -2;                           /* set length              */
       goto p_rule_36;                      /* part of rule is valid   */
     case ied_fct_dir_this:                 /* directory name in this stage */
       goto p_rule_dir_any_00;              /* directory name in any stage */
     case ied_fct_file_size:                /* max-file-size          */
       goto p_rule_file_size_00;            /* found <max-file-size>   */
     case ied_fct_select:                   /* select group           */
       goto p_rule_64;                      /* found select condition / not */
#ifdef D_INCL_FC_REGEX
     case ied_fct_regex:                    /* select regex           */
     case ied_fct_not_regex:                /* select not-regex       */
       goto p_rule_regex_00;                /* select with regular expression */
#endif
   }
   m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W execute invalid enum 0X%02X at position 0X%X.",
                 __LINE__, *((unsigned char *) achl_rule_cur), achl_rule_cur - ((char *) adsl_file_ctrl) );
   return FALSE;

   p_rule_fn_no_sub_00:                     /* file name no sub directory follows */
   if (bol_any_dir) {                       /* any directory stages    */
     iml_pos_fn = iml_no_dir;               /* after all sub-directories */
   }
   if (iml_pos_fn != iml_no_dir) {          /* not after all sub-directories */
     goto p_rule_48;                        /* rule not valid          */
   }
   iml1                                     /* length of file name     */
     = (*((unsigned char *) achl_rule_cur + 1) << 8)
         | *((unsigned char *) achl_rule_cur + 2);
   iml2 = 0;                                /* start of directory name */
   if (iml_pos_fn > 0) {                    /* already in file name    */
     iml2 = usrl_dir[ iml_pos_fn - 1 ] + 1;  /* start of directory name */
   }
   bol_rc = m_cmp_wc_i_vx_vx( &iml_cmp,
                              (char *) dsl_ucs_filename.ac_str + iml2,
                              dsl_ucs_filename.imc_len_str - iml2,
                              ied_chs_utf_8,  /* Unicode UTF-8         */
                              achl_rule_cur + 1 + 2,
                              iml1,
                              ied_chs_utf_8 );  /* Unicode UTF-8       */
   if (bol_rc == FALSE) {
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W execute m_cmp_wc_i_vx_vx() returned FALSE",
                   __LINE__ );
     return FALSE;
   }
   if (iml_cmp != 0) {                      /* strings do not compare  */
     goto p_rule_48;                        /* rule not valid          */
   }
   goto p_rule_40;                          /* rule valid              */

   p_rule_ext_no_sub_00:                    /* file name extension no sub directory */
   if (   (iml_no_dir != iml_pos_fn)        /* number of sub directories */
       && (bol_any_dir == FALSE)) {         /* any directory stages    */
     goto p_rule_48;                        /* rule not valid          */
   }

   if (iml_dot == 0) {                      /* no dot in filename      */
     goto p_rule_48;                        /* rule not valid          */
   }
   bol_rc = m_cmp_wc_i_vx_vx( &iml_cmp,
                              (char *) dsl_ucs_filename.ac_str + iml_dot,
                              dsl_ucs_filename.imc_len_str - iml_dot,
                              ied_chs_utf_8,  /* Unicode UTF-8         */
                              achl_rule_cur + 1 + 2,
                              achl_rule_this - (achl_rule_cur + 1 + 2),
                              ied_chs_utf_8 );  /* Unicode UTF-8       */
   if (bol_rc == FALSE) {
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W execute m_cmp_wc_i_vx_vx() returned FALSE",
                   __LINE__ );
     return FALSE;
   }
   if (iml_cmp != 0) {                      /* strings do not compare  */
     goto p_rule_48;                        /* rule not valid          */
   }
   goto p_rule_40;                          /* rule valid              */

   p_rule_file_00:                          /* file name in last stage */
   if (iml_dot == 0) {                      /* position after dot      */
     goto p_rule_48;                        /* rule not valid          */
   }
   if (bol_any_dir) {                       /* any directory stages    */
     iml_pos_fn = iml_no_dir;               /* after all sub-directories */
   } else if (iml_pos_fn != iml_no_dir) {   /* number of sub directories */
     goto p_rule_48;                        /* rule not valid          */
   }
   iml1                                     /* length of file name     */
     = (*((unsigned char *) achl_rule_cur + 1) << 8)
         | *((unsigned char *) achl_rule_cur + 2);
   if (iml1 & 0X8000) {                     /* wildcard set            */
     iml1 = 0;                              /* clear length            */
     goto p_rule_36;                        /* part of rule is valid   */
   }
   iml3 = 0;                                /* start of directory name */
   if (iml_pos_fn > 0) {                    /* already in file name    */
     iml3 = usrl_dir[ iml_pos_fn - 1 ] + 1;  /* start of directory name */
   }
   bol_rc = m_cmp_wc_i_vx_vx( &iml_cmp,
                              (char *) dsl_ucs_filename.ac_str + iml3,
                              iml_dot - 1 - iml3,
                              ied_chs_utf_8,  /* Unicode UTF-8         */
                              achl_rule_cur + 1 + 2,
                              iml1,
                              ied_chs_utf_8 );  /* Unicode UTF-8       */
   if (bol_rc == FALSE) {
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W execute m_cmp_wc_i_vx_vx() returned FALSE",
                   __LINE__ );
     return FALSE;
   }
   if (iml_cmp != 0) {                      /* strings do not compare  */
     /* file name not equal                                            */
     goto p_rule_48;                        /* rule not valid          */
   }
   goto p_rule_36;                          /* part of rule is valid   */

   p_rule_dir_any_00:                       /* directory name in any stage */
   if (iml_pos_fn >= iml_no_dir) {          /* number of sub directories */
     goto p_rule_48;                        /* rule not valid          */
   }
   iml1                                     /* length of directory name */
     = (*((unsigned char *) achl_rule_cur + 1) << 8)
         | *((unsigned char *) achl_rule_cur + 2);
   iml2 = iml_pos_fn;                       /* position in file name   */

   p_rule_dir_any_20:                       /* check directory name    */
   iml3 = 0;                                /* start of directory name */
   if (iml2 > 0) {                          /* already in file name    */
     iml3 = usrl_dir[ iml2 - 1 ] + 1;       /* start of directory name */
   }
   if (iml1 & 0X8000) {                     /* only wildcard           */
     iml1 = 0;                              /* length of rule          */
     iml_pos_fn = iml2 + 1;                 /* position in file name   */
     goto p_rule_36;                        /* part of rule is valid   */
   }
   bol_rc = m_cmp_wc_i_vx_vx( &iml_cmp,
                              (char *) dsl_ucs_filename.ac_str + iml3,
                              usrl_dir[ iml2 ] - iml3,
                              ied_chs_utf_8,  /* Unicode UTF-8         */
                              achl_rule_cur + 1 + 2,
                              iml1,
                              ied_chs_utf_8 );  /* Unicode UTF-8       */
   if (bol_rc == FALSE) {
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W execute m_cmp_wc_i_vx_vx() returned FALSE",
                   __LINE__ );
     return FALSE;
   }
   iml2++;                                  /* next sub directory      */
   if (iml_cmp != 0) {                      /* strings do not compare  */
     if (   (bol_any_dir)                   /* any directory stages    */
         && (iml2 < iml_no_dir)) {          /* number of sub directories */
       goto p_rule_dir_any_20;              /* check directory name    */
     }
     /* sub directory name not found                                   */
     goto p_rule_48;                        /* rule not valid          */
   }
   bol_any_dir = FALSE;                     /* any directory stages    */
   iml_pos_fn = iml2;                       /* position in file name   */

   p_rule_36:                               /* part of rule is valid   */
   achl_rule_cur += 1 + 2 + iml1;           /* after this part         */
   if (achl_rule_cur < achl_rule_this) {    /* rule contains more parts */
     goto p_rule_20;                        /* process part of rule    */
   }

   p_rule_40:                               /* rule valid              */
   switch (*((unsigned char *) achl_rule_this)) {
     case KW_CONF_RO:
       if (bol_file_rule) break;            /* rule for file access set */
       adsp_dfcexe->iec_dac = ied_dac_read_only;  /* access read-only  */
       if (   (bol_compression == FALSE)    /* rule with compression   */
           && (bol_file_size == FALSE)      /* rule with max-file-size */
           && (iml_rule_stack == 0)) {      /* not in select group     */
         return TRUE;                       /* all done                */
       }
       bol_file_rule = TRUE;                /* rule for file access set */
       break;
     case KW_CONF_RW:
       if (bol_file_rule) break;            /* rule for file access set */
       adsp_dfcexe->iec_dac = ied_dac_read_write;  /* access read-write */
       if (   (bol_compression == FALSE)    /* rule with compression   */
           && (bol_file_size == FALSE)      /* rule with max-file-size */
           && (iml_rule_stack == 0)) {      /* not in select group     */
         return TRUE;                       /* all done                */
       }
       bol_file_rule = TRUE;                /* rule for file access set */
       break;
     case KW_CONF_WO:
       if (bol_file_rule) break;            /* rule for file access set */
       adsp_dfcexe->iec_dac = ied_dac_write_only;  /* access write-only */
       if (   (bol_compression == FALSE)    /* rule with compression   */
           && (bol_file_size == FALSE)      /* rule with max-file-size */
           && (iml_rule_stack == 0)) {      /* not in select group     */
         return TRUE;                       /* all done                */
       }
       bol_file_rule = TRUE;                /* rule for file access set */
       break;
     case KW_CONF_DENY:
       if (bol_file_rule) break;            /* rule for file access set */
       adsp_dfcexe->iec_dac = ied_dac_deny;  /* access denied          */
       if (   (bol_compression == FALSE)    /* rule with compression   */
           && (bol_file_size == FALSE)      /* rule with max-file-size */
           && (iml_rule_stack == 0)) {      /* not in select group     */
         return TRUE;                       /* all done                */
       }
       bol_file_rule = TRUE;                /* rule for file access set */
       break;
     case KW_CONF_EXCL_COMPR:
       if (bol_compression == FALSE) break;  /* rule for compression set */
       adsp_dfcexe->boc_exclude_compression = TRUE;  /* <exclude-compression> */
       if (   (bol_compression == FALSE)    /* rule with compression   */
           && (bol_file_size == FALSE)      /* rule with max-file-size */
           && (iml_rule_stack == 0)) {      /* not in select group     */
         return TRUE;                       /* all done                */
       }
       bol_compression = FALSE;             /* rule for compression set */
       break;
     case KW_CONF_SEL_COND:
       /* group has been selected                                      */
       goto p_rule_88;                      /* group has been selected */
     case KW_CONF_SEL_NOT_CO:               /* <select-not-condition> */
       if (*achl_rule_start & D_FCT_GROUP_LAST) {  /* last select condition */
         /* group not selected                                         */
         achl_rule_cur = achl_rule_end;     /* current position in rules */
         goto p_rule_80;                    /* end of group            */
       }
       break;
   }
   goto p_rule_60;                          /* end of this rule        */

   p_rule_file_size_00:                     /* found <max-file-size>   */
   achl_rule_cur++;                         /* after enum              */
   adsp_dfcexe->ilc_max_file_size = 0;      /* clear <max-file-size>   */
   do {                                     /* loop copy max-file-size */
     adsp_dfcexe->ilc_max_file_size <<= 8;  /* shift <max-file-size>   */
     adsp_dfcexe->ilc_max_file_size |= *((unsigned char *) achl_rule_cur);  /* apply bits to <max-file-size> */
     achl_rule_cur++;                       /* input processed         */
   } while (achl_rule_cur < achl_rule_next);
   bol_file_size = FALSE;                   /* rule with max-file-size */
   goto p_rule_60;                          /* end of this rule        */

#ifdef D_INCL_FC_REGEX
   p_rule_regex_00:                         /* select with regular expression */
   achl_rule_cur++;                         /* after enum              */
   bol_rc = m_search_regex_exists( (char *) dsl_ucs_filename.ac_str, dsl_ucs_filename.imc_len_str,
                                   achl_rule_cur, achl_rule_next - achl_rule_cur );
   if (   (   (((enum ied_file_ctrl_type) (*achl_rule_start & D_FCT_MASK)) == ied_fct_regex)  /* select regex */
           && (bol_rc == FALSE))
       || (   (((enum ied_file_ctrl_type) (*achl_rule_start & D_FCT_MASK)) == ied_fct_not_regex)  /* select not-regex */
           && (bol_rc))) {                  /* not selected            */
     if ((*achl_rule_start & D_FCT_GROUP_LAST) == 0) {
       achl_rule_cur = achl_rule_next;      /* current position in rules */
       goto p_rule_00;                      /* start processing rules  */
     }
     /* group not selected                                             */
     achl_rule_cur = achl_rule_end;         /* end of rules            */
     goto p_rule_80;                        /* end of group            */
   }
   /* group has been selected                                          */
   goto p_rule_88;                          /* group has been selected */
#endif

   p_rule_48:                               /* rule not valid          */
   if (*achl_rule_this == KW_CONF_SEL_NOT_CO) {  /* <select-not-condition> */
     /* group has been selected                                        */
     goto p_rule_88;                        /* group has been selected */
   }
   if (*achl_rule_start & D_FCT_GROUP_LAST) {  /* last select condition */
     /* group not selected                                             */
     achl_rule_cur = achl_rule_end;         /* end of rules            */
     goto p_rule_80;                        /* end of group            */
   }

   p_rule_60:                               /* end of this rule        */
   achl_rule_cur = achl_rule_next;          /* current position in rules */
   goto p_rule_72;                          /* start next rule calculated */

   p_rule_64:                               /* found select condition / not */
   achl_rule_cur++;                         /* after enum              */
   /* nested rule                                                      */
   if (iml_rule_stack >= (MAX_RULES_STACK - 1)) {  /* position in rule stack */
     m_sub_printf( &dsl_sub_call_1, "xsl-dash-file-control-01-l%05d-W execute rule stack maximum reached",
                   __LINE__ );
     return FALSE;
   }
   achrl_rule_end[ iml_rule_stack ] = achl_rule_end;  /* maximum stack of nested rules (select-group) */
   iml_rule_stack++;                        /* position in rule stack  */
   achl_rule_end = achl_rule_cur + iml_rule_len - 1;  /* end of rules  */
   goto p_rule_00;                          /* start processing rules  */

   p_rule_72:                               /* start next rule calculated */
   if (achl_rule_cur < achl_rule_end) {     /* check if at end         */
     goto p_rule_00;                        /* start processing rules  */
   }
   if (iml_rule_stack == 0) {               /* position in rule stack  */
     return TRUE;
   }

   p_rule_80:                               /* end of group            */
   if (bol_file_rule) {                     /* rule for file access set */
     return TRUE;
   }
   iml_rule_stack--;                        /* position in rule stack  */
   achl_rule_end = achrl_rule_end[ iml_rule_stack ];  /* maximum stack of nested rules (select-group) */
   goto p_rule_72;                          /* start next rule calculated */

   p_rule_88:                               /* group has been selected */
   achl_rule_cur = achl_rule_next;          /* current position in rules */
   if ((*achl_rule_start & D_FCT_GROUP_LAST) == 0) {
     iml_rule_len                           /* length of rule          */
       = (*((unsigned char *) achl_rule_cur + 0) << 8)
           | *((unsigned char *) achl_rule_cur + 1);
     achl_rule_cur += 2;                    /* after this length       */
     achl_rule_next = achl_rule_cur + iml_rule_len;  /* next rule position */
     achl_rule_start = achl_rule_cur;       /* start of this rule      */
     goto p_rule_88;                        /* group has been selected */
   }
   goto p_rule_00;                          /* start processing rules  */
} /* end m_dash_file_control_execute()                                 */

extern "C" BOOL m_dash_file_control_end( struct dsd_dash_fc_execute *adsp_dfcexe ) {
   BOOL       bol_rc;                       /* return code             */

   bol_rc = adsp_dfcexe->amc_aux( adsp_dfcexe->vpc_userfld,
                                  DEF_AUX_MEMFREE,
                                  &adsp_dfcexe->ac_conf,
                                  0 );
   if (bol_rc == FALSE) {                   /* error occured           */
//   adsp_hl_clib_1->inc_return = DEF_IRET_ERRAU;
     return FALSE;
   }
   return TRUE;                             /* all done                */
} /* end m_dash_file_control_end()                                     */

/** retrieve number, may also include magnitude                        */
static BOOL m_get_numeric( HL_LONGLONG *ilp_max_file_size, char *achp_input, int imp_len_input ) {
   int        iml_digits;                   /* count digits            */
   char       *achl_rp;                     /* read pointer            */
   char       *achl_end;                    /* end of number           */

   *ilp_max_file_size = 0;                  /* clear value             */
   achl_rp = achp_input;                    /* read pointer            */
   achl_end = achp_input + imp_len_input;   /* end of number           */
   while ((achl_rp < achl_end) && (*achl_rp == ' ')) achl_rp++;
   if (achl_rp >= achl_end) return FALSE;   /* only spaces found       */
   iml_digits = 0;                          /* count digits            */

   while ((*achl_rp >= '0') && (*achl_rp <= '9')) {
     if ((*achl_rp != '0') || (iml_digits != 0)) {
       if (iml_digits > 18) return FALSE;   /* number too high         */
       *ilp_max_file_size *= 10;            /* multiply old value      */
       *ilp_max_file_size += *achl_rp - '0';  /* add new value         */
       iml_digits++;                        /* count digits            */
     }
     achl_rp++;                             /* increment read pointer  */
     if (achl_rp >= achl_end) break;
   }
   if (iml_digits == 0) return FALSE;       /* no number               */
   while ((achl_rp < achl_end) && (*achl_rp == ' ')) achl_rp++;
   while ((achl_rp < achl_end) && (*(achl_end - 1) == ' ')) achl_end--;
   if (achl_rp >= achl_end) return TRUE;    /* all done                */
   if ((achl_rp + 1) != achl_end) return FALSE;  /* too many characters */
   switch (*achl_rp) {                      /* check character         */
     case 'k':
     case 'K':
       *ilp_max_file_size <<= 10;           /* shift value             */
       iml_digits += 3;                     /* count digits            */
       break;
     case 'm':
     case 'M':
       *ilp_max_file_size <<= 20;           /* shift value             */
       iml_digits += 6;                     /* count digits            */
       break;
     case 'g':
     case 'G':
       *ilp_max_file_size <<= 30;           /* shift value             */
       iml_digits += 9;                     /* count digits            */
       break;
     case 't':
     case 'T':
       *ilp_max_file_size <<= 40;           /* shift value             */
       iml_digits += 12;                    /* count digits            */
       break;
     default:
       return FALSE;                        /* invalid character       */
   }
   if (iml_digits > 18) return FALSE;       /* number too high         */
   return TRUE;                             /* all done                */
} /* end m_get_numeric()                                               */

/** subroutine for output to console                                   */
static int m_sub_printf( struct dsd_sub_call_1 *adsp_sub_call_1, const char *achptext, ... ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1;                         /* working variable        */
   va_list    dsl_argptr;
   char       chrl_out1[512];

   va_start( dsl_argptr, achptext );
   iml1 = m_hlvsnprintf( chrl_out1, sizeof(chrl_out1), ied_chs_utf_8, achptext, dsl_argptr );
   va_end( dsl_argptr );
   bol_rc = adsp_sub_call_1->amc_aux( adsp_sub_call_1->vpc_userfld,
                                      DEF_AUX_CONSOLE_OUT,  /* output to console */
                                      chrl_out1, iml1 );
   return iml1;
} /* end m_sub_printf()                                                */

#ifdef TRACEHL1
/* subroutine to dump storage-content to console                       */
static void m_sub_console_out( struct dsd_sub_call_1 *adsp_sub_call_1,
                               char *achp_buff, int implength ) {
   BOOL       bol_rc;                       /* return code             */
   int        iml1, iml2, iml3, iml4, iml5, iml6;  /* working variable */
   char       byl1;                         /* working-variable        */
   char       chrlwork1[ 76 ];              /* buffer to print         */

   iml1 = 0;
   while (iml1 < implength) {
     iml2 = iml1 + 16;
     if (iml2 > implength) iml2 = implength;
     for ( iml3 = 4; iml3 < 75; iml3++ ) {
       chrlwork1[iml3] = ' ';
     }
     chrlwork1[58] = '*';
     chrlwork1[75] = '*';
     iml3 = 4;
     do {
       iml3--;
       chrlwork1[ iml3 ] = chrstrans[ (iml1 >> ((4 - 1 - iml3) << 2)) & 0X0F ];
     } while (iml3 > 0);
     iml4 = 6;                              /* start hexa digits here  */
     iml5 = 59;                             /* start ASCII here        */
     iml6 = 4;                              /* times normal            */
     do {
       byl1 = achp_buff[ iml1++ ];
       chrlwork1[ iml4++ ] = chrstrans[ (byl1 >> 4) & 0X0F ];
       chrlwork1[ iml4++ ] = chrstrans[ byl1 & 0X0F ];
       iml4++;
       if (byl1 > 0X20) {
         chrlwork1[ iml5 ] = byl1;
       }
       iml5++;
       iml6--;
       if (iml6 == 0) {
         iml4++;
         iml6 = 4;
       }
     } while (iml1 < iml2);
//   printf( "%.*s\n", sizeof(chrlwork1), chrlwork1 );
     bol_rc = adsp_sub_call_1->amc_aux( adsp_sub_call_1->vpc_userfld,
                                        DEF_AUX_CONSOLE_OUT,  /* output to console */
                                        chrlwork1, sizeof(chrlwork1) );
   }
} /* end m_sub_console_out()                                           */
#endif
