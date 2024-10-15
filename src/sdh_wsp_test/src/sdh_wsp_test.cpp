/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: sdh_wsp_test                                        |*/
/*| -------------                                                     |*/
/*|  DLL / Library for WebSecureProxy v3                              |*/
/*|    Server-Data-Hook                                               |*/
/*|  Test SDH                                                         |*/
/*|    Tests callback function of WSP                                 |*/
/*|  TJ 23.09.09                                                      |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB 2009                                           |*/
/*|  Copyright (C) HOB Germany 2009                                   |*/
/*|                                                                   |*/
/*| REQUIRED PROGRAMS:                                                |*/
/*| ------------------                                                |*/
/*|  MS Visual Studio 2005 (VC8)                                      |*/
/*|                                                                   |*/
/*| FUNCTION:                                                         |*/
/*| ---------                                                         |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#define MAX_CMD_NUM_PARAM 4
#define MAX_CMD_PARAM_LEN 2048
#define DIR_UNKNOWN 0
#define DIR_TOCLIENT 1
#define DIR_TOSERVER 2
#define DIR_FROMCLIENT 3
#define DIR_FROMSERVER 4

#define CMD_DATA                    0x0000
#define CMD_PRINT_DIRECT            0x0010
#define CMD_PRINT_CONSOLE           0x0011
#define CMD_MEM_GET                 0x0020
#define CMD_MEM_FREE                0x0021
#define CMD_MEM_READ                0x0022
#define CMD_MEM_WRITE               0x0023
#define CMD_CMA_QUERY               0x0030
#define CMD_CMA_SETSIZE             0x0031
#define CMD_CMA_READ                0x0032
#define CMD_CMA_WRITE               0x0033
#define CMD_CMA_LOCK_GLOBAL         0x0034
#define CMD_CMA_LOCK_REGION         0x0035
#define CMD_CMA_GET_LOCK_STATE      0x0036
#define CMD_CMA_SET_LOCK_STATE      0x0037
#define CMD_GET_RANDOM_BASE64       0x0040
#define CMD_TCP_CONN                0x0050
#define CMD_TCP_CLOSE               0x0051
#define CMD_TCP_GET_STATUS          0x0052
#define CMD_TCP_CONN_SSL            0x0053
#define CMD_STRING_FROM_EPOCH       0x0060
#define CMD_EPOCH_FROM_STRING       0x0061
#define CMD_DISKFILE_ACCESS         0x0070
#define CMD_DISKFILE_RELEASE        0x0071
#define CMD_DISKFILE_TIME_LM        0x0072
#define CMD_QUERY_MAIN_STR          0x0080
#define CMD_QUERY_CLIENT            0x0081

#define CMD_CRT_FILEOPEN            0x4000
#define CMD_CRT_FILECLOSE           0x4001
#define CMD_CRT_FILEREAD            0x4002
#define CMD_CRT_FILEWRITE           0x4003
#define CMD_CRT_FILEDELETE          0x4004

#define CMD_DISCONNECT              0x6000

#define CMD_GET_CONF_TCP_VALID      0x7000
#define CMD_GET_CONF_TCP_INVALID    0x7001
#define CMD_GET_CONF_FILE_VALID     0x7010
#define CMD_GET_CONF_FILE_INVALID   0x7011

#define CMD_NOP                     0x7FFE
#define CMD_GET_SDH_INFO            0x7FFF

#define LOCK_STATE_LOCKED           0x01
#define LOCK_STATE_STOP             0x02

#define TRACE_CMD_SIMPLE            0x0001
#define TRACE_CMD_EXT               0x0002
#define TRACE_SDH_FUNC              0x0004
#define TRACE_READ_DATA			0x0008

#define OUT_BUF_SIZE (3+MAX_CMD_NUM_PARAM*(2+MAX_CMD_PARAM_LEN))
#define IN_BUF_SIZE (3+MAX_CMD_NUM_PARAM*(2+MAX_CMD_PARAM_LEN))
#define WIN32_LEAN_AND_MEAN //supress compilation error redef of DOMDocument
#define _CRT_SECURE_NO_WARNINGS
#define DEF_HL_INCL_DOM

#ifdef HL_HPUX
#include <iostream>
#endif

/*+-------------------------------------------------------------------+*/
/*| System and library header files for XERCES.                       |*/
/*+-------------------------------------------------------------------+*/
#ifdef HL_HPUX
    #include <iostream>
#endif
#include <xercesc/dom/DOMNode.hpp>
#include <xercesc/dom/DOMLocator.hpp>
#include <xercesc/dom/impl/DOMElementImpl.hpp> // needed only for WSP2.3
/*+-------------------------------------------------------------------+*/
/*| System and library header files.                                  |*/
/*+-------------------------------------------------------------------+*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
//#include <conio.h>
#include <time.h>
#ifndef HL_UNIX
#include <windows.h>
//CRITICAL_SECTION ds_critprint;
//#define PRINT_DIRECT(...) {EnterCriticalSection(&ds_critprint);sprintf(chrs_out,__VA_ARGS__);fprintf(stderr,"%s",chrs_out);LeaveCriticalSection(&ds_critprint);}
#define PRINT_DIRECT(...) {sprintf(chrs_out,__VA_ARGS__);fprintf(stderr,"%s",chrs_out);}
#define SLEEP_SECONDS(a) Sleep(1000*a);
#else
#include "hob-hunix01.h"
#define SLEEP_SECONDS(a) sleep(a);
#define PRINT_DIRECT(...) {sprintf(chrs_out,__VA_ARGS__);fprintf(stderr,"%s",chrs_out);}
extern "C" unsigned int sleep(unsigned int);
#endif
#include <IBIPGW08-X1.hpp>
#include <hob-xsclib01.h>
#ifndef HL_HPUX
#include <iostream>
#endif
#define SDH_EXIT {PRINT_DIRECT ("SDH_WSP_TEST: SDH_EXIT called!"); exit(1);}
struct dsd_cmd
{
    unsigned short us_cmd;
    short im_numparam;
    short imr_parlen[MAX_CMD_NUM_PARAM];
    char chrr_par[MAX_CMD_NUM_PARAM][MAX_CMD_PARAM_LEN];
};


struct dsd_clib1_sesspar {
    bool bo_forcedir_c;
    bool bo_forcedir_s;
    bool bo_connected;
    char chr_input[IN_BUF_SIZE];
    int im_inputptr;
    char chr_output_c[OUT_BUF_SIZE];
    int im_outputptr_c;
    char chr_output_s[OUT_BUF_SIZE];
    int im_outputptr_s;
    struct dsd_aux_tcp_conn_1 ds_tcp;
    struct dsd_cmd ds_cmd;
};

struct dsd_clib1_sesscfg {                    /* structure session config */
    char chr_filename[256];
    char chr_wrongfile[256];
    char chr_serverineta[128];
    char chr_wrongserver[128];
    char chr_outineta[128];
    char chr_service[128];
    int im_serverport;
    char ch_lockstate;
};

struct dsd_proc_conf {                        /* structure configuration processing */
        struct dsd_hl_clib_dom_conf *ads_conf;
        struct dsd_clib1_sesscfg* ads_settings;
        char chr_error[256];
};

struct dsd_time_conv {
        int im_time;
        char chr_time[32];
};

static const char chrs_hello_msg[] =
"Test Server Data Hook (SDH_WSP_TEST) Version 3.01"
" Build: " 
__DATE__;
static char chrs_out[2048];
//static unsigned short us_tracelvl=TRACE_CMD_SIMPLE|TRACE_SDH_FUNC|TRACE_CMD_EXT;
static unsigned short us_tracelvl=0;

void m_print_conf(struct dsd_hl_clib_dom_conf *,const char *);
void m_proc_conf(struct dsd_proc_conf *,DOMNode *,int,char*);
int m_cmd_stat(char *, int ,struct dsd_cmd* );
int m_read_data(struct dsd_hl_clib_1 *,char *,int *,int);
void m_out(struct dsd_hl_clib_1 *,const char *,int,int);
BOOL m_write(struct dsd_hl_clib_1 *,char *,int *,int);
BOOL m_wchar_to_char(WCHAR* , char *, int );
void m_sendcmd(struct dsd_hl_clib_1 *,struct dsd_cmd *,int);

void m_proccmd(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_data(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_printf(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_print_console(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_mem_get(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_mem_read(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_mem_write(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_mem_free(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_cma_query(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_cma_setsize(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_cma_read(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_cma_write(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_cma_lock_global(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_cma_lock_region(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_cma_get_lock_state(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_cma_set_lock_state(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_get_random(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_tcp_conn(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_tcp_close(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_tcp_get_status(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_tcp_conn_ssl(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_diskfile_access(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_diskfile_release(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_diskfile_time_lm(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_epoch_from_string(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_string_from_epoch(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_query_main_str(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_query_client(struct dsd_hl_clib_1 *,struct dsd_cmd *);

void m_proc_crt_fileopen(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_crt_fileclose(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_crt_fileread(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_crt_filewrite(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_crt_filedelete(struct dsd_hl_clib_1 *,struct dsd_cmd *);

void m_proc_disconnect(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_get_conf_tcp_valid(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_get_conf_tcp_invalid(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_get_conf_file_valid(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_get_conf_file_invalid(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_nop(struct dsd_hl_clib_1 *,struct dsd_cmd *);
void m_proc_get_sdh_info(struct dsd_hl_clib_1 *,struct dsd_cmd *);

void m_setpar_bool(struct dsd_cmd *,int,bool);
void m_setpar_byte(struct dsd_cmd *,int,unsigned char);
void m_setpar_uint16(struct dsd_cmd *,int,unsigned short);
void m_setpar_uint32(struct dsd_cmd *,int,unsigned int);
void m_setpar_uint64(struct dsd_cmd *,int,unsigned long long);
void m_setpar_fileinfo(struct dsd_cmd *ads_cmd,int im_index,unsigned long long,unsigned long long,unsigned int,unsigned long long);
bool m_getpar_bool(struct dsd_cmd *,int);
unsigned char m_getpar_byte(struct dsd_cmd *,int);
unsigned short m_getpar_uint16(struct dsd_cmd *,int);
unsigned int m_getpar_uint32(struct dsd_cmd *,int);
unsigned long long m_getpar_uint64(struct dsd_cmd *,int);


extern "C" HL_DLL_PUBLIC BOOL m_hlclib_conf( struct dsd_hl_clib_dom_conf *ads_conf) {
    
    struct dsd_clib1_sesscfg ds_settings;
    struct dsd_proc_conf ds_procconf;
    char chr_tmp[1024];
    BOOL bo_ret;
#ifndef HL_UNIX
    //InitializeCriticalSection(&ds_critprint);
#endif
    m_print_conf(ads_conf,(char *)chrs_hello_msg);
    
    strcpy(ds_settings.chr_filename,"");
    strcpy(ds_settings.chr_wrongfile,"");
    strcpy(ds_settings.chr_serverineta,"");
    strcpy(ds_settings.chr_wrongserver,"");
    strcpy(ds_settings.chr_outineta,"");
    strcpy(ds_settings.chr_service,"");
    ds_settings.im_serverport=-1;

    ds_procconf.ads_conf=ads_conf;
    ds_procconf.ads_settings=&ds_settings;
    strcpy(ds_procconf.chr_error,"");

    if (ads_conf==NULL)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_hlclib_conf(): ads_conf is NULL!\n");
        PRINT_DIRECT("Exiting WSP\n");
        SDH_EXIT;
    }

    m_print_conf(ads_conf,"SDH configuration provided by WebSecureProxy:");
    m_proc_conf(&ds_procconf,ads_conf->adsc_node_conf,0,NULL);
    
    if (strlen(ds_procconf.chr_error)!=0)
    {
        m_print_conf(ads_conf,"SDH_WSP_TEST: Error occured while processing configuration file:");
        m_print_conf(ads_conf,ds_procconf.chr_error);
        return false;
    }

    if (strlen(ds_settings.chr_filename)==0)
    {
        m_print_conf(ads_conf,"SDH_WSP_TEST: Error occured while processing configuration file:");
        m_print_conf(ads_conf,"Parameter 'file-name' undefined!");
        return false;        
    }

    if (strlen(ds_settings.chr_wrongfile)==0)
    {
        m_print_conf(ads_conf,"SDH_WSP_TEST: Error occured while processing configuration file:");
        m_print_conf(ads_conf,"Parameter 'wrong-file-name' undefined!");
        return false;        
    }

    if (strlen(ds_settings.chr_serverineta)==0)
    {
        m_print_conf(ads_conf,"SDH_WSP_TEST: Error occured while processing configuration file:");
        m_print_conf(ads_conf,"Parameter 'server-ineta' undefined!");
        return false;        
    }
    if (strlen(ds_settings.chr_wrongserver)==0)
    {
        m_print_conf(ads_conf,"SDH_WSP_TEST: Error occured while processing configuration file:");
        m_print_conf(ads_conf,"Parameter 'wrong-server-ineta' undefined!");
        return false;        
    }

    if ((ds_settings.im_serverport<0)||(ds_settings.im_serverport>65535))
    {
        m_print_conf(ads_conf,"SDH_WSP_TEST: Error occured while processing configuration file:");
        m_print_conf(ads_conf,"Parameter 'server-port' undefined!");
        return false;        
    }
    sprintf(chr_tmp,"file-name: %s",ds_settings.chr_filename);
    m_print_conf(ads_conf,chr_tmp);
    sprintf(chr_tmp,"wrong-file-name: %s",ds_settings.chr_wrongfile);
    m_print_conf(ads_conf,chr_tmp);
    sprintf(chr_tmp,"server-ineta: %s",ds_settings.chr_serverineta);
    m_print_conf(ads_conf,chr_tmp);
    sprintf(chr_tmp,"wrong-server-ineta: %s",ds_settings.chr_wrongserver);
    m_print_conf(ads_conf,chr_tmp);
    sprintf(chr_tmp,"server-port: %d",ds_settings.im_serverport);
    m_print_conf(ads_conf,chr_tmp);


    bo_ret=ads_conf->amc_aux(ads_conf->vpc_userfld,
                                DEF_AUX_MEMGET,
                                ads_conf->aac_conf,
                                sizeof(struct dsd_clib1_sesscfg));
    if (bo_ret==false)
    {
        m_print_conf(ads_conf,"SDH_WSP_TEST: m_hlclib_conf(): memory allocation failed!");
        return false;
    }

    memcpy(*ads_conf->aac_conf,&ds_settings,sizeof(ds_settings));

    return true;
}

extern "C" HL_DLL_PUBLIC void m_hlclib01( struct dsd_hl_clib_1 *adsp_hl_clib_1 ) {

   struct dsd_clib1_sesscfg *ads_sesscfg;
   struct dsd_clib1_sesspar *ads_sesspar;
   struct dsd_cmd ds_cmd;
   BOOL bo_ret;
   int im_dir_in;
   int im_dir_out;
   int im_work,im_work2;

   
   ads_sesscfg=(struct dsd_clib1_sesscfg *)adsp_hl_clib_1->ac_conf;

   if ((us_tracelvl&TRACE_SDH_FUNC)!=0)
   {
       PRINT_DIRECT("SDH_WSP_TEST: DEF_IFUNC=%d\r\n",adsp_hl_clib_1->inc_func);
   }
   
   if (adsp_hl_clib_1->inc_func==DEF_IFUNC_START)
   {
        // Allocate memory for session parameters
        bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_MEMGET,
                                &adsp_hl_clib_1->ac_ext,
                                sizeof(struct dsd_clib1_sesspar));
        if (bo_ret==false)
        {
            PRINT_DIRECT("SDH_WSP_TEST: m_hlclib01(): Couldn't allocate memory for session parameters. DEF_AUX_MEMGET failed! ret=false\r\n");
            SDH_EXIT;
        }
        // Initialize session parameters
        ads_sesspar=(struct dsd_clib1_sesspar *)adsp_hl_clib_1->ac_ext;
        ads_sesspar->bo_forcedir_c=false;
        ads_sesspar->bo_forcedir_s=false;
        ads_sesspar->bo_connected=false;
        ads_sesspar->im_inputptr=0;
        strcpy(ads_sesspar->chr_input,"");
        ads_sesspar->im_outputptr_c=0;
        strcpy(ads_sesspar->chr_output_c,"");
        ads_sesspar->im_outputptr_s=0;
        strcpy(ads_sesspar->chr_output_s,"");
        adsp_hl_clib_1->ac_ext=ads_sesspar;
        // Initialize gobal paramters
        ads_sesscfg->ch_lockstate=0;
        return;
   }
   
   ads_sesspar=(struct dsd_clib1_sesspar *)adsp_hl_clib_1->ac_ext;

   im_dir_out=DIR_UNKNOWN;
   im_dir_in=DIR_UNKNOWN;

   switch(adsp_hl_clib_1->inc_func)
   {
        case(DEF_IFUNC_REFLECT):
            im_dir_out=DIR_TOCLIENT;
            im_dir_in=DIR_FROMCLIENT;
            ads_sesspar->bo_connected=false;
            break;
        case(DEF_IFUNC_FROMSERVER):
            im_dir_out=DIR_TOCLIENT;
            im_dir_in=DIR_FROMSERVER;
            ads_sesspar->bo_connected=true;
            break;
        case(DEF_IFUNC_TOSERVER):
            im_dir_out=DIR_TOSERVER;
            im_dir_in=DIR_FROMCLIENT;
            ads_sesspar->bo_connected=true;
            break;
        case(DEF_IFUNC_CLOSE):
            im_dir_out=DIR_UNKNOWN;
            im_dir_in=DIR_UNKNOWN;
            ads_sesspar->bo_connected=false;
            break;
        default:
            break;
   }

   // Check if connected to server
   if (ads_sesspar->bo_connected==false)
   {
        // Delete output buffer (server),if not connected to server
        if (ads_sesspar->im_outputptr_s!=0)
        {
            PRINT_DIRECT("SDH_WSP_TEST: m_hlclib01(): Skipping output data for server (not connected)\r\n");
            ads_sesspar->im_outputptr_s=0;
        }

        // Delete bo_forcedir_s flag, if not connected to server
        ads_sesspar->bo_forcedir_s=false;
   }

   // Check for output in current direction
   switch(im_dir_out)
   {
        case(DIR_TOCLIENT):
            if (ads_sesspar->im_outputptr_c!=0)
            {
                //send data to client
				bo_ret=m_write(adsp_hl_clib_1,ads_sesspar->chr_output_c,&ads_sesspar->im_outputptr_c,DIR_TOCLIENT);
                adsp_hl_clib_1->boc_callagain=true;
				if ((us_tracelvl&TRACE_SDH_FUNC)!=0) PRINT_DIRECT("SDH_WSP_TEST: callagain set (current dir is 'to client'). Output data for current direction!\n");
                return;
            }
            break;
        case(DIR_TOSERVER):
            if (ads_sesspar->im_outputptr_s!=0)
            {
                //send data to server
				bo_ret=m_write(adsp_hl_clib_1,ads_sesspar->chr_output_s,&ads_sesspar->im_outputptr_s,DIR_TOSERVER);
                adsp_hl_clib_1->boc_callagain=true;
				if ((us_tracelvl&TRACE_SDH_FUNC)!=0) PRINT_DIRECT("SDH_WSP_TEST: callagain set (current dir is 'to server'). Output data for current direction!\n");
                return;
            }
            break;        
        default:
            break;
   }
   
   // Check for output in reverse direction
   switch(im_dir_out)
   {
        case(DIR_TOCLIENT):
            if (ads_sesspar->im_outputptr_s!=0)
            {
                //call in reverse direction / set flag to force direction DIR_TOSERVER
                ads_sesspar->bo_forcedir_s=true;
                adsp_hl_clib_1->boc_callrevdir=true;
				if ((us_tracelvl&TRACE_SDH_FUNC)!=0) PRINT_DIRECT("SDH_WSP_TEST: callrevdir set (current dir is 'to client'). Output data for reverse direction!\n");
                return;
            }
            break;
        case(DIR_TOSERVER):
            if (ads_sesspar->im_outputptr_c!=0)
            {
                //call in reverse direction / set flag to force direction DIR_TOCLIENT
                ads_sesspar->bo_forcedir_c=true;
                adsp_hl_clib_1->boc_callrevdir=true;
				if ((us_tracelvl&TRACE_SDH_FUNC)!=0) PRINT_DIRECT("SDH_WSP_TEST: callrevdir set (current dir is 'to server'). Output data for reverse direction!\n");
                return;
            }
            break;        
        default:
            break;
   }
  
   //Handle direction forcing
   if (ads_sesspar->bo_forcedir_c==true)
   {
        if (im_dir_out==DIR_TOCLIENT)
        {
            //force successful -> call again in original direction
            ads_sesspar->bo_forcedir_c=false;
            adsp_hl_clib_1->boc_callrevdir=true;
			if ((us_tracelvl&TRACE_SDH_FUNC)!=0) PRINT_DIRECT("SDH_WSP_TEST: callrevdir set! (client force flag cleared!)\n");
            return;
        }
   }
   if (ads_sesspar->bo_forcedir_s==true)
   {
        if (im_dir_out==DIR_TOSERVER)
        {
            //force successful -> call again in original direction
            ads_sesspar->bo_forcedir_s=false;
            adsp_hl_clib_1->boc_callrevdir=true;
			if ((us_tracelvl&TRACE_SDH_FUNC)!=0) PRINT_DIRECT("SDH_WSP_TEST: callrevdir set! (server force flag cleared!)\n");
            return;
        }
   }

   if ((ads_sesspar->bo_forcedir_s==true)||(ads_sesspar->bo_forcedir_c==true))
   {
	    // force reverse direction (again)
        adsp_hl_clib_1->boc_callrevdir=true;
		if ((us_tracelvl&TRACE_SDH_FUNC)!=0) PRINT_DIRECT("SDH_WSP_TEST: callrevdir set! (force flag is still set!)\n");
        return;
   }

   if (im_dir_in==DIR_FROMCLIENT)
   {
        // Receive command from client        
        for(;;)
        {
            //Leave loop, if command is complete
            im_work=m_cmd_stat(ads_sesspar->chr_input,ads_sesspar->im_inputptr,&ds_cmd);
            if (im_work==0) break;

            if (im_work<0)
            {
                PRINT_DIRECT("SDH_WSP_TEST: Internal Error! m_cmd_stat() returned %d\r\n",im_work);
            }

            //Read data from gather structure
            im_work2=m_read_data(adsp_hl_clib_1,ads_sesspar->chr_input,&ads_sesspar->im_inputptr,im_work);

            if (im_work2==im_work)
            {
                //command might be complete or there might be more data available
                continue;
            }
            else
            {
                //not enough data available
                return;
            }
        }

        if ((us_tracelvl&TRACE_CMD_EXT)!=0)
        {
            PRINT_DIRECT("SDH_WSP_TEST: Received command from client:\r\n");
            PRINT_DIRECT("SDH_WSP_TEST: cmd=%04X\r\n",ds_cmd.us_cmd);
            for (im_work=0;im_work<ds_cmd.im_numparam;im_work++)
            {
                PRINT_DIRECT("SDH_WSP_TEST: param=");
                for (im_work2=0;im_work2<ds_cmd.imr_parlen[im_work];im_work2++)
                {
                    PRINT_DIRECT("%02X ",(ds_cmd.chrr_par[im_work][im_work2]&0xFF));
                }
                PRINT_DIRECT("\r\n");
            }
        }

        // Clear input buffer
        ads_sesspar->im_inputptr=0;

        // Process command

        m_proccmd(adsp_hl_clib_1,&ds_cmd);

        if ((ds_cmd.us_cmd==(CMD_TCP_CONN|0x8000))||(ds_cmd.us_cmd==(CMD_TCP_CONN_SSL|0x8000))||(ds_cmd.us_cmd==(CMD_TCP_CLOSE|0x8000)))
        {
            adsp_hl_clib_1->boc_callrevdir=true;
            adsp_hl_clib_1->boc_callagain=true;
            return;
        }

        if (im_dir_out==DIR_TOSERVER)
        {
            if (ads_sesspar->im_outputptr_s>0)
            {
                //write immediately
				m_write(adsp_hl_clib_1,ads_sesspar->chr_output_s,&ads_sesspar->im_outputptr_s,DIR_TOSERVER);
            }

            if (ads_sesspar->im_outputptr_c>0)
            {
                //call again in reverse direction
                if ((us_tracelvl&TRACE_SDH_FUNC)!=0) PRINT_DIRECT("SDH_WSP_TEST: CALLREVDIR\r\n");
                adsp_hl_clib_1->boc_callrevdir=true;
            }
        }
    
        if (im_dir_out==DIR_TOCLIENT)
        {
            if (ads_sesspar->im_outputptr_c>0)
            {
                //write immediately
				m_write(adsp_hl_clib_1,ads_sesspar->chr_output_c,&ads_sesspar->im_outputptr_c,DIR_TOCLIENT);
            }

            if (ads_sesspar->im_outputptr_c>0)
            {
                //call again in reverse direction
                if (im_dir_in==DIR_FROMCLIENT)
                {
                    if ((us_tracelvl&TRACE_SDH_FUNC)!=0) PRINT_DIRECT("SDH_WSP_TEST: CALLAGAIN\r\n");
                    adsp_hl_clib_1->boc_callagain=true;
                }
                else
                {
                    if ((us_tracelvl&TRACE_SDH_FUNC)!=0) PRINT_DIRECT("SDH_WSP_TEST: CALLREVDIR\r\n");
                    adsp_hl_clib_1->boc_callrevdir=true;
                }
            }
        }
   }

   if (im_dir_in==DIR_FROMSERVER)
   {
        int im_bufptr=0;
        //Read data from gather structure
        ds_cmd.us_cmd=CMD_DATA;
        ds_cmd.im_numparam=1;
        ds_cmd.imr_parlen[0]=m_read_data(adsp_hl_clib_1,&ds_cmd.chrr_par[0][0],&im_bufptr,MAX_CMD_PARAM_LEN);

        if (ds_cmd.imr_parlen[0]>0)
        {
            // data received from server -> forward data cmd to client (immediately)
            m_sendcmd(adsp_hl_clib_1,&ds_cmd,DIR_TOCLIENT);
			m_write(adsp_hl_clib_1,ads_sesspar->chr_output_c,&ads_sesspar->im_outputptr_c,DIR_TOCLIENT);
        }
   }
}


void m_print_conf(struct dsd_hl_clib_dom_conf *ads_conf,const char *ac_msg)
{
    BOOL bo_ret;
    bo_ret=ads_conf->amc_aux(ads_conf->vpc_userfld,
                                DEF_AUX_CONSOLE_OUT,
                                (void *)ac_msg,
                                strlen(ac_msg) );
    if (bo_ret==false)
    {
        PRINT_DIRECT("SDH_WSP_TEST: Console output failed!\n");
        PRINT_DIRECT("Exiting WSP\n");
        SDH_EXIT;
    }
    return;
}


void m_proc_conf(struct dsd_proc_conf *ads_procconf,DOMNode *ads_curr_node,int im_depth,char *ach_parent)
{
    int im_type;                    // Type of DOMNode
    WCHAR *awc_node_name;            // Name of DOMNode
    WCHAR *awc_node_val;            // Value of DOMNode
    char chr_tmp[1024];                // Buffer for conversion to CHAR    
    BOOL bo_work;

    if (ads_curr_node==NULL) return;
    im_type=(int)(long)ads_procconf->ads_conf->amc_call_dom(ads_curr_node, ied_hlcldom_get_node_type);
    switch(im_type)
    {
        case(DOMNode::ELEMENT_NODE):
            awc_node_name = (WCHAR *)ads_procconf->ads_conf->amc_call_dom(ads_curr_node, ied_hlcldom_get_node_name);        
            bo_work=m_wchar_to_char(awc_node_name,chr_tmp,sizeof(chr_tmp));
            if (bo_work==false)
            {
                if (strlen(ads_procconf->chr_error)==0) sprintf(ads_procconf->chr_error,"SDH_WSP_TEST: m_wchar_to_char() failed!\n");
                sprintf(chr_tmp,"???");
            }
            PRINT_DIRECT("<%s>",chr_tmp);
            m_proc_conf(ads_procconf,(DOMNode *)ads_procconf->ads_conf->amc_call_dom(ads_curr_node, ied_hlcldom_get_first_child),im_depth+1,chr_tmp);
            if (im_depth==0) PRINT_DIRECT("\r");
            PRINT_DIRECT("</%s>",chr_tmp);
            break;    
        case(DOMNode::TEXT_NODE):
            awc_node_val = (WCHAR *) ads_procconf->ads_conf->amc_call_dom(ads_curr_node, ied_hlcldom_get_node_value);
            if (awc_node_val==NULL)
            {
                if (strlen(ads_procconf->chr_error)==0) sprintf(ads_procconf->chr_error,"SDH_WSP_TEST: ied_hlcldom_get_node_value returned NULL!\n");
                PRINT_DIRECT("<NULL>");
                return;
            }
            else
            {
                bo_work=m_wchar_to_char(awc_node_val,chr_tmp,sizeof(chr_tmp));
                if (bo_work==false)
                {
                    if (strlen(ads_procconf->chr_error)==0) sprintf(ads_procconf->chr_error,"SDH_WSP_TEST: m_wchar_to_char() failed!\n");
                    sprintf(chr_tmp,"???");
                }
                PRINT_DIRECT("%s",chr_tmp);
                if ((im_depth==2)&&(ach_parent!=NULL))
                {
                    if (strcmp(ach_parent,"file-name")==0)
                    {
                        if (strlen(chr_tmp)<sizeof(ads_procconf->ads_settings->chr_filename))
                        {
                            strcpy(ads_procconf->ads_settings->chr_filename,chr_tmp);
                        }
                        else
                        {
                            if (strlen(ads_procconf->chr_error)==0) sprintf(ads_procconf->chr_error,"Value of parameter 'file-name' too long! (max len=%u)", sizeof(ads_procconf->ads_settings->chr_filename));
                        }
                    }
                    if (strcmp(ach_parent,"wrong-file-name")==0)
                    {
                        if (strlen(chr_tmp)<sizeof(ads_procconf->ads_settings->chr_wrongfile))
                        {
                            strcpy(ads_procconf->ads_settings->chr_wrongfile,chr_tmp);
                        }
                        else
                        {
                            if (strlen(ads_procconf->chr_error)==0) sprintf(ads_procconf->chr_error,"Value of parameter 'wrong-file-name' too long! (max len=%u)", sizeof(ads_procconf->ads_settings->chr_wrongfile));
                        }
                    }
                    if (strcmp(ach_parent,"server-ineta")==0)
                    {
                        if (strlen(chr_tmp)<sizeof(ads_procconf->ads_settings->chr_serverineta))
                        {
                            strcpy(ads_procconf->ads_settings->chr_serverineta,chr_tmp);
                        }
                        else
                        {
                            if (strlen(ads_procconf->chr_error)==0) sprintf(ads_procconf->chr_error,"Value of parameter 'server-ineta' too long! (max len=%u)", sizeof(ads_procconf->ads_settings->chr_serverineta));
                        }
                    }
                    if (strcmp(ach_parent,"wrong-server-ineta")==0)
                    {
                        if (strlen(chr_tmp)<sizeof(ads_procconf->ads_settings->chr_wrongserver))
                        {
                            strcpy(ads_procconf->ads_settings->chr_wrongserver,chr_tmp);
                        }
                        else
                        {
                            if (strlen(ads_procconf->chr_error)==0) sprintf(ads_procconf->chr_error,"Value of parameter 'wrong-server-ineta' too long! (max len=%u)", sizeof(ads_procconf->ads_settings->chr_wrongserver));
                        }
                    }
                    if (strcmp(ach_parent,"server-port")==0)
                    {
                        ads_procconf->ads_settings->im_serverport=atoi(chr_tmp);
                        if ((ads_procconf->ads_settings->im_serverport<0)||(ads_procconf->ads_settings->im_serverport>65535))
                        {
                            if (strlen(ads_procconf->chr_error)==0) sprintf(ads_procconf->chr_error,"Value of parameter 'server-port' out of range!");
                        }
                    }
                }
            }
            break;
        default:
            
            break;
            
    }
    if (ads_curr_node!=ads_procconf->ads_conf->adsc_node_conf)
    {
        m_proc_conf(ads_procconf,(DOMNode *)ads_procconf->ads_conf->amc_call_dom(ads_curr_node, ied_hlcldom_get_next_sibling),im_depth,ach_parent);
    }
    else
    {
        PRINT_DIRECT("\n");
    }
}

int m_cmd_stat(char *ach_buf, int im_buflen,struct dsd_cmd* ads_cmd)
{
    int im_work;
    int im_offset;
    int im_minlen=3;

    ads_cmd->us_cmd=0xFFFF;
    ads_cmd->im_numparam=-1;
    for (int im_work=0;im_work<MAX_CMD_NUM_PARAM;im_work++)
    {
        ads_cmd->imr_parlen[im_work]=-1;
    }

    
    if (im_buflen<3) return (im_minlen-im_buflen);

    ads_cmd->us_cmd=256*(*((unsigned char*)(ach_buf))&0xFF);
    ads_cmd->us_cmd+=(*((unsigned char*)(ach_buf+1)))&0xFF;
    ads_cmd->im_numparam=(*((char*)(ach_buf+2)))&0xFF;

    if ((ads_cmd->im_numparam<0)||(ads_cmd->im_numparam>MAX_CMD_NUM_PARAM))
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_cmd_stat() Protocol Error: number of parameters invalid: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }

    im_minlen+=2*ads_cmd->im_numparam;
    im_offset=3;

    for (im_work=0;im_work<ads_cmd->im_numparam;im_work++)
    {
        // try to get parameter length
        if (im_buflen<(im_offset+2))
        {
            // not enough data to determine parameter length;
            return (im_minlen-im_buflen);
        }

        // parameter length available
        ads_cmd->imr_parlen[im_work]=256*((*((char*)(ach_buf+im_offset)))&0xFF);
        ads_cmd->imr_parlen[im_work]+=(*((char*)(ach_buf+im_offset+1)))&0xFF;
        im_offset+=2;
        im_minlen+=ads_cmd->imr_parlen[im_work];
        
        //try to get parameter
        if (im_buflen<(im_offset+ads_cmd->imr_parlen[im_work]))
        {
            // not enough data to get parameter;
            return (im_minlen-im_buflen);
        }

        // check for valid parameter length
        if (ads_cmd->imr_parlen[im_work]>MAX_CMD_PARAM_LEN)
        {
            PRINT_DIRECT("SDH_WSP_TEST: m_cmd_stat() Protocol Error: Invalid paramter length: %d!\r\n",ads_cmd->imr_parlen[im_work]);
            SDH_EXIT;
        }

        // parameter complete
        memcpy(&ads_cmd->chrr_par[im_work][0],(ach_buf+im_offset),ads_cmd->imr_parlen[im_work]);
        im_offset+=ads_cmd->imr_parlen[im_work];
    }

    if (im_buflen>im_minlen)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_cmd_stat() Internal Error: Too many bytes in buffer!\r\n");
        SDH_EXIT;
    }
    if (im_buflen<im_minlen)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_cmd_stat() Internal Error: Too few bytes in buffer!\r\n");
        SDH_EXIT;
    }
    
    //command is complete
    return 0;

}

int m_read_data(struct dsd_hl_clib_1 *adsp_hl_clib_1,char *ach_buf,int *aim_bufptr,int im_bytestoread)
{
    struct dsd_gather_i_1 *ads_ga_in;
    int im_bytesread=0;
    char ch_in;
    ads_ga_in=adsp_hl_clib_1->adsc_gather_i_1_in;
    while (im_bytesread<im_bytestoread)
    {
        //Get first char from gather structure (if any)
		if (ads_ga_in==NULL)
		{
			if ((us_tracelvl&TRACE_READ_DATA)!=0) printf("SDH_WSP_TEST: m_readdata(): ads_ga_in is NULL!\n");
			return im_bytesread;
		}
        do
        {
            if (ads_ga_in->achc_ginp_cur==ads_ga_in->achc_ginp_end)
            {
                ads_ga_in=ads_ga_in->adsc_next;
                if (ads_ga_in==NULL) return im_bytesread;
            
            }
        } while (ads_ga_in->achc_ginp_cur==ads_ga_in->achc_ginp_end);
        ch_in=*ads_ga_in->achc_ginp_cur;
        ads_ga_in->achc_ginp_cur++;
        im_bytesread++;
        *((char*)(ach_buf+*aim_bufptr))=ch_in;
		if ((us_tracelvl&TRACE_READ_DATA)!=0) printf("SDH_WSP_TEST: m_readdata(): byte revceived: %02X\n",ch_in&0xFF);
        *aim_bufptr=(*aim_bufptr)+1;
    }
    return im_bytesread;
}

void m_out(struct dsd_hl_clib_1 *adsp_hl_clib_1,const char *ach_buf,int im_buflen,int im_dir)
{
    char *ach_out;
    int *aim_len;
    struct dsd_clib1_sesspar *ads_sesspar;
    
    ads_sesspar=(struct dsd_clib1_sesspar *)adsp_hl_clib_1->ac_ext;
    //m_print(adsp_hl_clib_1,"received data");
    //m_print_buffer(adsp_hl_clib_1,ach_buf,ach_buf+im_buflen);
    
    switch (im_dir)
    {
        case(DIR_TOSERVER):
            ach_out=ads_sesspar->chr_output_s;
            aim_len=&ads_sesspar->im_outputptr_s;
            break;
        case(DIR_TOCLIENT):
            ach_out=ads_sesspar->chr_output_c;
            aim_len=&ads_sesspar->im_outputptr_c;
            break;
        default:
            PRINT_DIRECT("SDH_WSP_TEST: m_out() received invalid direction!\n");
            SDH_EXIT;
    }
    
    if (((*aim_len)+im_buflen)>OUT_BUF_SIZE)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_out(): buffer overflow!\n");
        SDH_EXIT;
    }
    memcpy(ach_out+(*aim_len),ach_buf,im_buflen);
    *aim_len+=im_buflen;

    //m_print(adsp_hl_clib_1,"new output buffer:");
    //m_print_buffer(adsp_hl_clib_1,ach_out,ach_out+*aim_len);
    
}

BOOL m_write(struct dsd_hl_clib_1 *adsp_hl_clib_1,char *ach_buf ,int *aim_buflen, int im_dir)
{
    int im_datalen;
    int im_copylen;
    int im_dataoffset;
        int im_count;
    struct dsd_gather_i_1 *ads_ga;
    BOOL bo_ret;

    //m_print(adsp_hl_clib_1,"write data:");
    //m_print_buffer(adsp_hl_clib_1,ach_buf,ach_buf+*aim_buflen);
    
    im_dataoffset=sizeof(dsd_gather_i_1);
    im_datalen=adsp_hl_clib_1->inc_len_work_area-im_dataoffset;

    if (im_datalen<1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_write(): work area too small!\n");
        SDH_EXIT;
    }
    ads_ga=(struct dsd_gather_i_1 *)adsp_hl_clib_1->achc_work_area;
    im_copylen=*aim_buflen;
    bo_ret=true;
    if (im_datalen<(*aim_buflen)) 
    {
        im_copylen=im_datalen;
        bo_ret=false;
    }
    memcpy(adsp_hl_clib_1->achc_work_area+im_dataoffset,ach_buf,im_copylen);

    for(im_count=0;im_count<((*aim_buflen)-im_copylen);im_count++)
    {
        *((char *)(ach_buf+im_count))=*((char *)(ach_buf+im_copylen+im_count));
    }
    *aim_buflen=*aim_buflen-im_copylen;

    ads_ga->achc_ginp_cur=adsp_hl_clib_1->achc_work_area+im_dataoffset;
    ads_ga->achc_ginp_end=ads_ga->achc_ginp_cur+im_copylen;
    ads_ga->adsc_next=NULL;
#ifndef NEW_WSP_1102
    adsp_hl_clib_1->adsc_gather_i_1_out=ads_ga;
#else
	switch(im_dir)
	{
		case(DIR_TOCLIENT):
			adsp_hl_clib_1->adsc_gai1_out_to_client=ads_ga;
			break;
		case(DIR_TOSERVER):
			adsp_hl_clib_1->adsc_gai1_out_to_server=ads_ga;
			break;
		default:
			PRINT_DIRECT("\nInternal Error occurred in m_write(). Invalid direction!\n");
			SDH_EXIT;
	}
#endif
    return bo_ret;
}

BOOL m_wchar_to_char(WCHAR* awc_in, char *ach_out, int in_len)
{
    char *ach_curr;
    WCHAR *awc_curr;
    awc_curr=awc_in;
    ach_curr=ach_out;
    while (((int)(ach_curr-ach_out))<in_len)
    {
        *ach_curr=(*awc_curr)&0xFF;
        if ((*ach_curr)==0) return true;
        ach_curr++;
        awc_curr++;
    }
    return false;
}


// Process commands

void m_proccmd(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    switch(ads_cmd->us_cmd)
    {

        case(CMD_DATA):
                            m_proc_data(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_PRINT_DIRECT):    
                            m_proc_printf(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_PRINT_CONSOLE):    
                            m_proc_print_console(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_MEM_GET):
                            m_proc_mem_get(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_MEM_READ):
                            m_proc_mem_read(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_MEM_WRITE):
                            m_proc_mem_write(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_MEM_FREE):
                            m_proc_mem_free(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_CMA_QUERY):
                            m_proc_cma_query(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_CMA_SETSIZE):
                            m_proc_cma_setsize(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_CMA_READ):
                            m_proc_cma_read(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_CMA_WRITE):
                            m_proc_cma_write(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_CMA_LOCK_GLOBAL):
                            m_proc_cma_lock_global(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_CMA_LOCK_REGION):
                            m_proc_cma_lock_region(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_CMA_GET_LOCK_STATE):
                            m_proc_cma_get_lock_state(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_CMA_SET_LOCK_STATE):
                            m_proc_cma_set_lock_state(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_GET_RANDOM_BASE64):
                            m_proc_get_random(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_TCP_CONN):
                            m_proc_tcp_conn(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_TCP_CLOSE):
                            m_proc_tcp_close(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_TCP_GET_STATUS):
                            m_proc_tcp_get_status(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_TCP_CONN_SSL):
                            m_proc_tcp_conn_ssl(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_DISKFILE_ACCESS):
                            m_proc_diskfile_access(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_DISKFILE_RELEASE):
                            m_proc_diskfile_release(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_DISKFILE_TIME_LM):
                            m_proc_diskfile_time_lm(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_STRING_FROM_EPOCH):
                            m_proc_string_from_epoch(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_EPOCH_FROM_STRING):
                            m_proc_epoch_from_string(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_QUERY_MAIN_STR):
                            m_proc_query_main_str(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_QUERY_CLIENT):
                            m_proc_query_client(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_CRT_FILEOPEN):
                            m_proc_crt_fileopen(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_CRT_FILECLOSE):
                            m_proc_crt_fileclose(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_CRT_FILEREAD):
                            m_proc_crt_fileread(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_CRT_FILEWRITE):
                            m_proc_crt_filewrite(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_CRT_FILEDELETE):
                            m_proc_crt_filedelete(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_DISCONNECT):
                            m_proc_disconnect(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_GET_CONF_TCP_VALID):
                            m_proc_get_conf_tcp_valid(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_GET_CONF_TCP_INVALID):
                            m_proc_get_conf_tcp_invalid(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_GET_CONF_FILE_VALID):
                            m_proc_get_conf_file_valid(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_GET_CONF_FILE_INVALID):
                            m_proc_get_conf_file_invalid(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_NOP):
                            m_proc_nop(adsp_hl_clib_1,ads_cmd);
                            break;
        case(CMD_GET_SDH_INFO):
                            m_proc_get_sdh_info(adsp_hl_clib_1,ads_cmd);
                            break;

		default:			PRINT_DIRECT("SDH_WSP_TEST: m_proccmd(): Invalid command received!\r\n");
							SDH_EXIT;
    }
}

void m_proc_data(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    struct dsd_clib1_sesspar *ads_conf;
    int im_work;

    if (ads_cmd->im_numparam!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_data(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    ads_conf=(struct dsd_clib1_sesspar *)adsp_hl_clib_1->ac_ext;
    if (ads_conf->bo_connected==false)
    {
		PRINT_DIRECT("SDH_WSP_TEST: m_proc_data(): data will be dropped (no server connected)\r\n");
    }
    else
    {
        m_out(adsp_hl_clib_1,&ads_cmd->chrr_par[0][0],ads_cmd->imr_parlen[0],DIR_TOSERVER);
        if ((us_tracelvl&TRACE_CMD_EXT)!=0)
        {
            PRINT_DIRECT("SDH_WSP_TEST: data=");
            for (im_work=0;im_work<ads_cmd->imr_parlen[0];im_work++)
            {
                PRINT_DIRECT("%02X ",(ads_cmd->chrr_par[0][im_work]&0xFF));
            }
            PRINT_DIRECT("\r\n");
        }
    }
}

void m_proc_printf(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    if (ads_cmd->im_numparam!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_printf(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }

    PRINT_DIRECT("%s",ads_cmd->chrr_par[0]);
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=0;
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_print_console(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    bool bo_ret;
    if (ads_cmd->im_numparam!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_print_console(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }

    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_CONSOLE_OUT,
                                (void *)ads_cmd->chrr_par[0],
                                strlen(ads_cmd->chrr_par[0]) );
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_PRINT_CONSOLE string=%s, size=%d, ret=%d\r\n",ads_cmd->chrr_par[0],strlen(ads_cmd->chrr_par[0]),(bo_ret&0x01));
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    m_setpar_bool(ads_cmd,0,bo_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_mem_get(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    bool bo_ret;
    int im_size;
    unsigned long long ull_addr;
    void *auaddr=NULL;

    if (ads_cmd->im_numparam!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_mem_get(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[0]!=4)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_mem_get(): Invalid parameter size: %d\r\n",ads_cmd->imr_parlen[0]);
        SDH_EXIT;
    }

    im_size=(int) m_getpar_uint32(ads_cmd,0);
    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_MEMGET,
                                &auaddr,
                                im_size);
    ull_addr=(unsigned long long)auaddr;
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_MEM_GET addr=0x%016llx, size=%d, ret=%d\r\n",ull_addr,im_size,(bo_ret&0x01));
    }
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=2;
    m_setpar_bool(ads_cmd,0,bo_ret);
    m_setpar_uint64(ads_cmd,1,ull_addr);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_mem_read(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    void *auaddr=NULL;
    unsigned long long ull_addr;
    int im_size;
    if (ads_cmd->im_numparam!=2)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_mem_read(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[0]!=8)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_mem_read(): Invalid parameter size (0): %d\r\n",ads_cmd->imr_parlen[0]);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[1]!=4)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_mem_read(): Invalid parameter size (1): %d\r\n",ads_cmd->imr_parlen[1]);
        SDH_EXIT;
    }

    ull_addr=m_getpar_uint64(ads_cmd,0);
    im_size=(int) m_getpar_uint32(ads_cmd,1);

    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_MEM_READ addr=0x%016llx, size=%d\r\n",ull_addr,im_size);
    }

    if ((im_size<0)||(im_size>MAX_CMD_PARAM_LEN))
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_mem_read(): Invalid parameter value (1): %d\r\n",im_size);
        SDH_EXIT;
    }

     memcpy(&ads_cmd->chrr_par[0][0],(void*)ull_addr,(size_t)im_size);
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    ads_cmd->imr_parlen[0]=im_size;
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
    
}

void m_proc_mem_write(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    void *auaddr=NULL;
    unsigned long long ull_addr;
    int im_size;
    if (ads_cmd->im_numparam!=2)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_mem_write(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[0]!=8)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_mem_write(): Invalid parameter size (0): %d\r\n",ads_cmd->imr_parlen[0]);
        SDH_EXIT;
    }
    if ((ads_cmd->imr_parlen[1]<1)||(ads_cmd->imr_parlen[1]>MAX_CMD_PARAM_LEN))
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_mem_write(): Invalid parameter size: %d\r\n",ads_cmd->imr_parlen[1]);
        SDH_EXIT;
    }

    ull_addr=m_getpar_uint64(ads_cmd,0);
    im_size=ads_cmd->imr_parlen[1];

    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_MEM_WRITE addr=0x%016llx, size=%d\r\n",ull_addr,im_size);
    }
    memcpy((void*)ull_addr,&ads_cmd->chrr_par[1][0],(size_t)im_size);
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=0;
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_mem_free(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    void *auaddr=NULL;
    unsigned long long ull_addr;
    int im_size;
    bool bo_ret;

    if (ads_cmd->im_numparam!=2)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_mem_free(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[0]!=8)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_mem_free(): Invalid parameter size (0): %d\r\n",ads_cmd->imr_parlen[0]);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[1]!=4)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_mem_free(): Invalid parameter size (1): %d\r\n",ads_cmd->imr_parlen[1]);
        SDH_EXIT;
    }

    ull_addr=m_getpar_uint64(ads_cmd,0);
    im_size=(int)m_getpar_uint32(ads_cmd,1);
    auaddr=(void *)ull_addr;

    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_MEMFREE,
                                &auaddr,
                                im_size);
    if (bo_ret==false)
    {
        PRINT_DIRECT("DEF_AUX_MEMFREE failed! ret=false");
        return;
    }
    
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_MEM_FREE addr=0x%016llx, size=%d, ret=%d\r\n",ull_addr,im_size,(bo_ret&0x01));
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    m_setpar_bool(ads_cmd,0,bo_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_cma_query(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    struct dsd_hl_aux_c_cma_1 ds_cma;
    bool bo_ret;
    //char ch_enc;

    memset(&ds_cma,0,sizeof(ds_cma));
    

    if(ads_cmd->im_numparam!=2)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_query(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }

    if (ads_cmd->imr_parlen[1]!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_query(): Invalid parameter size(1): %d\r\n",ads_cmd->imr_parlen[1]);
        SDH_EXIT;
    }

    ds_cma.ac_cma_name=&ads_cmd->chrr_par[0][0];
    ds_cma.iec_chs_name=(ied_charset)m_getpar_byte(ads_cmd,1);
    ds_cma.inc_len_cma_name=ads_cmd->imr_parlen[0];
    if (ds_cma.iec_chs_name>3)ds_cma.inc_len_cma_name=ds_cma.inc_len_cma_name/2; //UTF-16
    if (ds_cma.iec_chs_name>6)ds_cma.inc_len_cma_name=ds_cma.inc_len_cma_name/2; //UTF-32
    ds_cma.iec_ccma_def=ied_ccma_query;
    ds_cma.inc_len_cma_area=-1;
        
    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_COM_CMA,
                                &ds_cma,
                                sizeof(ds_cma));
    
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_QUERY size=%d, ret=%d\r\n",ds_cma.inc_len_cma_area,(bo_ret&0x01));
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=2;
    m_setpar_bool(ads_cmd,0,bo_ret);
    m_setpar_uint32(ads_cmd,1,(unsigned)ds_cma.inc_len_cma_area);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_cma_setsize(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
	struct dsd_hl_aux_c_cma_1 ds_cma,ds_cma2;
    bool bo_ret;
	bool bo_resize;

//    char ch_enc;

    memset(&ds_cma,0,sizeof(ds_cma));
	memset(&ds_cma2,0,sizeof(ds_cma2));
    
    if (ads_cmd->im_numparam!=2)
    {    
            PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_setsize(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
            SDH_EXIT;
    }

    if ((ads_cmd->imr_parlen[1])!=4)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_setsize(): Invalid parameter size(1): %d\r\n",ads_cmd->imr_parlen[1]);
        SDH_EXIT;
    }
	
	ds_cma.ac_cma_name=&ads_cmd->chrr_par[0][0];
	ds_cma.iec_chs_name=ied_chs_ansi_819;
	ds_cma.inc_len_cma_name=ads_cmd->imr_parlen[0];
	ds_cma.iec_ccma_def=ied_ccma_query;
	ds_cma.inc_len_cma_area=-1;
		
	bo_resize=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
								DEF_AUX_COM_CMA,
								&ds_cma,
								sizeof(ds_cma));
	if (bo_resize==true)
	{
		//acquire lock 
		ds_cma2.ac_cma_name=&ads_cmd->chrr_par[0][0];
		ds_cma2.iec_chs_name=ied_chs_ansi_819;
		ds_cma2.inc_len_cma_name=ads_cmd->imr_parlen[0];
		ds_cma2.iec_ccma_def=ied_ccma_lock_global;
		ds_cma2.inc_lock_disp=0;
		ds_cma2.inc_lock_len=0;
		ds_cma2.imc_lock_type=D_CMA_ALL_ACCESS;
		ds_cma2.boc_ret_lock_fails=true;
		bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
									DEF_AUX_COM_CMA,
									&ds_cma2,
									sizeof(ds_cma2));
		if (bo_ret==false)
		{
			PRINT_DIRECT("SDH_WSP_TEST:  m_proc_cma_setsize(): Failed to set global lock!\n");
			SDH_EXIT;
		}
	}

    ds_cma.ac_cma_name=&ads_cmd->chrr_par[0][0];
    ds_cma.iec_chs_name=ied_chs_ansi_819;
    ds_cma.inc_len_cma_name=ads_cmd->imr_parlen[0];
    ds_cma.iec_ccma_def=ied_ccma_set_size;
    ds_cma.inc_len_cma_area=(int)m_getpar_uint32(ads_cmd,1);
        
    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_COM_CMA,
                                &ds_cma,
                                sizeof(ds_cma));
    
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_SETSIZE size=%d, ret=%d\r\n",ds_cma.inc_len_cma_area,(bo_ret&0x01));
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    m_setpar_bool(ads_cmd,0,bo_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);



	if (bo_resize==true)
	{
		//release lock
		ds_cma2.iec_ccma_def=ied_ccma_lock_release;
		bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
							DEF_AUX_COM_CMA,
							&ds_cma2,
							sizeof(ds_cma2));
		if (bo_ret==false)
		{
			PRINT_DIRECT("SDH_WSP_TEST:  m_proc_cma_setsize(): Failed to release global lock!\n");
			SDH_EXIT;
		}
	}
}


void m_proc_cma_read(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    struct dsd_hl_aux_c_cma_1 ds_cma;
    char ch_ret=0;
    bool bo_ret;
    //char ch_enc;
    int im_offset;
    int im_len;
    memset(&ds_cma,0,sizeof(ds_cma));
    

    if(ads_cmd->im_numparam!=3)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_read(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }

    if (ads_cmd->imr_parlen[1]!=4)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_read(): Invalid parameter size(1): %d\r\n",ads_cmd->imr_parlen[1]);
        SDH_EXIT;
    }
    
    if (ads_cmd->imr_parlen[2]!=4)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_read(): Invalid parameter size(2): %d\r\n",ads_cmd->imr_parlen[2]);
        SDH_EXIT;
    }


    im_offset=m_getpar_uint32(ads_cmd,1);
    im_len=m_getpar_uint32(ads_cmd,2);

    if (im_offset<0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_read(): Invalid parameter value (1): %d\r\n",im_offset);
        SDH_EXIT;
    }
    if ((im_len<0)||(im_len>MAX_CMD_PARAM_LEN))
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_read(): Invalid parameter value (2): %d\r\n",im_len);
        SDH_EXIT;
    }
    ds_cma.ac_cma_name=&ads_cmd->chrr_par[0][0];
    ds_cma.iec_chs_name=ied_chs_ansi_819;
    ds_cma.inc_len_cma_name=ads_cmd->imr_parlen[0];
    ds_cma.iec_ccma_def=ied_ccma_query;
    
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_READ offset=%d, len=%d\r\n",im_offset,im_len);
    }

    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_COM_CMA,
                                &ds_cma,
                                sizeof(ds_cma));
    
    if (bo_ret==true)
    {
        if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
        {
            PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_READ: cma query successful!\r\n");
        }

        //acquire read lock 
        ds_cma.iec_ccma_def=ied_ccma_lock_region;
        ds_cma.inc_lock_disp=im_offset;
        ds_cma.inc_lock_len=im_len;
        ds_cma.imc_lock_type=D_CMA_READ_DATA|D_CMA_SHARE_READ;
        ds_cma.boc_ret_lock_fails=true;
        bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_COM_CMA,
                                &ds_cma,
                                sizeof(ds_cma));
    
        if ((bo_ret==true)&&(ds_cma.achc_cma_area!=NULL))
        {
            if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
            {
                PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_READ: set read lock successful!\r\n");
            }

            //read data
            memcpy(&ads_cmd->chrr_par[1][0],ds_cma.achc_cma_area+im_offset,im_len);
            
            //release read lock
            ds_cma.iec_ccma_def=ied_ccma_lock_release;
            bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_COM_CMA,
                                &ds_cma,
                                sizeof(ds_cma));
            if (bo_ret==true)
            {
                if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
                {
                    PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_READ: release read lock successful!\r\n");
                }
            }
            else
            {
                if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
                {
                    PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_READ: release read lock failed!\r\n");
                }
                ch_ret=3;
            }
        }
        else
        {
            if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
            {
                PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_READ: set read lock failed!\r\n");
            }
            ch_ret=2;
        }
    }
    else
    {
        if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
        {
            PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_READ: cma query failed!\r\n");
        }
        ch_ret=1;
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=2;
    m_setpar_byte(ads_cmd,0,ch_ret);
    if (ch_ret==0)
    {
        //success
        ads_cmd->imr_parlen[1]=im_len;
    }
    else
    {
        //fail
        ads_cmd->imr_parlen[1]=0;
    }
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);

}

void m_proc_cma_write(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    struct dsd_hl_aux_c_cma_1 ds_cma;
    char ch_ret=0;
    bool bo_ret;
    //char ch_enc;
    int im_offset;
    
    memset(&ds_cma,0,sizeof(ds_cma));
    
    if(ads_cmd->im_numparam!=3)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_write(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[1]!=4)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_write(): Invalid parameter size(1): %d\r\n",ads_cmd->imr_parlen[1]);
        SDH_EXIT;
    }

    if (ads_cmd->imr_parlen[2]>MAX_CMD_PARAM_LEN)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_write(): Invalid parameter size(2): %d\r\n",ads_cmd->imr_parlen[2]);
        SDH_EXIT;
    }

    im_offset=m_getpar_uint32(ads_cmd,1);
    
    
    ds_cma.ac_cma_name=&ads_cmd->chrr_par[0][0];
    ds_cma.iec_chs_name=ied_chs_ansi_819;
    ds_cma.inc_len_cma_name=ads_cmd->imr_parlen[0];
    ds_cma.iec_ccma_def=ied_ccma_query;
    
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_WRITE offset=%d, len=%d\r\n",im_offset,ads_cmd->imr_parlen[2]);
    }

    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_COM_CMA,
                                &ds_cma,
                                sizeof(ds_cma));
    
    if (bo_ret==true)
    {
        if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
        {
            PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_WRITE: cma query successful!\r\n");
        }

        //acquire write lock 
        ds_cma.iec_ccma_def=ied_ccma_lock_region;
        ds_cma.inc_lock_disp=im_offset;
        ds_cma.inc_lock_len=ads_cmd->imr_parlen[2];
        ds_cma.imc_lock_type=D_CMA_WRITE_DATA;
        ds_cma.boc_ret_lock_fails=true;
        bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_COM_CMA,
                                &ds_cma,
                                sizeof(ds_cma));
    
        if ((bo_ret==true)&&(ds_cma.achc_cma_area!=NULL))
        {
            if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
            {
                PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_WRITE: set write lock successful!\r\n");
            }
            memcpy(ds_cma.achc_cma_area+im_offset,&ads_cmd->chrr_par[2][0],ads_cmd->imr_parlen[2]);

            //release write lock
            ds_cma.iec_ccma_def=ied_ccma_lock_rel_upd;
            bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_COM_CMA,
                                &ds_cma,
                                sizeof(ds_cma));
            if (bo_ret==true)
            {
                if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
                {
                    PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_WRITE: release write lock successful!\r\n");
                }
            }
            else
            {
                if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
                {
                    PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_WRITE: release write lock failed!\r\n");
                }
                ch_ret=3;
            }
            
        }
        else
        {
            if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
            {
                PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_WRITE: set write lock failed!\r\n");
            }
            ch_ret=2;
        }
    }
    else
    {
        if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
        {
            PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_WRITE: cma query failed!\r\n");
        }
        ch_ret=1;
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    m_setpar_byte(ads_cmd,0,ch_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);

}



void m_proc_cma_lock_global(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    struct dsd_clib1_sesscfg* ads_settings;
    struct dsd_hl_aux_c_cma_1 ds_cma;
    char ch_ret=-1;
    bool bo_ret;
    //char ch_enc;
    int im_acc;

    ads_settings=(struct dsd_clib1_sesscfg*)adsp_hl_clib_1->ac_conf;    
    memset(&ds_cma,0,sizeof(ds_cma));
    
    if(ads_cmd->im_numparam!=2)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_lock_global(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[1]!=4)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_lock_global(): Invalid parameter size(1): %d\r\n",ads_cmd->imr_parlen[1]);
        SDH_EXIT;
    }

    im_acc=m_getpar_uint32(ads_cmd,1);
    ds_cma.ac_cma_name=&ads_cmd->chrr_par[0][0];
    ds_cma.iec_chs_name=ied_chs_ansi_819;
    ds_cma.inc_len_cma_name=ads_cmd->imr_parlen[0];
    ds_cma.iec_ccma_def=ied_ccma_query;
        
    
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_LOCK_GLOBAL access=%d\r\n",im_acc);
    }

    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_COM_CMA,
                                &ds_cma,
                                sizeof(ds_cma));
    
    if (bo_ret==true)
    {
        if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
        {
            PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_LOCK_GLOBAL: cma query successful!\r\n");
        }

        //acquire lock 
        ds_cma.iec_ccma_def=ied_ccma_lock_global;
        ds_cma.inc_lock_disp=0;
        ds_cma.inc_lock_len=0;
        ds_cma.imc_lock_type=im_acc;
        ds_cma.boc_ret_lock_fails=true;
        bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_COM_CMA,
                                &ds_cma,
                                sizeof(ds_cma));
    
        if (bo_ret==true)
        {
            if (ds_cma.achc_cma_area==NULL)
            {
                PRINT_DIRECT("SDH_WSP_TEST: CMA address is NULL!\r\n");
                SDH_EXIT;
            }
            if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
            {
                PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_LOCK_GLOBAL: set persistent lock successful!\r\n");
            }
            ads_settings->ch_lockstate=LOCK_STATE_LOCKED;
            
            while((ads_settings->ch_lockstate&LOCK_STATE_STOP)==0)
            {
                SLEEP_SECONDS(1);
            }
            
            ds_cma.iec_ccma_def=ied_ccma_lock_rel_upd;
            bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_COM_CMA,
                                &ds_cma,
                                sizeof(ds_cma));
            if (bo_ret==true)
            {
                if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
                {
                    PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_LOCK_GLOBAL: release lock successful!\r\n");
                }
                ch_ret=0; // SUCCESS
            }
            else
            {
                ch_ret=3; // CMA LOCK RELEASE FAILED
            }
        }
        else
        {
            ch_ret=2; // CMA LOCK FAILED
        }
    }
    else
    {
        ch_ret=1; // CMA NOT FOUND
    }

    ads_settings->ch_lockstate=0;
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    m_setpar_byte(ads_cmd,0,(unsigned char) ch_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_cma_lock_region(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    struct dsd_clib1_sesscfg* ads_settings;
    struct dsd_hl_aux_c_cma_1 ds_cma;
    char ch_ret=-1;
    bool bo_ret;
    //char ch_enc;
    int im_acc;
    int im_offset;
    int im_len;

    ads_settings=(struct dsd_clib1_sesscfg*)adsp_hl_clib_1->ac_conf;    
    memset(&ds_cma,0,sizeof(ds_cma));
    
    if(ads_cmd->im_numparam!=4)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_lock_region(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[1]!=4)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_lock_region(): Invalid parameter size(1): %d\r\n",ads_cmd->imr_parlen[1]);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[2]!=4)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_lock_region(): Invalid parameter size(2): %d\r\n",ads_cmd->imr_parlen[2]);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[3]!=4)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_lock_region(): Invalid parameter size(3): %d\r\n",ads_cmd->imr_parlen[3]);
        SDH_EXIT;
    }

    im_offset=m_getpar_uint32(ads_cmd,1);
    im_len=m_getpar_uint32(ads_cmd,2);
    im_acc=m_getpar_uint32(ads_cmd,3);
    ds_cma.ac_cma_name=&ads_cmd->chrr_par[0][0];
    ds_cma.iec_chs_name=ied_chs_ansi_819;
    ds_cma.inc_len_cma_name=ads_cmd->imr_parlen[0];
    ds_cma.iec_ccma_def=ied_ccma_query;
        
    
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_LOCK_REGION offset=%d len=%d access=%d\r\n",im_offset,im_len,im_acc);
    }

    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_COM_CMA,
                                &ds_cma,
                                sizeof(ds_cma));
    
    if (bo_ret==true)
    {
        if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
        {
            PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_LOCK_REGION: cma query successful!\r\n");
        }

        //acquire lock 
        ds_cma.iec_ccma_def=ied_ccma_lock_region;
        ds_cma.inc_lock_disp=im_offset;
        ds_cma.inc_lock_len=im_len;
        ds_cma.imc_lock_type=im_acc;
        ds_cma.boc_ret_lock_fails=true;
        bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_COM_CMA,
                                &ds_cma,
                                sizeof(ds_cma));
    
        if (bo_ret==true)
        {
            if (ds_cma.achc_cma_area==NULL)
            {
                PRINT_DIRECT("SDH_WSP_TEST: CMA address is NULL!\r\n");
                SDH_EXIT;
            }
            if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
            {
                PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_LOCK_REGION: set persistent lock successful!\r\n");
            }
            ads_settings->ch_lockstate=LOCK_STATE_LOCKED;
            
            while((ads_settings->ch_lockstate&LOCK_STATE_STOP)==0)
            {
                SLEEP_SECONDS(1);
            }
            
            ds_cma.iec_ccma_def=ied_ccma_lock_rel_upd;
            bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_COM_CMA,
                                &ds_cma,
                                sizeof(ds_cma));
            if (bo_ret==true)
            {
                if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
                {
                    PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_LOCK_REGION: release lock successful!\r\n");
                }
                ch_ret=0; // SUCCESS
            }
            else
            {
                ch_ret=3; // CMA LOCK RELEASE FAILED
            }
        }
        else
        {
            ch_ret=2; // CMA LOCK FAILED
        }
    }
    else
    {
        ch_ret=1; // CMA NOT FOUND
    }

    ads_settings->ch_lockstate=0;
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    m_setpar_byte(ads_cmd,0,(unsigned char) ch_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_cma_get_lock_state(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    struct dsd_clib1_sesscfg* ads_settings;
    ads_settings=(struct dsd_clib1_sesscfg*)adsp_hl_clib_1->ac_conf;
    if (ads_cmd->im_numparam!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_get_lock_state(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_GET_LOCK_STATE: ret=%d\r\n",(ads_settings->ch_lockstate)&0xFF);
    }
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    m_setpar_byte(ads_cmd,0,(unsigned)ads_settings->ch_lockstate);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_cma_set_lock_state(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    struct dsd_clib1_sesscfg* ads_settings;
    ads_settings=(struct dsd_clib1_sesscfg*)adsp_hl_clib_1->ac_conf;    
    if (ads_cmd->im_numparam!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_cma_set_lock_state(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    ads_settings->ch_lockstate=m_getpar_byte(ads_cmd,0);

    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_CMA_SET_LOCK_STATE: state=%d\r\n",(ads_settings->ch_lockstate)&0xFF);
    }
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=0;
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_get_random(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    int im_len;
    bool bo_ret;
    char chr_rnd[256];

    if (ads_cmd->im_numparam!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_get_random(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }

    im_len=(unsigned char) m_getpar_byte(ads_cmd,0);

    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_RANDOM_BASE64,
                                (void *)chr_rnd,
                                im_len);

    if (bo_ret==false)
    {
        strcpy(chr_rnd,"");
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=2;
    m_setpar_bool(ads_cmd,0,bo_ret);
    memcpy(&ads_cmd->chrr_par[1][0],chr_rnd,im_len);
    ads_cmd->imr_parlen[1]=im_len;
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_tcp_conn(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
	struct dsd_unicode_string ads_ustr;
    char chr_ineta[MAX_CMD_PARAM_LEN+1];

    struct dsd_aux_tcp_conn_1 ds_tcp;
    //struct dsd_clib1_sesscfg *ads_session;
    bool bo_ret;
    
	if (ads_cmd->im_numparam!=3)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_tcp_conn(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }

    memset(chr_ineta,0,sizeof(chr_ineta));
    memset(&ds_tcp,0,sizeof(ds_tcp));

    if (ads_cmd->imr_parlen[0]>0)
    {
        memcpy(chr_ineta,&ads_cmd->chrr_par[0][0],ads_cmd->imr_parlen[0]);
		ds_tcp.dsc_target_ineta.ac_str=chr_ineta;
	}
	else
	{
		ds_tcp.dsc_target_ineta.ac_str=NULL;
    }

	ds_tcp.dsc_target_ineta.iec_chs_str=(ied_charset)m_getpar_byte(ads_cmd,1);
	ds_tcp.dsc_target_ineta.imc_len_str=ads_cmd->imr_parlen[0];	
	ds_tcp.imc_server_port=(int)m_getpar_uint16(ads_cmd,2);	
	ds_tcp.dsc_aux_tcp_def.ibc_ssl_client=0;


    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_TCP_CONN,
                                &ds_tcp,
                                sizeof(ds_tcp));
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_TCP_CONN: ret=%d state=%d\r\n",bo_ret&0x01,(ds_tcp.iec_tcpconn_ret&0xFF));
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=2;
    m_setpar_bool(ads_cmd,0,bo_ret);
    m_setpar_byte(ads_cmd,1,(unsigned char)ds_tcp.iec_tcpconn_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_tcp_conn_ssl(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
	struct dsd_unicode_string ads_ustr;
    char chr_ineta[MAX_CMD_PARAM_LEN+1];

    struct dsd_aux_tcp_conn_1 ds_tcp;
    //struct dsd_clib1_sesscfg *ads_session;
    bool bo_ret;
    
	if (ads_cmd->im_numparam!=3)
    {
		PRINT_DIRECT("SDH_WSP_TEST: m_proc_tcp_conn_ssl(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }

    memset(chr_ineta,0,sizeof(chr_ineta));
    memset(&ds_tcp,0,sizeof(ds_tcp));

    if (ads_cmd->imr_parlen[0]>0)
    {
        memcpy(chr_ineta,&ads_cmd->chrr_par[0][0],ads_cmd->imr_parlen[0]);
		ds_tcp.dsc_target_ineta.ac_str=chr_ineta;
	}
	else
	{
		ds_tcp.dsc_target_ineta.ac_str=NULL;
    }

	ds_tcp.dsc_target_ineta.iec_chs_str=(ied_charset)m_getpar_byte(ads_cmd,1);
	ds_tcp.dsc_target_ineta.imc_len_str=ads_cmd->imr_parlen[0];	
	ds_tcp.imc_server_port=(int)m_getpar_uint16(ads_cmd,2);	
    ds_tcp.dsc_aux_tcp_def.ibc_ssl_client=1;


    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_TCP_CONN,
                                &ds_tcp,
                                sizeof(ds_tcp));
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_TCP_CONN_SSL: ret=%d state=%d\r\n",bo_ret&0x01,(ds_tcp.iec_tcpconn_ret&0xFF));
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=2;
    m_setpar_bool(ads_cmd,0,bo_ret);
    m_setpar_byte(ads_cmd,1,(unsigned char)ds_tcp.iec_tcpconn_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}


void m_proc_tcp_close(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    bool bo_ret;

    if (ads_cmd->im_numparam!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_tcp_close(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_TCP_CLOSE,
                                NULL,
                                0);    
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_TCP_CLOSE: ret=%d\r\n",bo_ret&0x01);
    }
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    m_setpar_bool(ads_cmd,0,bo_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_diskfile_access(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    BOOL bo_ret;
    struct dsd_hl_aux_diskfile_1 ds_file;
    unsigned long long ull_addr_start,ull_addr_end,ull_addr_df1;
    unsigned int um_time;
    //char chr_fileinfo[28]; // 8 byte start addr, 8 byte end addr, 4 byte last_mod, 8 byte ads_int_df1;
    //int in_lastmodtime;
    

    if(ads_cmd->im_numparam!=2)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_diskfile_access(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }

    if (ads_cmd->imr_parlen[1]!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_diskfile_access(): Invalid parameter size(1): %d\r\n",ads_cmd->imr_parlen[1]);
        SDH_EXIT;
    }

    ds_file.ac_name=&ads_cmd->chrr_par[0][0];
    ds_file.iec_chs_name=(ied_charset)m_getpar_byte(ads_cmd,1);
    ds_file.inc_len_name=ads_cmd->imr_parlen[0];

    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_DISKFILE_ACCESS,
                                &ds_file,
                                sizeof(ds_file));

    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_DISKFILE_ACCESS: ret=%d\r\n",bo_ret&0x01);
    }

    ull_addr_start=0;
    ull_addr_end=0;
    ull_addr_df1=0;
    um_time=0;
    if (bo_ret!=false)
    {
        if (ds_file.iec_dfar_def==ied_dfar_ok)
        {
            ull_addr_start=(unsigned long long)ds_file.adsc_int_df1->achc_filecont_start;
            ull_addr_end=(unsigned long long)ds_file.adsc_int_df1->achc_filecont_end;
            ull_addr_df1=(unsigned long long)ds_file.adsc_int_df1;
        }
        um_time=ds_file.imc_time_last_mod;
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=4;
    m_setpar_bool(ads_cmd,0,bo_ret);
    m_setpar_byte(ads_cmd,1,ds_file.iec_dfar_def);
    m_setpar_uint64(ads_cmd,2,(unsigned long long)ds_file.ac_handle);
    m_setpar_fileinfo(ads_cmd,3,ull_addr_start,ull_addr_end,um_time,ull_addr_df1);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_diskfile_release(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    BOOL bo_ret;
    unsigned long long ull_handle;
    unsigned long ul_handle;
    void *avo_addr;

    if(ads_cmd->im_numparam!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_diskfile_release(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }

    if (ads_cmd->imr_parlen[0]!=8)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_diskfile_release(): Invalid parameter size(0): %d\r\n",ads_cmd->imr_parlen[0]);
        SDH_EXIT;
    }

    ull_handle=m_getpar_uint64(ads_cmd,0);
    ul_handle=(unsigned long) ull_handle;

    switch(sizeof(void *))
    {
        case(4):    avo_addr=&ul_handle;
                    break;
        case(8):    avo_addr=&ull_handle;
                    break;
        default:    PRINT_DIRECT("SDH_WSP_TEST: m_proc_diskfile_release(): Internal Error!\r\n");
                    SDH_EXIT;
    }

    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_DISKFILE_RELEASE,
                                avo_addr,
                                sizeof(void *));

    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_DISKFILE_ACCESS: handle=%p ret=%d\r\n",(void *)ull_handle,bo_ret&0x01);
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    m_setpar_bool(ads_cmd,0,bo_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_diskfile_time_lm(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    BOOL bo_ret_time;
    struct dsd_hl_aux_diskfile_1 ds_file;
    unsigned int um_time=0;

    memset(&ds_file,0,sizeof(ds_file));
    bo_ret_time=false;
    
    if(ads_cmd->im_numparam!=2)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_diskfile_time_lm(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }

    if (ads_cmd->imr_parlen[1]!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_diskfile_time_lm(): Invalid parameter size(1): %d\r\n",ads_cmd->imr_parlen[1]);
        SDH_EXIT;
    }

    ds_file.ac_name=&ads_cmd->chrr_par[0][0];
    ds_file.iec_chs_name=(ied_charset)m_getpar_byte(ads_cmd,1);
    ds_file.inc_len_name=ads_cmd->imr_parlen[0];

    
    bo_ret_time=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_DISKFILE_TIME_LM,
                                &ds_file,
                                sizeof(ds_file));
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_DISKFILE_TIME_LM: ret=%d\r\n",bo_ret_time&0x01);
    }

    um_time=(unsigned)ds_file.imc_time_last_mod;

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=3;
    m_setpar_bool(ads_cmd,0,bo_ret_time);
    m_setpar_byte(ads_cmd,1,ds_file.iec_dfar_def);
    m_setpar_uint32(ads_cmd,2,um_time);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_string_from_epoch(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    struct dsd_hl_aux_epoch_1 ds_epoch;
    char chr_time[1024];
    BOOL bo_ret;
    
    if (ads_cmd->im_numparam!=2)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_string_from_epoch(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[0]!=4)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_string_from_epoch(): Invalid parameter size(0): %d\r\n",ads_cmd->imr_parlen[0]);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[1]!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_string_from_epoch(): Invalid parameter size(1): %d\r\n",ads_cmd->imr_parlen[1]);
        SDH_EXIT;
    }
    memset(&ds_epoch,0,sizeof(ds_epoch));
    ds_epoch.ac_epoch_str=&chr_time[0];
    ds_epoch.imc_epoch_val=(int)m_getpar_uint32(ads_cmd,0);
    ds_epoch.iec_chs_epoch=(ied_charset)m_getpar_byte(ads_cmd,1);
    ds_epoch.inc_len_epoch=sizeof(chr_time);
    if (ds_epoch.iec_chs_epoch>3)ds_epoch.inc_len_epoch=ds_epoch.inc_len_epoch/2; //UTF-16
    if (ds_epoch.iec_chs_epoch>6)ds_epoch.inc_len_epoch=ds_epoch.inc_len_epoch/2; //UTF-32

    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_STRING_FROM_EPOCH,
                                &ds_epoch,
                                sizeof(ds_epoch));

    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_STRING_FROM_EPOCH: ret=%d epoch=%u\r\n",bo_ret&0x01,ds_epoch.imc_epoch_val);
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=2;
    m_setpar_bool(ads_cmd,0,bo_ret);
    if (bo_ret!=false)
    {
        ads_cmd->imr_parlen[1]=strlen(chr_time);
        memcpy(&ads_cmd->chrr_par[1][0],chr_time,strlen(chr_time));
    }
    else
    {
        ads_cmd->imr_parlen[1]=4;
        memset(&ads_cmd->chrr_par[1][0],0,4);
    }
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_epoch_from_string(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    struct dsd_hl_aux_epoch_1 ds_epoch;
    //char chr_time[1024];
    BOOL bo_ret;
    
    if (ads_cmd->im_numparam!=2)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_epoch_from_string(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[0]<=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_epoch_from_string(): Invalid parameter size(0): %d\r\n",ads_cmd->imr_parlen[0]);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[1]!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_epoch_from_string(): Invalid parameter size(1): %d\r\n",ads_cmd->imr_parlen[1]);
        SDH_EXIT;
    }
    memset(&ds_epoch,0,sizeof(ds_epoch));
    ds_epoch.imc_epoch_val=0;
    ds_epoch.ac_epoch_str=&ads_cmd->chrr_par[0][0];
    ds_epoch.iec_chs_epoch=(ied_charset)m_getpar_byte(ads_cmd,1);
    ds_epoch.inc_len_epoch=ads_cmd->imr_parlen[0];
    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_EPOCH_FROM_STRING,
                                &ds_epoch,
                                sizeof(ds_epoch));
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_EPOCH_FROM_STRING: ret=%d epoch=%u\r\n",bo_ret&0x01,ds_epoch.imc_epoch_val);
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=2;
    m_setpar_bool(ads_cmd,0,bo_ret);
    m_setpar_uint32(ads_cmd,1,(unsigned)ds_epoch.imc_epoch_val);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_query_main_str(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    void *avo_name;
    int im_len=0;
    BOOL bo_ret;

    if (ads_cmd->im_numparam!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_query_main_str(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }

    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_QUERY_MAIN_STR,
                                &avo_name,
                                sizeof(void*));
    
    if ((us_tracelvl&TRACE_CMD_SIMPLE)!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD_QUERY_MAIN_STR: ret=%d string=%s\r\n",bo_ret&0x01,(char *)avo_name);
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=2;
    if (bo_ret!=false)
    {
        im_len=strlen((char *)avo_name);
        memcpy(&ads_cmd->chrr_par[0][0],avo_name,im_len);
    }
    ads_cmd->imr_parlen[0]=im_len;
    m_setpar_bool(ads_cmd,1,bo_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}


void m_proc_query_client(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    struct dsd_aux_query_client ds_query;
    bool bo_ret;

    memset(&ds_query,0,sizeof(ds_query));

    bo_ret=adsp_hl_clib_1->amc_aux(adsp_hl_clib_1->vpc_userfld,
                                DEF_AUX_QUERY_CLIENT,
                                &ds_query,
                                sizeof(ds_query));
    if (ads_cmd->im_numparam!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_query_main_str(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=4;
    m_setpar_uint32(ads_cmd,0,ds_query.inc_addr_family);
    ads_cmd->imr_parlen[1]=32;
    memcpy(&ads_cmd->chrr_par[1][0],&ds_query.chrc_multih_ineta[0],sizeof(ds_query.chrc_multih_ineta));
    memcpy(&ads_cmd->chrr_par[1][16],&ds_query.chrc_client_ineta[0],sizeof(ds_query.chrc_client_ineta));
    m_setpar_uint32(ads_cmd,2,ds_query.inc_port);
    m_setpar_bool(ads_cmd,3,bo_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_crt_fileopen(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    FILE *ads_fd;
    unsigned long long ull_handle;
    
    if (ads_cmd->im_numparam!=2)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_crt_fileopen(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }

    ads_fd=fopen(&ads_cmd->chrr_par[0][0],&ads_cmd->chrr_par[1][0]);

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    ull_handle=(unsigned long long)ads_fd;
    m_setpar_uint64(ads_cmd,0,ull_handle);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_crt_fileclose(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    FILE *ads_fd;
    unsigned long long ull_handle;
    int in_ret;

    if (ads_cmd->im_numparam!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_crt_fileclose(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    ull_handle=m_getpar_uint64(ads_cmd,0);
    ads_fd=(FILE *)ull_handle;
    in_ret=fclose(ads_fd);
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    m_setpar_uint32(ads_cmd,0,(unsigned int)in_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_crt_fileread(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    FILE *ads_fd;
    unsigned long long ull_handle;
    size_t ds_size;
    size_t ds_ret;

    if (ads_cmd->im_numparam!=2)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_crt_fileread(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    
    if (ads_cmd->imr_parlen[0]!=8)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_crt_fileread(): Invalid handle size: %d\r\n",ads_cmd->imr_parlen[0]);
        SDH_EXIT;
    }

    ull_handle=m_getpar_uint64(ads_cmd,0);
    ads_fd=(FILE *)ull_handle;
    

    if (ads_cmd->imr_parlen[1]!=2)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_crt_fileread(): Invalid read count size: %d\r\n",ads_cmd->imr_parlen[1]);
        SDH_EXIT;
    }

    ds_size=(size_t)m_getpar_uint16(ads_cmd,1);
    
    if ((ds_size<1)||(ds_size>MAX_CMD_PARAM_LEN))
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_crt_fileread(): Invalid number of bytes to read: %d\r\n",ds_size);
        SDH_EXIT;
    }

    ds_ret=fread(&ads_cmd->chrr_par[1][0],1,ds_size,ads_fd);

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=2;
    m_setpar_uint32(ads_cmd,0,(unsigned int)ds_ret);
    ads_cmd->imr_parlen[1]=(int)ds_size;
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_crt_filewrite(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    FILE *ads_fd;
    unsigned long long ull_handle;
    size_t ds_size;
    size_t ds_ret;

    if (ads_cmd->im_numparam!=2)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_crt_filewrite(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    
    if (ads_cmd->imr_parlen[0]!=8)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_crt_filewrite(): Invalid handle size: %d\r\n",ads_cmd->imr_parlen[0]);
        SDH_EXIT;
    }

    ull_handle=m_getpar_uint64(ads_cmd,0);
    ads_fd=(FILE *)ull_handle;
    
    ds_size=(size_t)ads_cmd->imr_parlen[1];
    if (ds_size>MAX_CMD_PARAM_LEN)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_crt_filewrite(): Invalid data size: %d\r\n",ads_cmd->imr_parlen[0]);
        SDH_EXIT;
    }
    ds_ret=fwrite(&ads_cmd->chrr_par[1][0],1,ds_size,ads_fd);

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    m_setpar_uint32(ads_cmd,0,(unsigned int)ds_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_crt_filedelete(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    int in_ret;

    if (ads_cmd->im_numparam!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_crt_filedelete(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    
    in_ret=remove(&ads_cmd->chrr_par[0][0]);

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    m_setpar_uint32(ads_cmd,0,(unsigned int)in_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}


void m_proc_disconnect(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    if (ads_cmd->im_numparam!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_disconnect(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    if (ads_cmd->imr_parlen[0]!=4)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_disconnect(): Invalid parameter size(0): %d\r\n",ads_cmd->imr_parlen[0]);
        SDH_EXIT;
    }

    adsp_hl_clib_1->inc_return=(int)m_getpar_uint32(ads_cmd,0);
    PRINT_DIRECT("SDH_WSP_TEST: m_proc_disconnect(): inc_return= %d\r\n",adsp_hl_clib_1->inc_return);
        
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=0;
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}



void m_proc_tcp_get_status(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    bool bo_ret;
    struct dsd_clib1_sesspar* ads_session;
    ads_session=(struct dsd_clib1_sesspar*)adsp_hl_clib_1->ac_ext;
    
    if (ads_cmd->im_numparam!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_tcp_get_status(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    bo_ret=(ads_session->bo_connected);

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    m_setpar_bool(ads_cmd,0,bo_ret);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}


    
void m_proc_get_conf_tcp_valid(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    struct dsd_clib1_sesscfg *ads_session;
    ads_session=(struct dsd_clib1_sesscfg *)adsp_hl_clib_1->ac_conf;
    
    if (ads_cmd->im_numparam!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_get_conf_tcp_valid(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=4;
    memcpy(&ads_cmd->chrr_par[0][0],ads_session->chr_serverineta,strlen(ads_session->chr_serverineta));
    ads_cmd->imr_parlen[0]=strlen(ads_session->chr_serverineta);
    m_setpar_uint16(ads_cmd,1,(unsigned short)ads_session->im_serverport);
    memcpy(&ads_cmd->chrr_par[2][0],ads_session->chr_outineta,strlen(ads_session->chr_outineta));
    ads_cmd->imr_parlen[2]=strlen(ads_session->chr_outineta);
    memcpy(&ads_cmd->chrr_par[3][0],ads_session->chr_service,strlen(ads_session->chr_service));
    ads_cmd->imr_parlen[3]=strlen(ads_session->chr_service);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_get_conf_tcp_invalid(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
        struct dsd_clib1_sesscfg *ads_session;
    ads_session=(struct dsd_clib1_sesscfg *)adsp_hl_clib_1->ac_conf;
    
    if (ads_cmd->im_numparam!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_get_conf_tcp_invalid(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=4;
    memcpy(&ads_cmd->chrr_par[0][0],ads_session->chr_wrongserver,strlen(ads_session->chr_wrongserver));
    ads_cmd->imr_parlen[0]=strlen(ads_session->chr_wrongserver);
    m_setpar_uint16(ads_cmd,1,(unsigned short)ads_session->im_serverport);
    memcpy(&ads_cmd->chrr_par[2][0],ads_session->chr_outineta,strlen(ads_session->chr_outineta));
    ads_cmd->imr_parlen[2]=strlen(ads_session->chr_outineta);
    memcpy(&ads_cmd->chrr_par[3][0],ads_session->chr_service,strlen(ads_session->chr_service));
    ads_cmd->imr_parlen[3]=strlen(ads_session->chr_service);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_get_conf_file_valid(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    struct dsd_clib1_sesscfg *ads_session;
    ads_session=(struct dsd_clib1_sesscfg *)adsp_hl_clib_1->ac_conf;
    
    if (ads_cmd->im_numparam!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_get_conf_file_valid(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    memcpy(&ads_cmd->chrr_par[0][0],ads_session->chr_filename,strlen(ads_session->chr_filename));
    ads_cmd->imr_parlen[0]=strlen(ads_session->chr_filename);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
    
}

void m_proc_get_conf_file_invalid(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    struct dsd_clib1_sesscfg *ads_session;
    ads_session=(struct dsd_clib1_sesscfg *)adsp_hl_clib_1->ac_conf;
    
    if (ads_cmd->im_numparam!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_get_conf_file_invalid(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=1;
    memcpy(&ads_cmd->chrr_par[0][0],ads_session->chr_wrongfile,strlen(ads_session->chr_wrongfile));
    ads_cmd->imr_parlen[0]=strlen(ads_session->chr_wrongfile);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_nop(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=0;
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}

void m_proc_get_sdh_info(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd)
{
    bool bo_be;
    char ch_test;
    unsigned short us_test;
    //Detect Enderness
    
    us_test=0x0001;
    ch_test=*((char*)&us_test);
    
    switch (ch_test)
    {
        case(0):    //Big Endian
                    bo_be=true;
                    break;
        case(1):    //Little Endian
                    bo_be=false;
                    break;
        default:    //Error
                    PRINT_DIRECT("SDH_WSP_TEST: m_proc_get_sdh_info(): Internal Error during detection of enderness!");
                    SDH_EXIT;
    }

    if (ads_cmd->im_numparam!=0)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_proc_get_sdh_info(): Invalid number of parameters: %d\r\n",ads_cmd->im_numparam);
        SDH_EXIT;
    }

    ads_cmd->us_cmd|=0x8000;
    ads_cmd->im_numparam=2;
    memcpy(&ads_cmd->chrr_par[0][0],chrs_hello_msg,strlen(chrs_hello_msg));
    ads_cmd->imr_parlen[0]=strlen(chrs_hello_msg);
    m_setpar_bool(ads_cmd,1,bo_be);
    m_sendcmd(adsp_hl_clib_1,ads_cmd,DIR_TOCLIENT);
}


void m_sendcmd(struct dsd_hl_clib_1 *adsp_hl_clib_1,struct dsd_cmd *ads_cmd,int im_dir)
{
    int im_work;
    char chr_tmp[3];
    int im_work2;
    if ((us_tracelvl&TRACE_CMD_EXT)!=0)
    
    {
        PRINT_DIRECT("SDH_WSP_TEST: CMD-Reply:\r\n");
        PRINT_DIRECT("SDH_WSP_TEST: cmd=%04X\r\n",ads_cmd->us_cmd);
    }
    chr_tmp[0]=(char)(ads_cmd->us_cmd>>8)&0xFF;
    chr_tmp[1]=(char)(ads_cmd->us_cmd&0xFF);
    chr_tmp[2]=(char)(ads_cmd->im_numparam&0xFF);
    m_out(adsp_hl_clib_1,chr_tmp,3,im_dir);
    for (im_work=0;im_work<ads_cmd->im_numparam;im_work++)
    {
        chr_tmp[0]=(char)((ads_cmd->imr_parlen[im_work]>>8)&0xFF);
        chr_tmp[1]=(char)(ads_cmd->imr_parlen[im_work]&0xFF);
        m_out(adsp_hl_clib_1,chr_tmp,2,im_dir);
        m_out(adsp_hl_clib_1,&ads_cmd->chrr_par[im_work][0],ads_cmd->imr_parlen[im_work],im_dir);
        if ((us_tracelvl&TRACE_CMD_EXT)!=0)
    
        {
            PRINT_DIRECT("SDH_WSP_TEST: param=");
            for (im_work2=0;im_work2<ads_cmd->imr_parlen[im_work];im_work2++)
            {
                PRINT_DIRECT("%02X ",(ads_cmd->chrr_par[im_work][im_work2]&0xFF));
            }
            PRINT_DIRECT("\r\n");
        }
    }
}    


void m_setpar_bool(struct dsd_cmd *ads_cmd,int im_index,bool bo_val)
{
    ads_cmd->imr_parlen[im_index]=1;
    if (bo_val==true)
    {
        ads_cmd->chrr_par[im_index][0]=1;
    }
    else ads_cmd->chrr_par[im_index][0]=0;
}

void m_setpar_byte(struct dsd_cmd *ads_cmd,int im_index,unsigned char uch_val)
{
    ads_cmd->imr_parlen[im_index]=1;
    ads_cmd->chrr_par[im_index][0]=(char)uch_val;
}

void m_setpar_uint16(struct dsd_cmd *ads_cmd,int im_index,unsigned short us_val)
{
    int im_work;
    ads_cmd->imr_parlen[im_index]=2;
    for (im_work=ads_cmd->imr_parlen[im_index]-1;im_work>=0;im_work--)
    {
        ads_cmd->chrr_par[im_index][im_work]=(char)(us_val&0xFF);
        us_val=us_val>>8;
    }
}

void m_setpar_uint32(struct dsd_cmd *ads_cmd,int im_index,unsigned int um_val)
{
    int im_work;
    ads_cmd->imr_parlen[im_index]=4;
    for (im_work=ads_cmd->imr_parlen[im_index]-1;im_work>=0;im_work--)
    {
        ads_cmd->chrr_par[im_index][im_work]=(char)(um_val&0xFF);
        um_val=um_val>>8;
    }
}

void m_setpar_uint64(struct dsd_cmd *ads_cmd,int im_index,unsigned long long ull_val)
{
    int im_work;
    ads_cmd->imr_parlen[im_index]=8;
    for (im_work=ads_cmd->imr_parlen[im_index]-1;im_work>=0;im_work--)
    {
        ads_cmd->chrr_par[im_index][im_work]=(char)(ull_val&0xFF);
        ull_val=ull_val>>8;
    }
}

void m_setpar_fileinfo(struct dsd_cmd *ads_cmd,int im_index,unsigned long long ull_val1,unsigned long long ull_val2,unsigned int um_val3,unsigned long long ull_val4)
{
    int im_work;
    ads_cmd->imr_parlen[im_index]=28;

    // 1st parameter 8 byte BE
    for (im_work=7;im_work>=0;im_work--)
    {
        ads_cmd->chrr_par[im_index][im_work]=(char)(ull_val1&0xFF);
        ull_val1=ull_val1>>8;
    }

    // 2nd parameter 8 byte BE
    for (im_work=7;im_work>=0;im_work--)
    {
        ads_cmd->chrr_par[im_index][im_work+8]=(char)(ull_val2&0xFF);
        ull_val2=ull_val2>>8;
    }

    // 3rd parameter 4 byte BE
    for (im_work=3;im_work>=0;im_work--)
    {
        ads_cmd->chrr_par[im_index][im_work+16]=(char)(um_val3&0xFF);
        um_val3=um_val3>>8;
    }

    // 4th parameter 8 byte
    for (im_work=7;im_work>=0;im_work--)
    {
        ads_cmd->chrr_par[im_index][im_work+20]=(char)(ull_val4&0xFF);
        ull_val4=ull_val4>>8;
    }
}


bool m_getpar_bool(struct dsd_cmd *ads_cmd,int im_index)
{
    if (ads_cmd->imr_parlen[im_index]!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_getpar_bool(): invalid parameter length: %d\r\n",ads_cmd->imr_parlen[im_index]);
        SDH_EXIT;
    }
    switch(ads_cmd->chrr_par[im_index][0])
    {
        case (0):
            return false;
        case (1):
            return true;
        default:
            PRINT_DIRECT("SDH_WSP_TEST: m_getpar_bool(): not a boolean: %d\r\n",ads_cmd->chrr_par[im_index][0]&0xFF);
            SDH_EXIT;
    }
}

unsigned char m_getpar_byte(struct dsd_cmd *ads_cmd,int im_index)
{
    if (ads_cmd->imr_parlen[im_index]!=1)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_getpar_byte(): invalid parameter length: %d\r\n",ads_cmd->imr_parlen[im_index]);
        SDH_EXIT;
    }
    return (unsigned char) (ads_cmd->chrr_par[im_index][0]);
}

unsigned short m_getpar_uint16(struct dsd_cmd *ads_cmd,int im_index)
{
    unsigned short us_val=0;
    int im_work;
    if (ads_cmd->imr_parlen[im_index]!=2)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_getpar_unit16(): invalid parameter length: %d\r\n",ads_cmd->imr_parlen[im_index]);
        SDH_EXIT;
    }
    for (im_work=0;im_work<ads_cmd->imr_parlen[im_index];im_work++)
    {
        us_val=us_val<<8;
        us_val+=(unsigned char)(ads_cmd->chrr_par[im_index][im_work]);
    }
    return us_val;
}

unsigned int m_getpar_uint32(struct dsd_cmd *ads_cmd,int im_index)
{
    unsigned int um_val=0;
    int im_work;
    if (ads_cmd->imr_parlen[im_index]!=4)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_getpar_unit32(): invalid parameter length: %d\r\n",ads_cmd->imr_parlen[im_index]);
        SDH_EXIT;
    }
    for (im_work=0;im_work<ads_cmd->imr_parlen[im_index];im_work++)
    {
        um_val=um_val<<8;
        um_val+=(unsigned char)(ads_cmd->chrr_par[im_index][im_work]);
    }
    return um_val;
}

unsigned long long m_getpar_uint64(struct dsd_cmd *ads_cmd,int im_index)
{
    unsigned long long ull_val=0;
    int im_work;
    if (ads_cmd->imr_parlen[im_index]!=8)
    {
        PRINT_DIRECT("SDH_WSP_TEST: m_getpar_unit64(): invalid parameter length: %d\r\n",ads_cmd->imr_parlen[im_index]);
        SDH_EXIT;
    }
    for (im_work=0;im_work<ads_cmd->imr_parlen[im_index];im_work++)
    {
        ull_val=ull_val<<8;
        ull_val+=(unsigned char)(ads_cmd->chrr_par[im_index][im_work]);
    }
    return ull_val;
}
