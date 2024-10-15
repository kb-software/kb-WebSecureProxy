#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <windows.h>
#include <shlwapi.h>
#include<Tlhelp32.h>
#include <eh.h>
#include <fstream>
#include<LMErr.h>

#define ALUDEBUG
#define FASTINFO
#define PRVTMISALGN
//define ERRMSGBOX

#define DEF_PAGE_SIZE 4096
const short int DEF_ONE = 1;
const short int DEF_F_EYECATCHER = 0;   // eyecatcher
const short int DEF_PROCESS      = 1;   // process
const short int DEF_THREAD       = 2;   // thread
const short int DEF_LSS_DLL      = 3;   // load DLL from single step exception
const short int DEF_SS_EXC       = 4;   // single step exception
const short int DEF_CRASH_EXC    = 5;   // crash exception
const short int DEF_THL_DLL      = 6;   // loaded Dll from Toolhelp API
const short int DEF_MSG          = 7;   // message
const short int DEF_F_MEM     = 2048;   // memory 32 bits
//define DEF_EVTLOG       8   // eventlog
#define MSG_DUMP_EXIST   0x40000001L

static const byte* abyMemLimit = (const byte*)0x7FFFFFFF;

#define CHAR_CR        0X0D                 /* carriage-return         */
#define CHAR_LF        0X0A                 /* line-feed               */

#define GHFW(str) ((ULONG) ((str & 0X000000FF) << 24) \
        | ((str & 0X0000FF00) << 8) | ((str & 0X00FF0000) >> 8) \
        | ((str & 0XFF000000) >> 24))

#define GHHW(str) ((USHORT) ((str & 0X00FF) << 8) \
        | ((str & 0XFF00) >> 8))



#include "iswcord1.h"
//include "iswcord2.h"


void DisplayErrorText(DWORD ulErrorCode, char* achrPreText);

static BOOL bo_message = FALSE;
static char* achr_message;

//struct dsd_wcord1 dsg_wcord1;

void m_hl_setdump()
{
    SetUnhandledExceptionFilter(m_hl_toplevelexceptionfilter);
}

void m_hl_abend1( char *achp_msg ) 
{
	printf("Program abended with messsage:%s.\nCreating core dump...\n",achp_msg);
#ifdef ALUDEBUG
    printf( "m_hl_abend1 %s\n", achp_msg );
#endif
    //write message to eventlog
    HANDLE h_evtlog;
    char achr_time[9];
    int in_msglen;
    
    h_evtlog = RegisterEventSource(NULL,               // uses local computer
                                  TEXT("HOBDump"));    // source name
    if(!h_evtlog == NULL)
    {
        LPCSTR achr_log[1];
        achr_log[0] = (LPCSTR)achp_msg;
        _strtime(achr_time);
#ifdef ALUDEBUG
        printf("try to write msg %s to event log\n",achp_msg);
#endif
        if(!ReportEventA(h_evtlog,           // event log handle
                    EVENTLOG_INFORMATION_TYPE,  // event type
                    0,                    // category zero
                    MSG_DUMP_EXIST,       // event identifier
                    NULL,                 // no user security identifier
                    1,                    // one substitution string
                    8,                    // no data
                    achr_log,             // pointer to string array
                    achr_time))                // pointer to data
        {
            printf("ReportEvent failed with error:%i\n",GetLastError());
        }
        DeregisterEventSource(h_evtlog);
    }
    //set flag that there is a message and copy msg
    bo_message = TRUE;
    in_msglen = (int)strlen(achp_msg);
    achr_message = new char[in_msglen+1];
    achr_message[in_msglen] = 0;
    memcpy(achr_message,achp_msg,in_msglen);

    /*CSE::MapSEtoCE(); 
    try
    {
        RaiseException(0xE00000FF, EXCEPTION_NONCONTINUABLE , 0 ,NULL);
    }*/
    //catch(CSE /*se*/)
    /*{
		printf("catch");
	}*/

    __try
    {
		  RaiseException(0xffffffff, 0, 0, NULL);
    }
    __except(m_hl_toplevelexceptionfilter(GetExceptionInformation()))
    {}

}

CRITICAL_SECTION ds_csntlef;
bool bo_critinit = false;

LONG __stdcall m_hl_toplevelexceptionfilter(PEXCEPTION_POINTERS adsExcepPointers)
{
	bool bo_writememdump = true;    //indicates if to write virtuell memory in file
    bool bo_email = true;           //indicates if to start email program
    bool bo_def_filename = true;    //indicates if to use the default file name
	bool bo_sender = false;         //indicates if a sender name is specified
	bool bo_password = false;       //indicates if a password is specified
#ifdef EVENTLOG
	bool bo_eventlog = false;
	std::string str_evtfile;
#endif
    ULONG_PTR ulp_recordlen;			//length of one record for dumpfile
	int in_headerlen = 0;           //length of header of one record
    DWORD um_proc_id;               //current process id
    DWORD um_thread_id;             //current thread id
    DWORD um_temp = 0;              //working variable
    DWORD um_temp2 = 0;             //working variable
    DWORD um_retcode;               //return code of function call
    char* achr_eye;                 //eyecatcher for dumpfile
    char abyr_out[4096];            //buffer to write dumpfile
    BOOL bo_succes = FALSE;           //success function call
    HANDLE h_process = NULL;          //process handle
    HANDLE h_evtlog = NULL;           //eventlog handle
    HANDLE h_snapshot = NULL;         //handle of a system snapshot with toolhelp api 
    EXCEPTION_RECORD* ads_exceprec = NULL;
    CONTEXT* ads_excepcontext = NULL;
    HKEY h_key = NULL;                //handle of registry key
    DWORD um_dumpno = 0;              //number of dumps per day
    char achr_dumpno[5];              //number of dumps per day
    DWORD um_datebuflen = 10;         //dummy
    char achr_filename[24];           //name of dumpfile
    char achr_filepath[MAX_PATH+2];     //directory of dumpfile
#ifdef EVENTLOG
	char achr_filedir[MAX_PATH+2];      //save of dir of dumpfile 
#endif
	char achr_mailgateway[100];       //mailgateway
    char achr_emailrcpt[100];         //email recipient
    char achr_emailsender[100];       //email sender
    char achr_password[100];          //password to encode email
    FILE* af_dumpfile;
    std::string str_evtlogmsg;        //msg write to eventlog
    std::string str_regdir;           //registry path
    char achr_date[10];          //current date
    char achr_date_ft[7];        //current date in the format we want
    char achr_saveddate[10];     //date saved in registry

	 if(!bo_critinit) 
	 {
		 bo_critinit = true;
		 InitializeCriticalSection(&ds_csntlef);
	 }
    EnterCriticalSection(&ds_csntlef);

   achr_mailgateway[0] = '\0';
   achr_emailrcpt[0] = '\0';
   achr_emailsender[0] = '\0';
   achr_password[0] = '\0';
   achr_date[0] = '\0';
   achr_date_ft[0] = '\0';
   achr_saveddate[0] = '\0';

#ifdef FASTINFO
	char chr_shorterror[100] = "\"";
	char chr_fileposm32[65];
#endif
	//print exception with cause of exception if it is a 'real' crash
	if(!bo_message)
	{
        DWORD um_excepcode;
		DWORD um_curendpos = 0;
		char achr_reason[400] = "The exception ";

		um_excepcode = adsExcepPointers->ExceptionRecord->ExceptionCode;

		switch(um_excepcode)
		{
			case EXCEPTION_ACCESS_VIOLATION:
				memcpy(achr_reason + 14,"EXCEPTION_ACCESS_VIOLATION.\n",28);
				um_curendpos = 14 + 28;
				break;
			case EXCEPTION_DATATYPE_MISALIGNMENT:
				memcpy(achr_reason + 14,"EXCEPTION_DATATYPE_MISALIGNMENT.\n",33);
				um_curendpos = 14 + 33;
				break;
			case EXCEPTION_BREAKPOINT:
				memcpy(achr_reason + 14,"EXCEPTION_BREAKPOINT.\n",22);
				um_curendpos = 14 + 22;
				break;
			case EXCEPTION_SINGLE_STEP:
				memcpy(achr_reason + 14,"EXCEPTION_SINGLE_STEP.\n",23);
				um_curendpos = 14 + 23;
				break;
			case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
				memcpy(achr_reason + 14,"EXCEPTION_ARRAY_BOUNDS_EXCEEDED.\n",33);
				um_curendpos = 14 + 33;
				break;
			case EXCEPTION_FLT_DENORMAL_OPERAND:
				memcpy(achr_reason + 14,"EXCEPTION_FLT_DENORMAL_OPERAND.\n",31);
				um_curendpos = 14 + 31;
				break;
			case EXCEPTION_FLT_DIVIDE_BY_ZERO:
				memcpy(achr_reason + 14,"EXCEPTION_FLT_DIVIDE_BY_ZERO.\n",30);
				um_curendpos = 14 + 30;
				break;
			case EXCEPTION_FLT_INEXACT_RESULT:
				memcpy(achr_reason + 14,"EXCEPTION_FLT_INEXACT_RESULT.\n",30);
				um_curendpos = 14 + 30;
				break;
			case EXCEPTION_FLT_INVALID_OPERATION:
				memcpy(achr_reason + 14,"EXCEPTION_FLT_INVALID_OPERATION.\n",33);
				um_curendpos = 14 + 33;
				break;
			case EXCEPTION_FLT_OVERFLOW:
				memcpy(achr_reason + 14,"EXCEPTION_FLT_OVERFLOW.\n",24);
				um_curendpos = 14 + 24;
				break;
			case EXCEPTION_FLT_STACK_CHECK:
				memcpy(achr_reason + 14,"EXCEPTION_FLT_STACK_CHECK.\n",27);
				um_curendpos = 14 + 27;
				break;
			case EXCEPTION_FLT_UNDERFLOW:
				memcpy(achr_reason + 14,"EXCEPTION_FLT_UNDERFLOW.\n",25);
				um_curendpos = 14 + 25;
				break;
			case EXCEPTION_INT_DIVIDE_BY_ZERO:
				memcpy(achr_reason + 14,"EXCEPTION_INT_DIVIDE_BY_ZERO.\n",30);
				um_curendpos = 14 + 30;
				break;
			case EXCEPTION_INT_OVERFLOW:
				memcpy(achr_reason + 14,"EXCEPTION_INT_OVERFLOW.\n",24);
				um_curendpos = 14 + 24;
				break;
			case EXCEPTION_PRIV_INSTRUCTION:
				memcpy(achr_reason + 14,"EXCEPTION_PRIV_INSTRUCTION.\n",28);
				um_curendpos = 14 + 28;
				break;
			case EXCEPTION_IN_PAGE_ERROR:
				memcpy(achr_reason + 14,"EXCEPTION_IN_PAGE_ERROR.\n",25);
				um_curendpos = 14 + 25;
				break;
			case EXCEPTION_ILLEGAL_INSTRUCTION:
				memcpy(achr_reason + 14,"EXCEPTION_ILLEGAL_INSTRUCTION.\n",31);
				um_curendpos = 14 + 31;
				break;
			case EXCEPTION_NONCONTINUABLE_EXCEPTION:
				memcpy(achr_reason + 14,"EXCEPTION_NONCONTINUABLE_EXCEPTION.\n",36);
				um_curendpos = 14 + 36;
				break;
			case EXCEPTION_STACK_OVERFLOW:
				memcpy(achr_reason + 14,"EXCEPTION_STACK_OVERFLOW.\n",26);
				um_curendpos = 14 + 26;
				break;
			case EXCEPTION_INVALID_DISPOSITION:
				memcpy(achr_reason + 14,"EXCEPTION_INVALID_DISPOSITION.\n",31);
				um_curendpos = 14 + 31;
				break;
			case EXCEPTION_GUARD_PAGE:
				memcpy(achr_reason + 14,"EXCEPTION_GUARD_PAGE.\n",22);
				um_curendpos = 14 + 22;
				break;
			case EXCEPTION_INVALID_HANDLE:
				memcpy(achr_reason + 14,"EXCEPTION_INVALID_HANDLE.\n",26);
				um_curendpos = 14 + 26;
				break;
			case CONTROL_C_EXIT:
				memcpy(achr_reason + 14,"CONTROL_C_EXIT.\n",16);
				um_curendpos = 14 + 16;
				break;
			default:
				//sprintf(cpEvtCd +22,"%08x",adsExcepRec->ExceptionCode);
				um_curendpos = 14;
		} //switch

#ifdef FASTINFO
		memcpy(chr_shorterror+1,achr_reason + 14,um_curendpos - 14);
		sprintf(chr_shorterror + (um_curendpos - 15)," at 0x%p\"",adsExcepPointers->ExceptionRecord->ExceptionAddress);
		//chr_shorterror[64] = '\"';
#endif
		memcpy(achr_reason+ um_curendpos,"(",1);
		um_curendpos++;
		sprintf(achr_reason + um_curendpos,"0x%08x",um_excepcode);
		um_curendpos += (2 + 8);
		memcpy(achr_reason + um_curendpos,")",1);
		um_curendpos++;
		memcpy(achr_reason + um_curendpos,"occured in the application at location 0x",41);
		um_curendpos += 41;
		//sprintf(achr_reason + um_curendpos,"%08x.\n",adsExcepPointers->ExceptionRecord->ExceptionAddress);
		sprintf(achr_reason + um_curendpos,"%p.\n",adsExcepPointers->ExceptionRecord->ExceptionAddress);

		printf(achr_reason);

	}
#ifdef FASTINFO
	else
	{
		memcpy(chr_shorterror+1,achr_message,strlen(achr_message));
		chr_shorterror[strlen(achr_message)+1] = '\"';
	}
#endif
	printf("Writing core dump...\n");
	//init with ", because its a commandline arg in CreateProcess (space in path)
	achr_filepath[0] = '\"';
	//get current date
    _strdate(achr_date);
    //check if registry to use
    if(dsg_wcord1.achc_wregpardir != NULL)
    {
#ifdef ALUDEBUG
		printf("Trying to get values from registrykey:%s\n",dsg_wcord1.achc_wregpardir);
#endif
		str_regdir = (std::string)dsg_wcord1.achc_wregpardir;
        int index = (int)str_regdir.find('\\',0);
        //open reg key
        um_retcode = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                                  str_regdir.substr(index+1,str_regdir.length()).c_str(),
                                  0,
                                  KEY_READ,
                                  &h_key);
        if(um_retcode != ERROR_SUCCESS)
        {
            DisplayErrorText(um_retcode,"iswcord1 m_hl_toplevel... RegOpenKeyEx failed!");
            LeaveCriticalSection(&ds_csntlef);
            return EXCEPTION_EXECUTE_HANDLER;
        }
        //get the dumpfilepath from registry
        um_temp = MAX_PATH;
		//achr_filepath+1 because the first char has to be a quote
        um_retcode = RegQueryValueExA(h_key,"diskdirfd",0,NULL,(byte*)achr_filepath+1,&um_temp);
        if(um_retcode != ERROR_SUCCESS)
        {
            DisplayErrorText(um_retcode,"iswcord1 m_hl_toplevel... RegQueryValueEx2 failed!");
            LeaveCriticalSection(&ds_csntlef);
            return EXCEPTION_EXECUTE_HANDLER;
        }
#ifdef ALUDEBUG
		printf("	- dump directory: %s\n",achr_filepath+1);
#endif
#ifdef EVENTLOG
		//save directory
		memcpy(achr_filedir,achr_filepath+1,um_temp);
		achr_filepath[um_temp] = 0;
#endif
        //get mailgateway
        um_temp = 100;
        um_retcode = RegQueryValueExA(h_key,"ineta_mgw",0,NULL,(byte*)achr_mailgateway,&um_temp);
        if(um_retcode != ERROR_SUCCESS)
        {
            DisplayErrorText(um_retcode,"iswcord1 m_hl_toplevel... RegQueryValueEx3 failed.");
            //LeaveCriticalSection(&ds_csntlef);
            //return EXCEPTION_EXECUTE_HANDLER;
        }
        if(um_temp <= 1) //key value is empty, send no email
        {
            bo_email = false;
        }
        else
        {
            //get email recipient
            um_temp = 100;
            um_retcode = RegQueryValueExA(h_key,"email_rcpt",0,NULL,(byte*)achr_emailrcpt,&um_temp);
            if(um_retcode != ERROR_SUCCESS)
            {
                DisplayErrorText(um_retcode,"iswcord1 m_hl_toplevel... RegQueryValueEx4 failed.");
                //LeaveCriticalSection(&ds_csntlef);
                //return EXCEPTION_EXECUTE_HANDLER;
            }
            if(um_temp == 1) //key value is empty, send no email
            {
                bo_email = false;
            }
        }
#ifdef ALUDEBUG
		printf("	- send email:%i, recipient:%s\n",bo_email,achr_emailrcpt);
#endif
        //get email sender
        um_temp = 100;
        um_retcode = RegQueryValueExA(h_key,"email_sender",0,NULL,(byte*)achr_emailsender,&um_temp);
        if(um_retcode != ERROR_SUCCESS)
        {
            DisplayErrorText(um_retcode,"iswcord1 m_hl_toplevel... RegQueryValueEx5 failed.");
            //LeaveCriticalSection(&ds_csntlef);
            //return EXCEPTION_EXECUTE_HANDLER;
        }
#ifdef ALUDEBUG
		printf("	- email sender:%s\n",achr_emailsender);
#endif
		if(um_temp > 1)
			bo_sender  = true;
        //get password
        um_temp = 100;
        um_retcode = RegQueryValueExA(h_key,"password",0,NULL,(byte*)achr_password,&um_temp);
        if(um_retcode != ERROR_SUCCESS)
        {
            DisplayErrorText(um_retcode,"iswcord1 m_hl_toplevel... RegQueryValueEx6 failed.");
            //LeaveCriticalSection(&ds_csntlef);
            //return EXCEPTION_EXECUTE_HANDLER;
        }
#ifdef ALUDEBUG
		printf("	- password:%s\n",achr_password);
#endif
		if(um_temp > 1)
			bo_password = true;
#ifdef EVENTLOG
		//check if to read eventlog
		DWORD um_evtlog;
		um_retcode = RegQueryValueEx(h_key,"eventlog",0,NULL,(byte*)&um_evtlog,&um_temp);
		if(um_retcode != ERROR_SUCCESS)
		{
			DisplayErrorText(um_retcode,"iswcord1 m_hl_toplevel... RegQueryValueEx7 failed");
			bo_eventlog = false;
		}
 #ifdef ALUDEBUG
		printf("    - eventlog:%i\n",um_evtlog);
 #endif 
		if(um_evtlog == 0)
			bo_eventlog = false;
		else
			bo_eventlog = true;
#endif
    }//if(dsg_wcord1.achc_wregpardir != NULL)
    else
    {   //get all information from global struct
#ifdef ALUDEBUG
		printf("get values from global struct.\n");	
#endif
        if(dsg_wcord1.achc_diskdirfd == NULL)
		{
#ifdef ALUDEBUG
			printf("	- dump directory is null, returning.\n");
#endif
			printf("Failed to get dump directory,returning!\n");
         LeaveCriticalSection(&ds_csntlef);
         return EXCEPTION_EXECUTE_HANDLER;
		}
		//achr_filepath+1 because the first char has to be a quote
        strcpy(achr_filepath+1,dsg_wcord1.achc_diskdirfd);
#ifdef EVENTLOG
		//save directory
		memcpy(achr_filedir,dsg_wcord1.achc_diskdirfd,strlen(dsg_wcord1.achc_diskdirfd));
		achr_filedir[strlen(dsg_wcord1.achc_diskdirfd)] = 0;
#endif
#ifdef ALUDEBUG
		printf("	- dump directory:%s\n",achr_filepath+1);
#endif
		if(dsg_wcord1.achc_ineta_mgw == NULL || dsg_wcord1.achc_email_rcpt == NULL)
        {        
            bo_email = false;
        }
        else
        {
            strcpy(achr_mailgateway,dsg_wcord1.achc_ineta_mgw);
            strcpy(achr_emailrcpt,dsg_wcord1.achc_email_rcpt);
        }
#ifdef ALUDEBUG
		printf("	- send email:%i\n, mailgateway:%s\n, email rcpt:%s\n",
				bo_email,achr_mailgateway,achr_emailrcpt);
#endif
        if(dsg_wcord1.achc_email_sender != NULL)
		{
            strcpy(achr_emailsender,dsg_wcord1.achc_email_sender);
#ifdef ALUDEBUG
			printf("	- email sender:%s\n",achr_emailsender);
#endif
			bo_sender = true;
		}
		if(dsg_wcord1.achc_password != NULL)
		{
			strcpy(achr_password,dsg_wcord1.achc_password);
			//strcpy_s(achr_password,_countof(achr_password),dsg_wcord1.achc_password);
#ifdef ALUDEBUG
			printf("	- password:%s\n",achr_password);
#endif
			bo_password = true;
		}
#ifdef EVENTLOG	
		if(dsg_wcord1.bo_readevtlog)
		{
			bo_eventlog = true;
 #ifdef ALUDEBUG
			printf("    - eventlog:%i\n",bo_eventlog);
 #endif
		}
#endif
    }//else of if(dsg_wcord1.achc_wregpardir != NULL)    
    
    if(!bo_def_filename)
    {
        // create/open reg key to get numbering
        um_retcode = RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                                    "Software\\HOBSoftware\\HobDump",
                                    0,0,REG_OPTION_NON_VOLATILE,
                                    KEY_SET_VALUE | KEY_READ,NULL,&h_key,&um_temp);
        if(um_retcode != ERROR_SUCCESS )
        {
            DisplayErrorText(um_retcode,"iswcord1,m_hl_toplevel... RegCreateKeyEx failed: ");
            //using default file name
            bo_def_filename = true;
        }
    }
    if(!bo_def_filename)    
    {
        if(um_temp == REG_CREATED_NEW_KEY)
        {   //write first entry in registry
            //first the date
            um_retcode = RegSetValueExA(h_key,"Date",0,REG_SZ,(const byte*)achr_date,10);
            if(um_retcode != ERROR_SUCCESS)
            {
                DisplayErrorText(um_retcode,"RegSetValueEx (Date) failed: ");
            }
            //then the consecutive number per date
            um_dumpno = 1;//is the first dump
            um_retcode = RegSetValueExA(h_key,"Number",0,REG_DWORD,(const byte*)&um_dumpno,4);
            if(um_retcode != ERROR_SUCCESS)
            {
                DisplayErrorText(um_retcode,"RegSetValueEx (Number) failed: ");
            }
        }
        else  //key already exists
        {
            //check if date is the current date
            um_retcode = RegQueryValueExA(h_key,"Date",0,&um_temp,(byte*)achr_saveddate,&um_datebuflen);
            if(um_retcode != ERROR_SUCCESS)
            {
                DisplayErrorText(um_retcode,"RegQueryValueEx (Date) failed: ");
            }
            if(strcmp(achr_saveddate,achr_date) == 0)
            {
                //same date so increment number of dumps per date
                um_temp2 = sizeof(um_dumpno);
                um_retcode = RegQueryValueExA(h_key,"Number",0,&um_temp,(byte*)&um_dumpno,&um_temp2);
                if(um_retcode != ERROR_SUCCESS)
                {
                    DisplayErrorText(um_retcode,"RegQueryValueEx (Number) failed: ");
                }
                um_dumpno++;
                um_retcode = RegSetValueExA(h_key,"Number",0,REG_DWORD,(const byte*)&um_dumpno,4);
                if(um_retcode != ERROR_SUCCESS)
                {
                    DisplayErrorText(um_retcode,"RegSetValueEx (Number) failed: ");
                }
            }
            else
            {
                //is the first dump today
                //so set current date and number = 1
                um_retcode = RegSetValueExA(h_key,"Date",0,REG_SZ,(const byte*)achr_date,10);
                if(um_retcode != ERROR_SUCCESS)
                {
                    DisplayErrorText(um_retcode,"RegSetValueEx (Date) 22 failed: ");
                }
                um_dumpno = 1;
                um_retcode = RegSetValueExA(h_key,"Number",0,REG_DWORD,(const byte*)&um_dumpno,4);
                if(um_retcode != ERROR_SUCCESS)
                {
                    DisplayErrorText(um_retcode,"RegSetValueEx (Number) 22 failed: ");
                }
            }
        }//else of if(um_temp == REG_CREATED_NEW_KEY)

    }//if(!bo_def_filename)

    //remove '/' from date and format it
    achr_date_ft[0] = achr_date[6];
    achr_date_ft[1] = achr_date[7];
    achr_date_ft[2] = achr_date[0];
    achr_date_ft[3] = achr_date[1];
    achr_date_ft[4] = achr_date[3];
    achr_date_ft[5] = achr_date[4];
    achr_date_ft[6] = 0;

    strcpy(achr_filename,"hob_");
    if(!bo_def_filename)
    {
        strcat(achr_filename,achr_date_ft);
        strcat(achr_filename,"_");
        _ultoa(um_dumpno,achr_dumpno,10);
        strcat(achr_filename,achr_dumpno);
    }
    else
    {
        DWORD um_msofday;            //milliseconds of current day
        char achr_msofday[9];
        SYSTEMTIME ads_systime;        
        //get the past ms of day
        GetLocalTime(&ads_systime);
        um_msofday = ads_systime.wMilliseconds;
        um_msofday += (ads_systime.wSecond * 1000);
        um_msofday += (ads_systime.wMinute * 60 * 1000);
        um_msofday += (ads_systime.wHour * 60 * 60 * 1000);
        _ultoa(um_msofday,achr_msofday,10);
        //filename is current date plus past ms
        strcat(achr_filename,achr_date_ft);
        strcat(achr_filename,"_");
        strcat(achr_filename,achr_msofday);
    }
    strcat(achr_filename,".hld");
#ifdef ALUDEBUG
	printf("used filename:%s\n",achr_filename);
#endif
    //create path
	//achr_filepath+1 because the first char has to be a quote
    if(!PathFileExistsA(achr_filepath+1))
    {
        CreateDirectoryA(achr_filepath+1,NULL);
    }
    strcat(achr_filepath,"\\");
    strcat(achr_filepath,achr_filename);

    af_dumpfile = fopen(achr_filepath+1,"wb");
    if(af_dumpfile == NULL)
    {
        printf("Failed to open/create dumpfile.\n");
        LeaveCriticalSection(&ds_csntlef);
        return EXCEPTION_EXECUTE_HANDLER;
    }
	//filepath as quoted string because its a CreateProcess commandline argument 
	achr_filepath[0] = '\"';
	strcat(achr_filepath,"\"");
#ifdef ALUDEBUG
    printf("writing file %s\n",achr_filepath);
#endif
    ads_exceprec = adsExcepPointers->ExceptionRecord;
    ads_excepcontext = adsExcepPointers->ContextRecord;

    achr_eye = new char[100];
    um_proc_id = GetCurrentProcessId();
    um_thread_id = GetCurrentThreadId();
#ifdef ALUDEBUG
    printf("start CreateDump: Process:%i, Thread:%i\n",um_proc_id,um_thread_id);
#endif
    //eyecatcher
    sprintf( achr_eye, "Create Dump " __DATE__ );
    in_headerlen = sizeof(ulp_recordlen) + 2;
	ulp_recordlen = in_headerlen + 2 + (int)strlen(achr_eye);
#ifdef PRVTMISALGN
	memcpy(abyr_out,&ulp_recordlen,sizeof(ULONG_PTR));
	memcpy(abyr_out+sizeof(ULONG_PTR),&DEF_F_EYECATCHER,2);
	memcpy(abyr_out+sizeof(ULONG_PTR)+2,&DEF_ONE,2);
#else
	*((ULONG_PTR *) abyr_out) = ulp_recordlen;
    *((unsigned short int *) &abyr_out[sizeof(ULONG_PTR)]) = DEF_F_EYECATCHER;
    *((unsigned short int *) &abyr_out[sizeof(ULONG_PTR) + 2]) = 1;  /* version number    */
#endif
	memcpy( &abyr_out[sizeof(ULONG_PTR) + 4], achr_eye, strlen(achr_eye) );
    fwrite(abyr_out,sizeof(char),ulp_recordlen,af_dumpfile);
    //if this function called from m_hl_abend1
    //write the message in dumpfile
    if(bo_message)
    {
        memset(abyr_out,0,1024);
		ulp_recordlen = (int)strlen(achr_message) + in_headerlen;
#ifdef PRVTMISALGN
		memcpy(abyr_out, &ulp_recordlen, sizeof(ULONG_PTR));
		memcpy(abyr_out + sizeof(ULONG_PTR), &DEF_MSG, 2);
#else
        *((ULONG_PTR*) abyr_out) = ulp_recordlen;
        *((unsigned short int*) &abyr_out[sizeof(ULONG_PTR)]) = DEF_MSG;
#endif     
		memcpy(&abyr_out[in_headerlen],achr_message,ulp_recordlen - in_headerlen);
        fwrite(abyr_out,sizeof(char),ulp_recordlen,af_dumpfile);
        delete[] achr_message;
        bo_message = FALSE;
    }
    memset(abyr_out,0,1024);
    ulp_recordlen = in_headerlen + 4 + 4 + sizeof(*ads_exceprec) + sizeof(*ads_excepcontext);
#ifdef PRVTMISALGN
	memcpy(abyr_out, &ulp_recordlen, sizeof(ULONG_PTR));
	memcpy(abyr_out+sizeof(ULONG_PTR), &DEF_CRASH_EXC, 2);
	memcpy(abyr_out+in_headerlen,&um_proc_id,4);
	memcpy(abyr_out+in_headerlen+4,&um_thread_id,4);
#else
	//first record length
    *((ULONG_PTR *)abyr_out) = ulp_recordlen;
    //typ
    *((unsigned short int *) &abyr_out[sizeof(ULONG_PTR)]) = DEF_CRASH_EXC;
    //process id
    *((unsigned long int *) &abyr_out[in_headerlen]) = um_proc_id;
    //thread id
    *((unsigned long int *) &abyr_out[in_headerlen + 4]) = um_thread_id;
#endif
	//add exception record and context
    memcpy(&abyr_out[in_headerlen+ 4 +4],ads_exceprec,sizeof(*ads_exceprec));
    memcpy(&abyr_out[in_headerlen + 4+ 4 + sizeof(*ads_exceprec)],ads_excepcontext,sizeof(*ads_excepcontext));
    fwrite(abyr_out,sizeof(char),ulp_recordlen,af_dumpfile);

    //create snapshot to get all loaded dll
    // Show Modules in the Process
    BOOL bo_fok;
#ifdef ALUDEBUG
	printf("Trying to make Toolhelp32Snapshot.\n");
#endif
    MODULEENTRY32 ds_modul= { sizeof(MODULEENTRY32) };
    h_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, um_proc_id);
    if(h_snapshot == INVALID_HANDLE_VALUE)
		printf("CreateToolhelp32Snapshot failed with error code:%i\n",GetLastError());
	else
    {
#ifdef FASTINFO
		fpos_t fpos;
		if(fgetpos(af_dumpfile,&fpos) == 0)
		{
			_i64toa(fpos,chr_fileposm32,10);
#ifdef ALUDEBUG
			printf("##fileposm32:%s\n",chr_fileposm32);
#endif
		}
#endif
        bo_fok = Module32First(h_snapshot,&ds_modul);
        for( ;bo_fok; bo_fok = Module32Next(h_snapshot,&ds_modul) )
        {
            memset(abyr_out,0,1024);
            ulp_recordlen = in_headerlen + sizeof(MODULEENTRY32);
#ifdef PRVTMISALGN
			memcpy(abyr_out,&ulp_recordlen,sizeof(ULONG_PTR));
			memcpy(abyr_out+sizeof(ULONG_PTR),&DEF_THL_DLL,2);
#else
			*((ULONG_PTR*)&abyr_out) = ulp_recordlen;
            //typ
            *((unsigned short int *) &abyr_out[sizeof(ULONG_PTR)]) = DEF_THL_DLL;
#endif     
			memcpy(&abyr_out[in_headerlen],&ds_modul,sizeof(MODULEENTRY32));
			fwrite(abyr_out,sizeof(char),ulp_recordlen,af_dumpfile);
        }
    }

    memset(abyr_out,0,1024);
    h_process = OpenProcess( SYNCHRONIZE | PROCESS_DUP_HANDLE
                            | PROCESS_VM_READ | PROCESS_VM_WRITE
                            | PROCESS_VM_OPERATION,
                           FALSE,um_proc_id );
    if(h_process == NULL)
    {
        printf("CreateDump OpenProcess failed with error: %i",GetLastError());
    }

    if(h_process != NULL && bo_writememdump)
    {
#ifdef ALUDEBUG
        printf("Try to read process memory \n");
#endif

#ifdef OLDREADMEMORY
		byte* aby_memaddr = 0;          //virtuell memory address 	
		ulp_recordlen = in_headerlen + sizeof(ULONG_PTR) + DEF_PAGE_SIZE;
        while(aby_memaddr < abyMemLimit)
        {
            //printf("Try to read memory %08x\n",aby_memaddr);
            bo_succes = ReadProcessMemory( h_process, (const void*)aby_memaddr,
                                            abyr_out + 10, DEF_PAGE_SIZE, NULL );
            if(!bo_succes)
            {
                um_temp = GetLastError();
                if (um_temp != ERROR_PARTIAL_COPY)
                {
#ifdef ALUDEBUG                
					printf( "ReadProcessMemory Dump Addr %p Error %ld\n",
                             aby_memaddr, um_temp );
#endif               
				}
            }
            else
            {
                *((ULONG_PTR*) abyr_out) = ulp_recordlen;
                *((unsigned short int *) &abyr_out[sizeof(ULONG_PTR)]) = DEF_F_MEM;  /* func page */
				*((ULONG_PTR*)&abyr_out[in_headerlen]) = (ULONG_PTR)aby_memaddr;
				fwrite(abyr_out,sizeof(char),ulp_recordlen,af_dumpfile);
                //fDump.flush();
            }
            aby_memaddr += DEF_PAGE_SIZE;
        }//while(aby_memaddr < abyMemLimit)
#else //OLDREADMEMORY

//define _WIN64
		ULONG_PTR ulp_memaddr = 0;
		byte* abyr_memory;
		SYSTEM_INFO ds_sysinfo;
		ULONG_PTR ulp_maxuseraddr;
#if _WIN32_WINNT >= 0x0501
		GetNativeSystemInfo(&ds_sysinfo);
#else
		GetSystemInfo(&ds_sysinfo);	
#endif
		ulp_maxuseraddr = (ULONG_PTR)ds_sysinfo.lpMaximumApplicationAddress;     
#ifdef ALUDEBUG
		printf(" - maxuseraddress: %p\n",ulp_maxuseraddr);
#endif
		while(ulp_memaddr < ulp_maxuseraddr)
		{
            ///////////////////////////////////////////////////////////
            //  VirtualQuery:
            //    get size of region of same memory state
            //    if state is MEM_COMMIT:
			//    read the whole region
			//    else: get next address with VirtualQuery.
            //    break on highest possible address getted from
			//    GetNativeSystemInfo lpMaximumApplicationAddress
            ///////////////////////////////////////////////////////////
            
			MEMORY_BASIC_INFORMATION ds_meminfo;
            ULONG_PTR ulp_bytes;
            ulp_bytes = VirtualQuery((LPCVOID)ulp_memaddr,&ds_meminfo,sizeof(ds_meminfo)); 
            if(ulp_bytes != sizeof(ds_meminfo))
            {
#ifdef ALUDEBUG
				printf("stopped at addr.:%p\n",ds_meminfo.BaseAddress);
#endif			
				if(ulp_bytes)
                {
                    printf( "VirtualQuery returned invalid size %d\n", ulp_bytes );
                }
                break;   // at end of storage
            }
#ifdef ALUDEBUG
            printf( "BaseAddress=%p AllocationBase=%p AllocationProtect=%d\n RegionSize=%08X State=%d Protect=%d Type=%d\n\n",
                    ds_meminfo.BaseAddress, ds_meminfo.AllocationBase,
                    ds_meminfo.AllocationProtect,
                    ds_meminfo.RegionSize, ds_meminfo.State,
                    ds_meminfo.Protect, ds_meminfo.Type );
#endif
            if(ds_meminfo.State == MEM_COMMIT)
			{
				ulp_recordlen = in_headerlen + sizeof(ULONG_PTR) + ds_meminfo.RegionSize;
				abyr_memory = new byte[ulp_recordlen];
				bo_succes = ReadProcessMemory( h_process, (LPCVOID)ulp_memaddr,
                                               abyr_memory + in_headerlen + sizeof(ULONG_PTR),
											   ds_meminfo.RegionSize, (SIZE_T*)&ulp_bytes );
				if(!bo_succes)
				{
					um_temp = GetLastError();
					if (um_temp != ERROR_PARTIAL_COPY)
					{
#ifdef ALUDEBUG                
						printf( "ReadProcessMemory Dump Addr %p Error %ld\n",
							     ulp_memaddr, um_temp );
#endif               
					}
				}
				else
				{
#ifdef ALUDEBUG
					printf("ReadProcessMemory DumpAddr: %p successful\n",
							   ulp_memaddr);
#endif
#ifdef PRVTMISALGN
					memcpy(abyr_memory,&ulp_recordlen,sizeof(ULONG_PTR));
					memcpy(abyr_memory+sizeof(ULONG_PTR),&DEF_F_MEM,2);
					memcpy(abyr_memory+in_headerlen,&ulp_memaddr,sizeof(ULONG_PTR));
#else
					*((ULONG_PTR*) abyr_memory) = ulp_recordlen;
					*((unsigned short int *) &abyr_memory[sizeof(ULONG_PTR)]) = DEF_F_MEM;
					*((ULONG_PTR*)&abyr_memory[in_headerlen+6]) = ulp_memaddr;
#endif
#ifdef ALUDEBUG2
					printf("write that to dumpfile...\n");
#endif
					fwrite(abyr_memory,sizeof(char),ulp_recordlen,af_dumpfile);
#ifdef ALUDEBUG2
					printf("written that to dumpfile!\n");
#endif
				}
				delete[] abyr_memory;
			}
			ulp_memaddr = ((ULONG_PTR) ds_meminfo.BaseAddress) + ds_meminfo.RegionSize;  
#ifdef ALUDEBUG2
			printf("end of while, ulp_memaddr:%p, ulp_maxuseraddr%p\n",
					ulp_memaddr, ulp_maxuseraddr);
#endif
		}//while(ulp_memaddr < ulp_maxuseraddr)
#ifdef ALUDEBUG2
		printf("left while loop\n");
#endif

    } //if(bo_writememdump)

#endif //OLDREADMEMORY

#ifdef EVENTLOG
	if(bo_eventlog)
	{
		STARTUPINFO ds_si;
		PROCESS_INFORMATION ds_pi;
		//FILE *af_evtfile;
		//fpos_t pos;
		std::string str_cmdline;
		//DWORD um_filesize;
		//create call from dumpel.exe
		str_cmdline = "dumpel.exe";
		str_evtfile = (std::string)achr_filedir;
		str_evtfile += "\\";
		str_evtfile += "evtlog.txt";
		//dumpel -f Y:\AKBIX1\HLJWT\se-l"%1%".txt -l application
		str_cmdline += " -f ";
		str_cmdline += str_evtfile;
		str_cmdline += " -l application";
		ZeroMemory(&ds_si,sizeof(ds_si));
		ds_si.cb = sizeof(ds_si);
		ZeroMemory(&ds_pi,sizeof(ds_pi));
		//ds_si
		printf("Try to read eventlog...\n");
		if( CreateProcess(NULL, (LPSTR)str_cmdline.c_str(),
				    	   NULL, NULL, FALSE, 0, NULL,
						   NULL, &ds_si, &ds_pi )  )
		{
			printf("Eventlog saved at %s\n",str_evtfile.c_str());
		}
		else
		{
			DisplayErrorText(GetLastError(),"Start dumpel.exe failed.");
		}
		/*
		//open output file
		af_evtfile = fopen(str_evtfile.c_str(),"rb");
		if(af_evtfile != NULL)
		{
			fseek(af_evtfile,0,SEEK_END);
			fgetpos(af_evtfile,&pos);

		}//if(af_evtfile != NULL)
		*/
	}
#endif
    fclose(af_dumpfile);
    delete[] achr_eye;

    h_evtlog = RegisterEventSource(NULL,  // uses local computer
                        TEXT("HOBDump"));    // source name
    if(h_evtlog != NULL)
    {
        str_evtlogmsg = "HobDump was created. Saved at ";
        str_evtlogmsg += (std::string)achr_filepath;
        char achrTime[9];
        LPCSTR achrLog[1]; 
        achrLog[0] = (LPCSTR)str_evtlogmsg.c_str();
        _strtime(achrTime);
#ifdef ALUDEBUG
        printf("try to write msg %s to event log\n",str_evtlogmsg.c_str());
#endif
        printf("%s\n",achrLog[0]);
		if(!ReportEventA(h_evtlog,           // event log handle
                    EVENTLOG_INFORMATION_TYPE,  // event type
                    0,                    // category zero
                    MSG_DUMP_EXIST,       // event identifier
                    NULL,                 // no user security identifier
                    1,                    // one substitution string
                    8,                    // no data
                    achrLog, // pointer to string array
                    achrTime))                // pointer to data
        {
            printf("ReportEvent failed with error:%i\n",GetLastError());
        }
        DeregisterEventSource(h_evtlog);
    }
	else
		printf("RegisterEventSource failed with error:%i\n",GetLastError());

    //send dump as email
    if(bo_email)
    {
        std::string str_commandline;
        //TODO
#ifdef _WIN64
#ifdef _M_X64
		std::string str_appname = "ibmail01_x64.exe";
#elif _M_IA64
		std::string str_appname = "ibmail01_ia64.exe";
#endif
#else
        std::string str_appname = "ibmail01.exe";
#endif     
		STARTUPINFOA ds_si;
        PROCESS_INFORMATION ds_pi;
        //create commandline for email program
        str_commandline = str_appname;
		str_commandline += " /f=";
        str_commandline += (std::string)achr_filepath;
		str_commandline += " /g=";
        str_commandline += (std::string)achr_mailgateway;
        str_commandline += " /r=";
        str_commandline += (std::string)achr_emailrcpt;
        if(bo_sender)
        {
            str_commandline += " /s=";
            str_commandline += (std::string)achr_emailsender;
        }
        if(bo_password)
        {
            str_commandline += " /p=";
            str_commandline += (std::string)achr_password;
        }
#ifdef FASTINFO
		str_commandline += " /e=";
		str_commandline += (std::string)chr_shorterror;
		str_commandline += " /m=";
		str_commandline += (std::string)chr_fileposm32;
#endif
#ifdef EVENTLOG
		if(bo_eventlog && !str_evtfile.empty())
		{
			str_commandline += " /l=";
			str_commandline += str_evtfile;
		}
#endif
        ZeroMemory( &ds_si, sizeof(ds_si) );
        ds_si.cb = sizeof(ds_si);
        ZeroMemory( &ds_pi, sizeof(ds_pi) );
#ifdef ALUDEBUG
		printf("calling Createprocess with cmdline:%s\n",str_commandline.c_str());
#endif
		printf("Starting email program\n");
		// Start the email program
        if( !CreateProcessA( NULL, // No module name (use command line). 
                (LPSTR)str_commandline.c_str(), // Command line. 
                NULL,                // Process handle not inheritable. 
                NULL,                // Thread handle not inheritable. 
                FALSE,               // Set handle inheritance to FALSE. 
                0,                   // No creation flags. 
                NULL,                // Use parent's environment block. 
                NULL,                // Use parent's starting directory. 
                &ds_si,              // Pointer to STARTUPINFO structure.
                &ds_pi )             // Pointer to PROCESS_INFORMATION structure.
          )
        {
            DisplayErrorText(GetLastError(),"Start email program failed.");
        }
    }//if(bo_email)

	printf("End of exception handling.\n");

	LeaveCriticalSection(&ds_csntlef);
   return EXCEPTION_EXECUTE_HANDLER;
} //m_hl_toplevelexceptionfilter

// Displaying the Error Message
void DisplayErrorText(DWORD ulErrorCode, char* achrPreText)
{
    HMODULE hModule = NULL; // default to system source
    HANDLE h_evtlog;
    LPSTR MessageBuffer;
    char* achrOutMsg;
    DWORD dwBufferLength;
    int inLen1,inLen2;

    DWORD dwFormatFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER |
                FORMAT_MESSAGE_IGNORE_INSERTS |
                FORMAT_MESSAGE_FROM_SYSTEM ;

    // If dwLastError is in the network range, 
    //  load the message source.
    if(ulErrorCode >= NERR_BASE && ulErrorCode <= MAX_NERR) 
    {
        hModule = LoadLibraryEx(TEXT("netmsg.dll"), NULL,
                                LOAD_LIBRARY_AS_DATAFILE );

        if(hModule != NULL)
            dwFormatFlags |= FORMAT_MESSAGE_FROM_HMODULE;
    }

    // Call FormatMessage() to allow for message 
    //  text to be acquired from the system 
    //  or from the supplied module handle.
    dwBufferLength = FormatMessageA(dwFormatFlags,hModule, // module to get message from (NULL == system)
									   ulErrorCode,MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // default language
									   (LPSTR) &MessageBuffer,0,NULL);
    if(dwBufferLength > 0 )
    {
        //
        // Output message string on stderr.
        //       
        inLen1 = (int)strlen(achrPreText);
        inLen2 = (int)strlen(MessageBuffer);
        achrOutMsg = new char[inLen1 + inLen2 + 2];
        memcpy(achrOutMsg,achrPreText,inLen1);
        memcpy(achrOutMsg+ inLen1,MessageBuffer ,inLen2);
        achrOutMsg[inLen1 + inLen2] = 0;
        //make entry in event log
        h_evtlog = RegisterEventSource(NULL,  // uses local computer
                                      TEXT("HOBDump"));    // source name
        if(!h_evtlog == NULL)
        {
            char achrTime[9];
            LPCSTR achrLog[1]; 
            achrLog[0] = achrOutMsg;
            _strtime(achrTime);
            if(!ReportEventA(h_evtlog,           // event log handle
                        EVENTLOG_INFORMATION_TYPE,  // event type
                        0,                    // category zero
                        MSG_DUMP_EXIST,       // event identifier
                        NULL,                 // no user security identifier
                        1,                    // one substitution string
                        8,                    // no data
                        achrLog, // pointer to string array
                        achrTime))                // pointer to data
            {
                printf("ReportEvent failed with error:%i\n",GetLastError());
            }
            DeregisterEventSource(h_evtlog);
        }
        
        printf(achrOutMsg);
#ifdef ERRMSGBOX
        MessageBoxA(NULL,achrOutMsg,"iswcord1 error!",MB_OK);
#endif
        //
        // Free the buffer allocated by the system.
        //
        LocalFree(MessageBuffer);
        delete[] achrOutMsg;
    }

    //
    // If we loaded a message source, unload it.
    //
    if(hModule != NULL)
        FreeLibrary(hModule);
    
    return;
}

