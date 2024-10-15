/*+-------------------------------------------------------------------+*/
/*|                                                                   |*/
/*| PROGRAM NAME: HTUN_WIN32API.cpp                                   |*/
/*| -------------                                                     |*/
/*|  HOB Utility function library for use with the TAP-Win32 virtual  |*/
/*|    network adapter for Windows                                    |*/
/*|  Alan Duca 19.11.07                                               |*/
/*|                                                                   |*/
/*| COPYRIGHT:                                                        |*/
/*| ----------                                                        |*/
/*|  Copyright (C) HOB Germany 2007                                   |*/
/*|                                                                   |*/
/*+-------------------------------------------------------------------+*/

#include <stdlib.h>
#include <map>
#include <string>

#if defined HL_UNIX
#include "hob-unix01.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#ifdef HL_FREEBSD
#define TRY_150625
#ifndef TRY_150625
#include <sys/socket.h>
#endif
#endif
#include <net/if.h>
#ifdef HL_LINUX
#include <linux/if_tun.h>
#endif
#ifdef HL_FREEBSD
//#include <net/if_tun.h>
#include <sys/types.h>
#include <sys/uio.h>
#endif
#ifdef TRY_150625
#include <sys/socket.h>
#include <netinet/in.h>
#endif
#ifdef HL_FREEBSD
#include <net/if_tun.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
#include <netinet/if_ether.h>
//#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#endif
#include <netinet/in.h>
#else
#include <time.h>
#include <sys/timeb.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <setupapi.h>
#ifndef NO_TUN_DRIVER
#include <devguid.h>                        /* used for GUID_DEVCLASS_NET */
#include <setupapi.h>
#include <cfgmgr32.h>
// #include <netcfgx.h>
#endif
#endif

#define D_INCL_TUN_CTRL
#include "hob-tun01.h"
#include "hob-tuntapif01.h"
#if defined WIN32 || WIN64
#include "hob-os-system-1.h"
#endif

static const int MAX_ERR_STRING   = 1024;

static int im_retval;
static char str_tun_last_err[MAX_ERR_STRING] = "";

#if defined WIN32 || defined WIN64

static const char ADAPTER_KEY[]   = "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}";
static const int MAX_REG_STRING   = 1024;
static const int MAX_REG_VAL_SIZE = 256;
static const int MAX_COMM_STRING  = 1024;
static const int MAX_OPEN_KEYS    = 50;

static HANDLE a_ev_write = CreateEvent(NULL, FALSE, TRUE, NULL);
static OVERLAPPED ds_olap_write;

static HANDLE a_ev_read = CreateEvent(NULL, FALSE, TRUE, NULL);
static OVERLAPPED ds_olap_read;

#endif // defined WIN32 || defined WIN64

#if not defined WIN32 && not defined WIN64
TUNHANDLE dsg_tun_hdl = 0;
#endif

extern "C" int m_hl1_printf(char * aptext, ... );

using namespace std;

#if defined WIN32 || WIN64
//closes all [imp_hkey_count] open registry keys held within the array pointed at by aadsp_hkey_list
static int m_close_keys(HKEY* aadsp_hkey_list, int imp_hkey_count)
{
   HKEY adsl_hkey_to_close;
   for(int iml_i = 0; iml_i < imp_hkey_count; iml_i++)
   {
      adsl_hkey_to_close = *(aadsp_hkey_list + iml_i);
      im_retval = RegCloseKey(adsl_hkey_to_close);
      if(im_retval != ERROR_SUCCESS)
      {
         sprintf(str_tun_last_err,
                 "Error while closing registry key: %d",
                 im_retval);
         return -1;
      }
   }
   return 0;
}
//incremets number of open registry keys, and checks that limit has not been exceeded
static int m_inc_open_keys(int* aimp_open_key_cnt)
{
   (*aimp_open_key_cnt)++;
   if(*aimp_open_key_cnt > MAX_OPEN_KEYS)
   {
      sprintf(str_tun_last_err,
              "Open key limit exceeded: %d keys already open.",
              MAX_OPEN_KEYS);
      return -1;
   }
   return 0;
}
#endif //defined WIN32 || WIN64

int m_open_tun(TUNHANDLE* aap_tun_dev, char* strp_dev_name, const int imp_name_len)
{
#if defined WIN32 || WIN64

   //array holding handles to open registry keys
   HKEY radsl_open_hkeys[MAX_OPEN_KEYS];
   //number of open registry keys
   int iml_open_hkey_cnt = 0;
   //to hold path of file to be opened
   char strl_fil_path[MAX_REG_STRING];

   //////////////////////////////////////////////////////////
   //POSSIBLE SEPERATE FUNCTION//////////////////////////////
   //////////////////////////////////////////////////////////
   //This process is carried out every time a new registry
   //key is opened. Since this is done a number of times,
   //it may be a good idea to include it as a separate
   //function.
   //////////////////////////////////////////////////////////

   //get handle to adapters registry key
   HKEY adsl_adapter_key;
   im_retval = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
			                    ADAPTER_KEY,
			                    0,
			                    KEY_READ,
			                    &adsl_adapter_key);

   if(im_retval != ERROR_SUCCESS)
   {  //open key failed
      sprintf(str_tun_last_err,
              "Error opening registry key HKEY_LOCAL_MACHINE\\%s: %d",
              ADAPTER_KEY,
              im_retval);
      //close all opened keys
      m_close_keys(radsl_open_hkeys, iml_open_hkey_cnt);
      return -1;
   }
   else
   {  //open key OK
      //add handle of newly opened key to opened key handle array
      radsl_open_hkeys[iml_open_hkey_cnt] = adsl_adapter_key;
      //ensure limit of opened keys has not been exceeded
      if(m_inc_open_keys(&iml_open_hkey_cnt) != 0)
      {  //limit exceeded
         //close all opened keys
         m_close_keys(radsl_open_hkeys, iml_open_hkey_cnt);
         return -1;
      }
   }

   //////////////////////////////////////////////////////////
   //END: POSSIBLE SEPERATE FUNCTION/////////////////////////
   //////////////////////////////////////////////////////////

   //look into all sub-keys within the adapters reg key
   for(int iml_i = 0; TRUE; iml_i++)
   {
      //to hold name of 'i'th sub-key
      char strl_key_name[MAX_REG_STRING];
      DWORD ull_len = sizeof(strl_key_name);

      //get name of 'i'th sub-key
      im_retval = RegEnumKeyEx(adsl_adapter_key,
			                      iml_i,
			                      strl_key_name,
			                      &ull_len,
			                      NULL,
			                      NULL,
			                      NULL,
			                      NULL);

      if(im_retval == ERROR_NO_MORE_ITEMS)
      {  //all sub-keys checked
         sprintf(str_tun_last_err,
                 "No TAP-Win32 device is available. Make sure that there is at "
                 "least one unused TAP-Win32 device on the system. If a device name "
                 "was specified, make sure that it is not already in use.");
         m_close_keys(radsl_open_hkeys, iml_open_hkey_cnt);
         return -1;
      }
      else if(im_retval != ERROR_SUCCESS)
      {
         sprintf(str_tun_last_err,
                 "Error opening registry key HKEY_LOCAL_MACHINE\\%s (sub-key %d): %d",
                 ADAPTER_KEY,
                 iml_i,
                 im_retval);
         m_close_keys(radsl_open_hkeys, iml_open_hkey_cnt);
         return -1;
      }

      //to hold full path of 'i'th sub-key
      char strl_dev_key_name[MAX_REG_STRING];
      sprintf(strl_dev_key_name, "%s\\%s", ADAPTER_KEY, strl_key_name);

      //get handle to 'i'th sub-key
      HKEY adsl_dev_key;
      im_retval = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
			                       strl_dev_key_name,
			                       0,
			                       KEY_READ,
			                       &adsl_dev_key);

      if(im_retval != ERROR_SUCCESS)
      {
         if(im_retval == 5)
         {
            //todo: ACCESS TO REG KEY DENIED
            continue;
         }
         sprintf(str_tun_last_err,
                 "Error opening registry key HKEY_LOCAL_MACHINE\\%s: %d",
                 strl_dev_key_name,
                 im_retval);
         m_close_keys(radsl_open_hkeys, iml_open_hkey_cnt);
         return -1;
      }
      else
      {
         radsl_open_hkeys[iml_open_hkey_cnt] = adsl_dev_key;
         if(m_inc_open_keys(&iml_open_hkey_cnt) != 0)
         {
            m_close_keys(radsl_open_hkeys, iml_open_hkey_cnt);
            return -1;
         }
      }

      //read ComponentId value of 'i'th sub-key
      unsigned char rucl_comp_id[MAX_REG_VAL_SIZE];
      ull_len = sizeof(rucl_comp_id);
      memset(rucl_comp_id, 0, ull_len);
      DWORD ull_data_type;
      im_retval = RegQueryValueEx(adsl_dev_key,
				                       "ComponentId",
				                       NULL,
				                       &ull_data_type,
				                       rucl_comp_id,
				                       &ull_len);

      if(im_retval != ERROR_SUCCESS)
      {
         sprintf(str_tun_last_err,
                 "Error reading value from registry key HKEY_LOCAL_MACHINE\\%s: %d",
                 strl_dev_key_name,
                 im_retval);
      }

      //if 'i'th sub-key ComponentId value is "tap0108" (virtual adapter)
      if(!strcmp((char*)rucl_comp_id, "tap0801"))
      {
         //read NetCfgInstanceId (device guid) value of 'i'th sub-key
         unsigned char rucl_dev_guid[MAX_REG_VAL_SIZE];
         ull_len = sizeof(rucl_dev_guid);
         memset(rucl_dev_guid, 0, ull_len);
         im_retval = RegQueryValueEx(adsl_dev_key,
				                          "NetCfgInstanceId",
				                          NULL,
				                          &ull_data_type,
				                          rucl_dev_guid,
				                          &ull_len);

         if(im_retval != ERROR_SUCCESS)
         {
            sprintf(str_tun_last_err,
                    "Error reading value from registry key HKEY_LOCAL_MACHINE\\%s: %d",
                    strl_dev_key_name,
                    im_retval);
            m_close_keys(radsl_open_hkeys, iml_open_hkey_cnt);
            return -1;
         }

         //initialize path of file to open
         sprintf(strl_fil_path, "\\\\.\\Global\\%s.tap", rucl_dev_guid);

         //GET NAME OF VIRTUAL ADAPTER (REQUIRED FOR netsh)

         //get handle to key representing the virtual adapter
         HKEY adsl_devname_key;
         char strl_devname_key_name[MAX_REG_STRING];
         sprintf(strl_devname_key_name,
                 "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection",
                 rucl_dev_guid);
         im_retval = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
			                          strl_devname_key_name,
			                          0,
			                          KEY_READ,
			                          &adsl_devname_key);

         if(im_retval != ERROR_SUCCESS)
         {
            sprintf(str_tun_last_err,
                    "Error opening registry key HKEY_LOCAL_MACHINE\\%s: %d",
                    strl_devname_key_name,
                    im_retval);
            m_close_keys(radsl_open_hkeys, iml_open_hkey_cnt);
            return -1;
         }
         else
         {
            radsl_open_hkeys[iml_open_hkey_cnt] = adsl_devname_key;
            if(m_inc_open_keys(&iml_open_hkey_cnt) != 0)
            {
               m_close_keys(radsl_open_hkeys, iml_open_hkey_cnt);
               return -1;
            }
         }

         //read Name value of virtual adapter reg key
         ull_len = MAX_REG_VAL_SIZE;
         unsigned char strl_curr_dev_name[MAX_REG_VAL_SIZE];
         im_retval = RegQueryValueEx(adsl_devname_key,
				                          "Name",
				                          NULL,
				                          &ull_data_type,
				                          strl_curr_dev_name,
				                          &ull_len);

         if(im_retval != ERROR_SUCCESS)
         {
            sprintf(str_tun_last_err,
                    "Error reading value from registry key HKEY_LOCAL_MACHINE\\%s: %d",
                    strl_devname_key_name,
                    im_retval);
            m_close_keys(radsl_open_hkeys, iml_open_hkey_cnt);
            return -1;
         }

         //if device name specified as parameter, and current tap adapter name doesn't match, skip this adapter
         if(strcmp(strp_dev_name, "") && strcmp(strp_dev_name, (char*)strl_curr_dev_name))
            continue;

         //get handle to file
         *aap_tun_dev = CreateFile(strl_fil_path,
                                  GENERIC_READ | GENERIC_WRITE,
                                  FILE_SHARE_READ,
                                  0,
                                  OPEN_EXISTING,
                                  FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED,
                                  0);

         if(*aap_tun_dev == INVALID_HANDLE_VALUE) //error getting file handle
         {
            m_hl1_printf("Error getting handle to TAP-Win32 Virtual Adapter. System Error: %d\n",
                    GetLastError());
         }
         else
         {
            //set name of device
            if(!strcmp(strp_dev_name, ""))
               sprintf(strp_dev_name, (char*)strl_curr_dev_name);

            //set read and write events for read and write olap structs
            ds_olap_read.hEvent = a_ev_read;
            ds_olap_write.hEvent = a_ev_write;

            //close all open registry keys
            im_retval = m_close_keys(radsl_open_hkeys, iml_open_hkey_cnt);
            if(im_retval != 0)
            {
               sprintf(str_tun_last_err,
                  "Error while attempting to close opened registry keys: %d",
                       im_retval);
               return -1;
            }
            else
               return 0;
         }
      }
   }
#elif defined HL_UNIX

   int im_fd;
   char str_openmode[15] = "/dev/net/tun";

   if ((im_fd = open(str_openmode, O_RDWR)) < 0)
   {
	   sprintf(str_tun_last_err,
			   "m_open_tun: errno = %d (%s)\n",
			   errno,
			   strerror(errno));
	   return -1;
   }
   else
   {
	   *aap_tun_dev = im_fd;
	   return 0;
   }

#endif //defined WIN32 || WIN64
}// m_open_tun

/*

 */

//int m_init_tun(TUNHANDLE ap_tun_dev, const char* strp_dev_name, const char* strp_local_ep, const char* strp_remote_ep)
int m_init_tun( struct dsd_tun_intf_1* adsp_tun_intf_1 )
{
#if defined WIN32 || WIN64
//
//   //to hold system command
//   char strl_sys_comm[MAX_COMM_STRING];
//   //construct netsh command
//// sprintf(strl_sys_comm, "netsh interface ip set address \"%s\" static %s 255.255.255.252", strp_dev_name, strp_local_ep);
//// sprintf(strl_sys_comm, "netsh interface ip set address \"%s\" static %s 255.255.255.252", strp_dev_name, strp_local_ep);
//   sprintf( strl_sys_comm, "netsh interface ip set address \"%s\" static %d.%d.%d.%d %d.%d.%d.%d",
//            adsp_tun_intf_1->achc_adapter_name,
//            (unsigned char) adsp_tun_intf_1->chrc_ineta_locale[0],
//            (unsigned char) adsp_tun_intf_1->chrc_ineta_locale[1],
//            (unsigned char) adsp_tun_intf_1->chrc_ineta_locale[2],
//            (unsigned char) adsp_tun_intf_1->chrc_ineta_locale[3],
//            (unsigned char) adsp_tun_intf_1->chrc_netmask_1[0],
//            (unsigned char) adsp_tun_intf_1->chrc_netmask_1[1],
//            (unsigned char) adsp_tun_intf_1->chrc_netmask_1[2],
//            (unsigned char) adsp_tun_intf_1->chrc_netmask_1[3] );
//   m_hl1_printf("Issuing system command [%s]... ", strl_sys_comm);
//   //execute netsh command
//   if(system(strl_sys_comm) != 0) //netsh FAILED
//   {
//      sprintf(str_tun_last_err,
//              "Command [%s] failed",
//              strl_sys_comm);
//      return -1;
//   }
//
//   ULONG rull_end_points[2]; //initialised with end point addresses and passed to DeviceIoControl
//// rull_end_points[0] = inet_addr(strp_local_ep);
//// rull_end_points[1] = inet_addr(strp_remote_ep);
//// to-do 17.03.09 KB do not use unsigned long int
//   memcpy( &rull_end_points[0], adsp_tun_intf_1->chrc_ineta_locale, sizeof(unsigned long int) );
//   memcpy( &rull_end_points[1], adsp_tun_intf_1->chrc_ineta_remote, sizeof(unsigned long int) );
//
//   //try to set device endpoints (hence initiating TUN mode)
//   DWORD ull_retbytes;
//   if(!DeviceIoControl (adsp_tun_intf_1->dsc_tunhandle,
//                        CTL_CODE (FILE_DEVICE_UNKNOWN, 5, METHOD_BUFFERED, FILE_ANY_ACCESS),
//	                     rull_end_points,
//                        sizeof (rull_end_points),
//	                     rull_end_points,
//                        sizeof (rull_end_points),
//                        &ull_retbytes,
//                        NULL))
//   {  //TUN mode initialization FAILED
//      sprintf(str_tun_last_err,
//              "Error setting Virtual Adapter Point-to-Point Mode. System Error: %d",
//              GetLastError());
//      return -1;
//   }
//   else
//   {  //TUN mode initialization OK
//      return 0;
//   }
//#elif defined HL_UNIX
//
//   struct ifreq ds_ifr;
//
//   memset(&ds_ifr, 0, sizeof(ds_ifr));
//#ifdef HL_LINUX
//   ds_ifr.ifr_flags =  (IFF_TUN | IFF_NO_PI);
//
//   if ((im_retval = ioctl(adsp_tun_intf_1->dsc_tunhandle, TUNSETIFF, &ds_ifr)) < 0)
//   {
//	   sprintf(str_tun_last_err,
//			   "m_init_tun: errno = %d (%s)\n",
//			   errno,
//			   strerror(errno));
//	   close(adsp_tun_intf_1->dsc_tunhandle);
//	   return -2;
//   }
//#endif
//#ifdef HL_FREEBSD
//   int iml_in = 1;
//   im_retval = ioctl( adsp_tun_ctrl->imc_fd_tun, TUNSLMODE, &iml_in );                //  Equivalent
//   if (im_retval < 0) {                        /* error occured           */
//     printf("%d\n", strerror(errno));
//   }
//   iml_in = 0;                                                                     //  to
//   im_retval = ioctl( adsp_tun_ctrl->imc_fd_tun, TUNSIFHEAD, &iml_in );               //  IFF_NO_PI
//
//
//   iml_in = 0;
//   im_retval = ioctl( adsp_tun_ctrl->imc_fd_tun, FIONBIO, &iml_in );
//   if (iml_rc < 0) {                        /* error occured           */
//     printf("%d\n", strerror(errno));
//   }
//#endif
//
//   char str_ip[16];
//   inet_ntop(AF_INET, adsp_tun_intf_1->chrc_ineta_locale, str_ip, sizeof(str_ip));
//   char str_net_mask[16];
//   inet_ntop(AF_INET, adsp_tun_intf_1->chrc_netmask_1, str_net_mask, sizeof(str_net_mask));
//
//   char str_command[128];
//   snprintf(str_command,
//		   sizeof(str_command),
//		   "%s %s %s %s %s",
//           "/sbin/ifconfig",
//           ds_ifr.ifr_name,
//           str_ip,
//           "netmask",
//           str_net_mask);
//
//   if ((im_retval = system(str_command)) != 0)
//   {
//	   sprintf(str_tun_last_err,
//			   "m_init_tun: errno = %d (%s)\n",
//			   errno,
//			   strerror(errno));
//	   close(adsp_tun_intf_1->dsc_tunhandle);
//	   return -3;
//   }
//
   return 0;

#endif //defined WIN32 || WIN64
}// init_tun()

int m_connect_tun(TUNHANDLE ap_tun_dev)
{
#if defined WIN32 || WIN64

   ULONG ull_status = TRUE; //device status to set (Connected)
   DWORD ull_retbytes;
   //try to set dev status to connected
   im_retval = DeviceIoControl(ap_tun_dev,
                                CTL_CODE (FILE_DEVICE_UNKNOWN, 6, METHOD_BUFFERED, FILE_ANY_ACCESS),
                                &ull_status,
                                sizeof(ull_status),
                                &ull_status,
                                sizeof(ull_status),
                                &ull_retbytes,
                                NULL);

   if(im_retval == 0)
   {  //Error setting device status to connected
      sprintf(str_tun_last_err,
              "Error setting Virtual Adapter Status to \"Connected\". System Error: %d",
              GetLastError());
      return -1;
   }
   else
   {
      return 0;
   }
#elif defined HL_UNIX
   return 0;
#endif //defined WIN32 || WIN64
}// m_connect_tun

int m_readone_blk(TUNHANDLE ap_tun_dev, unsigned char* aucp_read_buff, int imp_buff_len, HANDLE ap_ev_cancel, int* aimp_bytes_read)
{
#if defined WIN32 || WIN64

      //make sure cancel event is non signalled
      if(ap_ev_cancel)
        ResetEvent(ap_ev_cancel);

      //try to read
      ds_olap_read.Offset = 0;
      ds_olap_read.OffsetHigh = 0;
      im_retval = ReadFile(ap_tun_dev,
                            aucp_read_buff,
                            imp_buff_len,
                            (LPDWORD)aimp_bytes_read,
                            &ds_olap_read);
      if(im_retval <= 0)
      {
         int iml_err = GetLastError();

         if(iml_err == ERROR_IO_PENDING)
         {  //read operation queued (PENDING)
            HANDLE arl_evs_resume[] = { a_ev_read, ap_ev_cancel };
            //wait for event to be signalled
            if(ap_ev_cancel != NULL)
              im_retval = WaitForMultipleObjects(2, arl_evs_resume, FALSE, INFINITE);
            else
              im_retval = WaitForMultipleObjects(1, &a_ev_read, TRUE, INFINITE);

            switch(im_retval)
            {
              case WAIT_OBJECT_0:
              {
                //get number of bytes read in overlapped operation
                im_retval = GetOverlappedResult(ap_tun_dev,
                                                &ds_olap_read,
                                                (LPDWORD)aimp_bytes_read,
                                                FALSE);
                //return code indicating read completed
                return 0;
              }; break;
              case WAIT_OBJECT_0 + 1:
              {
                //return code indicating read aborted
                return 1;
              }; break;
            }
         }
         else
         {  //read failed
            sprintf(str_tun_last_err,
                    "Error while reading from Virtual Adapter. System Error: %d",
                    GetLastError());
            return -1;
         }
      }
      else
      {
         return 0;
      }

#elif defined HL_UNIX

      *aimp_bytes_read = read(ap_tun_dev, aucp_read_buff, imp_buff_len);
      if(*aimp_bytes_read < 0)
      {
    	  sprintf(str_tun_last_err,
    	  			   "m_readone_blk: errno = %d (%s)\n",
    	  			   errno,
    	  			   strerror(errno));
    	  return -1;
      }
      else
      {
    	  return 0;
      }

#endif //defined WIN32 || WIN64
}// m_readone_blk

int m_writeone_blk(TUNHANDLE ap_tun_dev, const unsigned char* aucp_write_buff, int imp_data_len, HANDLE ap_ev_cancel, int* aimp_bytes_written)
{
#if defined WIN32 || WIN64

   //make sure cancel event is non signalled
   if(ap_ev_cancel)
      ResetEvent(ap_ev_cancel);

   //check if there is already another write in progress
   if(WaitForMultipleObjects(1, &a_ev_write, TRUE, 0) == WAIT_OBJECT_0)
   {  //event is signalled: no writing being done
      //try to write
      ds_olap_write.Offset = 0;
      ds_olap_write.OffsetHigh = 0;
      im_retval = WriteFile(ap_tun_dev,
                             aucp_write_buff,
                             imp_data_len,
                             (LPDWORD)aimp_bytes_written,
                             &ds_olap_write);
      if(im_retval <= 0)
      {
         int iml_err = GetLastError();

         if(iml_err == ERROR_IO_PENDING)
         {  //write operation queued (PENDING)
            HANDLE arl_evs_resume[] = { a_ev_write, ap_ev_cancel };
            //wait for event to be signalled
            if(ap_ev_cancel != NULL)
              im_retval = WaitForMultipleObjects(2, arl_evs_resume, FALSE, INFINITE);
            else
              im_retval = WaitForMultipleObjects(1, &a_ev_write, TRUE, INFINITE);

            switch(im_retval)
            {
              case WAIT_OBJECT_0:
              {
                //get number of bytes written in overlapped operation
                im_retval = GetOverlappedResult(ap_tun_dev,
                                                &ds_olap_write,
                                                (LPDWORD)aimp_bytes_written,
                                                FALSE);
                //return code indicating write completed
                return 0;
              }
              case WAIT_OBJECT_0 + 1:
              {
                //return code indicating write aborted
                return 1;
              }
            }
         }
         else
         {  //write failed
            sprintf(str_tun_last_err,
                    "Error while writing to Virtual Adapter. System Error: %d",
                    GetLastError());
            return -1;
         }
      }
      else
      {
         return 0;
      }
   }
   else
   {  //pending write operation exists
      sprintf(str_tun_last_err,
              "Error while writing to Virtual Adapter. Pending write still incomplete.");
      return -1;
   }

#elif defined HL_UNIX

   *aimp_bytes_written = write(ap_tun_dev, aucp_write_buff, imp_data_len);
   if(*aimp_bytes_written < 0)
   {
	   sprintf(str_tun_last_err,
			   "m_writeone_blk: errno = %d (%s)\n",
			   errno,
			   strerror(errno));
	   return -1;
   }
   else
           return 0;

#endif //defined WIN32 || WIN64
}// m_writeone_blk

int m_close_tun(TUNHANDLE ap_tun_dev)
{
#if defined WIN32 || WIN64

   //close handle to file
   if(CloseHandle(ap_tun_dev))
   {
      return 0;
   }
   else
   {
      //close failed
      sprintf(str_tun_last_err,
              "Handle close failed. System Error: %d"
              ,GetLastError());
      return -1;
   }

#elif defined HL_UNIX

   im_retval = close(ap_tun_dev);
   if(im_retval < 0)
   {
	   sprintf(str_tun_last_err,
			   "m_close_tun: errno = %d (%s)\n",
			   errno,
			   strerror(errno));
	   return -1;
   }
   else
   {
	   return 0;
   }

#endif //defined WIN32 || WIN64
}// m_close_tun

char* m_tun_last_err()
{
   return str_tun_last_err;
}// m_tun_last_err

#ifdef B100818
/* added 29.11.08 KB - return the address of the INETA of the TUN adapter */
/* Alan Duca, please complete this - to-do */
/* TODO: This should not be hardcoded. */
extern "C" char * m_get_wsptun_ineta_ipv4_adapter()
{
   static unsigned ipv4 = inet_addr("10.24.39.1");
   return (char*)&ipv4;
} /* end m_get_wsptun_ineta_ipv4_adapter()                             */
#endif

extern "C" BOOL m_calc_remote_ineta_ipv4(char *achp_local, char *achp_remote)
{
   char chl_a = achp_local[3] & 3;
   if (chl_a == 0 || chl_a == 3)
       return FALSE;

   *(long*)achp_remote = *(long*)achp_local;
   achp_remote[3] ^= 3;
   return TRUE;
}

///////////////////////////////////////////////////////
// HOB TUN ADAPTER INTERFACE
///////////////////////////////////////////////////////

static int m_get_ineta_ch( unsigned int *amp_ineta, char *achp_value );
static BOOL m_install_adapter( WCHAR *awcp_path_inf );
static int m_get_guid( char *achp_buffer, int imp_buf_len, int imp_instance_id );
static int m_vnic_get_interface( char *achp_out, int imp_out_len, char *achp_guid );
static int m_get_local_mac( char *, char * );

static int m_get_ineta_ch( unsigned int *amp_ineta, char *achp_value ) {
   BOOL       bol1;                         /* working variable        */
   int        iml1, iml2;                   /* working variables       */
   char       *achl_w1;                     /* working variable        */
   unsigned char chrl_ineta_w1[4];          /* INETA                   */

   iml1 = 0;                                /* first digit             */
   achl_w1 = achp_value;                    /* get value               */

   p_ineta_20:                              /* retrieve number of INETA */
   iml2 = 0;                                /* clear number            */
   bol1 = FALSE;                            /* no digit yet            */
   while ((*achl_w1 >= '0') && (*achl_w1 <= '9')) {
     iml2 *= 10;                            /* shift old value         */
     iml2 += *achl_w1 - '0';
     if (iml2 >= 256) return -1;
     achl_w1++;                             /* next digit              */
     bol1 = TRUE;                           /* digit found             */
   }
   if (bol1 == FALSE) return -1;            /* no digit found          */
   chrl_ineta_w1[ iml1++ ] = (unsigned char) iml2;
   if (iml1 == 4) {                         /* all parts set           */
     if (*achl_w1 != 0) return -1;          /* too many parts          */
     /* INETA decoded                                                  */
     *amp_ineta = *((unsigned int*) chrl_ineta_w1);
     return 0;                              /* all valid               */
   }
   if (*achl_w1 == '.') {                   /* separator found         */
     achl_w1++;                             /* next character          */
     goto p_ineta_20;                       /* retrieve number of INETA */
   }
   return -1;
} /* end m_get_ineta_ch()                                              */

#if defined WIN32 || WIN64
/** get TUN adapter, install or uninstall as requested                 */
BOOL m_proc_adapter( struct dsd_tun_ctrl *adsp_tun_ctrl,
                     BOOL bop_uninstall,
                     WCHAR* awcp_path_inf,
                     enum ied_strategy_inst_win_driver iep_siwd ) {  /* strategy install - uninstall Windows TUN driver */
   BOOL       bol1;                         /* working variable        */
   BOOL       bol_ret;                      /* return value            */
   BOOL       bol_pass_2;                   /* is second pass          */
   LONG       iml_rc;                       /* return value            */
   int        iml_instance_id;              /* instance id             */
   DWORD      dwl_index;                    /* index of adapters       */
   DWORD      dwl_error;                    /* error returned          */
   DWORD      dwl_len;                      /* length                  */
   HDEVINFO   dsl_h_info;
   HKEY       dsl_h_dev_reg;
   HANDLE     dsl_h_eve;
   SP_DEVINFO_DATA dsl_info_data;
   char       chrl_work1[ 512 ];            /* working variable        */
#ifdef XYZ1
/** test */
// int        iml_dummy;
// int        *aimp_adapter_no = &iml_dummy;
   BOOL       bop_delete_at_startup = TRUE;
#endif

   bol_ret = TRUE;                          /* return success          */
   adsp_tun_ctrl->imc_instance_id = 0;      /* no adapter found yet    */
   bol_pass_2 = FALSE;                      /* is second pass          */

   p_getada_00:                             /* start scanning adapters */

   /* Get all network adapters                                         */
   GUID dsl_classdevs = GUID_DEVCLASS_NET;
   dsl_h_info = SetupDiGetClassDevs( &dsl_classdevs, NULL, NULL, DIGCF_PRESENT );
#ifdef TRACEHL1
   m_hl1_printf( "xstuntapif-l%05d-T SetupDiGetClassDevs() returned %p.", __LINE__, dsl_h_info );
#endif
   if (dsl_h_info == INVALID_HANDLE_VALUE) {
     m_hl1_printf( "xstuntapif-l%05d-W SetupDiGetClassDevs() error %d.",
                   __LINE__, GetLastError() );
     return FALSE;
   }
   dwl_index = 0;                           /* clear index             */
   memset( &dsl_info_data, 0, sizeof(dsl_info_data) );
   dsl_info_data.cbSize = sizeof(SP_DEVINFO_DATA);

   p_getada_20:                             /* get next adapter        */
   bol1 = SetupDiEnumDeviceInfo( dsl_h_info, dwl_index, &dsl_info_data);
   if (bol1 == FALSE) {                     /* returned error          */
     dwl_error = GetLastError();            /* get last error          */
     if (dwl_error == ERROR_NO_MORE_ITEMS) {
       goto p_getada_80;                    /* end of adapters         */
     }
     m_hl1_printf( "xstuntapif-l%05d-W SetupDiEnumDeviceInfo() error %d.",
                   __LINE__, dwl_error );
     goto p_getada_80;                      /* end of adapters         */
   }
   dsl_h_dev_reg = SetupDiOpenDevRegKey( dsl_h_info, &dsl_info_data, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_READ );
   if (dsl_h_dev_reg == INVALID_HANDLE_VALUE) {  /* error occured      */
     m_hl1_printf( "xstuntapif-l%05d-W SetupDiOpenDevRegKey() error %d.",
                   __LINE__, GetLastError() );
     goto p_getada_60;                      /* end of this adapter     */
   }
   dwl_len = sizeof(chrl_work1);
   iml_rc = RegQueryValueExA( dsl_h_dev_reg, "ComponentId", NULL, NULL,
                              (BYTE *) chrl_work1, &dwl_len );
   if (iml_rc != ERROR_SUCCESS) {           /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W RegQueryValueExA() error %d.",
                   __LINE__, iml_rc );
     goto p_getada_40;                      /* close registry key      */
   }
#ifdef TRACEHL1
   m_hl1_printf( "xstuntapif-l%05d-T RegQueryValueExA( ... \"ComponentId\" ... () returned string \"%s\"",
                 __LINE__, chrl_work1 );
#endif
   if (strcmp( chrl_work1, "hobtun" )) {
     goto p_getada_40;                      /* close registry key      */
   }
#ifdef TRACEHL1
   printf( "xstuntapif-l%05d-T found adapter \"hobtun\" index %d.\n", __LINE__, dwl_index );
#endif
   dwl_len = sizeof(iml_instance_id);
   iml_rc = RegQueryValueExA( dsl_h_dev_reg, "InstanceId", NULL, NULL,
                              (BYTE *) &iml_instance_id, &dwl_len );
   if (iml_rc != ERROR_SUCCESS) {           /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W RegQueryValueExA() error %d.",
                   __LINE__, iml_rc );
     goto p_getada_40;                      /* close registry key      */
   }
   sprintf( chrl_work1, "\\\\.\\Global\\hobtun%d", iml_instance_id );
#ifdef NOT_YET_120828
   dsl_h_eve = CreateEventA( NULL, FALSE, FALSE, chrl_work1 );
#ifdef TRACEHL1
   m_hl1_printf( "xstuntapif-l%05d-T CreateEventA( ... , %s ) returned %p error %d.",
                 __LINE__, chrl_work1, dsl_h_eve, GetLastError() );
#endif
#else
   dsl_h_eve = CreateFileA( chrl_work1, GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ, 0, OPEN_EXISTING,
                            FILE_ATTRIBUTE_SYSTEM | FILE_FLAG_OVERLAPPED, 0 );
   if (dsl_h_eve == INVALID_HANDLE_VALUE) {
     m_hl1_printf( "xstuntapif-l%05d-W CreateFileA( %s ) failed. System Error: %d.",
                   __LINE__, chrl_work1, GetLastError() );
     goto p_getada_40;                      /* close registry key      */
   }
#endif
   while (dsl_h_eve != INVALID_HANDLE_VALUE) {  /* function succeeded  */
       if (   (adsp_tun_ctrl->imc_instance_id <= 0)              /* no adapter found yet    */
         && (bop_uninstall == FALSE)) {     /* is not uninstall        */
       adsp_tun_ctrl->imc_instance_id = iml_instance_id;        /* set adapter found       */
       adsp_tun_ctrl->dsc_handle = dsl_h_eve;   /* pass event opened       */
       if (   (bol_pass_2)                  /* is second pass          */
           || (iep_siwd == ied_siwd_no_inst_uninst)  /* no install or uninstall */
           || (iep_siwd == ied_siwd_only_inst)) {  /* only install when needed */
         goto p_getada_80;                  /* end of adapters         */
       }
       break;                               /* do not uninstall        */
     }
     bol1 = CloseHandle( dsl_h_eve );       /* close event again       */
     if (bol1 == FALSE) {                   /* error occured           */
       m_hl1_printf( "xstuntapif-l%05d-W CloseHandle() error %d.",
                     __LINE__, GetLastError() );
     }
     if (iep_siwd == ied_siwd_no_inst_uninst) break;  /* no install or uninstall */
     if (iep_siwd == ied_siwd_only_inst) break;  /* only install when needed */
     if (   (bop_uninstall == FALSE)        /* is not uninstall        */
         && (iep_siwd != ied_siwd_uninst_startup)) {  /* uninstall at startup */
       break;
     }
     /* uninstall the driver                                           */
// to-do 02.08.13 KB - routine is missing
     break;
   }

   p_getada_40:                             /* close registry key      */
   iml_rc = RegCloseKey( dsl_h_dev_reg );
   if (iml_rc != ERROR_SUCCESS) {           /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W RegCloseKey() error %d.",
                   __LINE__, iml_rc );
   }

   p_getada_60:                             /* end of this adapter     */
   dwl_index++;                             /* increment index         */
   goto p_getada_20;                        /* get next adapter        */

   p_getada_80:                             /* end of adapters         */
   bol1 = SetupDiDestroyDeviceInfoList( dsl_h_info );
   if (bol1 == FALSE) {                     /* returned error          */
     m_hl1_printf( "xstuntapif-l%05d-W SetupDiDestroyDeviceInfoList() error %d.",
                   __LINE__, GetLastError() );
   }
   while (   (adsp_tun_ctrl->imc_instance_id <= 0)  /* no adapter found yet    */
          && (bop_uninstall == FALSE)) {    /* is not uninstall        */
     if (iep_siwd == ied_siwd_no_inst_uninst) {  /* no install or uninstall */
       bol_ret = FALSE;                     /* return failed           */
       break;
     }
//   bol1 = m_install_adapter( dsl_h_info, "F:\\AKBIX1\\XBHPPPT3\\hobtun.inf" );
     bol_pass_2 = TRUE;                     /* is second pass          */
     bol1 = m_install_adapter( awcp_path_inf );
     if (bol1) {                            /* installation succeeded  */
       goto p_getada_00;                    /* start scanning adapters */
     }
     bol_ret = FALSE;                       /* return failed           */
     break;
   }
   return bol_ret;
} /* end m_proc_adapter()                                               */
#endif

#if defined WIN32 || WIN64
/** install the TUN driver                                             */
static BOOL m_install_adapter( WCHAR *awcp_path_inf ) {
// int        iml1, iml2;                   /* working variables       */
   BOOL       bol_rc;                       /* return value            */
   DWORD      dwl_reboot;
   HDEVINFO   dsl_h_info;
   HMODULE    dsl_h_dll;
#ifdef XYZ1
   HRESULT    dsl_h_res;
#endif
   amd_inst_sel_driver aml_install_selected_driver;
   GUID       dsl_class_guid;
   SP_DEVINFO_DATA dsl_dev_info_data;
   SP_DEVINSTALL_PARAMS_W dsl_dev_inst_params;
   WCHAR      wcrl_class_name[ MAX_CLASS_NAME_LEN * sizeof(WCHAR) ] = {0};
   char       chrl_hw_id_list[ LINE_LEN ];
   WCHAR      wcrl_inf_path[MAX_PATH * sizeof(WCHAR)] = {0};

   dsl_h_dll = LoadLibraryA( "newdev.dll" );
   if (dsl_h_dll == NULL) {                 /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W LoadLibraryA() error %d.",
                   __LINE__, GetLastError() );
     return FALSE;
   }
   aml_install_selected_driver = (amd_inst_sel_driver) GetProcAddress( dsl_h_dll, "InstallSelectedDriver" );
   if (aml_install_selected_driver == NULL) {  /* error occured        */
     m_hl1_printf( "xstuntapif-l%05d-W GetProcAddress() error %d.",
                   __LINE__, GetLastError() );
     FreeLibrary( dsl_h_dll );
     return FALSE;
   }

   bol_rc = GetFullPathNameW(awcp_path_inf, MAX_PATH, wcrl_inf_path, NULL);
   if (bol_rc == FALSE) {
     m_hl1_printf( "xstuntapif-l%05d-W GetFullPathNameA() error %d.",
                   __LINE__, GetLastError() );
     FreeLibrary( dsl_h_dll );
     return FALSE;
   }

#ifdef TRACEHL1
// printf( "hobtun_win-l%05d-T SetupDiGetINFClassA( %s , ... )\n", __LINE__, wcrl_inf_path );
#endif
   bol_rc = SetupDiGetINFClassW( wcrl_inf_path, &dsl_class_guid, wcrl_class_name, sizeof(wcrl_class_name), NULL );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W SetupDiGetINFClassA() error %d.",
                   __LINE__, GetLastError() );
     FreeLibrary( dsl_h_dll );
     return FALSE;
   }

   /* Create a container for the device that is to be installed        */
   dsl_h_info = SetupDiCreateDeviceInfoList( &dsl_class_guid, NULL );
   if (dsl_h_info == INVALID_HANDLE_VALUE) {  /* error occured         */
     m_hl1_printf( "xstuntapif-l%05d-W SetupDiCreateDeviceInfoList() error %d.",
                   __LINE__, GetLastError() );
     FreeLibrary( dsl_h_dll );
     return FALSE;
   }

   /* Create device element in the class                               */
   dsl_dev_info_data.cbSize = sizeof(SP_DEVINFO_DATA);
   bol_rc = SetupDiCreateDeviceInfoW( dsl_h_info, wcrl_class_name,
                                      &dsl_class_guid, NULL, NULL,
                                      DICD_GENERATE_ID, &dsl_dev_info_data );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W SetupDiCreateDeviceInfoA() error %d.",
                   __LINE__, GetLastError() );
     FreeLibrary( dsl_h_dll );
     return FALSE;
   }
   /* Select the device so that InstallSelectedDriver installs it.     */
   bol_rc = SetupDiSetSelectedDevice( dsl_h_info, &dsl_dev_info_data );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W SetupDiSetSelectedDevice() error %d.",
                   __LINE__, GetLastError() );
     FreeLibrary( dsl_h_dll );
     return FALSE;
   }
   memset( &dsl_dev_inst_params, 0, sizeof(dsl_dev_inst_params) );
   dsl_dev_inst_params.cbSize = sizeof(dsl_dev_inst_params);
   bol_rc = SetupDiGetDeviceInstallParamsW( dsl_h_info, &dsl_dev_info_data, &dsl_dev_inst_params );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W SetupDiGetDeviceInstallParamsA() error %d.",
                   __LINE__, GetLastError() );
     FreeLibrary( dsl_h_dll );
     return FALSE;
   }
   /* Only build the driver list out of the passed-in INF.             */
   dsl_dev_inst_params.Flags |= DI_ENUMSINGLEINF;
#ifdef XYZ1
   /* get part of achp_path_inf which is the path only                 */
   iml1 = iml2 = 0;                         /* clear indices           */
   while (TRUE) {                           /* loop over all characters */
     if (*(achp_path_inf + iml1) == 0) break;  /* zero-terminated      */
     if (*(achp_path_inf + iml1) == '\\') {  /* found backslash - directory */
       iml2 = iml1;                         /* save position last backslash */
     }
     iml1++;                                /* increment index         */
   }
// strcpy(ds_dev_inst_params.DriverPath, chrl_inf_path);
   memcpy( dsl_dev_inst_params.DriverPath, achp_path_inf, iml2 );
   *(dsl_dev_inst_params.DriverPath + iml2) = 0;  /* make zero-terminated */
#endif
   wcscpy( dsl_dev_inst_params.DriverPath, wcrl_inf_path );

   /* Add the HardwareID to the Device's HardwareID property.          */
#ifdef XYZ1
   memset( chrl_hw_id_list, 0, sizeof(chrl_hw_id_list) );
   dsl_h_res = StringCchCopyA( chrl_hw_id_list, LINE_LEN, "hobtun" );
   if (dsl_h_res != S_OK) {                 /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W StringCchCopyA() error %p.",
                   __LINE__, dsl_h_res );
     FreeLibrary( dsl_h_dll );
     return FALSE;
   }
   bol_rc = SetupDiSetDeviceRegistryPropertyA( dsl_h_info,
                                               &dsl_dev_info_data, SPDRP_HARDWAREID,
                                               (LPBYTE) chrl_hw_id_list, (DWORD) (lstrlen( chrl_hw_id_list ) + 2) );
#endif
   memset( chrl_hw_id_list, 0, sizeof(chrl_hw_id_list) );
   strcpy( chrl_hw_id_list, "hobtun" );
   bol_rc = SetupDiSetDeviceRegistryPropertyA( dsl_h_info,
                                               &dsl_dev_info_data, SPDRP_HARDWAREID,
//                                             (LPBYTE) chrl_hw_id_list, (DWORD) (strlen( chrl_hw_id_list ) + 2) );
                                               (LPBYTE) chrl_hw_id_list, (DWORD) sizeof( chrl_hw_id_list ) );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W SetupDiSetDeviceRegistryPropertyA() error %d.",
                   __LINE__, GetLastError() );
     FreeLibrary( dsl_h_dll );
     return FALSE;
   }

   dsl_dev_inst_params.FlagsEx |= DI_FLAGSEX_ALLOWEXCLUDEDDRVS;
   bol_rc = SetupDiSetDeviceInstallParamsW( dsl_h_info, &dsl_dev_info_data, &dsl_dev_inst_params );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W SetupDiSetDeviceInstallParams() error %d.",
                   __LINE__, GetLastError() );
     FreeLibrary( dsl_h_dll );
     return FALSE;
   }
#ifdef TRACEHL1
   m_hl1_printf( "xstuntapif-l%05d-T after SetupDiSetDeviceInstallParams() dsl_dev_inst_params", __LINE__ );
   m_console_out( (char *) &dsl_dev_inst_params, sizeof(dsl_dev_inst_params) );
   m_hl1_printf( "xstuntapif-l%05d-T &dsl_dev_info_data=%p &dsl_dev_inst_params=%p chrl_hw_id_list=%p.",
                 __LINE__, &dsl_dev_info_data, &dsl_dev_inst_params, chrl_hw_id_list );
#endif

   /* Build a list of compatible drivers.                              */
   bol_rc = SetupDiBuildDriverInfoList( dsl_h_info, &dsl_dev_info_data, SPDIT_COMPATDRIVER );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W SetupDiBuildDriverInfoList() error %d.",
                   __LINE__, GetLastError() );
     FreeLibrary( dsl_h_dll );
     return FALSE;
   }
#ifdef TRACEHL1
   m_hl1_printf( "xstuntapif-l%05d-T before SetupDiCallClassInstaller() dsl_dev_info_data", __LINE__ );
   m_console_out( (char *) &dsl_dev_info_data, sizeof(dsl_dev_info_data) );
#endif

   /* Pick the best driver in the list of drivers that was built.      */
   bol_rc = SetupDiCallClassInstaller( DIF_SELECTBESTCOMPATDRV, dsl_h_info, &dsl_dev_info_data );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W SetupDiCallClassInstaller() error %d.",
                   __LINE__, GetLastError() );
     FreeLibrary( dsl_h_dll );
     return FALSE;
   }

   /* Register our device.                                             */
   bol_rc = SetupDiCallClassInstaller( DIF_REGISTERDEVICE, dsl_h_info, &dsl_dev_info_data );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W SetupDiCallClassInstaller() error %d.",
                   __LINE__, GetLastError() );
     FreeLibrary( dsl_h_dll );
     return FALSE;
   }

   /* Install the device.                                              */
   bol_rc = aml_install_selected_driver( NULL, dsl_h_info, NULL, TRUE, &dwl_reboot );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W InstallSelectedDriver() error %d.",
                   __LINE__, GetLastError() );
     FreeLibrary( dsl_h_dll );
     return FALSE;
   }
// to-do 29.08.12 KB
    if (dwl_reboot & (DI_NEEDREBOOT | DI_NEEDRESTART))
    {
#ifdef XYZ1
        cout << "Error: Unable to properly initialize a new adapter. "
            << "A reboot is required before the HOBTUN driver can be used. "
            << "Please reboot the machine." << endl;
#endif
     FreeLibrary( dsl_h_dll );
        return FALSE;
    }

   bol_rc = FreeLibrary( dsl_h_dll );
   if (bol_rc == FALSE) {                   /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W FreeLibrary() error %d.",
                   __LINE__, GetLastError() );
     return FALSE;
   }
   return TRUE;
} /* end m_install_adapter()                                           */
#endif

#if defined WIN32 || WIN64
static int m_get_guid( char *achp_buffer, int imp_buf_len, int imp_instance_id ) {
   int        iml_rc;                       /* return code             */
   int        iml_len_name_1;               /* length of name one      */
// int        iml1;                         /* working variable        */
   int        iml_rg_item;                  /* enumerate items         */
   int        iml_instance_id = 0;          /* adapter InstanceID value */
   DWORD      dwl_len;                      /* pass length             */
   DWORD      dwl_data_type;                /* return data type        */
   HKEY       dsl_reg_h_1;                  /* registry handle         */
   HKEY       dsl_reg_h_2;                  /* registry handle         */
   char       chrl_key_1[ 4096 ];           /* space for key           */
   char       chrl_value_1[ 4096 ];         /* space for value         */

   strcpy( chrl_key_1, ADAPTER_KEY );
   iml_rc = RegOpenKeyExA( HKEY_LOCAL_MACHINE,
                           chrl_key_1,
                           0,
                           KEY_READ,
                           &dsl_reg_h_1 );
   if (iml_rc != ERROR_SUCCESS) {           /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-E RegOpenKeyExA() failed with code %d/%d.",
                   __LINE__, iml_rc, GetLastError() );
     return -1;
   }
   iml_len_name_1 = strlen( chrl_key_1 );   /* length of name one      */
   chrl_key_1[ iml_len_name_1++ ] = '\\';
   iml_rg_item = 0;                         /* enumerate items         */

   p_enum_00:                               /* enumerate items         */
   dwl_len = sizeof(chrl_key_1) - iml_len_name_1;  /* pass length      */
#ifdef TRACEHL1
   m_hl1_printf( "xstuntapif-l%05d-T before RegEnumKeyExA() dwl_len=%d/0X%X.",
                 __LINE__, dwl_len, dwl_len );
#endif
   iml_rc = RegEnumKeyExA( dsl_reg_h_1,
                           iml_rg_item,
                           &chrl_key_1[ iml_len_name_1 ],
                           &dwl_len,
                           NULL,
                           NULL,
                           NULL,
                           NULL );
#ifdef TRACEHL1
   m_hl1_printf( "xstuntapif-l%05d-T RegEnumKeyExA() returned dwl_len=%d/0X%X.",
                 __LINE__, dwl_len, dwl_len );
#endif
   if (iml_rc == ERROR_NO_MORE_ITEMS) {
     m_hl1_printf( "xstuntapif-l%05d-E No VNIC device is available.", __LINE__ );
     return -1;
   }
   if (iml_rc != ERROR_SUCCESS) {           /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-E RegEnumKeyExA() failed with code %d/%d.",
                   __LINE__, iml_rc, GetLastError() );
     RegCloseKey( dsl_reg_h_1 );
     return -1;
   }
   iml_rc = RegOpenKeyExA( HKEY_LOCAL_MACHINE,
                           chrl_key_1,
                           0,
                           KEY_READ,
                           &dsl_reg_h_2 );
   if (iml_rc == ERROR_ACCESS_DENIED) {     /* access denied           */
     iml_rg_item++;                         /* enumerate items         */
     goto p_enum_00;                        /* enumerate items         */
   }
   if (iml_rc != ERROR_SUCCESS) {           /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-E RegOpenKeyExA() failed with code %d/%d.",
                   __LINE__, iml_rc, GetLastError() );
     RegCloseKey( dsl_reg_h_1 );
     return -1;
   }
   dwl_len = sizeof(chrl_value_1);
   iml_rc = RegQueryValueExA( dsl_reg_h_2,
                              "ComponentId",
                              NULL,
                              &dwl_data_type,
                              (unsigned char *) chrl_value_1,
                              &dwl_len );
   if (iml_rc == ERROR_FILE_NOT_FOUND) {    /* error occured           */
     goto p_not_found;                      /* name not found          */
   }
   if (iml_rc != ERROR_SUCCESS) {           /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-E RegQueryValueExA() failed with code %d/%d.",
                   __LINE__, iml_rc, GetLastError() );
     RegCloseKey( dsl_reg_h_1 );
     RegCloseKey( dsl_reg_h_2 );
     return -1;
   }
#ifdef TRACEHL1
   m_hl1_printf( "xstuntapif-l%05d-T RegQueryValueExA( ... \"ComponentId\" ... ) returned \"%s\".",
                 __LINE__, chrl_value_1 );
#endif
   if (!strcmp( chrl_value_1, "hobtun" )) {
     dwl_len = sizeof(iml_instance_id);
     iml_rc = RegQueryValueExA( dsl_reg_h_2,
                                "InstanceId",
                                NULL,
                                NULL,
                                (BYTE *) &iml_instance_id,
                                &dwl_len );
     if (iml_rc == ERROR_FILE_NOT_FOUND) {    /* error occured           */
       goto p_not_found;                      /* InstanceIdnot found          */
     }
     if (iml_rc != ERROR_SUCCESS) {           /* error occured           */
       m_hl1_printf( "xstuntapif-l%05d-W RegQueryValueExA() error %d.",
                     __LINE__, iml_rc );
       RegCloseKey( dsl_reg_h_1 );
       RegCloseKey( dsl_reg_h_2 );
       return -1;
     }

     if (iml_instance_id == imp_instance_id) {
       goto p_found_00;                       /* adapter found           */
     }
   }

   p_not_found:                             /* name not found          */
   iml_rc = RegCloseKey( dsl_reg_h_2 );
   if (iml_rc != ERROR_SUCCESS) {           /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W RegCloseKey() failed with code %d/%d.",
                   __LINE__, iml_rc, GetLastError() );
   }
   iml_rg_item++;                           /* enumerate items         */
   goto p_enum_00;                          /* enumerate items         */

   p_found_00:                              /* adapter found           */
   dwl_len = imp_buf_len;
   iml_rc = RegQueryValueExA( dsl_reg_h_2,
                              "NetCfgInstanceId",
                              NULL,
                              &dwl_data_type,
                              (unsigned char *) achp_buffer,
                              &dwl_len );
   if (iml_rc != ERROR_SUCCESS) {           /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-E RegQueryValueExA() failed with code %d/%d.",
                   __LINE__, iml_rc, GetLastError() );
     RegCloseKey( dsl_reg_h_1 );
     RegCloseKey( dsl_reg_h_2 );
     return -1;
   }
   iml_rc = RegCloseKey( dsl_reg_h_2 );
   if (iml_rc != ERROR_SUCCESS) {           /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W RegCloseKey() failed with code %d/%d.",
                   __LINE__, iml_rc, GetLastError() );
   }
   iml_rc = RegCloseKey( dsl_reg_h_1 );
   if (iml_rc != ERROR_SUCCESS) {           /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W RegCloseKey() failed with code %d/%d.",
                   __LINE__, iml_rc, GetLastError() );
   }
   return dwl_len;
} /* end m_get_guid()                                                  */
#endif

#if defined WIN32 || WIN64
static int m_vnic_get_interface( char *achp_out, int imp_out_len, char *achp_guid ) {
   int        iml_rc;                       /* return code             */
   int        iml_repeat;                   /* clear times repeated    */
   DWORD      dwl_len;                      /* pass length             */
   DWORD      dwl_data_type;                /* return data type        */
   HKEY       dsl_reg_h_1;                  /* registry handle         */
   char       chrl_key_1[ 4096 ];           /* space for key           */

   sprintf( chrl_key_1, CONNECTION_KEY_MASK, achp_guid );
   iml_repeat = 0;                          /* clear times repeated    */
   while (TRUE) {
     iml_rc = RegOpenKeyExA( HKEY_LOCAL_MACHINE,
                             chrl_key_1,
                             0,
                             KEY_ALL_ACCESS,
                             &dsl_reg_h_1 );
#ifdef TRACEHL1
     m_hl1_printf( "xstuntapif-l%05d-T RegOpenKeyExA() returned %d %d.",
                   __LINE__, iml_rc, GetLastError() );
#endif
     if (iml_rc == ERROR_SUCCESS) break;    /* no error                */
     iml_repeat++;                          /* increment times repeated */
     if (iml_repeat >= DEF_REPEAT_SET_INETA) {
       m_hl1_printf( "xstuntapif-l%05d-E RegOpenKeyExA() failed %d times",
                     __LINE__, DEF_REPEAT_SET_INETA );
       return -1;
     }
     Sleep( DEF_SLEEP_SET_INETA );
   }
   iml_repeat = 0;                          /* clear times repeated    */
   while (TRUE) {
     dwl_len = imp_out_len;
     iml_rc = RegQueryValueExA( dsl_reg_h_1,
                                "Name",
                                NULL,
                                &dwl_data_type,
                                (unsigned char *) achp_out,
                                &dwl_len );
#ifdef TRACEHL1
     m_hl1_printf( "xstuntapif-l%05d-T RegQueryValueExA() returned %d %d.",
                    __LINE__, iml_rc, GetLastError() );
#endif
     if (iml_rc == ERROR_SUCCESS) break;    /* no error                */
     iml_repeat++;                          /* increment times repeated */
     if (iml_repeat >= DEF_REPEAT_SET_INETA) {
       m_hl1_printf( "xstuntapif-l%05d-E RegQueryValueExA() failed %d times",
                     __LINE__, DEF_REPEAT_SET_INETA );
       RegCloseKey( dsl_reg_h_1 );
       return -1;
     }
     Sleep( DEF_SLEEP_SET_INETA );
   }
   iml_rc = RegCloseKey( dsl_reg_h_1 );
   if (iml_rc != ERROR_SUCCESS) {           /* error occured           */
     m_hl1_printf( "xstuntapif-l%05d-W RegCloseKey() failed with code %d/%d.",
                   __LINE__, iml_rc, GetLastError() );
   }
#ifdef XYZ1
   sprintf( chrl_key_1, "netsh interface ip set address \"%s\" static %s 255.255.255.252",
            chrl_value_1, achp_local_ineta );
   iml_repeat = 0;                          /* clear times repeated    */
   while (TRUE) {
     iml_rc = system( chrl_key_1 );
#ifdef TRACEHL1
     printf( "xstuntapif-l%05d-T system() returned %d %d.\n",
             __LINE__, iml_rc, GetLastError() );
#endif
     if (iml_rc == 0) break;                /* no error                */
     iml_repeat++;                          /* increment times repeated */
     if (iml_repeat >= DEF_REPEAT_SET_INETA) {
       printf( "xstuntapif-l%05d-E system( netsh ... ) failed %d times\n",
               __LINE__, DEF_REPEAT_SET_INETA );
       return -1;
     }
     Sleep( DEF_SLEEP_SET_INETA );
   }
#endif
   return 0;                                /* all done                */
} /* end m_vnic_get_interface()                                            */
#endif

#if defined WIN32 || WIN64
static int m_get_local_mac( char *achp_buffer, char *achp_local_ineta ) {
   DWORD      dwl_rc;                       /* return code             */
   char       *achl_buffer;                 /* buffer for adapter information */
   unsigned long int uml_len_buffer;        /* length of buffer        */
   PIP_ADAPTER_INFO adsl_ai_w1;             /* adapter info            */
   PIP_ADDR_STRING adsl_as_w1;              /* adapter string          */

   achl_buffer = NULL;                      /* buffer for adapter information */
   uml_len_buffer = 0;                      /* length of buffer        */
   dwl_rc = GetAdaptersInfo( (PIP_ADAPTER_INFO) achl_buffer, &uml_len_buffer );
   if (dwl_rc != ERROR_BUFFER_OVERFLOW) {
     m_hl1_printf( "xstuntapif-l%05d-W GetAdaptersInfo() failed with code %d/%d.",
                   __LINE__, dwl_rc, GetLastError() );
     return -1;
   }
   achl_buffer = (char *) malloc( uml_len_buffer );
   dwl_rc = GetAdaptersInfo( (PIP_ADAPTER_INFO) achl_buffer, &uml_len_buffer );
   if (dwl_rc != NO_ERROR) {
     m_hl1_printf( "xstuntapif-l%05d-W GetAdaptersInfo() failed with code %d/%d.",
             __LINE__, dwl_rc, GetLastError() );
     free( achl_buffer );
     return -1;
   }
   adsl_ai_w1 = (PIP_ADAPTER_INFO) achl_buffer;  /* adapter info       */

   p_adapter_20:                            /* loop over the adapters  */
   adsl_as_w1 = &adsl_ai_w1->IpAddressList;
   do {                                     /* loop over list          */
     if (!strcmp( adsl_as_w1->IpAddress.String, achp_local_ineta )) {
       memcpy( achp_buffer, adsl_ai_w1->Address, adsl_ai_w1->AddressLength );
       break;
     }
     adsl_as_w1 = adsl_as_w1->Next;         /* get next in chain       */
   } while (adsl_as_w1);
   if (adsl_as_w1 == NULL) {                /* not this adapter        */
     adsl_ai_w1 = adsl_ai_w1->Next;         /* get next in chain       */
     if (adsl_ai_w1) {                      /* check this one          */
       goto p_adapter_20;                   /* loop over the adapters  */
     }
   }
   free( achl_buffer );                     /* free memory again       */
   if (adsl_ai_w1 == NULL) {                /* adapter not found       */
     m_hl1_printf( "xstuntapif-l%05d-W m_get_local_mac() did not find INETA",
             __LINE__ );
     return -1;
   }
   return 0;                                /* all done                */
} /* end m_get_local_mac()                                             */
#endif

dsd_vnic::dsd_vnic()
{
#if defined _WIN32
    ads_impl = new dsd_win_intf;
#endif
} // dsd_vnic()

dsd_vnic::~dsd_vnic()
{
#if defined _WIN32
    delete ads_impl;
#endif
} // ~dsd_vnic

// Initializes the adapter
bool dsd_vnic::m_init_ipv4(char* astr_vnic_ip4, char* astr_vnic_mask, dsd_tun_ctrl* ads_tun_ctrl)
{
    bool bo_ret = true;

#if defined _WIN32
    bo_ret = ads_impl->m_init(astr_vnic_ip4, astr_vnic_mask, ads_tun_ctrl);
#else
    /*
    dsd_tun_intf_1 ds_tun_intf;
    ds_tun_intf.dsc_tunhandle = 0;

    in_addr ds_vnic_ip_one;
    memset(&ds_vnic_ip_one, 0, sizeof(ds_vnic_ip_one));
    inet_pton(AF_INET, astr_vnic_ip4, &ds_vnic_ip_one);
    memcpy(ds_tun_intf.chrc_ineta_locale, &(ds_vnic_ip_one.s_addr),
        sizeof(ds_tun_intf.chrc_ineta_locale));

    in_addr ds_vnic_mask;
    memset(&ds_vnic_mask, 0, sizeof(ds_vnic_mask));
    inet_pton(AF_INET, astr_vnic_mask, &ds_vnic_mask);
    memcpy(ds_tun_intf.chrc_netmask_1, &(ds_vnic_mask.s_addr), sizeof(ds_tun_intf.chrc_netmask_1));

    if(m_open_tun(&(ds_tun_intf.dsc_tunhandle), NULL, 0) != 0)
        bo_ret = false;
    if(bo_ret)
    {
        if(m_init_tun(&ds_tun_intf) != 0)
            bo_ret = false;
    }

    if(bo_ret)
        dsg_tun_hdl = ds_tun_intf.dsc_tunhandle;
    */
#endif

    return bo_ret;
} // m_init_ipv4


int dsd_vnic::m_read(byte* aby_buff, unsigned int um_max_read_size, unsigned int& um_bytes_read)
{
    int in_ret = 0;

    if (aby_buff)
    {
#if defined WIN32 || defined WIN64
        in_ret = ads_impl->m_read(aby_buff, um_max_read_size, um_bytes_read);
#else
        int32_t im_bytes_read = 0;
        in_ret = m_readone_blk(dsg_tun_ctrl.imc_fd_tun, aby_buff, um_max_read_size, NULL, &im_bytes_read);
        if(in_ret == 0)
            um_bytes_read = im_bytes_read;
#endif
    }

    return in_ret;
} // m_read

#if defined _WIN32
bool dsd_vnic::m_read_ex(byte* aby_buff, unsigned int um_buff_size, unsigned int& um_bytes_read,
    HANDLE a_handle)
{
    bool bo_ret = false;

    if (aby_buff)
        bo_ret = ((dsd_win_intf*)ads_impl)->m_read_ex(aby_buff, um_buff_size, um_bytes_read, a_handle);

    return bo_ret;
} // m_read_ex

#ifdef GRATUITOUSARP
struct dsd_vnic_garp
{
	char chrc_new_ipv4[4];
	char chrc_cur_ipv4[4];
	char chrc_mac[6];
	bool b_param_is_mac;
		/*true if caller is specifying the card's mac address as card identifier
		  false if caller is specifying the card's current ip address as card identifier*/
	ied_tun_driver_error ie_error_code;
};

#define IOCTL_VNIC_ID_GARP				 DEFINE_CTL_CODE(0x903)

bool dsd_vnic::m_send_garp(byte byr_new_ip[4], PIP_ADAPTER_INFO ads_cur_adp_info)
{

	return ads_impl->m_send_garp(byr_new_ip,ads_cur_adp_info);

	
}
/*bool dsd_vnic::m_send_garp(byte byr_new_ip[4], byte byr_ip[4], byte byr_mac[6], BOOL bo_param_is_mac)
{

	return ads_impl->m_send_garp(byr_new_ip,byr_ip,byr_mac,bo_param_is_mac);

	
}*/


IP_ADDRESS_STRING m_print_adapter_info(PIP_ADAPTER_INFO ads_cur_adp_info)
{
	IP_ADDR_STRING ads_ip_addr_list = ads_cur_adp_info->IpAddressList;
	PIP_ADDR_STRING ads_ip_addr =(PIP_ADDR_STRING) &ads_ip_addr_list;
	IP_ADDRESS_STRING ds_ip_string ;

	m_hl1_printf("current adapter name = %s, address length = %d\n",
		ads_cur_adp_info->AdapterName, ads_cur_adp_info->AddressLength);

	if(ads_cur_adp_info->AddressLength == 6)
	{
		m_hl1_printf("mac address = %x:%x:%x:%x:%x:%x\n", ads_cur_adp_info->Address[0],
							ads_cur_adp_info->Address[1],ads_cur_adp_info->Address[2],
							ads_cur_adp_info->Address[3],ads_cur_adp_info->Address[4],
							ads_cur_adp_info->Address[5]);
	}
	else
	{
		m_hl1_printf("address length is not 6 :: currently not handled\n");
	}

			
	while (ads_ip_addr != NULL)
	{
	   ds_ip_string = ads_ip_addr->IpAddress;
	   m_hl1_printf("ip address : %s\n", ds_ip_string.String);
	   ads_ip_addr = ads_ip_addr->Next;
	}

	switch(ads_cur_adp_info->Type)
	{
		case MIB_IF_TYPE_OTHER:
			m_hl1_printf("adapter type : Other ");
			break;
		
		case MIB_IF_TYPE_ETHERNET:
			m_hl1_printf("adapter type : Ethernet");
			break;

		case IF_TYPE_ISO88025_TOKENRING:
			m_hl1_printf("adapter type : Token Ring ");
			break;

		case MIB_IF_TYPE_PPP:
			m_hl1_printf("adapter type : PPP ");
			break;

		case MIB_IF_TYPE_LOOPBACK:
			m_hl1_printf("adapter type : Loopback ");
			break;

		case MIB_IF_TYPE_SLIP:
			m_hl1_printf("adapter type : SLIP ");
			break;

		case IF_TYPE_IEEE80211:
			m_hl1_printf("adapter type : IEEE80211 ");
			break;

		default :
			m_hl1_printf("adapter type : unknown");

	}

	return ds_ip_string;
}

void m_add_mac_to_garp(dsd_vnic_garp *ads_garp,PIP_ADAPTER_INFO ads_cur_adp_info )
{	
	unsigned int um_count;

	for(um_count =0; um_count < ads_cur_adp_info->AddressLength; um_count++)
	{
		ads_garp->chrc_mac[um_count] = ads_cur_adp_info->Address[um_count];
	}
	//m_hl1_printf("mac address to be included in GARP announcement");
}

void m_convert_ip_string_to_byte_array(char *ac_string, byte **aab_cur_ip)
{
	unsigned int um_count;
	char *ac_end;
	unsigned int um_cur_int;

	for (um_count = 0; um_count < 4; um_count++)
	{
	   ac_end = strchr(ac_string,'.');
	   *ac_end = '\0';
	   um_cur_int = atoi(ac_string);
	   *aab_cur_ip[um_count] = (byte) um_cur_int;
	   ac_string = (ac_end + 1);
	}
}

bool dsd_win_intf::m_send_garp(byte byr_new_ip[4], PIP_ADAPTER_INFO ads_cur_adp_info)
{
	BOOL bo_ret = TRUE;
	dsd_vnic_garp ds_garp;
	DWORD dw_bytes_returned = 0;

	memset(&ds_garp, 0, sizeof(dsd_vnic_garp));
	m_add_mac_to_garp(&ds_garp, ads_cur_adp_info);
	//setting the new ip within the structure to be passed to the driver
	for (unsigned int um_ip_count = 0; um_ip_count < 4; um_ip_count++)
		ds_garp.chrc_new_ipv4[um_ip_count] = byr_new_ip[um_ip_count];

	//bo_ret = DeviceIoControl(a_adapter_handle, IOCTL_VNIC_ID_GARP, &ds_garp,
           // sizeof(ds_garp), &ds_garp, sizeof(ds_garp), &dw_bytes_returned, NULL);

	return bo_ret ? true : false;

}

/*bool dsd_win_intf::m_send_garp(byte byr_new_ip[4], byte byr_ip[4], byte byr_mac[6], BOOL bo_param_is_mac)
{
    BOOL bo_ret = TRUE;
	dsd_vnic_garp ds_garp;
    DWORD dw_bytes_returned = 0;
	int m_num_adps;
    PIP_ADAPTER_INFO ads_adp_info = NULL;
	PIP_ADAPTER_INFO ads_cur_adp_info = NULL;
	byte ab_cur_ip[4];
	char *ac_start;
	IP_ADDRESS_STRING ds_ip_string;

	memset(&ds_garp, 0, sizeof(dsd_vnic_garp));

	//just a check to make sure there is at least one network adapter installed
	if (GetAdaptersInfo(ads_adp_info, &dw_bytes_returned) != ERROR_BUFFER_OVERFLOW)
        return false;

    m_num_adps = (dw_bytes_returned / sizeof(IP_ADAPTER_INFO)) + 1;
    m_hl1_printf("number of adapters = %d\n",m_num_adps );

	//ads_adp_info will contain a list of NIC info structures currently intalled on the host
    ads_adp_info = new IP_ADAPTER_INFO[m_num_adps];

    if (GetAdaptersInfo(ads_adp_info, &dw_bytes_returned) == NO_ERROR)
    {
        ads_cur_adp_info = ads_adp_info;

        while (ads_cur_adp_info)
        {	
			//printing some adapter info...only used for debuggging
			ds_ip_string =  m_print_adapter_info(ads_cur_adp_info);	

            if (bo_param_is_mac)
			{  //compare mac addresses : if they match include mac address in GARP info to be passed to driver
				if ((ads_cur_adp_info->Address[0] == byr_mac[0]) && (ads_cur_adp_info->Address[1] == byr_mac[1]) &&
					(ads_cur_adp_info->Address[2] == byr_mac[2]) && (ads_cur_adp_info->Address[3] == byr_mac[3]) &&
					(ads_cur_adp_info->Address[4] == byr_mac[4]) && (ads_cur_adp_info->Address[5] == byr_mac[5]))
				{
					m_add_mac_to_garp(&ds_garp,ads_cur_adp_info);
				}
			}
			else
			{ //compare ip addresses : if they match include MAC ADDRESS in GARP info to be passed to driver
				ac_start = ds_ip_string.String;		
				m_convert_ip_string_to_byte_array(ac_start,(unsigned char **)&ab_cur_ip);

				if ((ab_cur_ip[0] == byr_ip[0]) && (ab_cur_ip[1] == byr_ip[1]) &&
					 (ab_cur_ip[2] == byr_ip[2]) && (ab_cur_ip[3] == byr_ip[3]))
				{
					m_add_mac_to_garp(&ds_garp,ads_cur_adp_info);
				}
			}
            ads_cur_adp_info = ads_cur_adp_info->Next;
        }
    }

	//setting the new ip within the structure to be passed to the driver
	for (unsigned int um_ip_count = 0; um_ip_count < 4; um_ip_count++)
		ds_garp.chrc_new_ipv4[um_ip_count] = byr_new_ip[um_ip_count];

	bo_ret = DeviceIoControl(a_adapter_handle, IOCTL_VNIC_ID_GARP, &ds_garp,
            sizeof(ds_garp), &ds_garp, sizeof(ds_garp), &dw_bytes_returned, NULL);

	return bo_ret ? true : false;
}*/
// m_send_arp
#endif

int dsd_vnic::m_get_read_ex_result(int in_wait_for_multiple_objects_result,
    unsigned int& um_bytes_read, HANDLE a_handle)
{
    return ((dsd_win_intf*)ads_impl)->m_get_read_ex_result(in_wait_for_multiple_objects_result,
        um_bytes_read, a_handle);
} // m_get_read_ex_result
#endif


int dsd_vnic::m_write(byte* aby_buff, unsigned int um_buf_size, unsigned int &um_bytes_written)
{
    int in_ret = 0;

    if (aby_buff)
    {
#if defined WIN32 || defined WIN64
        in_ret = ads_impl->m_write(aby_buff, um_buf_size, um_bytes_written);
#else
        int32_t im_bytes_written = 0;
        in_ret = m_writeone_blk(dsg_tun_ctrl.imc_fd_tun, aby_buff, um_buf_size, NULL, &im_bytes_written);
        if(in_ret == 0)
            um_bytes_written = im_bytes_written;
#endif
    }

    return in_ret;
} // m_write

int dsd_vnic::m_write(dsd_vector* ads_vector, int in_count)
{
    int in_ret = 0;

    if (ads_vector)
    {
#if defined WIN32 || defined WIN64
        in_ret = ads_impl->m_write(ads_vector, in_count);
#else
        in_ret = writev(dsg_tun_ctrl.imc_fd_tun, (iovec*)ads_vector, in_count);
        if (in_ret == 0 || in_ret == -1)
            in_ret = -1;
        else
            in_ret = 0;
#endif
    }

    return in_ret;
} // m_write

#if defined _WIN32
int dsd_vnic::m_get_fd()
{
    int im_ret = 0;

    return im_ret;
} // m_get_fd

char* dsd_vnic::m_get_devname()
{
    char* astr = NULL;

    return astr;
} // m_get_devname

unsigned int dsd_vnic::m_get_if_index()
{
    return ads_impl->m_get_if_index(ads_impl->um_ip);
} // m_get_if_index

// dsd_hobsrhlp_proc* dsd_vnic::m_get_prochlp()
// {
//     dsd_hobsrhlp_proc* ads_ret = NULL;

//     return ads_ret;
// } // m_get_prochlp

// dsd_tun_info* dsd_vnic::m_get_tun_info()
// {
//     dsd_tun_info* ads_ret = NULL;

//     return ads_ret;
// }

bool dsd_vnic::m_add_static_route_ipv4(char* ach_intranet, char* ach_mask, bool bo_single,
    char* ach_proxy_gw)
{
    bool bo_ret = false;

    if (ach_intranet && ach_mask)
        bo_ret = ads_impl->m_add_static_route_ipv4(ach_intranet, ach_mask, bo_single, ach_proxy_gw);

    return bo_ret;
} // m_add_static_route_ipv4

bool dsd_vnic::m_remove_static_route_ipv4(char* ach_ip, char* ach_mask, bool bo_single,
    char* ach_proxy_gw, bool bo_del_route)
{
    bool bo_ret = false;

    if (ach_ip && ach_mask)
    {
        bo_ret = ads_impl->m_remove_static_route_ipv4(ach_ip, ach_mask, bo_single, ach_proxy_gw,
            bo_del_route);
    }

    return bo_ret;
} // m_remove_static_route_ipv4
#endif

unsigned int dsd_vnic::m_get_hook_ip()
{
#if defined WIN32 || defined WIN64
    return ads_impl->m_get_hook_ip();
#else
    return 0;
#endif
}

void dsd_vnic::m_terminating()
{
#if defined WIN32 || defined WIN64
    ads_impl->m_terminating();
#endif
} // m_terminating

void dsd_vnic::m_destroy()
{
}


#if defined WIN32 || defined WIN64
dsd_win_intf::dsd_win_intf()
{
    um_hook_ip = 0;
    a_adapter_handle = NULL;
    memset(chr_hook_ip, 0, sizeof(chr_hook_ip));
    a_cancel_event = CreateEventA(NULL, TRUE, FALSE, NULL);

    bo_ip6_installed = false; // m_is_ipv6_installed();
    bo_init_done = false;
} // dsd_win_intf

dsd_win_intf::~dsd_win_intf()
{
   map<HANDLE, OVERLAPPED*>::iterator pos;
   OVERLAPPED* ads_overlapped;

   while (!ds_read_ex_coll.empty())
   {
      pos = ds_read_ex_coll.begin();
      ads_overlapped = pos->second;
      delete ads_overlapped;
      ds_read_ex_coll.erase(pos);
   }

   CloseHandle(a_cancel_event);
} // ~dsd_win_intf

bool dsd_win_intf::m_init(char* astr_vnic_ip4, char* astr_vnic_mask, dsd_tun_ctrl* ads_tun_ctrl)
{
    return m_init_gen(astr_vnic_ip4, astr_vnic_mask, ads_tun_ctrl);
} // m_init

bool dsd_win_intf::m_init_gen(char* astr_vnic_ip4, char* astr_vnic_mask, dsd_tun_ctrl* ads_tun_ctrl)
{
    bool bo_ret = true;
    bool bo_installed = false;
    DWORD dw_written = 0;

    if (!ads_tun_ctrl)
    {
        m_hl1_printf( "xstuntapif-l%05d-W m_init_gen() received an invalid control structure.",
                      __LINE__);
        return false;
    }

    if (ads_tun_ctrl->dsc_handle == INVALID_HANDLE_VALUE || ads_tun_ctrl->dsc_handle == 0)
    {
        m_hl1_printf( "xstuntapif-l%05d-W m_init_gen() received an invalid handle.",
                      __LINE__);
        return false;
    }

    a_adapter_handle = ads_tun_ctrl->dsc_handle;

    // If the adapter was already inititalized we need to clean-up information
    // related to the previous initialization.

    BOOL bo_ioctl = DeviceIoControl(a_adapter_handle, IOCTL_VNIC_ID_ARP_DEL_ALL_ENDPTS, NULL,
            0, NULL, 0, &dw_written, NULL);
    if (!bo_ioctl)
    {
        m_hl1_printf("hobtun_win-l%05d-E m_add_arp_endpt(): DeviceIoControl(DEL_ALL_ENDPTS) failed"
            " with error %d.", __LINE__, GetLastError());
        bo_ret = false;
    }

    // Configure the adapter IP address.

    if (bo_ret)
        bo_ret = m_assign_ipv4(astr_vnic_ip4, astr_vnic_mask, NULL, ads_tun_ctrl->imc_instance_id);

    if (bo_installed && !bo_ret)
        m_terminating();
    else
        bo_init_done = true;

    return bo_ret;
} // m_init

bool dsd_win_intf::m_assign_ipv4(char* astr_vnic_ip, char* astr_vnic_mask, char* ach_new_name,
                                 int im_instance_id)
{
    bool bo_ret = true;
    char str_def_ip[] = DEFAULT_IP4;
    char str_def_mask[] = DEFAULT_IP4_MASK;
    char str_hook_ip[16] = {0};

#ifdef TRACEHL1
    m_hl1_printf( "hobtun_win-l%05d-T dsd_win_intf::m_assign_ip( %s , %s , %s ) called\n",
            __LINE__, astr_vnic_ip, astr_vnic_mask, ach_new_name );
#endif

    if (!astr_vnic_ip)
        astr_vnic_ip = str_def_ip;

    if (!astr_vnic_mask)
        astr_vnic_mask = str_def_mask;

    // GUIDs are 32 character hexadecimal strings. These are stored as unicode in the registry.
    char chr_guid[64] = {0};
    if (m_get_guid(chr_guid, sizeof(chr_guid), im_instance_id))
    {
        if (m_assign_static_ip(chr_guid, astr_vnic_ip, astr_vnic_mask, 5, 5000,
            ach_new_name, false) != S_OK)
        {
            bo_ret = false;
            m_hl1_printf( "xstuntapif-l%05d-E Failed to configure the TUN adapter IP address.",
                           __LINE__ );
        }
        else
        {
            um_ip = inet_addr(astr_vnic_ip);

            if (!m_calc_hook_ip(astr_vnic_ip, astr_vnic_mask, false))
            {
                bo_ret = false;
                m_hl1_printf( "xstuntapif-l%05d-E Failed to obtain the TUN adapter hook IP address.",
                              __LINE__ );
            }
            else
            {
                um_hook_ip = ntohl(um_hook_ip);
                in_addr ds_hook;
                ds_hook.s_addr = um_hook_ip;
                strcpy(str_hook_ip, inet_ntoa(ds_hook));
            }
        }
    }
    else
    {
        m_hl1_printf( "xstuntapif-l%05d-E Failed to obtain adapter GUID.",
                      __LINE__ );
    }

    if (bo_ret)
        bo_ret = m_add_arp_endpt(ied_et_ip, str_hook_ip, astr_vnic_mask, 0, false);

    return bo_ret;
} // m_assign_ipv4

/*
bool dsd_win_intf::m_enable_disable_proto(ied_proto ie_proto, char* ach_guid, bool bo_enable)
{
    bool bo_done = false;
    INetCfg* ads_netcfg = NULL;
    INetCfgLock* ads_lock = NULL;
    IEnumNetCfgComponent*     ads_enum_component = NULL;
    INetCfgComponent*         ads_component;
    INetCfgComponentBindings* ads_bindings;
    INetCfgBindingPath*       ads_binding_path;
    IEnumNetCfgBindingPath*   ads_enum_binding_path;
    ULONG ul_fetched = 0;
    LPWSTR awstr_client = NULL;
    LPWSTR awstr_display_name = NULL;
    wchar_t wcr_proto[11] = {0};
    wchar_t wcr_guid[64] = {0};

    if (ie_proto == ie_proto_ipv4)
        wcscpy(wcr_proto, L"ms_tcpip-");
    else
        wcscpy(wcr_proto, L"ms_tcpip6-");

    mbstowcs(wcr_guid, ach_guid, strlen(ach_guid));

    CoInitialize(NULL);

    HRESULT hres = CoCreateInstance(CLSID_CNetCfg, NULL, CLSCTX_SERVER, IID_INetCfg,
        (LPVOID*)&ads_netcfg);
    if (SUCCEEDED(hres))
    {
        hres = ads_netcfg->QueryInterface(IID_INetCfgLock, (LPVOID*)&ads_lock);
        if (hres == S_OK)
        {
            hres = ads_lock->AcquireWriteLock(5, L"hobtunintf", &awstr_client);
            if (hres == S_OK)
            {
                hres = ads_netcfg->Initialize(NULL);
                if (hres == S_OK)
                {
                    hres = ads_netcfg->EnumComponents(&GUID_DEVCLASS_NET, &ads_enum_component);
                    if (hres == S_OK)
                    {
                        while (true)
                        {
                            hres = ads_enum_component->Next(1, &ads_component, &ul_fetched);
                            if (hres == S_OK && ul_fetched == 1)
                            {
                                ads_component->GetBindName(&awstr_display_name);
                                if (!wcscmp(awstr_display_name, wcr_guid))
                                {
                                    CoTaskMemFree(awstr_display_name);
                                    hres = ads_component->QueryInterface(
                                        IID_INetCfgComponentBindings, (PVOID*)&ads_bindings);
                                    if (hres == S_OK)
                                    {
                                        hres = ads_bindings->EnumBindingPaths(EBP_ABOVE,
                                            &ads_enum_binding_path);
                                        if (hres == S_OK)
                                        {
                                            while (!bo_done)
                                            {
                                                hres = ads_enum_binding_path->Next(
                                                    1, &ads_binding_path, &ul_fetched);
                                                if (hres == S_OK && ul_fetched == 1)
                                                {
                                                    ads_binding_path->GetPathToken(&awstr_display_name);
                                                    if (!wcsncmp(awstr_display_name, wcr_proto,
                                                        wcslen(wcr_proto)))
                                                    {
                                                       ads_binding_path->Enable(bo_enable);
                                                       bo_done = true;
                                                    }
                                                    CoTaskMemFree(awstr_display_name);
                                                }
                                                else
                                                {
                                                    break;
                                                }

                                                if (bo_done)
                                                {
                                                    hres = ads_netcfg->Apply();
                                                    break;
                                                }
                                            }
                                        }
                                        ads_binding_path->Release();
                                    }
                                }
                                ads_component->Release();
                            }
                            break;
                        }
                        ads_component->Release();
                    }
                }
                if (awstr_client)
                    CoTaskMemFree(awstr_client);
            }
            ads_lock->ReleaseWriteLock();
        }
        ads_netcfg->Release();
    }

    return bo_done;
} // m_disable_proto
*/

// Calculate the adapter's next hop - used for route creation.
bool dsd_win_intf::m_calc_hook_ip(char* astr_ip, char* astr_mask, bool bo_ipv6)
{
    bool bo_ret = true;
    unsigned int um_min = 0;
    unsigned int um_max = 0;
    unsigned int um_passed_ip = 0;

    if (!astr_ip)
    {
        assert(false);
        bo_ret = false;
    }

    if (bo_ret)
    {
        if (!bo_ipv6 && !astr_mask)
        {
            assert(false);
            bo_ret = false;
        }
    }

    if (!bo_ipv6)
    {
        if (bo_ret)
        {
            unsigned int um_mask = htonl(inet_addr(astr_mask));
            um_passed_ip = htonl(inet_addr(astr_ip));

            unsigned int um_subnet = htonl(um_ip) & um_mask;

            unsigned int um_range = 0xFFFFFFFF - um_mask;
            um_min = um_subnet;
            um_max = um_subnet | um_range;

            if (um_passed_ip == um_min || um_passed_ip == um_max)
                bo_ret = false;
        }

        if (bo_ret)
        {
            if (um_passed_ip == um_min + 1)
                um_hook_ip = um_passed_ip + 1;
            else if (um_passed_ip == um_max - 1)
                um_hook_ip = um_passed_ip - 1;
            else
                um_hook_ip = um_passed_ip + 1;
        }
    }
    else if (bo_ret)
    {
        // Since the IPv6 address space is HUGE we will just take the next address and hope that the
        // IP address that was passed did not happen to be one less than an already assigned IP.

        memcpy(chr_hook_ip, astr_ip, sizeof(chr_hook_ip));

        if (chr_hook_ip[14] == 0xFE || chr_hook_ip[15] == 0xFF)
            chr_hook_ip[14]++;
        else
            chr_hook_ip[15]++;
    }

    return bo_ret;
} // m_calc_hook_ip

/*
bool dsd_win_intf::m_get_guid(char* ach_guid)
{
    bool bo_ret = false;

    assert(ach_guid);
    if (!ach_guid)
        return bo_ret;

    HKEY a_adapter_key = SetupDiOpenDevRegKey(dss_h_info, &dss_dev_info_data,
        DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_READ);
    if (a_adapter_key == INVALID_HANDLE_VALUE)
    {
        m_hl1_printf("hobtun_win-l%05d-E m_get_guid(): failed to obtain adapter registry key.",
            __LINE__);
        return bo_ret;
    }

    unsigned char uchr_comp_id[MAX_REG_VAL_SIZE];
    DWORD dw_len = MAX_REG_VAL_SIZE;
    DWORD dw_data_type;
    LONG il_ret = RegQueryValueExA(a_adapter_key, NET_CFG_INSTANCE_ID, NULL, &dw_data_type,
        uchr_comp_id, &dw_len);

    if (il_ret == ERROR_SUCCESS)
    {
#ifdef TRACEHL1
        m_hl1_printf( "hobtun_win-l%05d-T dsd_win_intf::m_get_guid() RegQueryValueExA( ... , \"NetCfgInstanceId\" , ... ) got \"%s\"\n",
                __LINE__, uchr_comp_id );
#endif
        memcpy(ach_guid, &uchr_comp_id, dw_len);
        bo_ret = true;
    }

    RegCloseKey(a_adapter_key);

    return bo_ret;
} // m_get_guid
*/

HRESULT dsd_win_intf::m_assign_static_ip(char* ach_guid, char* ach_ip, char* ach_mask,
    unsigned int um_tries, unsigned int um_wait, char* ach_new_name, bool bo_ipv6)
{
    // netsh is being used here because the IP helper API does not allow to set a single IP but
    // only allows adding an IP address to an interface. If, for example, an application
    // sets an IP address using a different method, and then the IP heler API is used (say after
    // the original application crashes), any routes added by the original application will still
    // present in the system. This would not be ideal.

    // netsh interface ip set address "<Connection Name>" static <ip> <mask>
    // IPv6:
    // netsh interface ipv6 set address "<Connection Name>" <ip>

    // Note that several operations need a retry mechanism. For example, the registry might still
    // not be updated with information about the VNIC just created. Therefore querying the registry
    // might fail. Windows does not seem to provide a notification mechanism by which we would be
    // informed that the operation (such as adding or removing VNICs, setting a VNIC's IP address,
    // etc) is complete; for this reason a delay is inserted between retries.

    HKEY a_conn_key;
    LONG il_ret;
    unsigned int um_tries_left;

    char chr_guid_str[64] = {0};
    char chr_conn_key[256] = {0};
    char chr_conn_name[256] = {0};
    dsd_os_sys_1 ds_os;
    ulong ul_conn_name_buf_size = sizeof(chr_conn_name);

    strcpy(chr_guid_str, ach_guid);
    sprintf(chr_conn_key, "SYSTEM\\CurrentControlSet\\Control\\Network\\"
        "{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection", chr_guid_str);

    um_tries_left = um_tries;

    while (chr_guid_str > 0)
    {
        il_ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, chr_conn_key, 0, KEY_ALL_ACCESS, &a_conn_key);
        if (il_ret == ERROR_SUCCESS)
            break;

        um_tries_left--;

        // Wait some time before retrying the operation.
        if (um_tries_left > 0)
            Sleep(um_wait);
    }

    if (il_ret == ERROR_SUCCESS)
    {
        um_tries_left = um_tries;
        DWORD dw_type = 0;

        while (um_tries_left > 0)
        {
            il_ret = RegQueryValueExA(a_conn_key, NAME, 0, &dw_type, (BYTE*)chr_conn_name,
                &ul_conn_name_buf_size);

            if (il_ret == ERROR_SUCCESS)
                break;

            um_tries_left--;

            // Wait some time before retrying the operation.
            if (um_tries_left > 0)
                Sleep(um_wait);
        }

        RegCloseKey(a_conn_key);
    }

    if (il_ret == ERROR_SUCCESS && !m_is_ip_already_assigned_to_adapter(chr_conn_name, bo_ipv6,
        ach_ip))
    {
        unsigned int um_size = 128 + (int)strlen(chr_conn_name);
        char* ach_buf = new char[um_size];
        il_ret = E_FAIL;

        if (bo_ipv6)
        {
            sprintf(ach_buf, "netsh interface ipv6 set address \"%s\" %s store=active",
                chr_conn_name, ach_ip);
        }
        else
        {
            sprintf(ach_buf, "netsh interface ip set address \"%s\" static %s %s store=active",
                chr_conn_name, ach_ip, ach_mask);
        }

#ifdef TRACEHL1
        m_hl1_printf( "hobtun_win-l%05d-T dsd_win_intf::m_assign_vnic_static_ip() call system( %s )\n", __LINE__, ach_buf );
#endif

        // Ensure that the required protocol is enabled and the unrequired one disabled.
        // m_enable_disable_proto(bo_ipv6 ? ie_proto_ipv6 : ie_proto_ipv4, ach_guid, true);

        // If an initialization has already been carried out, do not disable other protocols since
        // this could cause the previous initialization to stop working.
        // if (!bo_init_done)
        //    m_enable_disable_proto(bo_ipv6 ? ie_proto_ipv4 : ie_proto_ipv6, ach_guid, false);

        char chr_buf[1024] = {0};
        memset(&ds_os, 0, sizeof(ds_os));
        ds_os.achc_buffer = chr_buf;
        ds_os.imc_len_buffer = sizeof(chr_buf);

        um_tries_left = um_tries;
        while (um_tries_left > 0)
        {
            if (m_call_system_1(&ds_os, ach_buf) == 0)
            {
                if (ds_os.imc_proc_rc == 0)
                {
                    il_ret = ERROR_SUCCESS;
                    break;
                }
                else
                {
                    um_tries_left--;

                    // Wait for some time before retrying the operation.
                    if (um_tries_left > 0)
                        Sleep(um_wait);
                }
            }
        }

        delete[] ach_buf;
    }

    if (il_ret != ERROR_SUCCESS)
    {
        m_hl1_printf("hobtun_win-l%05d-E m_assign_static_ip(): assignment of %s failed "
            "with error: %s", __LINE__, ach_ip, ds_os.achc_buffer);
        return E_FAIL;
    }

    il_ret = m_set_forwarding(chr_conn_name, bo_ipv6);
    if (il_ret != ERROR_SUCCESS)
        return E_FAIL;

    if (ach_new_name)
    {
        il_ret = m_assign_connection_name(chr_conn_name, ach_new_name);
        if (il_ret != ERROR_SUCCESS)
            return E_FAIL;
    }

    return S_OK;
} // m_assign_static_ip

// Looks up the given ach_ip to see if it is assigned to the adapter name given in ach_conn_name.
// Supports both IPv4 and IPv6 (unicast addresses).
bool dsd_win_intf::m_is_ip_already_assigned_to_adapter(const char* ach_conn_name, bool bo_ipv6,
    const char* ach_ip)
{
    bool bo_ret = false;
    PIP_ADAPTER_ADDRESSES ads_adapter_addrs = NULL;
    PIP_ADAPTER_ADDRESSES ads_curr_adp = NULL;
    PIP_ADAPTER_UNICAST_ADDRESS ads_addr = NULL;
    SOCKADDR* ads_sockaddr;
    ULONG ul_sz = 0;
    int in_ret = 0;

    // Convert the connection name to wchar_t (required since the adapter descriptions in
    // IP_ADAPTER_ADDRESSES are in wchar_t).
    wchar_t wch_conn_name[255] = {0};
    size_t un_num_converted = 0;
    mbstowcs_s(&un_num_converted, wch_conn_name, sizeof(wch_conn_name) / 4, ach_conn_name,
        strlen(ach_conn_name));

    // Get a list of adapters and obtain the address information for the required family.
    in_ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_DNS_SERVER, NULL, ads_adapter_addrs, &ul_sz);
    if (in_ret == ERROR_BUFFER_OVERFLOW)
    {
        ads_adapter_addrs = new IP_ADAPTER_ADDRESSES[ul_sz];

        in_ret = GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_DNS_SERVER, NULL, ads_adapter_addrs,
            &ul_sz);
        if (in_ret == ERROR_SUCCESS)
        {
            ads_curr_adp = ads_adapter_addrs;

            // Find the adapter with the provided friendly name.
            while (ads_curr_adp)
            {
                if (!wcscmp(wch_conn_name, ads_curr_adp->FriendlyName))
                {
                    // Get a pointer to the list of Unicast addresses for the selected adapter.
                    ads_addr = ads_curr_adp->FirstUnicastAddress;

                    // Loop over all addresses for the given family or until the address is matched.
                    while (ads_addr)
                    {
                        ads_sockaddr = ads_addr->Address.lpSockaddr;

                        // Match the provided IP address with the current adapter's current
                        // address.
                        sockaddr_in* ads = (sockaddr_in*)ads_sockaddr;
                        char* ach_addr = inet_ntoa(ads->sin_addr);
                        if (!_stricmp(ach_addr, ach_ip))
                        {
                            // IP address is already set on the adapter; do not set again!
                            bo_ret = true;
                            break;
                        }

                        ads_addr = ads_addr->Next;
                    }
                    break;
                }
                else
                {
                    // Get the next adapter.
                    ads_curr_adp = ads_curr_adp->Next;
                }
            }
        }
        delete[] ads_adapter_addrs;
    }

    return bo_ret;
} // m_is_ip_already_assigned_to_adapter

LONG dsd_win_intf::m_assign_connection_name(char* ach_conn_name, char* ach_new_name)
{
    LONG il_ret = ERROR_SUCCESS;

    if ((ach_conn_name && strlen(ach_conn_name) <= 256) &&
        (ach_new_name && strlen(ach_new_name) <= 256))
    {
        unsigned int um_size = 128 + (int)strlen(ach_conn_name) + (int)strlen(ach_new_name);
        char* ach_buf = new char[um_size];

        sprintf(ach_buf, "netsh interface set interface name=\"%s\" newname=\"%s\"",
            ach_conn_name, ach_new_name);

#ifdef TRACEHL1
            m_hl1_printf( "hobtun_win-l%05d-T dsd_win_intf::m_assign_connection_name() call system( %s )\n", __LINE__, ach_buf );
#endif
        char chr_buf[1024] = {0};
        dsd_os_sys_1 ds_os;

        unsigned int um_tries_left = 5;
        while (um_tries_left > 0)
        {
            memset(&ds_os, 0, sizeof(ds_os));
            ds_os.achc_buffer = chr_buf;
            ds_os.imc_len_buffer = sizeof(chr_buf);

            if (m_call_system_1(&ds_os, ach_buf) == 0)
            {
                if (ds_os.imc_proc_rc == 0)
                {
                    il_ret = ERROR_SUCCESS;
                    break;
                }
                else
                {
                    um_tries_left--;

                    // Wait some time before retrying the operation
                    if (um_tries_left > 0)
                        Sleep(1000);
                }
            }
        }

        delete[] ach_buf;
    }

    return il_ret;
} // m_assign_connection_name

LONG dsd_win_intf::m_set_forwarding(char* ach_adapter_name, bool bo_ipv6)
{
    char chr_ip[] = "ip  ";
    if (bo_ipv6)
    {
        strcpy(chr_ip, "ipv6");
    }
    else
    {
        // IPv4 IP forwarding can only be set using netsh starting with Windows Vista.

        OSVERSIONINFO ds_os_ver;
        memset(&ds_os_ver, 0, sizeof(ds_os_ver));
        ds_os_ver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
        if (GetVersionEx(&ds_os_ver))
        {
            if (ds_os_ver.dwMajorVersion < 6)
                return ERROR_SUCCESS;
        }
        else
        {
            m_hl1_printf("hobtun_win-l%05d-E m_set_forwarding(): GetVersionEx() failed with",
                " error %d.", __LINE__, GetLastError());
        }
    }

    char chr_enable_forwarding[1024] = {0};
    sprintf(chr_enable_forwarding, "netsh interface %s set interface interface=\"%s\" "
        "forwarding=enabled", chr_ip, ach_adapter_name);

    unsigned int um_tries_left = 5;
    unsigned int um_wait = 1000;
    LONG il_ret = E_FAIL;

    while (um_tries_left > 0)
    {
        char chr_buf[1024] = {0};
        dsd_os_sys_1 ds_os;
        memset(&ds_os, 0, sizeof(ds_os));
        ds_os.achc_buffer = chr_buf;
        ds_os.imc_len_buffer = sizeof(chr_buf);

        if (m_call_system_1(&ds_os, chr_enable_forwarding) == 0)
        {
            if (ds_os.imc_proc_rc == 0)
            {
                il_ret = ERROR_SUCCESS;
                break;
            }
            else
            {
                um_tries_left--;

                // Wait some time before retrying the operation
                if (um_tries_left > 0)
                    Sleep(um_wait);
            }
        }
    }

    return il_ret;
} // m_set_forwarding

bool dsd_win_intf::m_close()
{
    return CloseHandle(a_adapter_handle) ? true : false;
} // m_close

int dsd_win_intf::m_read(byte* aby_buff, unsigned int um_buff_size, unsigned int& um_bytes_read)
{
    int in_ret = 0;
    unsigned int um_reset = 0;
    HANDLE a_read_event = CreateEventA(NULL, FALSE, TRUE, NULL);
    OVERLAPPED ds_read;
    ds_read.hEvent = a_read_event;
    ds_read.Offset = 0;
    ds_read.OffsetHigh = 0;

    if (a_cancel_event)
        um_reset = ResetEvent(a_cancel_event);

    in_ret = ReadFile(a_adapter_handle, aby_buff, um_buff_size, (LPDWORD)&um_bytes_read, &ds_read);
    if (in_ret <= 0)
    {
        if (GetLastError() == ERROR_IO_PENDING)
        {
            HANDLE resume_ev[] = { a_read_event, a_cancel_event};

            if (a_cancel_event)
                in_ret = WaitForMultipleObjects(2, resume_ev, FALSE, INFINITE);
            else
                in_ret = WaitForMultipleObjects(1, &a_read_event, TRUE, INFINITE);

            switch(in_ret)
            {
            case WAIT_OBJECT_0:
                if (GetOverlappedResult(a_adapter_handle, &ds_read, (LPDWORD)&um_bytes_read, FALSE))
                    in_ret = 0;
                break;

            case WAIT_FAILED:
            case WAIT_OBJECT_0 + 1:
                in_ret = 1;
                break;

            default:
                break;
            }
        }
        else
        {
            m_hl1_printf("hobtun_win-l%05d-E m_read(): ReadFile(): error %d.",
                __LINE__, GetLastError());
            in_ret = -1;
        }
    }
    else        // ReadFile() returned immediately
    {
        in_ret = 0;
    }

    CloseHandle(a_read_event);

    return in_ret;
} // m_read

// Allows an application to do the wait itself.
// Call m_get_read_ex_result() with the same handle after WaitForMutlipleObjects() returns.
// Returns true if the function succeeds. If false is returned use GetLastError().
// If ERROR_IO_PENDING is returned if the read was pended.
bool dsd_win_intf::m_read_ex(byte* aby_buff, unsigned int um_buff_size, unsigned int& um_bytes_read,
    HANDLE a_handle)
{
    // Set to 0 to indicate if data was available.
    // Upon return, if 0: no data was available, read pended.
    //                >0: data was available and was placed in aby_buff.
    um_bytes_read = 0;

    if (!a_handle || a_handle == INVALID_HANDLE_VALUE)
        return false;

    OVERLAPPED* ads_read = new OVERLAPPED;
    memset(ads_read, 0, sizeof(OVERLAPPED));
    ads_read->hEvent = a_handle;
    ds_read_ex_coll.insert(pair<HANDLE, OVERLAPPED*>(a_handle, ads_read));

    return ReadFile(a_adapter_handle, aby_buff, um_buff_size, (LPDWORD)&um_bytes_read,
        ads_read) ? true : false;
} // m_read_ex

// Processes input after WaitForMultipleObjects().
int dsd_win_intf::m_get_read_ex_result(int in_wait_for_multiple_objects_result,
    unsigned int& um_bytes_read, HANDLE a_handle)
{
    int in_ret = -1;
    OVERLAPPED* ads_read;
    um_bytes_read = 0;
    map<HANDLE, OVERLAPPED*>::iterator elem = ds_read_ex_coll.find(a_handle);

    if (elem != ds_read_ex_coll.end())
    {
        ads_read = elem->second;

        switch (in_wait_for_multiple_objects_result)
        {
        case WAIT_OBJECT_0:
            if (GetOverlappedResult(a_adapter_handle, ads_read, (LPDWORD)&um_bytes_read, FALSE))
            {
                ds_read_ex_coll.erase(a_handle);
                delete ads_read;
                in_ret = 0;
            }
            break;

        case WAIT_FAILED:
        case WAIT_OBJECT_0 + 1:
            in_ret = 1;
            break;

        default:
            in_ret = -1;
            break;
        }
    }
    return in_ret;
} // m_get_read_ex_result

// Writes an IP packet to the TUN adapter
int dsd_win_intf::m_write(byte* aby_buff, unsigned int um_buff_size, unsigned int& um_bytes_written)
{
    int in_ret = 0;
    um_bytes_written = 0;
    HANDLE a_write_event = CreateEventA(NULL, FALSE, TRUE, NULL);
    OVERLAPPED ds_write;    // Async write
    ds_write.hEvent = a_write_event;
    ds_write.Offset = 0;
    ds_write.OffsetHigh = 0;

    // Make sure cancel event is non signalled
    if (a_cancel_event)
        ResetEvent(a_cancel_event);

    if (aby_buff && um_buff_size >= 20)         // We need to have the IP header
    {
#ifdef TRACEHL1
        m_hl1_printf( "hobtun_win-l%05d-T dsd_win_intf::m_write() call WriteFile( ... , %d, ... )\n", __LINE__, um_buff_size );
#endif
        // Try to write
        in_ret = WriteFile(a_adapter_handle, aby_buff, um_buff_size, (LPDWORD)&um_bytes_written,
            &ds_write);
        if (in_ret <= 0)
        {
            if (GetLastError() == ERROR_IO_PENDING)
            {
                HANDLE arl_evs_resume[] = { a_write_event, a_cancel_event };

                if (a_cancel_event != NULL)
                    in_ret = WaitForMultipleObjects(2, arl_evs_resume, FALSE, INFINITE);
                else
                    in_ret  = WaitForMultipleObjects(1, &a_write_event, TRUE, INFINITE);

                switch (in_ret)
                {
                case WAIT_OBJECT_0:
                    in_ret  = GetOverlappedResult(a_adapter_handle, &ds_write,
                        (LPDWORD)&um_bytes_written, FALSE);
                    return 0;

                case WAIT_OBJECT_0 + 1:
                    return 1;
                }
            }
            else
            {
                m_hl1_printf("hobtun_win-l%05d-E m_write(): WriteFile(): error %d.",
                    __LINE__, GetLastError());
                ResetEvent(a_write_event);
                in_ret = -1;
            }
        }
        else
        {
            in_ret = 0;
        }
    }
    else
    {
        m_hl1_printf("hobtun_win-l%05d-E m_write(): Packet too short.", __LINE__);
        in_ret = -1;
    }

    CloseHandle(a_write_event);

    return in_ret;
}// m_write

int dsd_win_intf::m_write(dsd_vector* ads_vec, int in_count)
{
    BOOL bo_ret = FALSE;
    int in_ret = 0;
    DWORD dw_returned = 0;

#ifdef TRACEHL1
    m_hl1_printf( "hobtun_win-l%05d-T dsd_win_intf::m_write() call DeviceIoControl( ... , %d, ... )\n",
            __LINE__, in_count * sizeof(dsd_vector) );
#endif
    bo_ret = DeviceIoControl(a_adapter_handle, IOCTL_VNIC_WRITE_VECTOR, ads_vec,
        in_count * sizeof(dsd_vector), NULL, 0, &dw_returned, NULL);

    if (!bo_ret)
        in_ret = -1;

    return in_ret;
} // m_write

bool dsd_win_intf::m_add_arp_endpt(ied_endpoint_type ie_type, char* ach_intranet, char* ach_mask,
    unsigned int um_subnet_prefix, bool bo_ipv6)
{
    // Possible return codes returned by IOCTL_VNIC_ID_ARP_ADD_ENDPT:
    // ied_ec_no_error
    // ied_ec_alloc_failed

    BOOL bo_ret = TRUE;
    dsd_vnic_add_endpt ds_add_endpt;
    DWORD dw_bytes_returned = 0;

    assert(ie_type == ied_et_ip);
    memset(&ds_add_endpt, 0, sizeof(dsd_vnic_add_endpt));

    if (ie_type != ied_et_ip)
        bo_ret = FALSE;

    if (bo_ret)
    {
        ds_add_endpt.ie_error_code = ied_tde_noerror;
        ds_add_endpt.ds_endpt.iec_type = ie_type;

        if (bo_ipv6)
        {
            ds_add_endpt.ds_endpt.boc_use_ipv6 = true;
            ds_add_endpt.ds_endpt.imc_prefix_ipv6 = um_subnet_prefix;
            memcpy(ds_add_endpt.ds_endpt.chrc_ineta_ipv6, ach_intranet, 16);
        }
        else
        {
            ds_add_endpt.ds_endpt.boc_use_ipv4 = true;
            *((unsigned int*)ds_add_endpt.ds_endpt.chrc_ineta_ipv4) = inet_addr(ach_intranet);
            *((unsigned int*)ds_add_endpt.ds_endpt.chrc_mask_ipv4) = inet_addr(ach_mask);
        }

#ifdef TRACEHL1
        m_hl1_printf( "hobtun_win-l%05d-T dsd_win_intf::m_add_arp_endpt() call DeviceIoControl( ... , %d, ... )\n",
                __LINE__, sizeof(ds_add_endpt) );
#endif

        bo_ret = DeviceIoControl(a_adapter_handle, IOCTL_VNIC_ID_ARP_ADD_ENDPT, &ds_add_endpt,
            sizeof(ds_add_endpt), &ds_add_endpt, sizeof(ds_add_endpt), &dw_bytes_returned, NULL);
    }

    if (bo_ret && ds_add_endpt.ie_error_code != ied_tde_noerror)
    {
        assert(ds_add_endpt.ie_error_code == ied_tde_allocation_failed);
        bo_ret = false;
    }
    else if (!bo_ret)
    {
        m_hl1_printf("hobtun_win-l%05d-E m_add_arp_endpt(): DeviceIoControl():"
            " error %d.", __LINE__, GetLastError());
    }

    return bo_ret ? true : false;
} // m_add_arp_endpt

bool dsd_win_intf::m_del_arp_endpt(ied_endpoint_type ie_type, char* ach_intranet, char* ach_mask,
    unsigned int um_subnet_prefix, byte byr_next_hop_mac[6], bool bo_ipv6)
{
    // Possible return codes returned by IOCTL_VNIC_ID_ARP_ADD_ENDPT:
    // ied_ec_no_error
    // ied_ec_alloc_failed

    BOOL bo_ret = TRUE;
    dsd_vnic_add_endpt ds_add_endpt;
    DWORD dw_bytes_returned = 0;

    assert(ie_type == ied_et_ip);
    memset(&ds_add_endpt, 0, sizeof(dsd_vnic_add_endpt));

    if (ie_type != ied_et_ip)
        bo_ret = FALSE;

    if (bo_ret)
    {
        dsd_vnic_add_endpt ds_add_endpt;
        memset(&ds_add_endpt, 0, sizeof(dsd_vnic_add_endpt));

        ds_add_endpt.ie_error_code = ied_tde_noerror;
        ds_add_endpt.ds_endpt.iec_type = ie_type;

        if (bo_ipv6)
        {
            ds_add_endpt.ds_endpt.boc_use_ipv6 = true;
            ds_add_endpt.ds_endpt.imc_prefix_ipv6 = um_subnet_prefix;
            memcpy(ds_add_endpt.ds_endpt.chrc_ineta_ipv6, ach_intranet, 16);
            memcpy(ds_add_endpt.ds_endpt.chrc_mac, byr_next_hop_mac, 6);
        }
        else
        {
            ds_add_endpt.ds_endpt.boc_use_ipv4 = true;
            *((unsigned int*)ds_add_endpt.ds_endpt.chrc_ineta_ipv4) = inet_addr(ach_intranet);
            *((unsigned int*)ds_add_endpt.ds_endpt.chrc_mask_ipv4) = inet_addr(ach_mask);
            strncpy(ds_add_endpt.ds_endpt.chrc_mac, (const char*)byr_next_hop_mac, 6);
        }

        bo_ret = DeviceIoControl(a_adapter_handle, IOCTL_VNIC_ID_ARP_DEL_ENDPT, &ds_add_endpt,
            sizeof(ds_add_endpt), &ds_add_endpt, sizeof(ds_add_endpt), &dw_bytes_returned, NULL);
    }

    if (bo_ret && ds_add_endpt.ie_error_code != ied_tde_noerror)
    {
        assert(ds_add_endpt.ie_error_code == ied_tde_allocation_failed);
        bo_ret = false;
    }

    return bo_ret ? true : false;
} // m_del_arp_endpt

bool dsd_win_intf::m_add_static_route_ipv4(char* ach_intranet, char* ach_mask, bool bo_single,
    char* ach_proxy_gw)
{
#ifdef TRACEHL1
    m_hl1_printf( "hobtun_win-l%05d-T dsd_win_intf::m_add_static_route() called\n",
            __LINE__ );
#endif

    bool bo_ret = true;
    DWORD dw_ret = 0;
    unsigned int um_metric;

    bo_ret = m_get_if_metric(um_metric);
    if (bo_ret)
    {
        MIB_IPFORWARDROW ds_route;
        ds_route.dwForwardDest = inet_addr(ach_intranet);
        ds_route.dwForwardMask = inet_addr(ach_mask);
        ds_route.dwForwardNextHop = um_hook_ip;
        ds_route.dwForwardAge = INFINITE;
        ds_route.dwForwardIfIndex = m_get_if_index(um_ip);
        ds_route.dwForwardMetric1 = um_metric;
        ds_route.dwForwardMetric2 = -1;
        ds_route.dwForwardMetric3 = -1;
        ds_route.dwForwardMetric4 = -1;
        ds_route.dwForwardMetric5 = -1;
        ds_route.dwForwardNextHopAS = 0;
        ds_route.dwForwardPolicy = 0;
        ds_route.dwForwardProto = MIB_IPPROTO_NETMGMT;
        ds_route.dwForwardType = MIB_IPROUTE_TYPE_DIRECT;

        dw_ret = CreateIpForwardEntry(&ds_route);
        if (dw_ret != ERROR_SUCCESS && dw_ret != ERROR_OBJECT_ALREADY_EXISTS)
        {
            m_hl1_printf("hobtun_win-l%05d-E m_add_static_route_ipv4(): CreateIpForwardEntry():"
                " error %d.", __LINE__, dw_ret);
            bo_ret = false;
        }
    }

    if (bo_ret)
    {
        // WSP requires an extra ARP entry. Since the Virtual IP is part of the internal network,
        // this network needs to know that packets have to be passed to the real adapter of the
        // gateway on the internal network (instead of sending them directly). This proxy ARP entry
        // is used for this.

        // VPNv2 also needs an extra ARP entry (see ticket 21631). Since VPNv2 does know know the
        // address of the adapter attached to the intranet, some extra work has to be done.
        unsigned int um_proxy_if_index = 0;
        char chr_proxy_adapter[16] = {0};

        if (!ach_proxy_gw)
        {
            if (m_get_adp(ach_intranet, ach_mask, chr_proxy_adapter))
                ach_proxy_gw = chr_proxy_adapter;
        }

        if (ach_proxy_gw)
            um_proxy_if_index = m_get_if_index(inet_addr(ach_proxy_gw));

        if (um_proxy_if_index != 0)
        {
            dw_ret = CreateProxyArpEntry(inet_addr(ach_intranet), 0xFFFFFFFF, um_proxy_if_index);
            if (dw_ret != NO_ERROR && dw_ret != ERROR_OBJECT_ALREADY_EXISTS)
            {
                m_hl1_printf("hobtun_win-l%05d-E m_add_static_route_ipv4(): CreateProxyArpEntry():"
                    " error %d.", __LINE__, dw_ret);
                bo_ret = false;
            }
        }
        else if (ach_proxy_gw)
        {
            m_hl1_printf("hobtun_win-l%05d-E m_add_static_route_ipv4(): Failed to obtain interface"
                " index. Check the ach_proxy_gw parameter for correctness.", __LINE__);
            bo_ret = false;
        }
    }

    return bo_ret;
} // m_add_static_route_ipv4


bool dsd_win_intf::m_get_if_metric(unsigned int& um_metric_out)
{
    bool bo_ret = false;
    um_metric_out = 1;

    OSVERSIONINFO ds_os_ver;
    memset(&ds_os_ver, 0, sizeof(ds_os_ver));
    ds_os_ver.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    if (GetVersionEx(&ds_os_ver))
    {
        if (ds_os_ver.dwMajorVersion >= 6)
        {
            DWORD il_ret = 0;
            ULONG ul_size = 0;
            int im_tries = 5;

            while (im_tries > 0)
            {
                im_tries--;
                PMIB_IPFORWARDTABLE ads_route_table = NULL;

                il_ret = GetIpForwardTable(ads_route_table, &ul_size, 0);
                if (il_ret == ERROR_INSUFFICIENT_BUFFER)
                {
                    ads_route_table = new MIB_IPFORWARDTABLE[ul_size];
                    il_ret = GetIpForwardTable(ads_route_table, &ul_size, 0);
                    if (il_ret == NO_ERROR)
                    {
                        for (unsigned int i = 0; i < ads_route_table->dwNumEntries; i++)
                        {
                            if (ads_route_table->table[i].dwForwardDest == um_ip)
                            {
                                um_metric_out += (unsigned int)ads_route_table->table[i].dwForwardMetric1;
                                bo_ret = true;
                                break;
                            }
                        }
                    }
                    else
                    {
                        m_hl1_printf("hobtun_win-l%05d-E m_get_if_metric(): GetIpForwardTable():"
                            " error %d.", __LINE__, il_ret);
                    }

                    delete[] ads_route_table;
                    if (bo_ret)
                        break;
                    else
                        Sleep(1000);
                }
                else
                {
                    m_hl1_printf("hobtun_win-l%05d-E m_get_if_metric(): GetIpForwardTable():"
                        " error %d.", __LINE__, il_ret);
                }
            }
        }
        else
        {
            bo_ret = true;
        }
    }
    else
    {
        m_hl1_printf("hobtun_win-l%05d-E m_get_if_metric(): GetVersionEx(): error %d.",
            __LINE__, GetLastError());
    }

    if (!bo_ret)
    {
        m_hl1_printf("hobtun_win-l%05d-E m_get_if_metric(): failed to obtain interface index.",
            __LINE__);
    }

    return bo_ret;
} // m_get_if_metric

bool dsd_win_intf::m_remove_static_route_ipv4(char* ach_intranet, char* ach_mask, bool bo_single,
    char* ach_proxy_gw, bool bo_del_route)
{
    bool bo_ret = true;
    in_addr ds_next_hop;
    ds_next_hop.s_addr = um_ip;

    PMIB_IPFORWARDTABLE ads_route_table = NULL;
    PMIB_IPFORWARDROW ads_route = NULL;
    ulong ul_table_size = 0;
    unsigned int um_dest = inet_addr(ach_intranet);
    unsigned int um_mask = inet_addr(ach_mask);
    DWORD dw_ret = 0;

    dw_ret = GetIpForwardTable(ads_route_table, &ul_table_size, true);
    if (dw_ret != ERROR_INSUFFICIENT_BUFFER)
        return false;

    ads_route_table = new MIB_IPFORWARDTABLE[ul_table_size];
    if (GetIpForwardTable(ads_route_table, &ul_table_size, true) == NO_ERROR)
    {
        for (DWORD i = 0; i < ads_route_table->dwNumEntries; i++)
        {
            ads_route = &ads_route_table->table[i];

            if (ads_route->dwForwardDest == um_dest &&
                ads_route->dwForwardMask == um_mask &&
                ads_route->dwForwardNextHop == um_ip)
            {
                dw_ret = DeleteIpForwardEntry(ads_route);
                if (dw_ret != ERROR_SUCCESS)
                {
                    m_hl1_printf("hobtun_win-l%05d-E m_remove_static_route_ipv4():"
                        " DeleteIpForwardEntry(): error %d.", __LINE__, GetLastError());
                }
            }
        }
    }
    delete[] ads_route_table;

    if (bo_ret)
    {
        unsigned int um_proxy_if_index = 0;
        char chr_proxy_adapter[16] = {0};

        if (!ach_proxy_gw)
        {
            if (m_get_adp(ach_intranet, ach_mask, chr_proxy_adapter))
                ach_proxy_gw = chr_proxy_adapter;
        }

        if (ach_proxy_gw)
            um_proxy_if_index = m_get_if_index(inet_addr(ach_proxy_gw));

        if (um_proxy_if_index)
        {
            dw_ret = DeleteProxyArpEntry(um_dest, um_mask, um_proxy_if_index);
            if (dw_ret != ERROR_SUCCESS)
            {
                m_hl1_printf("hobtun_win-l%05d-E m_remove_static_route_ipv4():"
                    " DeleteProxyArpEntry(): error %d.", __LINE__, GetLastError());
            }
        }
    }

    return bo_ret;
} // m_remove_static_route_ipv4

bool dsd_win_intf::m_get_vnic_mac(byte* aby_mac)
{
    assert(aby_mac);
    if (!aby_mac)
        return false;

    bool bo_found = false;
    DWORD buf_len = 0;
    int im_num_adps = 0;
    PIP_ADAPTER_INFO ads_adp_info = NULL;
    PIP_ADAPTER_INFO ads = NULL;

    if (GetAdaptersInfo(ads_adp_info, &buf_len) != ERROR_BUFFER_OVERFLOW)
        return false;

    im_num_adps = (buf_len / sizeof(IP_ADAPTER_INFO)) + 1;
    ads_adp_info = new IP_ADAPTER_INFO[im_num_adps];

    if (GetAdaptersInfo(ads_adp_info, &buf_len) == NO_ERROR)
    {
        in_addr ds_vnic_ip;
        ds_vnic_ip.s_addr = um_ip;
        ads = ads_adp_info;

        while (ads)
        {
            PIP_ADDR_STRING ads_ipaddr_list = &ads->IpAddressList;
            while (ads_ipaddr_list)
            {
                if (!strcmp(ads_ipaddr_list->IpAddress.String, inet_ntoa(ds_vnic_ip)))
                {
                    memcpy(aby_mac, ads->Address, ads->AddressLength);
                    bo_found = true;
                    break;
                }
                ads_ipaddr_list = ads_ipaddr_list->Next;
            }

            if (bo_found)
                break;

            ads = ads->Next;
        }
    }

    delete[] ads_adp_info;

    return true;
} // m_get_vnic_mac

unsigned int dsd_win_intf::m_get_if_index(unsigned int um_if_ip)
{
    bool bo_found = false;
    unsigned int um_ret = 0;
    unsigned int um_tries  = 0;
    ULONG ul_size = 0;
    PMIB_IPADDRTABLE ads_net_table = NULL;
    PMIB_IPADDRROW ads_row = NULL;

    DWORD ret = GetIpAddrTable(ads_net_table, &ul_size, TRUE);
    if (ret != ERROR_INSUFFICIENT_BUFFER)
        return 0;

    ads_net_table = new MIB_IPADDRTABLE[ul_size];

    while (!bo_found)
    {
        ret = GetIpAddrTable(ads_net_table, &ul_size, TRUE);

        if (ret == NO_ERROR || ret == ERROR_NO_DATA)
        {
            for (DWORD i = 0; i < ads_net_table->dwNumEntries; i++)
            {
                ads_row = &ads_net_table->table[i];

                if (ads_row->dwAddr == um_if_ip)
                {
                    um_ret = ads_row->dwIndex;
                    bo_found = true;
                    break;
                }
            }
        }

        if (!bo_found && um_tries <= 5)
        {
            Sleep(1000);
            ++um_tries;
        }
        else if (!bo_found)
        {
            break;
        }
    }

    delete[] ads_net_table;

    return um_ret;
} // m_get_if_index

bool dsd_win_intf::m_get_adp(char* ach_intranet, char* ach_mask, char* ach_adp)
{
    bool bo_ret = false;

    if (!ach_adp)
        return false;

    DWORD buf_len = 0;
    int im_num_adps = 0;
    PIP_ADAPTER_INFO ads_adp_info = NULL;
    PIP_ADAPTER_INFO ads = NULL;

    if (GetAdaptersInfo(ads_adp_info, &buf_len) != ERROR_BUFFER_OVERFLOW)
        return false;

    im_num_adps = (buf_len / sizeof(IP_ADAPTER_INFO)) + 1;
    ads_adp_info = new IP_ADAPTER_INFO[im_num_adps];

    unsigned int um_intra = inet_addr(ach_intranet) & inet_addr(ach_mask);

    if (GetAdaptersInfo(ads_adp_info, &buf_len) == NO_ERROR)
    {
        ads = ads_adp_info;

        while (ads)
        {
            PIP_ADDR_STRING ads_ip_str = &ads->IpAddressList;
            while (ads_ip_str)
            {
                unsigned int um_adp_intra = inet_addr(ads_ip_str->IpAddress.String) & inet_addr(ach_mask);

                if (um_adp_intra == um_intra)
                {
                    strcpy(ach_adp, ads_ip_str->IpAddress.String);
                    bo_ret = true;
                    break;
                }
                ads_ip_str = ads_ip_str->Next;
            }

            if (bo_ret)
                break;

            ads = ads->Next;
        }
    }

    delete[] ads_adp_info;

    return bo_ret;
} // m_get_adp

unsigned int dsd_win_intf::m_get_hook_ip()
{
   return um_hook_ip;
}

void dsd_win_intf::m_terminating()
{
    if (a_adapter_handle)
    {
        DWORD dw_ret;
        DeviceIoControl(a_adapter_handle, IOCTL_VNIC_ID_ARP_DEL_ALL_ENDPTS,
            NULL, 0, NULL, 0, &dw_ret, NULL);
        SetEvent(a_cancel_event);
    }

    m_close();
    // ds_installer.m_uninstall();
} // m_terminating

#endif
