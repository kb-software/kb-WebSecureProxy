//+-------------------------------------------------------------------+
//|                                                                   |
//| PROGRAM NAME: tun_WIN32API.h                                      |
//| -------------                                                     |
//|  Header file for HOB Utility function library for use with the    |
//|    TAP-Win32 virtual network adapter for Windows                  |
//|  Alan Duca 19.11.07                                               |
//|                                                                   |
//| COPYRIGHT:                                                        |
//| ----------                                                        |
//|  Copyright (C) HOB Germany 2007                                   |
//|  Copyright (C) HOB Germany 2009                                   |
//|                                                                   |
//+-------------------------------------------------------------------+

#include <stdio.h>
//#include <hobsrhlp.h>
#include <cassert>
#include <list>

#if defined WIN32 || defined WIN64
#include <windows.h>
#include <iphlpapi.h>
#elif defined HL_UNIX
#define HANDLE void*
#ifdef HL_FREEBSD
#include <sys/socket.h>
#endif
#include <net/if.h>
#include <arpa/inet.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>

//#include "types_defines.h"
#ifndef byte
#define byte unsigned char
#endif

#endif // defined WIN32 || WIN64
#include "hob-htcp-int-01.h"

#if defined WIN32 || WIN64
#define TUNHANDLE HANDLE
#elif defined HL_UNIX
#define TUNHANDLE int
extern TUNHANDLE dsg_tun_hdl;
#endif // defined WIN32 || WIN64

struct dsd_tun_intf_1 {             // TUN interface
   TUNHANDLE  dsc_tunhandle;        // TUN handle
   char       *achc_adapter_name;   // Adapter name
   char       chrc_ineta_locale[4]; // Local end-point
   char       chrc_ineta_remote[4]; // Remote end-point
   char       chrc_netmask_1[4];    // Network mask
};

#if defined WIN32 || WIN64
typedef BOOL (WINAPI *amd_inst_sel_driver) (__in HWND hwndParent,
        __in HDEVINFO DeviceInfoSet, __in LPCTSTR Reserved, __in BOOL Backup,
        __out PDWORD bReboot);
#endif

//
// Find a tun device on the system and get handle to it.
// This function looks through the windows registry in search for
// an available TAP-Win32 virtual adapter. It may either be used to
// return a handle to any one of a number of available virtual adapters,
// or to return a handle to a specific virtual adapter.
//
// @param   aap_tun_dev    Pointer to the virtual device handle. Initialised
//                         by this function.
// @param   strp_dev_name  Pointer to the beginning of a string. If this
//                         string is the empty string, then the function will
//                         return the handle to the first available virtual
//                         adapter it finds. Otherwise, the function will
//                         return the handle to the virtual device who's name
//                         corresponds to the value of this string.
// @param   imp_name_len   Specifies the size of the buffer pointed to by
//                         strp_dev_name.
// @return  An int which is 0 on success, and non-zero on faliure. Further
//          information about the reason af failure can be obtained by
//          calling m_tun_last_err().
//
int m_open_tun(TUNHANDLE* aa_tun_dev,
               char*      astr_dev_name,
               const int  imp_name_len);

//
// Configures a virtual device to work in TUN mode, as opposed to TAP mode.
// This function configures the local and remote endpoints of the virtual
// adapter to be used for the reading and writing of ip packets. It also
// configures the ip address and subnet mask for this device. Local and
// remote endpoints need to be configured in order for a TAP-Win32 adapter
// to operate in TUN mode. Additionally, the endpoints must be the two
// "middle" host addresses of any 255.255.255.252 subnet (eg.: 10.1.1.1 and
// 10.1.1.2 or 68.128.40.57 and 68.128.40.58).
//
// @param   ap_tun_dev      Handle to the virtual device to be configured.
//                          Obtainable by calling m_open_tun().
// @param   strp_dev_name   Name of the device being pointed to by
//                          ap_tun_dev (as listed in the "Control Panel").
// @param   strp_local_ep   The address of the local endpoint, in string
//                          representation. This is also the address which
//                          will be assigned to the virtual interface.
// @param   strp_remote_ep  The address of the remote endpoint, in string
//                          representation. Any ip packets directed to this
//                          address will be pushed to application level.
// @return  An int which is 0 on success, and non-zero on faliure. Further
//          information about the reason af failure can be obtained by
//          calling m_tun_last_err().
//
#ifdef B090317
int m_init_tun(const TUNHANDLE ap_tun_dev,
               const char*     strp_dev_name,
               const char*     strp_local_ep,
               const char*     strp_remote_ep);
#endif
int m_init_tun( struct dsd_tun_intf_1 * );

//
// Sets virtual adapter's status to "Connected".
// The status of an opened TAP-Win32 adapter is set to "Connected".
//
// @param   ap_tun_dev  Handle pointing to the device which should be
//                      assigned the "Connected" status.
// @return  An int which is 0 on success, and non-zero on faliure. Further
//          information about the reason af failure can be obtained by
//          calling m_tun_last_err().
//
int m_connect_tun(const TUNHANDLE ap_tun_dev);

//
// Read a single captured packet from the virtual device.
// A single call to this method causes the read of a single ip
// packet from the virtual device. If packets to be read are available,
// this function returns immediately. Otherwise, it enters blocking
// state until a packet has been read.
//
// @param   ap_tun_dev       Handle pointing to the device to be read from.
// @param   aucp_read_buff   Pointer to a buffer. This buffer will be populated
//                           by this function with data read from the virtual
//                           adapter. This buffer must be allocated and freed by
//                           the caller.
// @param   imp_buff_len     Length of the buffer pointed to by aucp_read_buff.
// @param   ap_ev_cancel     Event which, if signalled, will abort the read.
// @param   aimp_bytes_read  Pointer to an integer which will be set by this
//                           function to represent the number of bytes read from
//                           the virtual adapter.
// @return  An int which is >= 0 on success, and < 0 on faliure. Further
//          information about the reason af failure can be obtained by
//          calling m_tun_last_err(). If the read has been completed the call
//          returns 0. If the read has been aborted, the call returns 1.
//
int m_readone_blk(TUNHANDLE      ap_tun_dev,
                  unsigned char* aucp_read_buff,
                  int            imp_buff_len,
                  HANDLE         ap_ev_cancel,
                  int*           aimp_bytes_read);

//
// Write a single ip packet through the virtual device.
// A single call to this method writes a single ip packet to the network
// through the specified virtual device. Though this function operates in
// blocking mode (blocks execution until the packet has been completely written)
// it has been observed that this method does not slow down to accomodate the
// maximum throughput of the network (it has been observed that the sendto()
// Winsock method slows down to accomodate this). Therefore, packets are pushed
// to the system as fast as possible.
//
// @param   ap_tun_dev          Handle to the virtual adapter through which to
//                              write anip packet.
// @param   aucp_write_buff     Pointer to a buffer containing the ip packet to
//                              be written to the network.
// @param   imp_data_len        Number of bytes to be written to the network.
// @param   ap_ev_cancel        Event which, if signalled, will abort the write.
// @param   aimp_bytes_written  Pointer to an int specifying the number of bytes
//                              actually written to the network.
// @return  An int which is >= 0 on success, and < 0 on faliure. Further
//          information about the reason af failure can be obtained by
//          calling m_tun_last_err().  If the write has been completed the call
//          returns 0. If the write has been aborted, the call returns 1.
//
int m_writeone_blk(TUNHANDLE            ap_tun_dev,
                   const unsigned char* aucp_write_buff,
                   int                  imp_data_len,
                   HANDLE               ap_ev_cancel,
                   int*                 aimp_bytes_written);

//
// Closes an active virtual adapter.
// This function closes the specified virtual adapter, making it available
// once more. Any connections are note terminated gracefully.
//
// @param   ap_tun_dev  Handle to the virtual device to close and release.
// @return  An int which is 0 on success, and non-zero on faliure. Further
//          information about the reason af failure can be obtained by
//          calling m_tun_last_err().
//
int m_close_tun(TUNHANDLE ap_tun_dev);

//
// Returns a description of the last error caused by a tun_WIN32API function.
//
// @return  pointer to the error string.
//
char* m_tun_last_err();

///////////////////////////////////////////////////////
// HOB TUN ADAPTER INTERFACE
///////////////////////////////////////////////////////

#if defined WIN32 || WIN64
BOOL m_proc_adapter( struct dsd_tun_ctrl* adsp_tun_ctrl,
                     BOOL bop_uninstall, WCHAR* awcp_path_inf,
                     enum ied_strategy_inst_win_driver iep_siwd );
#endif

#if defined WIN32 || defined WIN64
// General typedefs
typedef int             int32_t;
typedef unsigned char   byte;
typedef unsigned short  uint16_t;
typedef unsigned int    uint32_t;
typedef unsigned long   ulong;
#endif

// Endpoint information
enum ied_endpoint_type
{
    ied_et_ip,
    ied_et_sn
};

// Structure used to pass non-contiguous data buffers to the driver.
struct dsd_vector
{
    char* ach_buf;      // Pointer to the size of the data
    size_t ul_size;     // Length of data
};

// Generic patform-specific class. This class will be derived from, and is pure
// virtual to force every platform to override the functions with their own
// implementation.

#if defined WIN32 || defined WIN64
class dsd_platform
{
public:
    unsigned int um_ip;

    virtual ~dsd_platform()
    {
    };

    // Initialize the adapter with the given IP address.
#if defined _LINUX || defined _BSD
    virtual bool m_init(char* astr_vnic_ip, char* astr_vnic_mask, bool bo_need_sr) = 0;
#else
    virtual bool m_init(char* astr_vnic_ip4, char* astr_vnic_mask,
        dsd_tun_ctrl* ads_tun_ctrl) = 0;
#endif

    // Write a single packet.
    virtual int m_write(byte* aby_buff, unsigned int um_buff_size, unsigned int& um_bytes_written) = 0;

    // Write gather structures.
    virtual int m_write(dsd_vector* ads_vec, int in_count) = 0;

    // Read a single packet.
    virtual int m_read(byte* aby_buff, unsigned int um_buff_size, unsigned int& um_bytes_read) = 0;

    // Adds a static route to hook packets for a specific intranet to the TUN adapter.
    virtual bool m_add_static_route_ipv4(char* ach_intranet, char* ach_mask, bool bo_single = false,
        char* ach_proxy_gw = NULL) = 0;

    // Remove a static route associated with the TUN adapter.
    virtual bool m_remove_static_route_ipv4(char* ach_ip, char* ach_mask, bool bo_single = false,
        char* ach_proxy_gw = NULL, bool bo_del_route = true) = 0;

    // Adds an IPv6 static route to hook packets for a specific intranet to the TUN adapter.
    virtual bool m_add_static_route_ipv6(char* ach_intranet, unsigned int um_prefix)
    {
        return false;
    };

    // Remove an IPv6 static route associated with the TUN adapter.
    virtual bool m_remove_static_route_ipv6(char* ach_intranet, unsigned int um_prefix)
    {
        return false;
    };

    // Manually add an ARP proxy entry (for when m_add_static route does not suffice).
    // virtual bool m_create_proxy_arp_entry(char* ach_ip, char* ach_netmask) = 0;

    // Manually remove an ARP proxy entry.
    // virtual bool m_remove_proxy_arp_entry(char* ach_ip, char* ach_netmask) = 0;

    // Retrieves the interface index for the TUN adapter.
    virtual unsigned int m_get_if_index(unsigned int um_if_ip) = 0;

    // Returns the file descriptor associated with the adapter
    virtual int m_get_fd() { return 0; };

    // Returns the device name associated with the adapter
    virtual char* m_get_devname() { return NULL; };

    // Returns hobsrhlp object
    // virtual dsd_hobsrhlp_proc* m_get_prochlp() { return NULL; };

    // Returns a pointer to the tun info object (used for FD_SET, etc).
    // virtual dsd_tun_info* m_get_tun_info() { return NULL; };

    // Check if IPv6 is installed.
    virtual bool m_is_ipv6_installed() { return false; };

    // IPv4: Obtain the "hooking IP" which needs to be used as the next hop address
    // when adding routes.
    virtual unsigned int m_get_hook_ip() { return 0; };

    // Cancels all pending reads and writes.
    virtual void m_terminating() = 0;

protected:
    unsigned int um_if_index;
    char chr_ipv6[16];

    dsd_platform()
    {
        um_ip = um_if_index = 0;
        memset(chr_ipv6, 0, sizeof(chr_ipv6));
    };

private:
    // Open a handle/file-descriptor to the adapter.
#if defined _LINUX || defined _BSD
    virtual bool m_open(char* astr_vnic_ip, char* astr_vnic_mask, bool bo_need_sr) = 0;
#endif

    // Close the handle/file-descriptor to the adapter.
    virtual bool m_close() = 0;
};

class dsd_win_intf : public dsd_platform
{
public:
    HANDLE a_adapter_handle;
    HANDLE a_cancel_event;

    dsd_win_intf();
    ~dsd_win_intf();

    // Initialize the adapter with the given IP address, mask and hook endpoint.
    bool m_init(char* astr_vnic_ip4, char* astr_vnic_mask, dsd_tun_ctrl* ads_tun_ctrl);

    // Read a single packet from the adapter. Uses IRP_MJ_READ.
    int m_read(byte* aby_buff, unsigned int um_buff_size, unsigned int& um_bytes_read);

    bool m_read_ex(byte* aby_buff, unsigned int um_buff_size, unsigned int& um_bytes_read,
       HANDLE a_handle);

    // Processes input after WaitForMultipleObjects().
    int m_get_read_ex_result(int in_wait_for_multiple_objects_result, unsigned int& um_bytes_read,
        HANDLE a_handle);

    // Write a single packet to the adapter. Uses IRP_MJ_WRITE.
    int m_write(byte* aby_buff, unsigned int um_buff_size, unsigned int& um_bytes_written);

    // Writes a single packet represented by a vector of dsd_vector to the adapter.
    int m_write(dsd_vector* ads_vec, int in_count);

    // Retreives the index associated with an interface. Returns 0 on error.
    unsigned int m_get_if_index(unsigned int um_if_ip);

    // Retrieves the metric associated with routes for a specific adapter.
    // Returns true on success, result is placed in um_metric_out.
    bool m_get_if_metric(unsigned int& um_metric_out);

    // Update ach_adp to reflect the name of the adapter which has an address on the given.
    bool m_get_adp(char* ach_intranet, char* ach_mask, char* ach_adp);

    // Adds an IPv4 static route to hook packets for a specific intranet to the
    // TUN adapter. Also allows for ARP proxying.
    bool m_add_static_route_ipv4(char* ach_intranet, char* ach_mask, bool bo_single = false,
        char* ach_proxy_gw = NULL);

    // Remove an IPv4 static route associated with the TUN adapter.
    bool m_remove_static_route_ipv4(char* ach_intranet, char* ach_mask, bool bo_single = false,
        char* ach_proxy_gw = NULL, bool bo_del_route = true);

    // IPv4: Obtain the "hooking IP" which needs to be used as the next hop address
    // when adding routes.
    unsigned int m_get_hook_ip();

    // Adds an IPv6 static route to hook packets for a specific intranet to the TUN adapter.
    // bool m_add_static_route_ipv6(char* ach_intranet, unsigned int um_prefix);

    // Remove an IPv6 static route associated with the TUN adapter.
    // bool m_remove_static_route_ipv6(char* ach_intranet, unsigned int um_prefix);

    // Check if IPv6 is installed.
    // bool m_is_ipv6_installed();

    // Manually add an ARP proxy entry (for when m_add_static route does not suffice).
    // bool m_create_proxy_arp_entry(char* ach_ip, char* ach_netmask);

    // Manually remove an ARP proxy entry.
    // bool m_remove_proxy_arp_entry(char* ach_ip, char* ach_netmask);

    void m_terminating();

private:
    // Set to true if IPv6 is installed on the machine.
    bool bo_ip6_installed;

    // Set to true if the adapter was successfully initialised at least once.
    bool bo_init_done;

    // Installation class
    // dsd_tun_installer ds_installer;

    // Async read - WaitForMultipleObjects() done by the caller.
    // map allows for multiple threads, the key is the handle.
    std::map<HANDLE, OVERLAPPED*> ds_read_ex_coll;

    // IPv4 address used to hook packets with.
    unsigned int um_hook_ip;

    // IPv6 address used to hook packets with.
    char chr_hook_ip[16];

    bool m_init_gen(char* astr_vnic_ip4, char* astr_vnic_mask, dsd_tun_ctrl* ads_tun_ctrl);

    // Assign an IPv4 address and mask to the adapter (called from m_init). Can also change the
    // connection name.
    bool m_assign_ipv4(char* astr_vnic_ip, char* astr_vnic_mask, char* ach_new_name,
        int im_interface_id);

    // Assign an IPv6 address and subnet prefix to the adapter (called from m_init). Can also
    // change the connection name.
    bool m_assign_ipv6(char* astr_vnic_ip, unsigned int um_subnet_prefix, char* ach_new_name);

    enum ied_proto
    {
        ie_proto_ipv4,
        ie_proto_ipv6
    };

    // Enables or disables the specified protocol binding from the installed adapter.
    // bool m_enable_disable_proto(ied_proto ie_proto, char* ach_guid, bool bo_enable);

    // Calculate the hook IP. Returns false if the given IP is invalid. Sets um_hook_ip or
    // chr_hook_ip.
    bool m_calc_hook_ip(char* astr_ip, char* astr_mask, bool bo_ipv6);

    // Close the handle/file-descriptor to the adapter.
    bool m_close();

    // Obtain the GUID of the virtual adapter.
    // bool m_get_guid(char* ach_guid);

    HRESULT m_assign_static_ip(char* ach_guid, char* ach_ip, char* ach_mask, unsigned int um_tries,
        unsigned int um_wait, char* ach_new_name, bool bo_ipv6);

    bool m_is_ip_already_assigned_to_adapter(const char* ach_conn_name, bool bo_ipv6,
        const char* ach_ip);

    LONG m_assign_connection_name(char* ach_conn_name, char* ach_new_name);

    LONG m_set_forwarding(char* ach_adapter_name, bool bo_ipv6);

    bool m_get_vnic_mac(byte* aby_mac);

    bool m_add_arp_endpt(ied_endpoint_type ie_type, char* ach_intranet, char* ach_mask,
        unsigned int um_subnet_prefix, bool bo_ipv6);

    bool m_del_arp_endpt(ied_endpoint_type ie_type, char* ach_intranet, char* ach_mask,
        unsigned int um_subnet_prefix, byte byr_next_hop_mac[6], bool bo_ipv6);

    // Declaration for pointers to RtlIpv6StringToAddressA().
    typedef LONG (NTAPI *a_ipv6_string_to_address)(__in char* S, __out char *Terminator,
        __out IN6_ADDR *Addr);

    // Declaration for pointers to RtlIpv6AddressToStringA().
    typedef LONG (NTAPI *a_ipv6_address_to_string)(__in const IN6_ADDR *Addr, __out char* S);
};
#endif // _WIN32

class dsd_vnic
{
public:
    dsd_vnic();
    ~dsd_vnic();

    // If astr_vnic_ip4 is provided, the IPv4 address will be set, otherwise a default,
    // hard-coded IP will be used (10.0.1.1).
    // If astr_vnic_mask is provided, the IPv4 mask will be set, otherwise a default,
    // hard-coded mask will be used (255.255.255.0).

    // Return Value:
    // True:  Initialization was successful.
    // False: Initialization not successful.
    bool m_init_ipv4(char* astr_vnic_ip4, char* astr_vnic_mask, dsd_tun_ctrl* ads_tun_ctrl);

    // If astr_vnic_ip6 is provided, the IPv6 address will be set, otherwise a default,
    // hard-coded IP will be used (2154:4567:89AB::1).
    // If a value for um_subnet_prefix is provided, the IPv6 prefix will be set, otherwise a default,
    // hard-coded prefix will be used (64).
    // ach_inf_path is used on Windows to specify the path to the HOBTUN INF file. The same folder
    // also needs to contain the HOBTUN driver. If this parameter is not specified, the current
    // folder is assumed to contain the INF file.
    // ach_inf_path. This cannot be more than MAX_PATH.
    // ach_new_name is used on Windows to specify the desired connection name.
    // ie_siwd controls how adapters are installed and uninstalled (Windows only).
    // bo_need_sr true if this is to be executed as non-superuser on Linux/BSD.
    // This function must be called before any other function calls.
    //
    // Return Value:
    // True:  Initialization was successful.
    // False: Initialization not successful.
#if defined WIN32 || WIN64
    bool m_init_ipv6(char* astr_vnic_ip6 = NULL, unsigned int um_subnet_prefix = 0,
        char* ach_inf_path = NULL, char* ach_new_name = NULL,
        ied_strategy_inst_win_driver ie_siwd = ied_siwd_uninst_all, bool bo_need_sr = false);
#endif

    // This function attempts an asynchronous read operation from the adapter.
    // When a packet is received, aby_buff will hold a copy of the packet.
    // um_max_read_size is the maximum amount of data to be read, and
    // um_bytes_read is the size of the data returned in aby_buff.
    //
    // Return Value:
    // -1: An error occured.
    // 1:  Read aborted.
    // 0:  Read successful.
    int m_read(byte* aby_buff, unsigned int um_max_read_size, unsigned int& um_bytes_read);

#ifdef _WIN32
    // Registers a read operation with the driver. The calling application is responsable of using
    // WaitForMultipleObjects() on a_read_handle and calling m_get_read_ex_result() upon return.
    //
    // Return Value: true: success.
    //               false: use GetLastError() to obtain error information.
    //                      If GetLastError() returns ERROR_IO_PENDING the function did not fail and
    //                      the read was pended.
    // um_bytes_read is used to indicate data received as follows:
    // Upon return, if 0: no data was available, read pended.
    //                >0: data was available and was placed in aby_buff.
    //
    // N.B: um_bytes_read is always set to 0 when the function is called. This is only applicable
    // for Windows.

    bool m_read_ex(byte* aby_buff, unsigned int um_buff_size, unsigned int& um_bytes_read,
        HANDLE a_handle);

    // Return Value:
    // -1: An error occured.
    // 1:  Read aborted.
    // 0:  Read successful.
    int m_get_read_ex_result(int in_wait_for_multiple_objects_result, unsigned int& um_bytes_read,
        HANDLE a_handle);
#endif

    // This function writes the contents of aby_buff to the driver.
    // If any pending writes are present, this function will wait until writing
    // again.
    // um_buf_size is the size of data inside aby_buff.
    // um_bytes_written is the amount of data copied to the driver.
    //
    // Return Value:
    // -1: An error occured.
    // 0:  Write successful.
    int m_write(byte* aby_buff, unsigned int um_buf_size, unsigned int& um_bytes_written);

    // This function writes buffers described by ads_vector to the TUN.
    // The data described by ads_vector is non-contiguous.
    // ads_vector is the first element of the array representing data to be written.
    // un_total_len is the total number of bytes in all elements of the array.
    //
    // Return Value:
    // -1: An error occured.
    // 0: Write successful.
    int m_write(dsd_vector* ads_vector, int in_count);

    // Returns the file descriptor associated with the adapter (not for
    // Windows).
    int m_get_fd();

    // Returns the device name associated with the adapter (not for Windows).
    char* m_get_devname();

    // Returns the index associated with the TUN adapter.
    unsigned int m_get_if_index();

    // Used by applications that need special rights to allow them to use
    // the special rights module for other purposes (for example, creating
    // sockets). Not implemented/needed for Windows.
    // dsd_hobsrhlp_proc* m_get_prochlp();

    // Returns a pointer to the dsd_tun_info structure. This may be required
    // for multiplexing I/O operations (FD_SET etc).
    // Not implemented for Windows.
    // dsd_tun_info* m_get_tun_info();

    // IPv4
    // This function adds a static route to the Operating System's routing table.
    // ach_intranet is the destination of the route.
    // ach_mask is the subnet mask for ach_intranet.
    // bo_single can be set to true to allow for a route to be created for a single IP if
    // the intranet is an IP (not network) but the mask is a network.
    //
    // Return value:
    // true:  Route addition successful.
    // false: Route addition failed.
    bool m_add_static_route_ipv4(char* ach_intranet, char* ach_mask, bool bo_single = false,
        char* ach_proxy_gw = NULL);

    // IPv4
    // This function removes a static route from the Operating System's routing table.
    // ach_intranet is the destination of the route.
    // ach_mask is the subnet mask for ach_intranet.
    //
    // Return value:
    // true:  Route removal successful.
    // false: Route removal failed.
    bool m_remove_static_route_ipv4(char* ach_intranet, char* ach_mask, bool bo_single = false,
        char* ach_proxy_gw = NULL, bool bo_del_route = true);

    // IPv6
    // This function adds a static route (non-persistant) to the Operating
    // System's routing table.
    // ach_intranet is the destination of the route.
    // um_prefix is the network prefix for ach_intranet.
    //
    // Return value:
    // true:  Route addition successful.
    // false: Route addition failed.
    bool m_add_static_route_ipv6(char* ach_intranet, unsigned int um_prefix);

    // IPv4: Obtain the "hooking IP" which needs to be used as the next hop address
    // when adding routes.
    unsigned int m_get_hook_ip();

    // IPv6
    // This function removes a static route (non-persistant) from the Operating
    // System's routing table.
    // ach_intranet is the destination of the route.
    // um_prefix is the network prefix for ach_intranet.
    //
    // Return value:
    // true:  Route removal successful.
    // false: Route removal failed.
    bool m_remove_static_route_ipv6(char* ach_intranet, unsigned int um_prefix);

    // Checks if IPv6 is installed.
    //
    // Return value:
    // true: IPv6 is installed.
    // false: IPv6 is uninstalled.
    bool m_is_ipv6_installed();

    // Create a proxy ARP entry. Should only be used when m_add_static_route_ipv4) cannot create
    // such entries. One such case is having a 32 bit network mask but requiring automatic
    // adapter selection.
    // ach_ip is the IP address to do the proxying for.
    // ach_netmask is the network mask for ach_ip (the mask of the network and not of the IP).
    //
    // Return value:
    // true: Proxy ARP addition successful.
    // false: Proxy ARP addition failed.
    bool m_create_proxy_arp_entry(char* ach_ip, char* ach_netmask);

    // Remove a proxy ARP entry that was created with m_create_proxy_arp_entry().
    // ach_ip is the IP address to do the proxying for.
    // ach_netmask is the network mask for ach_ip (the mask of the network and not of the IP).
    //
    // Return value:
    // true: Proxy ARP removal successful.
    // false: Proxy ARP removal failed.
    bool m_remove_proxy_arp_entry(char* ach_ip, char* ach_netmask);

    // Notifies the interface that the application is terminating. This cancels
    // all pending actions.
    void m_terminating();

    // Destroys the interface.
    void m_destroy();

private:
    // Hides implementation details and makes usage far cleaner. There is no
    // real need to show the user a large list of private functions that will
    // never be used.

#if defined WIN32 || WIN64
    dsd_platform* ads_impl;
#endif
};

#if defined _WIN32
#define ETH_TYPE                            0x0008         // IPv4
#define ETH_FRAME_SIZE                      14             // Size of ethernet (MAC) header

#define DEFINE_CTL_CODE(a)                  CTL_CODE(FILE_DEVICE_UNKNOWN, a, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_VNIC_ID_ARP_ADD_ENDPT         DEFINE_CTL_CODE(0x900)
#define IOCTL_VNIC_ID_ARP_DEL_ENDPT         DEFINE_CTL_CODE(0x901)
#define IOCTL_VNIC_ID_ARP_DEL_ALL_ENDPTS    DEFINE_CTL_CODE(0x902)
#define IOCTL_VNIC_WRITE_VECTOR             DEFINE_CTL_CODE(0x9BA)

#define MAX_MAC_ADDRESS_LEN                 20
#define DEF_REPEAT_SET_INETA                4
#define DEF_SLEEP_SET_INETA                 50
#define DEFAULT_IP4                         "10.0.1.1"
#define DEFAULT_IP4_MASK                    "255.255.255.0"
#define HOB_TUN_NAME                        "\\\\.\\Global\\hobtun"

// Registry entries

#define NAME                "Name"
#define INSTANCE_ID         "InstanceId"
#define COMPONENT_ID        "ComponentId"
#define NET_CFG_INSTANCE_ID "NetCfgInstanceId"
#define CONNECTION_KEY_MASK "SYSTEM\\CurrentControlSet\\Control\\Network\\{4D36E972-E325-11CE-BFC1-08002BE10318}\\%s\\Connection"

typedef enum ied_tun_driver_error
{
    ied_tde_noerror = 0,
    ied_tde_unexpected,
    ied_tde_allocation_failed,
    ied_tde_mac_not_found,
} ied_tun_driver_error;

// Used for VNIC ARP proxying
struct dsd_vnic_endpt
{
    BOOL              boc_use_ipv4;
    BOOL              boc_use_ipv6;
    ied_endpoint_type iec_type;
    char              chrc_ineta_ipv4[4];
    char              chrc_mask_ipv4[4];
    char              chrc_ineta_ipv6[16];
    int               imc_prefix_ipv6;
    char              chrc_mac[6];
};

// Add endpoint structure for IO_CONTROL
struct dsd_vnic_add_endpt
{
    dsd_vnic_endpt ds_endpt;
    ied_tun_driver_error ie_error_code;
};

#endif // _WIN32
