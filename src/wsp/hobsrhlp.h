#ifndef HOBSRHLP_H
#define HOBSRHLP_H

#define HOBSR_NAME  "hobsr"

#ifdef _LINUX
#include <net/if.h>
#include <sys/types.h>

#define HOB_IF_NAMESIZE  IF_NAMESIZE

typedef struct _dsd_tun_info
{
    int in_fd;
    char str_name[HOB_IF_NAMESIZE+1];
    char str_ip[16];
    char str_net_mask[16];
    int in_if_index;
} dsd_tun_info;

typedef struct _dsd_hobsrhlp_proc 
{
    pid_t ds_pid;
    int in_fd_proc;
    int in_idx_proc;
} dsd_hobsrhlp_proc;

#else

#define HOB_IF_NAMESIZE  16

typedef void dsd_tun_info;
typedef void dsd_hobsrhlp_proc;

#endif  // _LINUX

#ifdef __cplusplus
extern "C" {
#endif

dsd_hobsrhlp_proc* m_hobsrhlp_intf_start(char* str_path);
void m_hobsrhlp_intf_stop(dsd_hobsrhlp_proc* ads_prochlp);

int m_hobsrhlp_intf_get_raw_sock(dsd_hobsrhlp_proc* ads_prochlp,
    int in_protocol, int* ain_err);
int m_hobsrhlp_intf_bind_sock(dsd_hobsrhlp_proc* ads_prochlp, int in_sock_fd,
    unsigned us_sock_port, int* ain_err);
int m_hobsrhlp_intf_bindv2_sock(dsd_hobsrhlp_proc* ads_prochlp, int in_sock_fd,
    void* a_addr, int addr_len);
int m_hobsrhlp_intf_connect_sock(dsd_hobsrhlp_proc* ads_prochlp,
    int in_sock_fd, void* a_addr, int addr_len);
#ifndef _WIN32
int m_hobsrhlp_intf_unlink_sock(dsd_hobsrhlp_proc* ads_prochlp, char* ach_addr,
    int in_addr_len);
#endif

int m_hobsrhlp_intf_get_tun_if(dsd_hobsrhlp_proc* ads_prochlp,
    dsd_tun_info* ads_tun_info);
int m_hobsrhlp_intf_add_route(dsd_hobsrhlp_proc* ads_prochlp,
    dsd_tun_info* ads_tun_info, char* astr_network, char* astr_netmask,
    char* astr_error, int in_error_len);
int m_hobsrhlp_intf_del_route(dsd_hobsrhlp_proc* ads_prochlp,
    dsd_tun_info* ads_tun_info, char* astr_network, char* astr_netmask,
    char* astr_error, int in_error_len);

#ifdef __cplusplus
}
#endif

#endif  // HOBSRHLP_H
