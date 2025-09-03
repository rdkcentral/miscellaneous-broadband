#ifndef GW_STATS_COLLECTION_H
#define GW_STATS_COLLECTION_H

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <pcap.h>
#include <sysevent/sysevent.h>
#include "secure_wrapper.h"


#define LOG_FILE "/rdklogs/logs/gateway_stats_logs.txt"

//System Stats
// Structure to store PID details
typedef struct
{
    uint32_t   pid;
    char       pName[18];
    uint32_t   rss;
    uint32_t   pss;
    uint32_t   mem_util;
    uint32_t   cpu_util;
} pidStats;

// Structure to store system statistics
typedef struct system_stats {
    uint64_t timestamp_ms;
    char model[64];
    char firmware[128];
    char cmac[32];
    char uptime[64];
    double cpu_usage;
    double free_memory;
    double slab_memory;
    double avail_memory;
    double cached_mem;
    double slab_unreclaim;
    double loadavg_1min;
    double loadavg_5min;
    double loadavg_15min;
    uint32_t rootfs_used_kb;
    uint32_t rootfs_total_kb;
    uint32_t tmpfs_used_kb;
    uint32_t tmpfs_total_kb;
    int pid_stats_count;
    pidStats* pid_stats;
    struct system_stats *next;
} SystemStats;

//WAN stats
typedef struct wan_stats {
    uint64_t timestamp_ms;
    char interface_status[32];
    char ipv4_address[32];
    char ipv6_address[128];
    char gateway_status[32];
    double packet_loss;
    double latency;
    double jitter;
    double dns_time;
    char rx_bytes[64];
    char tx_bytes[64];
    char rx_dropped[64];
    char tx_dropped[64];
    char ipv4_lease[32];
    char ipv6_lease[32];
    struct wan_stats *next;
} WanStats;

//LAN Stats
// Structure to store client details
typedef struct {
    uint64_t timestamp_ms;
    char mac_address[32];
    char ip_addr[64];
    char host_name[64];
    char status[16];
    char tx_bytes[64];
    char rx_bytes[64];
    int  tcp_est_counts;
} ClientDetails;

// Structure to store LAN statistics
typedef struct lan_stats {
    uint64_t timestamp_ms;
    char ipv4_address[64];
    char ipv6_address[128];
    char rx_bytes[64];
    char tx_bytes[64];
    char rx_dropped[64];
    char tx_dropped[64];
    ClientDetails *clients;
    int client_count;
    struct lan_stats *next;
} LanStats;

//IPv6 Monitoring Stats
typedef struct ipv6_mon_stats {
    uint64_t timestamp_ms;
    char global_ipv6_address[128];
    char link_local_ipv6_address[128];
    char ipv6_reachability[32];
    double ipv4_latency;
    double ipv6_latency;
    double ipv4_packet_loss;
    double ipv6_packet_loss;
    struct ipv6_mon_stats *next;
} IPv6MonitoringStats;

//TCP Stats
typedef struct tcp_stats {
    uint64_t timestamp_ms;
    char TCPLostRetransmit[32];  //Retransmissions for packets that still didn’t get ACKed (true losses)
    char TCPRetransFail[32];     //Retransmissions that failed entirely (after all retries)
    char TCPSackFailures[32];    //SACK-based retransmissions that failed
    char TCPTimeouts[32];        //TCP connection timeouts (no ACK received in time)
    char TCPAbortOnTimeout[32];  //Connections aborted because of timeout
    char ListenOverflows[32];    //Times the socket backlog queue was full — client connections dropped
    char TCPOrigDataSent[32];    //Original bytes sent (useful for rate estimation)
    struct tcp_stats *next;
}TcpStats;

//Restart Count Stats
typedef struct {
    int fw_restart_count;
    char **fw_restart_time;
    int wan_restart_count;
    char **wan_restart_time;
}RestartCountStats;

// Function declarations
//System params
void initialize_system_stats(SystemStats *stats);
void initialize_restart_count_stats(RestartCountStats *stats);
void collect_system_stats(SystemStats *stats);

void get_cpu_usage(double *cpu_usage);
void get_memory_info(double *free_memory, double *slab_memory, double *avail_memory, double *cached_mem, double *slab_unreclaim);
void get_load_average(double *load1, double *load5, double *load15);
void get_device_model(char *model, size_t size);
void get_firmware_version(char *firmware, size_t size);
void get_cmac_address(char *cmac, size_t size);
void get_device_uptime(char *uptime, size_t size);
void get_fs_data(char* path, uint32_t* used_kb, uint32_t* total_kb);

//WAN Stats
void initialize_wan_stats(WanStats *stats);
void collect_wan_stats(WanStats *stats);

void check_wan_interface_status(char *status, size_t size);
void get_wan_ipv4_address(char *ipv4_address, size_t size);
void get_wan_ipv6_address(char *ipv6_address, size_t size);
void check_gateway_reachability(char *status, size_t size);
void calculate_packet_loss(const char *gateway_ip, double *packet_loss);
void measure_latency(const char *gateway_ip, double *latency, double* dns_time);
void calculate_jitter(const char *interface, double *jitter);
void get_ipv4_lease_time(char *ipv4_lease, size_t size);
void get_ipv6_lease_time(char *ipv6_lease, size_t size);
void collect_interface_stats(const char *interface, char *rx_bytes, char *tx_bytes, char *rx_dropped, char *tx_dropped);

//LAN Stats
void initialize_lan_stats(LanStats *stats);
void collect_lan_stats(LanStats *stats);

void get_lan_ipv4_address(char *ipv4_address, size_t size);
void get_lan_ipv6_address(char *ipv6_address, size_t size);
void free_lan_stats(LanStats *stats);
void get_all_clients(LanStats *stats);
void get_client_traffic_stats(LanStats *stats);

//IPv6 Monitoring Stats
void initialize_ipv6_monitoring_stats(IPv6MonitoringStats *stats);
void collect_ipv6_monitoring_stats(IPv6MonitoringStats *stats, const char *ipv4_site, const char *ipv6_site);

void check_ipv6_address_assignment(char *global_address, size_t global_size, char *link_local_address, size_t link_local_size);
void check_ipv6_routing_reachability(const char *ipv6_site, char *status, size_t size);
void compare_dual_stack_performance(const char *ipv4_site, const char *ipv6_site, double *ipv4_latency, double *ipv6_latency, double *ipv4_packet_loss, double *ipv6_packet_loss);

//TCP Stats
void initialize_tcp_stats(TcpStats *stats);
void collect_tcp_stats(TcpStats *stats);
void get_tcp_params(TcpStats *stats);


//helper.h
void log_message(const char *format, ...);
void execute_command(const char *command, char *output, size_t size);
void get_current_timestamp(char *timestamp, size_t size);

#define TIME_NSEC_IN_SEC   1000000000
#define TIME_USEC_IN_SEC   1000000
#define TIME_MSEC_IN_SEC   1000
#define TIME_NSEC_PER_MSEC (TIME_NSEC_IN_SEC / TIME_MSEC_IN_SEC)

static inline uint64_t timespec_to_timestamp(const struct timespec *ts)
{
    return (uint64_t)ts->tv_sec * TIME_MSEC_IN_SEC + ts->tv_nsec / TIME_NSEC_PER_MSEC;
}

static inline uint64_t get_timestamp_ms(void)
{
    struct timespec              ts;

    memset (&ts, 0, sizeof (ts));
    if(clock_gettime(CLOCK_REALTIME, &ts) != 0)
    {
        return 0;
    }
    else
        return timespec_to_timestamp(&ts);
}

#endif // GW_STATS_COLLECTION_H