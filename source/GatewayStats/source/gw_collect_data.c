#include "gateway_stats.h"

uint32_t sampling_interval;
uint32_t reporting_interval;

gw_stats_report g_report;

int gw_stats_init() {
    log_message("Gateway Stats Init\n");
    memset(&g_report, 0, sizeof(gw_stats_report));

    // Set initial counts for each stats array (change as needed)
    g_report.n_system_stats = 1;
    g_report.n_wan_stats = 1;
    g_report.n_lan_stats = 1;
    g_report.n_ipv6_stats = 1;
    g_report.n_tcp_stats = 1;

    g_report.system_stats = (SystemStats*)malloc(sizeof(SystemStats) * g_report.n_system_stats);
    g_report.wan_stats = (WanStats*)malloc(sizeof(WanStats) * g_report.n_wan_stats);
    g_report.lan_stats = (LanStats*)malloc(sizeof(LanStats) * g_report.n_lan_stats);
    g_report.ipv6_stats = (IPv6MonitoringStats*)malloc(sizeof(IPv6MonitoringStats) * g_report.n_ipv6_stats);
    g_report.tcp_stats = (TcpStats*)malloc(sizeof(TcpStats) * g_report.n_tcp_stats);
    g_report.restart_count_stats = (RestartCountStats*)malloc(sizeof(RestartCountStats));
    if (!g_report.system_stats || !g_report.wan_stats || !g_report.lan_stats ||
        !g_report.ipv6_stats || !g_report.tcp_stats || !g_report.restart_count_stats) {
        log_message("Failed to allocate memory for stats structures\n");
        return -1;
    }
    initialize_system_stats(g_report.system_stats);
    initialize_wan_stats(g_report.wan_stats);
    initialize_lan_stats(g_report.lan_stats);
    initialize_ipv6_monitoring_stats(g_report.ipv6_stats);
    initialize_tcp_stats(g_report.tcp_stats);
    initialize_restart_count_stats(g_report.restart_count_stats);

    sampling_interval = SAMPLING_INTERVAL;
    reporting_interval = REPORTING_INTERVAL;

    return 0;
}

int gw_stats_collect() {
    log_message("Collecting Gateway Stats\n");
    collect_system_stats(g_report.system_stats);
    collect_wan_stats(g_report.wan_stats);
    collect_lan_stats(g_report.lan_stats);
    collect_tcp_stats(g_report.tcp_stats);
    collect_ipv6_monitoring_stats(g_report.ipv6_stats, "8.8.8.8", "google.com");

    log_message("Gateway Stats collected\n");
    return 0;
}

void save_to_text(const SystemStats *system_stats, const WanStats *wan_stats, const LanStats *lan_stats, const TcpStats *tcp_stats, const IPv6MonitoringStats *ipv6_stats) {
    log_message("In save_to_text\n");

    FILE *file = fopen("/rdklogs/logs/gateway_stats_data.txt", "a");
    if (!file) {
        fprintf(stderr, "Failed to open file for writing\n");
        return;
    }

    char timestamp[64];
    get_current_timestamp(timestamp, sizeof(timestamp));

    // Write system_params
    fprintf(file, "system_params: %s|%s|%s|%s|%s|%.3f|%.3f|%.3f|%.3f|%.3f|%.3f|%.3f|%.3f|%.3f|%d|%d|%d|%d\n",
            timestamp, system_stats->model, system_stats->firmware, system_stats->cmac,
            system_stats->uptime, system_stats->cpu_usage, system_stats->free_memory, system_stats->slab_memory,
            system_stats->avail_memory, system_stats->cached_mem, system_stats->slab_unreclaim,
            system_stats->loadavg_1min, system_stats->loadavg_5min, system_stats->loadavg_15min,
            system_stats->rootfs_used_kb, system_stats->rootfs_total_kb,
            system_stats->tmpfs_used_kb, system_stats->tmpfs_total_kb);

    // Write WAN statistics
    fprintf(file, "wan: %s|%s|%s|%s|%s|%s|%s|%s|%s|%.3f|%.3f|%.3f|%.3f|%s|%s\n",
            timestamp, wan_stats->gateway_status, wan_stats->interface_status, wan_stats->ipv4_address,
            wan_stats->ipv6_address, wan_stats->rx_bytes, wan_stats->tx_bytes, wan_stats->rx_dropped,
            wan_stats->tx_dropped, wan_stats->packet_loss, wan_stats->latency, wan_stats->jitter, wan_stats->dns_time,
            wan_stats->ipv4_lease, wan_stats->ipv6_lease);

    // Write LAN statistics
    fprintf(file, "lan: %s|%s|%s|%s|%s|%s|%s|%d\n",
            timestamp, lan_stats->ipv4_address, lan_stats->ipv6_address, lan_stats->rx_bytes,
            lan_stats->tx_bytes, lan_stats->rx_dropped, lan_stats->tx_dropped, lan_stats->client_count);

    // Write LAN client details
    for (int i = 0; i < lan_stats->client_count; i++) {
        fprintf(file, "client|%s|%s|%s|%s|%s|%s|%d\n",
            lan_stats->clients[i].mac_address,
            lan_stats->clients[i].host_name,
            lan_stats->clients[i].ip_addr,
            lan_stats->clients[i].status,
            lan_stats->clients[i].tx_bytes,
            lan_stats->clients[i].rx_bytes,
            lan_stats->clients[i].tcp_est_counts);
    }

    // Write IPv6 monitoring statistics
    fprintf(file, "ipv6_monitoring: %s|%s|%s|%s|%.3f|%.3f|%.3f|%.3f\n",
            timestamp, ipv6_stats->ipv6_reachability, ipv6_stats->global_ipv6_address,
            ipv6_stats->link_local_ipv6_address, ipv6_stats->ipv4_latency, ipv6_stats->ipv6_latency,
            ipv6_stats->ipv4_packet_loss, ipv6_stats->ipv6_packet_loss);

    // Write TCP statistics in the format: tcp|..|..|...
    fprintf(file, "tcp|%s|%s|%s|%s|%s|%s|%s\n",
        tcp_stats->TCPLostRetransmit,
        tcp_stats->TCPRetransFail,
        tcp_stats->TCPSackFailures,
        tcp_stats->TCPTimeouts,
        tcp_stats->TCPAbortOnTimeout,
        tcp_stats->ListenOverflows,
        tcp_stats->TCPOrigDataSent);
    
    // Write PID statistics
    if (system_stats && system_stats->pid_stats && system_stats->pid_stats_count > 0) {
        for (int i = 0; i < system_stats->pid_stats_count; i++) {
            fprintf(file, "pid_stats|%d|%s|%d|%d|%d|%d\n",
                system_stats->pid_stats[i].pid,
                system_stats->pid_stats[i].pName,
                system_stats->pid_stats[i].rss,
                system_stats->pid_stats[i].pss,
                system_stats->pid_stats[i].cpu_util,
                system_stats->pid_stats[i].mem_util
            );
        }
    }

    fclose(file);
    log_message("save_to_text done!\n");
}

int gw_stats_save() {
    save_to_text(g_report.system_stats, g_report.wan_stats, g_report.lan_stats, g_report.tcp_stats, g_report.ipv6_stats);
    return 0;
}

int gw_stats_deInit() {
    log_message("Deinitializing Gateway Statistics...\n");

    free_lan_stats(g_report.lan_stats);
    free(g_report.system_stats);
    free(g_report.wan_stats);
    free(g_report.lan_stats);
    free(g_report.tcp_stats);
    free(g_report.ipv6_stats);

    log_message("Gateway Statistics deinitialization completed.\n");
    return 0;
}
