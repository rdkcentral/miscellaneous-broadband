#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "gateway_stats.pb-c.h"
#include "gateway_stats.h"


static Report* report_struct_create()
{
    Report *report = calloc(1, sizeof(Report));
    if (!report) {
        log_message("%s: calloc failed\n", __FUNCTION__);
        return NULL;
    }
    report__init(report);
    report->timestamp_ms = get_timestamp_ms();
    return report;
}

static SystemStats** system_stats_struct_create(system_stats_t *src, size_t n_system_stats)
{
    if (!src || !n_system_stats) {
        log_message("%s: Invalid input\n", __FUNCTION__);
        return NULL;
    }

    SystemStats **systemStatsArray = calloc(n_system_stats, sizeof(SystemStats*));
    if (!systemStatsArray) {
        log_message("%s: calloc failed\n", __FUNCTION__);
        return NULL;
    }

    size_t i = 0;
    system_stats_t *curr = src;
    while (curr && i < n_system_stats) {
        systemStatsArray[i] = calloc(1, sizeof(SystemStats));
        if (!systemStatsArray[i]) {
            log_message("%s: calloc failed for index %zu\n", __FUNCTION__, i);
            // Free previously allocated memory
            for (size_t j = 0; j < i; j++) {
            SAFE_FREE(&systemStatsArray[j]);
            }
            SAFE_FREE(&systemStatsArray);
            return NULL;
        }
        system_stats__init(systemStatsArray[i]);

        systemStatsArray[i]->timestamp_ms = curr->timestamp_ms;
        systemStatsArray[i]->cpu_usage = curr->cpu_usage;
        systemStatsArray[i]->free_memory = curr->free_memory;
        systemStatsArray[i]->slab_memory = curr->slab_memory;
        systemStatsArray[i]->avail_memory = curr->avail_memory;
        systemStatsArray[i]->cached_mem = curr->cached_mem;
        systemStatsArray[i]->slab_unreclaim = curr->slab_unreclaim;
        systemStatsArray[i]->loadavg_1min = curr->loadavg_1min;
        systemStatsArray[i]->loadavg_5min = curr->loadavg_5min;
        systemStatsArray[i]->loadavg_15min = curr->loadavg_15min;
        systemStatsArray[i]->rootfs_used_kb = curr->rootfs_used_kb;
        systemStatsArray[i]->rootfs_total_kb = curr->rootfs_total_kb;
        systemStatsArray[i]->tmpfs_used_kb = curr->tmpfs_used_kb;
        systemStatsArray[i]->tmpfs_total_kb = curr->tmpfs_total_kb;

        systemStatsArray[i]->model = strdup(curr->model);
        systemStatsArray[i]->firmware = strdup(curr->firmware);
        systemStatsArray[i]->cmac = strdup(curr->cmac);
        systemStatsArray[i]->uptime = strdup(curr->uptime);

        curr = curr->next;
        i++;
    }
    return systemStatsArray;
}

WanStats **wan_stats_struct_create (wan_stats_t *src, size_t n_wan_stats)
{
    if (!src || !n_wan_stats) {
        log_message("%s: Invalid input\n", __FUNCTION__);
        return NULL;
    }

    WanStats **wanStatsArray = calloc(n_wan_stats, sizeof(WanStats*));
    if (!wanStatsArray) {
        log_message("%s: calloc failed\n", __FUNCTION__);
        return NULL;
    }

    size_t i = 0;
    wan_stats_t *curr = src;
    while (curr && i < n_wan_stats) {
        wanStatsArray[i] = calloc(1, sizeof(WanStats));
        if (!wanStatsArray[i]) {
            log_message("%s: calloc failed for index %zu\n", __FUNCTION__, i);
            // Free previously allocated memory
            for (size_t j = 0; j < i; j++) {
            SAFE_FREE(&wanStatsArray[j]);
            }
            SAFE_FREE(&wanStatsArray);
            return NULL;
        }
        wan_stats__init(wanStatsArray[i]);

        wanStatsArray[i]->timestamp_ms = curr->timestamp_ms;
        wanStatsArray[i]->packet_loss = curr->packet_loss;
        wanStatsArray[i]->latency = curr->latency;
        wanStatsArray[i]->jitter = curr->jitter;
        wanStatsArray[i]->dns_time = curr->dns_time;

        wanStatsArray[i]->interface_status = strdup(curr->interface_status);
        wanStatsArray[i]->ipv4_address = strdup(curr->ipv4_address);
        wanStatsArray[i]->ipv6_address = strdup(curr->ipv6_address);
        wanStatsArray[i]->gateway_status = strdup(curr->gateway_status);
        wanStatsArray[i]->rx_bytes = strdup(curr->rx_bytes);
        wanStatsArray[i]->tx_bytes = strdup(curr->tx_bytes);
        wanStatsArray[i]->rx_dropped = strdup(curr->rx_dropped);
        wanStatsArray[i]->tx_dropped = strdup(curr->tx_dropped);
        wanStatsArray[i]->ipv4_lease = strdup(curr->ipv4_lease);
        wanStatsArray[i]->ipv6_lease = strdup(curr->ipv6_lease);

        curr = curr->next;
        i++;
    }
    return wanStatsArray;
}

LanStats **lan_stats_struct_create (lan_stats_t *src, size_t n_lan_stats)
{
    if (!src || !n_lan_stats) {
        log_message("%s: Invalid input\n", __FUNCTION__);
        return NULL;
    }

    LanStats **lanStatsArray = calloc(n_lan_stats, sizeof(LanStats*));
    if (!lanStatsArray) {
        log_message("%s: calloc failed\n", __FUNCTION__);
        return NULL;
    }

    size_t i = 0;
    lan_stats_t *curr = src;
    while (curr && i < n_lan_stats) {
        lanStatsArray[i] = calloc(1, sizeof(LanStats));
        if (!lanStatsArray[i]) {
            log_message("%s: calloc failed for index %zu\n", __FUNCTION__, i);
            // Free previously allocated memory
            for (size_t j = 0; j < i; j++) {
            SAFE_FREE(&lanStatsArray[j]);
            }
            SAFE_FREE(&lanStatsArray);
            return NULL;
        }
        lan_stats__init(lanStatsArray[i]);

        lanStatsArray[i]->timestamp_ms = curr->timestamp_ms;

        lanStatsArray[i]->ipv4_address = strdup(curr->ipv4_address);
        lanStatsArray[i]->ipv6_address = strdup(curr->ipv6_address);
        lanStatsArray[i]->rx_bytes = strdup(curr->rx_bytes);
        lanStatsArray[i]->tx_bytes = strdup(curr->tx_bytes);
        lanStatsArray[i]->rx_dropped = strdup(curr->rx_dropped);
        lanStatsArray[i]->tx_dropped = strdup(curr->tx_dropped);

        curr = curr->next;
        i++;
    }
    return lanStatsArray;
}

IPv6MonitoringStats **ipv6Mon_stats_struct_create (ipv6_mon_stats_t *src, size_t n_ipv6_stats)
{
    if (!src || !n_ipv6_stats) {
        log_message("%s: Invalid input\n", __FUNCTION__);
        return NULL;
    }

    IPv6MonitoringStats **ipv6MonStatsArray = calloc(n_ipv6_stats, sizeof(IPv6MonitoringStats*));
    if (!ipv6MonStatsArray) {
        log_message("%s: calloc failed\n", __FUNCTION__);
        return NULL;
    }

    size_t i = 0;
    ipv6_mon_stats_t *curr = src;
    while (curr && i < n_ipv6_stats) {
        ipv6MonStatsArray[i] = calloc(1, sizeof(IPv6MonitoringStats));
        if (!ipv6MonStatsArray[i]) {
            log_message("%s: calloc failed for index %zu\n", __FUNCTION__, i);
            // Free previously allocated memory
            for (size_t j = 0; j < i; j++) {
            SAFE_FREE(&ipv6MonStatsArray[j]);
            }
            SAFE_FREE(&ipv6MonStatsArray);
            return NULL;
        }
        ipv6_monitoring_stats__init(ipv6MonStatsArray[i]);

        ipv6MonStatsArray[i]->timestamp_ms = curr->timestamp_ms;
        ipv6MonStatsArray[i]->ipv4_latency = curr->ipv4_latency;
        ipv6MonStatsArray[i]->ipv6_latency = curr->ipv6_latency;
        ipv6MonStatsArray[i]->ipv4_packet_loss = curr->ipv4_packet_loss;
        ipv6MonStatsArray[i]->ipv6_packet_loss = curr->ipv6_packet_loss;
        ipv6MonStatsArray[i]->ipv6_reachability = strdup(curr->ipv6_reachability);
        ipv6MonStatsArray[i]->global_ipv6_address = strdup(curr->global_ipv6_address);
        ipv6MonStatsArray[i]->link_local_ipv6_address = strdup(curr->link_local_ipv6_address);

        curr = curr->next;
        i++;
    }
    return ipv6MonStatsArray;
}

TcpStats **tcp_stats_struct_create (tcp_stats_t *src, size_t n_tcp_stats)
{
    if (!src || !n_tcp_stats) {
        log_message("%s: Invalid input\n", __FUNCTION__);
        return NULL;
    }

    TcpStats **tcpStatsArray = calloc(n_tcp_stats, sizeof(TcpStats*));
    if (!tcpStatsArray) {
        log_message("%s: calloc failed\n", __FUNCTION__);
        return NULL;
    }

    size_t i = 0;
    tcp_stats_t *curr = src;
    while (curr && i < n_tcp_stats) {
        tcpStatsArray[i] = calloc(1, sizeof(TcpStats));
        if (!tcpStatsArray[i]) {
            log_message("%s: calloc failed for index %zu\n", __FUNCTION__, i);
            // Free previously allocated memory
            for (size_t j = 0; j < i; j++) {
            SAFE_FREE(&tcpStatsArray[j]);
            }
            SAFE_FREE(&tcpStatsArray);
            return NULL;
        }
        tcp_stats__init(tcpStatsArray[i]);

        tcpStatsArray[i]->timestamp_ms = curr->timestamp_ms;

        tcpStatsArray[i]->tcplostretransmit = strdup(curr->TCPLostRetransmit);
        tcpStatsArray[i]->tcpretransfail = strdup(curr->TCPRetransFail);
        tcpStatsArray[i]->tcpsackfailures = strdup(curr->TCPSackFailures);
        tcpStatsArray[i]->tcptimeouts = strdup(curr->TCPTimeouts);
        tcpStatsArray[i]->tcpabortontimeout = strdup(curr->TCPAbortOnTimeout);
        tcpStatsArray[i]->listenoverflows = strdup(curr->ListenOverflows);
        tcpStatsArray[i]->tcporigdatasent = strdup(curr->TCPOrigDataSent);

        curr = curr->next;
        i++;
    }
    return tcpStatsArray;
}

ClientStats **client_stats_struct_create (client_stats_t *src, size_t n_client_stats)
{
    if (!src || !n_client_stats) {
        log_message("%s: Invalid input\n", __FUNCTION__);
        return NULL;
    }

    ClientStats **clientStatsArray = calloc(n_client_stats, sizeof(ClientStats*));
    if (!clientStatsArray) {
        log_message("%s: calloc failed\n", __FUNCTION__);
        return NULL;
    }

    size_t i = 0;
    client_stats_t *curr = src;
    while (curr && i < n_client_stats) {
        clientStatsArray[i] = calloc(1, sizeof(ClientStats));
        if (!clientStatsArray[i]) {
            log_message("%s: calloc failed for index %zu\n", __FUNCTION__, i);
            // Free previously allocated memory
            for (size_t j = 0; j < i; j++) {
                SAFE_FREE(&clientStatsArray[j]);
            }
            SAFE_FREE(&clientStatsArray);
            return NULL;
        }
        client_stats__init(clientStatsArray[i]);

        clientStatsArray[i]->timestamp_ms = curr->timestamp_ms;
        clientStatsArray[i]->client_count = curr->client_count;

        if (curr->clients && curr->client_count > 0) {
            clientStatsArray[i]->n_client_details = curr->client_count;
            clientStatsArray[i]->client_details = calloc(curr->client_count, sizeof(ClientDetails*));
            if (!clientStatsArray[i]->client_details) {
                log_message("%s: calloc failed for client_details\n", __FUNCTION__);
                SAFE_FREE(&clientStatsArray[i]);
                // Free previously allocated memory
                for (size_t k = 0; k < i; k++) {
                    SAFE_FREE(&clientStatsArray[k]);
                }
                SAFE_FREE(&clientStatsArray);
                return NULL;
            }

            // curr->clients is an array of client_details_t, not a linked list
            for (size_t j = 0; j < (size_t)curr->client_count; j++) {
                clientStatsArray[i]->client_details[j] = calloc(1, sizeof(ClientDetails));
                if (!clientStatsArray[i]->client_details[j]) {
                    log_message("%s: calloc failed for client_details index %zu\n", __FUNCTION__, j);
                    // Free previously allocated memory
                    for (size_t k = 0; k < j; k++) {
                        SAFE_FREE(&clientStatsArray[i]->client_details[k]);
                    }
                    SAFE_FREE(&clientStatsArray[i]->client_details);
                    SAFE_FREE(&clientStatsArray[i]);
                    for (size_t k = 0; k < i; k++) {
                        SAFE_FREE(&clientStatsArray[k]);
                    }
                    SAFE_FREE(&clientStatsArray);
                    return NULL;
                }
                client_details__init(clientStatsArray[i]->client_details[j]);
                clientStatsArray[i]->client_details[j]->mac_address = strdup(curr->clients[j].mac_address);
                clientStatsArray[i]->client_details[j]->ip_addr = strdup(curr->clients[j].ip_addr);
                clientStatsArray[i]->client_details[j]->host_name = strdup(curr->clients[j].host_name);
                clientStatsArray[i]->client_details[j]->status = strdup(curr->clients[j].status);
                clientStatsArray[i]->client_details[j]->tx_bytes = strdup(curr->clients[j].tx_bytes);
                clientStatsArray[i]->client_details[j]->rx_bytes = strdup(curr->clients[j].rx_bytes);
                clientStatsArray[i]->client_details[j]->tcp_est_counts = curr->clients[j].tcp_est_counts;
                clientStatsArray[i]->client_details[j]->ipv4_synack_min_latency = curr->clients[j].ipv4_synack_min_latency;
                clientStatsArray[i]->client_details[j]->ipv4_synack_max_latency = curr->clients[j].ipv4_synack_max_latency;
                clientStatsArray[i]->client_details[j]->ipv4_synack_avg_latency = curr->clients[j].ipv4_synack_avg_latency;
                clientStatsArray[i]->client_details[j]->ipv4_ack_min_latency = curr->clients[j].ipv4_ack_min_latency;
                clientStatsArray[i]->client_details[j]->ipv4_ack_max_latency = curr->clients[j].ipv4_ack_max_latency;
                clientStatsArray[i]->client_details[j]->ipv4_ack_avg_latency = curr->clients[j].ipv4_ack_avg_latency;
                clientStatsArray[i]->client_details[j]->ipv6_synack_min_latency = curr->clients[j].ipv6_synack_min_latency;
                clientStatsArray[i]->client_details[j]->ipv6_synack_max_latency = curr->clients[j].ipv6_synack_max_latency;
                clientStatsArray[i]->client_details[j]->ipv6_synack_avg_latency = curr->clients[j].ipv6_synack_avg_latency;
                clientStatsArray[i]->client_details[j]->ipv6_ack_min_latency = curr->clients[j].ipv6_ack_min_latency;
                clientStatsArray[i]->client_details[j]->ipv6_ack_max_latency = curr->clients[j].ipv6_ack_max_latency;
                clientStatsArray[i]->client_details[j]->ipv6_ack_avg_latency = curr->clients[j].ipv6_ack_avg_latency;
            }
        }
        curr = curr->next;
        i++;
    }
    return clientStatsArray;
}

PidStats **pid_stats_struct_create (pid_stats_t *src, size_t n_pid_stats)
{
    if (!src || !n_pid_stats) {
        log_message("%s: Invalid input\n", __FUNCTION__);
        return NULL;
    }

    PidStats **pidStatsArray = calloc(n_pid_stats, sizeof(PidStats*));
    if (!pidStatsArray) {
        log_message("%s: calloc failed\n", __FUNCTION__);
        return NULL;
    }

    size_t i = 0;
    pid_stats_t *curr = src;
    while (curr && i < n_pid_stats) {
        pidStatsArray[i] = calloc(1, sizeof(PidStats));
        if (!pidStatsArray[i]) {
            log_message("%s: calloc failed for index %zu\n", __FUNCTION__, i);
            // Free previously allocated memory
            for (size_t j = 0; j < i; j++) {
                SAFE_FREE(&pidStatsArray[j]);
            }
            SAFE_FREE(&pidStatsArray);
            return NULL;
        }
        pid_stats__init(pidStatsArray[i]);

        pidStatsArray[i]->timestamp_ms = curr->timestamp_ms;
        pidStatsArray[i]->count = curr->count;

        if (curr->pid_details && curr->count > 0) {
            int j = 0;
            pidStatsArray[i]->n_pid_details = curr->count;
            pidStatsArray[i]->pid_details = calloc(curr->count, sizeof(PidDetails*));
            if (!pidStatsArray[i]->pid_details) {
                log_message("%s: calloc failed for pid_details\n", __FUNCTION__);
                SAFE_FREE(&pidStatsArray[i]);
                // Free previously allocated memory
                for (size_t k = 0; k < i; k++) {
                    SAFE_FREE(&pidStatsArray[k]);
                }
                SAFE_FREE(&pidStatsArray);
                return NULL;
            }

            // If pid_details_t is an array, iterate using index
            for (j = 0; j < curr->count; j++) {
                pidStatsArray[i]->pid_details[j] = calloc(1, sizeof(PidDetails));
                if (!pidStatsArray[i]->pid_details[j]) {
                    log_message("%s: calloc failed for pid_details index %d\n", __FUNCTION__, j);
                    // Free previously allocated memory
                    for (int k = 0; k < j; k++) {
                        SAFE_FREE(&pidStatsArray[i]->pid_details[k]);
                    }
                    SAFE_FREE(&pidStatsArray[i]->pid_details);
                    SAFE_FREE(&pidStatsArray[i]);
                    for (size_t k = 0; k < i; k++) {
                        SAFE_FREE(&pidStatsArray[k]);
                    }
                    SAFE_FREE(&pidStatsArray);
                    return NULL;
                }
                pid_details__init(pidStatsArray[i]->pid_details[j]);
                pidStatsArray[i]->pid_details[j]->pid = curr->pid_details[j].pid;
                pidStatsArray[i]->pid_details[j]->rss = curr->pid_details[j].rss;
                pidStatsArray[i]->pid_details[j]->pss = curr->pid_details[j].pss;
                pidStatsArray[i]->pid_details[j]->mem_util = curr->pid_details[j].mem_util;
                pidStatsArray[i]->pid_details[j]->cpu_util = curr->pid_details[j].cpu_util;
                pidStatsArray[i]->pid_details[j]->pname = strdup(curr->pid_details[j].pName);
            }
        }
        curr = curr->next;
        i++;
    }
    return pidStatsArray;
}

static RestartCountStats* restart_count_stats_struct_create(restart_count_stats_t *src) {
    if (!src) {
        log_message("%s: Invalid input\n", __FUNCTION__);
        return NULL;
    }

    RestartCountStats *restartCountStats = calloc(1, sizeof(RestartCountStats));
    if (!restartCountStats) {
        log_message("%s: calloc failed\n", __FUNCTION__);
        return NULL;
    }
    restart_count_stats__init(restartCountStats);

    restartCountStats->fw_restart_count = src->fw_restart_count;
    restartCountStats->n_fw_restart_time = src->fw_restart_count;
    if (src->fw_restart_count > 0 && src->fw_restart_time) {
        restartCountStats->fw_restart_time = calloc(src->fw_restart_count, sizeof(char*));
        if (!restartCountStats->fw_restart_time) {
            log_message("%s: calloc failed for fw_restart_time\n", __FUNCTION__);
            SAFE_FREE(&restartCountStats);
            return NULL;
        }
        for (int i = 0; i < src->fw_restart_count; i++) {
            restartCountStats->fw_restart_time[i] = strdup(src->fw_restart_time[i]);
        }
    }

    restartCountStats->wan_restart_count = src->wan_restart_count;
    restartCountStats->n_wan_restart_time = src->wan_restart_count;
    if (src->wan_restart_count > 0 && src->wan_restart_time) {
        restartCountStats->wan_restart_time = calloc(src->wan_restart_count, sizeof(char*));
        if (!restartCountStats->wan_restart_time) {
            log_message("%s: calloc failed for wan_restart_time\n", __FUNCTION__);
            if (restartCountStats->fw_restart_time) {
                for (size_t i = 0; i < restartCountStats->n_fw_restart_time; i++) {
                    SAFE_FREE(&restartCountStats->fw_restart_time[i]);
                }
                SAFE_FREE(&restartCountStats->fw_restart_time);
            }
            SAFE_FREE(&restartCountStats);
            return NULL;
        }
        for (int i = 0; i < src->wan_restart_count; i++) {
            restartCountStats->wan_restart_time[i] = strdup(src->wan_restart_time[i]);
        }
    }
    return restartCountStats;
}


static void free_system_stats_struct(SystemStats **systemStats, size_t n_systemStats)
{
    if (!systemStats) {
        return;
    }
    for (size_t i = 0; i < n_systemStats; i++) {
        if (systemStats[i]) {
            SAFE_FREE(&systemStats[i]->model);
            SAFE_FREE(&systemStats[i]->firmware);
            SAFE_FREE(&systemStats[i]->cmac);
            SAFE_FREE(&systemStats[i]->uptime);
            SAFE_FREE(&systemStats[i]);
        }
    }
    SAFE_FREE(&systemStats);
}

static void free_wan_stats_struct(WanStats **wanStats, size_t n_wanStats)
{
    if (!wanStats) {
        return;
    }
    for (size_t i = 0; i < n_wanStats; i++) {
        if (wanStats[i]) {
            SAFE_FREE(&wanStats[i]->interface_status);
            SAFE_FREE(&wanStats[i]->ipv4_address);
            SAFE_FREE(&wanStats[i]->ipv6_address);
            SAFE_FREE(&wanStats[i]->gateway_status);
            SAFE_FREE(&wanStats[i]->rx_bytes);
            SAFE_FREE(&wanStats[i]->tx_bytes);
            SAFE_FREE(&wanStats[i]->rx_dropped);
            SAFE_FREE(&wanStats[i]->tx_dropped);
            SAFE_FREE(&wanStats[i]->ipv4_lease);
            SAFE_FREE(&wanStats[i]->ipv6_lease);
            SAFE_FREE(&wanStats[i]);
        }
    }
    SAFE_FREE(&wanStats);
}

static void free_lan_stats_struct(LanStats **lanStats, size_t n_lanStats)
{
    if (!lanStats) {
        return;
    }
    for (size_t i = 0; i < n_lanStats; i++) {
        if (lanStats[i]) {
            SAFE_FREE(&lanStats[i]->ipv4_address);
            SAFE_FREE(&lanStats[i]->ipv6_address);
            SAFE_FREE(&lanStats[i]->rx_bytes);
            SAFE_FREE(&lanStats[i]->tx_bytes);
            SAFE_FREE(&lanStats[i]->rx_dropped);
            SAFE_FREE(&lanStats[i]->tx_dropped);
            SAFE_FREE(&lanStats[i]);
        }
    }
    SAFE_FREE(&lanStats);
}

static void free_ipv6Mon_stats_struct(IPv6MonitoringStats **ipv6MonStats, size_t n_ipv6MonStats)
{
    if (!ipv6MonStats) {
        return;
    }
    for (size_t i = 0; i < n_ipv6MonStats; i++) {
        if (ipv6MonStats[i]) {
            SAFE_FREE(&ipv6MonStats[i]->ipv6_reachability);
            SAFE_FREE(&ipv6MonStats[i]->global_ipv6_address);
            SAFE_FREE(&ipv6MonStats[i]->link_local_ipv6_address);
            SAFE_FREE(&ipv6MonStats[i]);
        }
    }
    SAFE_FREE(&ipv6MonStats);
}

static void free_tcp_stats_struct(TcpStats **tcpStats, size_t n_tcpStats)
{
    if (!tcpStats) {
        return;
    }
    for (size_t i = 0; i < n_tcpStats; i++) {
        if (tcpStats[i]) {
            SAFE_FREE(&tcpStats[i]->tcplostretransmit);
            SAFE_FREE(&tcpStats[i]->tcpretransfail);
            SAFE_FREE(&tcpStats[i]->tcpsackfailures);
            SAFE_FREE(&tcpStats[i]->tcptimeouts);
            SAFE_FREE(&tcpStats[i]->tcpabortontimeout);
            SAFE_FREE(&tcpStats[i]->listenoverflows);
            SAFE_FREE(&tcpStats[i]->tcporigdatasent);
            SAFE_FREE(&tcpStats[i]);
        }
    }
    SAFE_FREE(&tcpStats);
}

static void free_client_stats_struct(ClientStats **clientStats, size_t n_clientStats)
{
    if (!clientStats) {
        return;
    }
    for (size_t i = 0; i < n_clientStats; i++) {
        if (clientStats[i]) {
            if (clientStats[i]->client_details) {
                for (size_t j = 0; j < clientStats[i]->n_client_details; j++) {
                    if (clientStats[i]->client_details[j]) {
                        SAFE_FREE(&clientStats[i]->client_details[j]->mac_address);
                        SAFE_FREE(&clientStats[i]->client_details[j]->ip_addr);
                        SAFE_FREE(&clientStats[i]->client_details[j]->host_name);
                        SAFE_FREE(&clientStats[i]->client_details[j]->status);
                        SAFE_FREE(&clientStats[i]->client_details[j]->tx_bytes);
                        SAFE_FREE(&clientStats[i]->client_details[j]->rx_bytes);
                        SAFE_FREE(&clientStats[i]->client_details[j]);
                    }
                }
                SAFE_FREE(&clientStats[i]->client_details);
            }
            SAFE_FREE(&clientStats[i]);
        }
    }
    SAFE_FREE(&clientStats);
}

static void free_pid_stats_struct(PidStats **pidStats, size_t n_pidStats)
{
    if (!pidStats) {
        return;
    }
    for (size_t i = 0; i < n_pidStats; i++) {
        if (pidStats[i]) {
            if (pidStats[i]->pid_details) {
                for (size_t j = 0; j < pidStats[i]->n_pid_details; j++) {
                    if (pidStats[i]->pid_details[j]) {
                        SAFE_FREE(&pidStats[i]->pid_details[j]->pname);
                        SAFE_FREE(&pidStats[i]->pid_details[j]);
                    }
                }
                SAFE_FREE(&pidStats[i]->pid_details);
            }
            SAFE_FREE(&pidStats[i]);
        }
    }
    SAFE_FREE(&pidStats);
}

static void free_restart_count_stats_struct(RestartCountStats *restartCountStats)
{
    if (!restartCountStats) {
        return;
    }
    // Free fw_restart_time array
    if (restartCountStats->fw_restart_time) {
        for (size_t i = 0; i < restartCountStats->n_fw_restart_time; i++) {
            SAFE_FREE(&restartCountStats->fw_restart_time[i]);
        }
        SAFE_FREE(&restartCountStats->fw_restart_time);
    }
    // Free wan_restart_time array
    if (restartCountStats->wan_restart_time) {
        for (size_t i = 0; i < restartCountStats->n_wan_restart_time; i++) {
            SAFE_FREE(&restartCountStats->wan_restart_time[i]);
        }
        SAFE_FREE(&restartCountStats->wan_restart_time);
    }
    SAFE_FREE(&restartCountStats);
}

static void free_report_struct(Report *report)
{
    if (!report) {
        return;
    }
    free_system_stats_struct(report->systemstats, report->n_systemstats);
    free_wan_stats_struct(report->wanstats, report->n_wanstats);
    free_lan_stats_struct(report->lanstats, report->n_lanstats);
    free_ipv6Mon_stats_struct(report->ipv6monstats, report->n_ipv6monstats);
    free_tcp_stats_struct(report->tcpstats, report->n_tcpstats);
    free_client_stats_struct(report->clientstats, report->n_clientstats);
    free_pid_stats_struct(report->pidstats, report->n_pidstats);
    free_restart_count_stats_struct(report->restartcountstats);
    SAFE_FREE(&report);
}

void* encode_report(gw_stats_report *rpt, size_t *buff_len) {
    Report *report = NULL;
    SystemStats **systemStats = NULL;
    WanStats **wanStats = NULL;
    LanStats **lanStats = NULL;
    IPv6MonitoringStats **ipv6MonStats = NULL;
    TcpStats **tcpStats = NULL;
    ClientStats **clientStats = NULL;
    PidStats **pidStats = NULL;
    RestartCountStats *restartCountStats = NULL;

    size_t len = 0;
    void *buffer = NULL;

    if (!rpt) {
        log_message("%s: rpt is NULL\n", __FUNCTION__);
        return NULL;
    }

    report = report_struct_create();
    if (!report) {
        log_message("%s: report_struct_create FAILED\n", __FUNCTION__);
    }

    systemStats  = system_stats_struct_create(rpt->system_stats, rpt->n_system_stats);
    if (systemStats) {
        report->systemstats = systemStats;
        report->n_systemstats = rpt->n_system_stats;
    }

    wanStats = wan_stats_struct_create(rpt->wan_stats, rpt->n_wan_stats);
    if (wanStats) {
        report->wanstats = wanStats;
        report->n_wanstats = rpt->n_wan_stats;
    }

    lanStats = lan_stats_struct_create(rpt->lan_stats, rpt->n_lan_stats);
    if (lanStats) {
        report->lanstats = lanStats;
        report->n_lanstats = rpt->n_lan_stats;
    }

    ipv6MonStats = ipv6Mon_stats_struct_create(rpt->ipv6_stats, rpt->n_ipv6_stats);
    if (ipv6MonStats) {
        report->ipv6monstats = ipv6MonStats;
        report->n_ipv6monstats = rpt->n_ipv6_stats;
    }

    tcpStats = tcp_stats_struct_create(rpt->tcp_stats, rpt->n_tcp_stats);
    if (tcpStats) {
        report->tcpstats = tcpStats;
        report->n_tcpstats = rpt->n_tcp_stats;
    }

    clientStats = client_stats_struct_create(rpt->client_stats, rpt->n_client_stats);
    if (clientStats) {
        report->clientstats = clientStats;
        report->n_clientstats = rpt->n_client_stats;
    }

    pidStats = pid_stats_struct_create(rpt->pid_stats, rpt->n_pid_stats);
    if (pidStats) {
        report->pidstats = pidStats;
        report->n_pidstats = rpt->n_pid_stats;
    }

    restartCountStats = restart_count_stats_struct_create(rpt->restart_count_stats);
    if (restartCountStats) {
        report->restartcountstats = restartCountStats;
    }

    len = report__get_packed_size(report);
    buffer = (void*) calloc(1, len);
    if (!buffer) {
        log_message("%s: calloc failed for buffer\n", __FUNCTION__);
        goto cleanup;
    }
    report__pack(report, buffer);
    *buff_len = len;
    log_message("%s: Encoded report size: %zu bytes\n", __FUNCTION__, len);

cleanup:
    free_report_struct(report);
    return buffer;
}