#include "gateway_stats.h"

extern uint32_t sampling_interval;
extern uint32_t reporting_interval;

extern gw_stats_report g_report;
extern char* encoded_buffer;
extern size_t encoded_buffer_len;

int gw_stats_init() {
    log_message("Gateway Stats Init\n");
    memset(&g_report, 0, sizeof(gw_stats_report));

    g_report.system_stats = NULL;
    g_report.n_system_stats = 0;

    g_report.wan_stats = NULL;
    g_report.n_wan_stats = 0;

    g_report.lan_stats = NULL;
    g_report.n_lan_stats = 0;

    g_report.ipv6_stats = NULL;
    g_report.n_ipv6_stats = 0;

    g_report.tcp_stats = NULL;
    g_report.n_tcp_stats = 0;

    g_report.client_stats = NULL;
    g_report.n_client_stats = 0;

    g_report.pid_stats = NULL;
    g_report.n_pid_stats = 0;

    g_report.restart_count_stats = (restart_count_stats_t *)malloc(sizeof(restart_count_stats_t));
    if (g_report.restart_count_stats) {
        g_report.restart_count_stats->fw_restart_count = 0;
        g_report.restart_count_stats->fw_restart_time = NULL;
        g_report.restart_count_stats->wan_restart_count = 0;
        g_report.restart_count_stats->wan_restart_time = NULL;
    }

    sampling_interval = SAMPLING_INTERVAL;
    reporting_interval = REPORTING_INTERVAL;

    return 0;
}

int gw_stats_collect() {
    // system_stats_t
    system_stats_t *new_ss = (system_stats_t *)malloc(sizeof(system_stats_t));
    if (new_ss == NULL) {
        log_message("Failed to allocate memory for system_stats_t.\n");
        return -1;
    }
    initialize_system_stats(new_ss);
    collect_system_stats(new_ss);

    if (g_report.n_system_stats == 0) {
        g_report.system_stats = new_ss;
    } else {
        new_ss->next = g_report.system_stats;
        g_report.system_stats = new_ss;
    }
    g_report.n_system_stats++;

    // wan_stats_t
    wan_stats_t *new_ws = (wan_stats_t *)malloc(sizeof(wan_stats_t));
    if (new_ws == NULL) {
        log_message("Failed to allocate memory for wan_stats_t.\n");
        return -1;
    }
    initialize_wan_stats(new_ws);
    collect_wan_stats(new_ws);

    if (g_report.n_wan_stats == 0) {
        g_report.wan_stats = new_ws;
    } else {
        new_ws->next = g_report.wan_stats;
        g_report.wan_stats = new_ws;
    }
    g_report.n_wan_stats++;

    // lan_stats_t
    lan_stats_t *new_ls = (lan_stats_t *)malloc(sizeof(lan_stats_t));
    if (new_ls == NULL) {
        log_message("Failed to allocate memory for lan_stats_t.\n");
        return -1;
    }
    initialize_lan_stats(new_ls);
    collect_lan_stats(new_ls);

    if (g_report.n_lan_stats == 0) {
        g_report.lan_stats = new_ls;
    } else {
        new_ls->next = g_report.lan_stats;
        g_report.lan_stats = new_ls;
    }
    g_report.n_lan_stats++;

    // tcp_stats_t
    tcp_stats_t *new_ts = (tcp_stats_t *)malloc(sizeof(tcp_stats_t));
    if (new_ts == NULL) {
        log_message("Failed to allocate memory for tcp_stats_t.\n");
        return -1;
    }
    initialize_tcp_stats(new_ts);
    collect_tcp_stats(new_ts);

    if (g_report.n_tcp_stats == 0) {
        g_report.tcp_stats = new_ts;
    } else {
        new_ts->next = g_report.tcp_stats;
        g_report.tcp_stats = new_ts;
    }
    g_report.n_tcp_stats++;

    //ipv6_mon_stats_t
    ipv6_mon_stats_t *new_ipv6s = (ipv6_mon_stats_t *)malloc(sizeof(ipv6_mon_stats_t));
    if (new_ipv6s == NULL) {
        log_message("Failed to allocate memory for ipv6_mon_stats_t.\n");
        return -1;
    }
    initialize_ipv6_monitoring_stats(new_ipv6s);
    collect_ipv6_monitoring_stats(new_ipv6s, "8.8.8.8", "google.com");

    if (g_report.n_ipv6_stats == 0) {
        g_report.ipv6_stats = new_ipv6s;
    } else {
        new_ipv6s->next = g_report.ipv6_stats;
        g_report.ipv6_stats = new_ipv6s;
    }
    g_report.n_ipv6_stats++;

    // client_stats_t
    client_stats_t *new_cs = (client_stats_t *)malloc(sizeof(client_stats_t));
    if (new_cs == NULL) {
        log_message("Failed to allocate memory for client_stats_t.\n");
        return -1;
    }
    initialize_client_stats(new_cs);
    collect_client_stats(new_cs);

    if (g_report.n_client_stats == 0) {
        g_report.client_stats = new_cs;
    } else {
        new_cs->next = g_report.client_stats;
        g_report.client_stats = new_cs;
    }
    g_report.n_client_stats++;

    // pid_stats_t
    pid_stats_t *new_ps = (pid_stats_t *)malloc(sizeof(pid_stats_t));
    if (new_ps == NULL) {
        log_message("Failed to allocate memory for pid_stats_t.\n");
        return -1;
    }
    initialize_pid_stats(new_ps);
    collect_pid_stats(new_ps);

    if (g_report.n_pid_stats == 0) {
        g_report.pid_stats = new_ps;
    } else {
        new_ps->next = g_report.pid_stats;
        g_report.pid_stats = new_ps;
    }
    g_report.n_pid_stats++;


    log_message("Gateway Stats collected\n");
    return 0;
}

void save_to_text(const gw_stats_report *report) {
    log_message("In save_to_text\n");

    FILE *file = fopen("/rdklogs/logs/gateway_stats_data.txt", "a");
    if (!file) {
        fprintf(stderr, "Failed to open file for writing\n");
        return;
    }

    char timestamp[64];
    get_current_timestamp(timestamp, sizeof(timestamp));

    // system_stats_t linked list
    const system_stats_t *system_stats = report->system_stats;
    while (system_stats) {
        fprintf(file, "system_params: %s|%llu|%s|%s|%s|%s|%.3f|%.3f|%.3f|%.3f|%.3f|%.3f|%.3f|%.3f|%.3f|%u|%u|%u|%u\n",
                timestamp, system_stats->timestamp_ms, system_stats->model, system_stats->firmware, system_stats->cmac,
                system_stats->uptime, system_stats->cpu_usage, system_stats->free_memory, system_stats->slab_memory,
                system_stats->avail_memory, system_stats->cached_mem, system_stats->slab_unreclaim,
                system_stats->loadavg_1min, system_stats->loadavg_5min, system_stats->loadavg_15min,
                system_stats->rootfs_used_kb, system_stats->rootfs_total_kb,
                system_stats->tmpfs_used_kb, system_stats->tmpfs_total_kb);
        system_stats = system_stats->next;
    }

    // wan_stats_t linked list
    const wan_stats_t *wan_stats = report->wan_stats;
    while (wan_stats) {
        fprintf(file, "wan: %s|%lld|%s|%s|%s|%s|%s|%s|%s|%s|%.3f|%.3f|%.3f|%.3f|%s|%s\n",
                timestamp, wan_stats->timestamp_ms, wan_stats->gateway_status, wan_stats->interface_status, wan_stats->ipv4_address,
                wan_stats->ipv6_address, wan_stats->rx_bytes, wan_stats->tx_bytes, wan_stats->rx_dropped,
                wan_stats->tx_dropped, wan_stats->packet_loss, wan_stats->latency, wan_stats->jitter, wan_stats->dns_time,
                wan_stats->ipv4_lease, wan_stats->ipv6_lease);
        wan_stats = wan_stats->next;
    }

    // lan_stats_t linked list
    const lan_stats_t *lan_stats = report->lan_stats;
    while (lan_stats) {
        fprintf(file, "lan: %s|%lld|%s|%s|%s|%s|%s|%s\n",
                timestamp, lan_stats->timestamp_ms, lan_stats->ipv4_address, lan_stats->ipv6_address, lan_stats->rx_bytes,
                lan_stats->tx_bytes, lan_stats->rx_dropped, lan_stats->tx_dropped);
        lan_stats = lan_stats->next;
    }

    // client_stats_t linked list
    const client_stats_t *client_stats = report->client_stats;
    while (client_stats) {
        for (int i = 0; i < client_stats->client_count; ++i) {
            const client_details_t *cd = &client_stats->clients[i];
            fprintf(file,
            "client: cnt: %d |%llu|%s|%s|%s|%s|%s|%s|%d|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u|%u\n",
            client_stats->client_count, client_stats->timestamp_ms,
            cd->ip_addr, cd->host_name, cd->tx_bytes, cd->rx_bytes,
            cd->mac_address, cd->status, cd->tcp_est_counts,
            cd->ipv4_synack_min_latency, cd->ipv4_synack_max_latency, cd->ipv4_synack_avg_latency,
            cd->ipv4_ack_min_latency, cd->ipv4_ack_max_latency, cd->ipv4_ack_avg_latency,
            cd->ipv6_synack_min_latency, cd->ipv6_synack_max_latency, cd->ipv6_synack_avg_latency,
            cd->ipv6_ack_min_latency, cd->ipv6_ack_max_latency, cd->ipv6_ack_avg_latency
            );
        }
        client_stats = client_stats->next;
    }

    // pid_stats_t linked list
    const pid_stats_t *pid_stats = report->pid_stats;
    while (pid_stats) {
        for (int i = 0; i < pid_stats->count; ++i) {
            const pid_details_t *pd = &pid_stats->pid_details[i];
            fprintf(file, "pid_stats: %llu|%u|%s|%u|%u|%u|%u\n",
                    pid_stats->timestamp_ms, pd->pid, pd->pName, pd->rss,
                    pd->pss, pd->mem_util, pd->cpu_util);
        }
        pid_stats = pid_stats->next;
    }

    // tcp_stats_t linked list
    const tcp_stats_t *tcp_stats = report->tcp_stats;
    while (tcp_stats) {
        fprintf(file, "tcp|%lld|%s|%s|%s|%s|%s|%s|%s\n",
            tcp_stats->timestamp_ms,
            tcp_stats->TCPLostRetransmit,
            tcp_stats->TCPRetransFail,
            tcp_stats->TCPSackFailures,
            tcp_stats->TCPTimeouts,
            tcp_stats->TCPAbortOnTimeout,
            tcp_stats->ListenOverflows,
            tcp_stats->TCPOrigDataSent);
        tcp_stats = tcp_stats->next;
    }

    // ipv6_mon_stats_t linked list
    const ipv6_mon_stats_t *ipv6_stats = report->ipv6_stats;
    while (ipv6_stats) {
        fprintf(file, "ipv6_monitoring: %s|%lld|%s|%s|%s|%.3f|%.3f|%.3f|%.3f\n",
                timestamp, ipv6_stats->timestamp_ms, ipv6_stats->ipv6_reachability, ipv6_stats->global_ipv6_address,
                ipv6_stats->link_local_ipv6_address, ipv6_stats->ipv4_latency, ipv6_stats->ipv6_latency,
                ipv6_stats->ipv4_packet_loss, ipv6_stats->ipv6_packet_loss);
        ipv6_stats = ipv6_stats->next;
    }

    // restart_count_stats_t
    const restart_count_stats_t *rc_stats = report->restart_count_stats;
    if (rc_stats) {
        fprintf(file, "restart_count_stats: fw_restart_count=%d, wan_restart_count=%d\n",
                rc_stats->fw_restart_count, rc_stats->wan_restart_count);

        fprintf(file, "fw_restart_time:");
        for (int i = 0; i < rc_stats->fw_restart_count; ++i) {
            if (rc_stats->fw_restart_time && rc_stats->fw_restart_time[i]) {
                fprintf(file, "%s", rc_stats->fw_restart_time[i]);
                if (i < rc_stats->fw_restart_count - 1) {
                    fprintf(file, "|");
                }
            }
        }
        fprintf(file, "\n");
        fprintf(file, "wan_restart_time:");
        for (int i = 0; i < rc_stats->wan_restart_count; ++i) {
            if (rc_stats->wan_restart_time && rc_stats->wan_restart_time[i]) {
                fprintf(file, "%s", rc_stats->wan_restart_time[i]);
                if (i < rc_stats->wan_restart_count - 1) {
                    fprintf(file, "|");
                }
            }
        }
        fprintf(file, "\n");
    }

    fclose(file);
    log_message("save_to_text done!\n");
}

int gw_stats_save() {
    save_to_text(&g_report);
    return 0;
}

int gw_stats_reset() {
    log_message("Reset Gateway Statistics...\n");

    // Free system_stats_t linked list
    system_stats_t *ss = g_report.system_stats;
    while (ss) {
        system_stats_t *next = ss->next;
        free(ss);
        ss = next;
    }
    g_report.system_stats = NULL;
    g_report.n_system_stats = 0;

    // Free wan_stats_t linked list
    wan_stats_t *ws = g_report.wan_stats;
    while (ws) {
        wan_stats_t *next = ws->next;
        free(ws);
        ws = next;
    }
    g_report.wan_stats = NULL;
    g_report.n_wan_stats = 0;

    // Free lan_stats_t linked list
    lan_stats_t *ls = g_report.lan_stats;
    while (ls) {
        lan_stats_t *next = ls->next;
        free(ls);
        ls = next;
    }
    g_report.lan_stats = NULL;
    g_report.n_lan_stats = 0;

    // Free ipv6_mon_stats_t linked list
    ipv6_mon_stats_t *ipv6s = g_report.ipv6_stats;
    while (ipv6s) {
        ipv6_mon_stats_t *next = ipv6s->next;
        free(ipv6s);
        ipv6s = next;
    }
    g_report.ipv6_stats = NULL;
    g_report.n_ipv6_stats = 0;

    // Free tcp_stats_t linked list
    tcp_stats_t *ts = g_report.tcp_stats;
    while (ts) {
        tcp_stats_t *next = ts->next;
        free(ts);
        ts = next;
    }
    g_report.tcp_stats = NULL;
    g_report.n_tcp_stats = 0;

    // Free client_stats_t linked list
    client_stats_t *cs = g_report.client_stats;
    while (cs) {
        if (cs->clients) {
            free(cs->clients);
        }
        client_stats_t *next = cs->next;
        free(cs);
        cs = next;
    }
    g_report.client_stats = NULL;
    g_report.n_client_stats = 0;

    // Free pid_stats_t linked list
    pid_stats_t *ps = g_report.pid_stats;
    while (ps) {
        if (ps->pid_details) {
            free(ps->pid_details);
        }
        pid_stats_t *next = ps->next;
        free(ps);
        ps = next;
    }
    g_report.pid_stats = NULL;
    g_report.n_pid_stats = 0;

    // Free and reinitialize restart_count_stats as in init function
    if (g_report.restart_count_stats) {
        // Free fw_restart_time array if allocated
        if (g_report.restart_count_stats->fw_restart_time) {
            free(g_report.restart_count_stats->fw_restart_time);
            g_report.restart_count_stats->fw_restart_time = NULL;
        }
        // Free wan_restart_time array if allocated
        if (g_report.restart_count_stats->wan_restart_time) {
            free(g_report.restart_count_stats->wan_restart_time);
            g_report.restart_count_stats->wan_restart_time = NULL;
        }
        free(g_report.restart_count_stats);
        g_report.restart_count_stats = NULL;
    }
    g_report.restart_count_stats = (restart_count_stats_t *)malloc(sizeof(restart_count_stats_t));
    if (g_report.restart_count_stats) {
        g_report.restart_count_stats->fw_restart_count = 0;
        g_report.restart_count_stats->fw_restart_time = NULL;
        g_report.restart_count_stats->wan_restart_count = 0;
        g_report.restart_count_stats->wan_restart_time = NULL;
    }

    SAFE_FREE(&encoded_buffer);
    encoded_buffer_len = 0;

    log_message("Gateway Statistics Reset completed.\n");
    return 0;
}

int gw_stats_free_buffer(gw_stats_report *report) {
    if (!report) return -1;
    gw_stats_reset(report);
    free(report);

    return 0;
}