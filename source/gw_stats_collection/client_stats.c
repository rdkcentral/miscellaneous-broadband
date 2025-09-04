#include "gw_stats.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>

void initialize_client_stats(client_stats_t *stats) {
    memset(stats, 0, sizeof(client_stats_t));
    stats->timestamp_ms = 0;
    stats->clients = NULL;
    stats->client_count = 0;
    stats->next = NULL;
}

void get_all_clients(client_stats_t *stats) {
    static bool is_initialized = false;
    char command[256], output[128], mac_address[32];
    int host_count = 0;
    FILE *fp = popen("dmcli eRT retv Device.Hosts.HostNumberOfEntries", "r");
    if (fp) {
        if (fgets(output, sizeof(output), fp)) {
            host_count = atoi(output);
        }
        pclose(fp);
    }
    if (!is_initialized) {
        stats->clients = NULL;
        stats->client_count = 0;
        is_initialized = true;
    }
    for (int i = 1; i <= host_count; i++) {
        snprintf(command, sizeof(command), "dmcli eRT retv Device.Hosts.Host.%d.PhysAddress", i);
        execute_command(command, mac_address, sizeof(mac_address));
        if (strlen(mac_address) == 0) {
            log_message("Failed to retrieve MAC address for host %d\n", i);
            continue;
        }
        // Check if client already exists
        client_details_t *client = NULL;
        for (int j = 0; j < stats->client_count; j++) {
            if (strcasecmp(stats->clients[j].mac_address, mac_address) == 0) {
                client = &stats->clients[j];
                break;
            }
        }
        if (!client) {
            // New client, allocate and set mac_address
            stats->clients = realloc(stats->clients, (stats->client_count + 1) * sizeof(client_details_t));
            client = &stats->clients[stats->client_count];
            memset(client, 0, sizeof(client_details_t));
            strncpy(client->mac_address, mac_address, sizeof(client->mac_address));
            stats->client_count++;
        }
        strncpy(client->tx_bytes, "", sizeof(client->tx_bytes));
        strncpy(client->rx_bytes, "", sizeof(client->rx_bytes));
        snprintf(command, sizeof(command), "dmcli eRT retv Device.Hosts.Host.%d.IPAddress", i);
        execute_command(command, client->ip_addr, sizeof(client->ip_addr));
        snprintf(command, sizeof(command), "dmcli eRT retv Device.Hosts.Host.%d.HostName", i);
        execute_command(command, client->host_name, sizeof(client->host_name));
        snprintf(command, sizeof(command), "dmcli eRT retv Device.Hosts.Host.%d.Active", i);
        execute_command(command, output, sizeof(output));
        strncpy(client->status, strstr(output, "true") ? "connected" : "not connected", sizeof(client->status));
    }
}

void get_client_traffic_stats(client_stats_t *stats) {
    FILE *fp = popen("traffic_count -L", "r");
    if (!fp) {
        fprintf(stderr, "Failed to execute traffic_count command\n");
        return;
    }
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        char mac_address[32], tx_bytes[64], rx_bytes[64];
        if (sscanf(line, "%31[^|]|%*[^|]|%63[^|]|%*[^|]|%63[^|]|%*s", mac_address, rx_bytes, tx_bytes) == 3) {
            for (int i = 0; i < stats->client_count; i++) {
                if (strcasecmp(stats->clients[i].mac_address, mac_address) == 0) {
                    strncpy(stats->clients[i].tx_bytes, tx_bytes, sizeof(stats->clients[i].tx_bytes));
                    strncpy(stats->clients[i].rx_bytes, rx_bytes, sizeof(stats->clients[i].rx_bytes));
                    break;
                }
            }
        }
    }
    pclose(fp);
}

// API to populate tcp_est_counts for each client
void get_client_tcp_est_counts(client_stats_t *stats) {
    char command[256];
    char output[32];
    for (int i = 0; i < stats->client_count; i++) {
        // Use the client's IP address for connection tracking
        snprintf(command, sizeof(command),
            "cat /proc/net/nf_conntrack | grep '%s' | grep -i 'established' | wc -l",
            stats->clients[i].ip_addr);
        execute_command(command, output, sizeof(output));
        stats->clients[i].tcp_est_counts = atoi(output);
    }
}

static void parse_latency_section(client_stats_t *stats, const char *section, bool is_ipv6) {
    if (!section) return;

    // Skip header (before first semicolon)
    const char *data = strchr(section, ';');
    if (!data) return;
    data++; // move after first semicolon

    char *dup = strdup(data);
    if (!dup) return;

    char *saveptr = NULL;
    char *entry = strtok_r(dup, ";", &saveptr);

    while (entry) {
        char mac[32] = {0};
        char metrics[256] = {0};
        char ports[128] = {0};

        // First token: MAC
        strncpy(mac, entry, sizeof(mac) - 1);

        // Metrics
        char *metrics_str = strtok_r(NULL, ";", &saveptr);
        if (!metrics_str) break;
        strncpy(metrics, metrics_str, sizeof(metrics) - 1);

        // Ports
        char *ports_str = strtok_r(NULL, ";", &saveptr);
        if (!ports_str) break;
        strncpy(ports, ports_str, sizeof(ports) - 1);

        // Parse metrics
        unsigned int count;
        unsigned int syn_min, syn_max, syn_avg, syn_99;
        unsigned int ack_min, ack_max, ack_avg, ack_99;
        if (sscanf(metrics,
                   "%u,%u,%u,%u,%u,%u,%u,%u,%u",
                   &count,
                   &syn_min, &syn_max, &syn_avg, &syn_99,
                   &ack_min, &ack_max, &ack_avg, &ack_99) == 9) {

            for (int i = 0; i < stats->client_count; i++) {
                if (strcasecmp(stats->clients[i].mac_address, mac) == 0) {
                    if (!is_ipv6) {
                        stats->clients[i].ipv4_synack_min_latency = syn_min;
                        stats->clients[i].ipv4_synack_max_latency = syn_max;
                        stats->clients[i].ipv4_synack_avg_latency = syn_avg;
                        stats->clients[i].ipv4_ack_min_latency = ack_min;
                        stats->clients[i].ipv4_ack_max_latency = ack_max;
                        stats->clients[i].ipv4_ack_avg_latency = ack_avg;
                    } else {
                        stats->clients[i].ipv6_synack_min_latency = syn_min;
                        stats->clients[i].ipv6_synack_max_latency = syn_max;
                        stats->clients[i].ipv6_synack_avg_latency = syn_avg;
                        stats->clients[i].ipv6_ack_min_latency = ack_min;
                        stats->clients[i].ipv6_ack_max_latency = ack_max;
                        stats->clients[i].ipv6_ack_avg_latency = ack_avg;
                    }
                }
            }
        }

        entry = strtok_r(NULL, ";", &saveptr);
    }

    free(dup);
}

void get_tcp_latency_for_clients(client_stats_t *stats) {
    char output[8192];
    FILE *fp = popen("dmcli eRT retv Device.QOS.X_RDK_LatencyMeasure_TCP_Stats_Report", "r");
    if (!fp) {
        log_message("Failed to run dmcli for TCP latency stats\n");
        return;
    }
    size_t len = fread(output, 1, sizeof(output) - 1, fp);
    pclose(fp);
    if (len <= 0) return;
    output[len] = '\0';

    char *ipv4_part = strtok(output, "|");
    char *ipv6_part = strtok(NULL, "|");

    parse_latency_section(stats, ipv4_part, false);
    parse_latency_section(stats, ipv6_part, true);
}


void collect_client_stats(client_stats_t *stats) {
    stats->timestamp_ms = get_timestamp_ms();
    get_all_clients(stats);
    get_client_traffic_stats(stats);
    get_client_tcp_est_counts(stats);
    get_tcp_latency_for_clients(stats);
}