#include "gw_stats.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <errno.h>

void initialize_client_stats(ClientStats *stats) {
    memset(stats, 0, sizeof(ClientStats));
    stats->timestamp_ms = 0;
    stats->clients = NULL;
    stats->client_count = 0;
    stats->next = NULL;
}

void get_all_clients(ClientStats *stats) {
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
        log_message("Using new clients structure\n");
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
        ClientDetails *client = NULL;
        for (int j = 0; j < stats->client_count; j++) {
            if (strcasecmp(stats->clients[j].mac_address, mac_address) == 0) {
                client = &stats->clients[j];
                break;
            }
        }
        if (!client) {
            // New client, allocate and set mac_address
            stats->clients = realloc(stats->clients, (stats->client_count + 1) * sizeof(ClientDetails));
            client = &stats->clients[stats->client_count];
            memset(client, 0, sizeof(ClientDetails));
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

void get_client_traffic_stats(ClientStats *stats) {
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
void get_client_tcp_est_counts(ClientStats *stats) {
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

void collect_client_stats(ClientStats *stats) {
    log_message("collect_client_stats started\n");
    stats->timestamp_ms = get_timestamp_ms();
    get_all_clients(stats);
    get_client_traffic_stats(stats);
    get_client_tcp_est_counts(stats);
    log_message("collect_client_stats completed\n");
}