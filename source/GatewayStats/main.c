#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cJSON.h"

#include "gw_stats.h"

// Common helper function to execute a command and fetch its output
void execute_command(const char *command, char *output, size_t size) {
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to run command: %s\n", command);
        strncpy(output, "N/A", size);
        return;
    }
    fgets(output, size, fp);
    output[strcspn(output, "\n")] = '\0';
    pclose(fp);
}

// Function to get the current timestamp in the required format
void get_current_timestamp(char *timestamp, size_t size) {
    struct timespec ts;
    struct tm *tm_info;

    clock_gettime(CLOCK_REALTIME, &ts);
    tm_info = localtime(&ts.tv_sec);
    strftime(timestamp, size, "%Y-%m-%d-%H:%M:%S", tm_info); // Format: yyyy-mm-dd-hh:mm:ss
    snprintf(timestamp + strlen(timestamp), size - strlen(timestamp), ".%03ld", ts.tv_nsec / 1000000); // Append milliseconds
}

// Function to save statistics to a text file
void save_to_text(const SystemStats *system_stats, const WanStats *wan_stats, const LanStats *lan_stats, const IPv6MonitoringStats *ipv6_stats) {
    FILE *file = fopen("/rdklogs/logs/gateway_stats_data.txt", "a"); // Open in append mode
    if (!file) {
        fprintf(stderr, "Failed to open file for writing\n");
        return;
    }

    char timestamp[64];
    get_current_timestamp(timestamp, sizeof(timestamp));

    // Write system_params
    fprintf(file, "system_params: %s|%s|%s|%s|%s|%.3f|%.3f|%.3f\n",
            timestamp, system_stats->model, system_stats->firmware, system_stats->cmac,
            system_stats->uptime, system_stats->cpu_usage, system_stats->free_memory, system_stats->slab_memory);

    // Write WAN statistics
    fprintf(file, "wan: %s|%s|%s|%s|%s|%s|%s|%s|%s|%.3f|%.3f|%.3f|%.3f\n",
            timestamp, wan_stats->gateway_status, wan_stats->interface_status, wan_stats->ipv4_address,
            wan_stats->ipv6_address, wan_stats->rx_bytes, wan_stats->tx_bytes, wan_stats->rx_dropped,
            wan_stats->tx_dropped, wan_stats->packet_loss, wan_stats->latency, wan_stats->jitter, wan_stats->dns_time);

    // Write LAN statistics
    fprintf(file, "lan: %s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%d|%d|%d|%d|%d\n",
            timestamp, lan_stats->ipv4_address, lan_stats->ipv6_address, lan_stats->rx_bytes,
            lan_stats->tx_bytes, lan_stats->rx_dropped, lan_stats->tx_dropped,
            lan_stats->channel_util_2_4ghz, lan_stats->channel_util_5ghz, lan_stats->channel_util_6ghz,
            lan_stats->total_clients, lan_stats->client_count_2_4ghz, lan_stats->client_count_5ghz,
            lan_stats->client_count_6ghz, lan_stats->client_count_eth);

    // Write 2.4GHz clients
    for (int i = 0; i < lan_stats->client_count_2_4ghz; i++) {
        fprintf(file, "2.4|%s|%s|%s|%s|%s|%s|%s|%s\n",
                lan_stats->clients_2_4ghz[i].mac_address, lan_stats->clients_2_4ghz[i].ip_addr,
                lan_stats->clients_2_4ghz[i].rssi, lan_stats->clients_2_4ghz[i].snr,
                lan_stats->clients_2_4ghz[i].host_name, lan_stats->clients_2_4ghz[i].status,
                lan_stats->clients_2_4ghz[i].tx_bytes, lan_stats->clients_2_4ghz[i].rx_bytes);
    }

    // Write 5GHz clients
    for (int i = 0; i < lan_stats->client_count_5ghz; i++) {
        fprintf(file, "5|%s|%s|%s|%s|%s|%s|%s|%s\n",
                lan_stats->clients_5ghz[i].mac_address, lan_stats->clients_5ghz[i].ip_addr,
                lan_stats->clients_5ghz[i].rssi, lan_stats->clients_5ghz[i].snr,
                lan_stats->clients_5ghz[i].host_name, lan_stats->clients_5ghz[i].status,
                lan_stats->clients_5ghz[i].tx_bytes, lan_stats->clients_5ghz[i].rx_bytes);
    }

    // Write 6GHz clients
    for (int i = 0; i < lan_stats->client_count_6ghz; i++) {
        fprintf(file, "6|%s|%s|%s|%s|%s|%s|%s|%s\n",
                lan_stats->clients_6ghz[i].mac_address, lan_stats->clients_6ghz[i].ip_addr,
                lan_stats->clients_6ghz[i].rssi, lan_stats->clients_6ghz[i].snr,
                lan_stats->clients_6ghz[i].host_name, lan_stats->clients_6ghz[i].status,
                lan_stats->clients_6ghz[i].tx_bytes, lan_stats->clients_6ghz[i].rx_bytes);
    }

    // Write Ethernet clients
    for (int i = 0; i < lan_stats->client_count_eth; i++) {
        fprintf(file, "eth|%s|%s|%s|%s|%s|%s\n",
                lan_stats->eth_clients[i].mac_address, lan_stats->eth_clients[i].ip_addr,
                lan_stats->eth_clients[i].host_name, lan_stats->eth_clients[i].status,
                lan_stats->eth_clients[i].tx_bytes, lan_stats->eth_clients[i].rx_bytes);
    }

    // Write IPv6 monitoring statistics
    fprintf(file, "ipv6_monitoring: %s|%s|%s|%s|%.3f|%.3f|%.3f|%.3f\n",
            timestamp, ipv6_stats->ipv6_reachability, ipv6_stats->global_ipv6_address,
            ipv6_stats->link_local_ipv6_address, ipv6_stats->ipv4_latency, ipv6_stats->ipv6_latency,
            ipv6_stats->ipv4_packet_loss, ipv6_stats->ipv6_packet_loss);

    fclose(file);
}

int main() {
    SystemStats *system_stats = (SystemStats *)malloc(sizeof(SystemStats));
    WanStats *wan_stats = (WanStats *)malloc(sizeof(WanStats));
    LanStats *lan_stats = (LanStats *)malloc(sizeof(LanStats));
    IPv6MonitoringStats *ipv6_stats = (IPv6MonitoringStats *)malloc(sizeof(IPv6MonitoringStats));

    if (system_stats == NULL || wan_stats == NULL || lan_stats == NULL || ipv6_stats == NULL) {
        fprintf(stderr, "Failed to allocate memory for statistics structures\n");
        free(system_stats);
        free(wan_stats);
        free(lan_stats);
        free(ipv6_stats);
        return EXIT_FAILURE;
    }

    printf("Starting Gateway statistics collection...\n");

    // Initialize statistics
    initialize_system_stats(system_stats);
    initialize_wan_stats(wan_stats);
    initialize_lan_stats(lan_stats);
    initialize_ipv6_monitoring_stats(ipv6_stats);

    // Collect statistics
    collect_system_stats(system_stats);
    collect_wan_stats(wan_stats);
    collect_lan_stats(lan_stats);
    collect_ipv6_monitoring_stats(ipv6_stats, "8.8.8.8", "google.com");

    // Save results to JSON
    // save_to_json(system_stats, wan_stats, lan_stats, ipv6_stats);

    // Save results to text
    save_to_text(system_stats, wan_stats, lan_stats, ipv6_stats);

    printf("Gateway statistics collection completed.\n");

    // Free allocated memory
    free_lan_stats(lan_stats);
    free(system_stats);
    free(wan_stats);
    free(lan_stats);
    free(ipv6_stats);

    return 0;
}
