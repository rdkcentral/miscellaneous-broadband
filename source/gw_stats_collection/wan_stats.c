#include "gw_stats.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>

#define WAN_INTERFACE "erouter0"

// API to initialize WAN statistics
void initialize_wan_stats(WanStats *stats) {
    memset(stats, 0, sizeof(WanStats));
    stats->timestamp_ms = 0;
    strncpy(stats->interface_status, "N/A", sizeof(stats->interface_status));
    strncpy(stats->ipv4_address, "N/A", sizeof(stats->ipv4_address));
    strncpy(stats->ipv6_address, "N/A", sizeof(stats->ipv6_address));
    strncpy(stats->gateway_status, "N/A", sizeof(stats->gateway_status));
    stats->packet_loss = -1.0;
    stats->latency = -1.0;
    stats->jitter = -1.0;
    stats->dns_time = -1.0;
    strncpy(stats->rx_bytes, "", sizeof(stats->rx_bytes));
    strncpy(stats->tx_bytes, "", sizeof(stats->tx_bytes));
    strncpy(stats->rx_dropped, "", sizeof(stats->rx_dropped));
    strncpy(stats->tx_dropped, "", sizeof(stats->tx_dropped));
    strncpy(stats->ipv4_lease, "", sizeof(stats->ipv4_lease));
    strncpy(stats->ipv6_lease, "", sizeof(stats->ipv6_lease));
    stats->next = NULL;
}

// API to check WAN Interface Status
void check_wan_interface_status(char *status, size_t size) {
    execute_command("ifconfig " WAN_INTERFACE " | grep 'UP' > /dev/null && echo 'UP' || echo 'DOWN'", status, size);
}

// API to get WAN IPv4 Address
void get_wan_ipv4_address(char *ipv4_address, size_t size) {
    execute_command("ifconfig " WAN_INTERFACE " | awk '/inet addr:/ {print $2}' | cut -d: -f2", ipv4_address, size);
}

// API to get WAN IPv6 Address
void get_wan_ipv6_address(char *ipv6_address, size_t size) {
    execute_command("ifconfig " WAN_INTERFACE " | awk '/inet6 addr:/ && /Scope:Global/ {print $3}' | cut -d'/' -f1", ipv6_address, size);
}

// API to check Gateway Reachability
void check_gateway_reachability(char *status, size_t size) {
    char command[256];
    char output[256];
    FILE *fp;

    snprintf(command, sizeof(command), "ip neigh show | grep -i %s", WAN_INTERFACE);
    fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to run command: %s\n", command);
        strncpy(status, "Offline", size);
        return;
    }

    int reachable = 0;
    while (fgets(output, sizeof(output), fp)) {
        if (strstr(output, "REACHABLE") || strstr(output, "STALE")) {
            reachable = 1;
            break;
        }
    }
    pclose(fp);

    strncpy(status, reachable ? "Online" : "Offline", size);
}

// API to calculate Packet Loss
// API to calculate Packet Drop Rate for WAN interface
void calculate_packet_loss(const char *interface, double *drop_rate) {
    char rx_dropped_path[128], tx_dropped_path[128];
    char rx_packets_path[128], tx_packets_path[128];
    unsigned long rx_dropped1 = 0, tx_dropped1 = 0, rx_packets1 = 0, tx_packets1 = 0;
    unsigned long rx_dropped2 = 0, tx_dropped2 = 0, rx_packets2 = 0, tx_packets2 = 0;
    FILE *fp;

    // Paths to statistics files
    snprintf(rx_dropped_path, sizeof(rx_dropped_path), "/sys/class/net/%s/statistics/rx_dropped", interface);
    snprintf(tx_dropped_path, sizeof(tx_dropped_path), "/sys/class/net/%s/statistics/tx_dropped", interface);
    snprintf(rx_packets_path, sizeof(rx_packets_path), "/sys/class/net/%s/statistics/rx_packets", interface);
    snprintf(tx_packets_path, sizeof(tx_packets_path), "/sys/class/net/%s/statistics/tx_packets", interface);

    // Read initial values
    fp = fopen(rx_dropped_path, "r");
    if (fp) { fscanf(fp, "%lu", &rx_dropped1); fclose(fp); }
    fp = fopen(tx_dropped_path, "r");
    if (fp) { fscanf(fp, "%lu", &tx_dropped1); fclose(fp); }
    fp = fopen(rx_packets_path, "r");
    if (fp) { fscanf(fp, "%lu", &rx_packets1); fclose(fp); }
    fp = fopen(tx_packets_path, "r");
    if (fp) { fscanf(fp, "%lu", &tx_packets1); fclose(fp); }

    // Sleep for a short interval (e.g., 1 second)
    sleep(1);

    // Read values again
    fp = fopen(rx_dropped_path, "r");
    if (fp) { fscanf(fp, "%lu", &rx_dropped2); fclose(fp); }
    fp = fopen(tx_dropped_path, "r");
    if (fp) { fscanf(fp, "%lu", &tx_dropped2); fclose(fp); }
    fp = fopen(rx_packets_path, "r");
    if (fp) { fscanf(fp, "%lu", &rx_packets2); fclose(fp); }
    fp = fopen(tx_packets_path, "r");
    if (fp) { fscanf(fp, "%lu", &tx_packets2); fclose(fp); }

    unsigned long delta_dropped = (rx_dropped2 - rx_dropped1) + (tx_dropped2 - tx_dropped1);
    unsigned long delta_packets = (rx_packets2 - rx_packets1) + (tx_packets2 - tx_packets1);

    if (delta_packets > 0) {
        *drop_rate = (double)delta_dropped / (double)delta_packets;
    } else {
        *drop_rate = 0.0;
    }
}

// API to measure Latency (RTT)
void measure_latency(const char *gateway_ip, double *latency, double *dns_time) {
    char command[256];
    char output[64];
    snprintf(command, sizeof(command), "dig %s | grep 'Query time:' | awk '{print $4}'", gateway_ip);
    execute_command(command, output, sizeof(output));
    *latency = atof(output);
    *dns_time = atof(output);
}

// API to calculate Jitter using pcap
// Jitter is the variation in the delay of received packets.
// This function measures the time difference between consecutive packets
// and computes the average absolute variation in delay.
void calculate_jitter(const char *interface, double *jitter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    struct pcap_pkthdr header;
    const u_char *packet;
    struct timeval prev_timestamp = {0, 0};
    struct timeval curr_timestamp;
    double total_jitter = 0.0;

    handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface, errbuf);
        *jitter = -1.0;
        return;
    }

    for (int i = 0; i < 10; i++) {
        packet = pcap_next(handle, &header);
        if (packet == NULL) continue;

        curr_timestamp = header.ts;
        if (prev_timestamp.tv_sec != 0 || prev_timestamp.tv_usec != 0) {
            double diff = (curr_timestamp.tv_sec - prev_timestamp.tv_sec) * 1e6 +
                          (curr_timestamp.tv_usec - prev_timestamp.tv_usec);
            total_jitter += diff > 0 ? diff : -diff;
        }
        prev_timestamp = curr_timestamp;
    }

    // Convert jitter to milliseconds and round to 3 decimal places
    *jitter = (total_jitter / 9) / 1000.0; // Average jitter in milliseconds
    *jitter = (int)(*jitter * 1000.0 + 0.5) / 1000.0;   // Round to 3 decimal places

    pcap_close(handle);
}

// API to collect interface statistics (rx_bytes, tx_bytes, rx_dropped, tx_dropped)
void collect_interface_stats(const char *interface, char *rx_bytes, char *tx_bytes, char *rx_dropped, char *tx_dropped) {
    char command[256];
    char buffer[256];
    FILE *fp;

    snprintf(command, sizeof(command), "ip -s link show %s", interface);
    fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to run command: %s\n", command);
        return;
    }

    while (fgets(buffer, sizeof(buffer), fp)) {
        if (strstr(buffer, "RX:")) {
            if (fgets(buffer, sizeof(buffer), fp)) {
                sscanf(buffer, "%s %*s %*s %s", rx_bytes, rx_dropped);
            }
        } else if (strstr(buffer, "TX:")) {
            if (fgets(buffer, sizeof(buffer), fp)) {
                sscanf(buffer, "%s %*s %*s %s", tx_bytes, tx_dropped);
            }
        }
    }

    pclose(fp);
}

// API to get WAN IPv4 Lease Time Remaining
void get_wan_ipv4_lease(char *ipv4_lease, size_t size) {
    execute_command("dmcli eRT retv Device.DHCPv4.Client.1.LeaseTimeRemaining", ipv4_lease, size);
}

// API to get WAN IPv6 Lease Time Remaining
void get_wan_ipv6_lease(char *ipv6_lease, size_t size) {
    execute_command("ip -6 route show | grep default | cut -d' ' -f11 | sed 's/sec//'", ipv6_lease, size);
}

// API to collect WAN statistics using the WanStats structure
void collect_wan_stats(WanStats *stats) {
    check_wan_interface_status(stats->interface_status, sizeof(stats->interface_status));
    get_wan_ipv4_address(stats->ipv4_address, sizeof(stats->ipv4_address));
    get_wan_ipv6_address(stats->ipv6_address, sizeof(stats->ipv6_address));
    check_gateway_reachability(stats->gateway_status, sizeof(stats->gateway_status));
    calculate_packet_loss(WAN_INTERFACE, &stats->packet_loss);
    measure_latency("8.8.8.8", &stats->latency, &stats->dns_time);
    calculate_jitter(WAN_INTERFACE, &stats->jitter);
    collect_interface_stats(WAN_INTERFACE, stats->rx_bytes, stats->tx_bytes, stats->rx_dropped, stats->tx_dropped);
    get_wan_ipv4_lease(stats->ipv4_lease, sizeof(stats->ipv4_lease));
    get_wan_ipv6_lease(stats->ipv6_lease, sizeof(stats->ipv6_lease));
}