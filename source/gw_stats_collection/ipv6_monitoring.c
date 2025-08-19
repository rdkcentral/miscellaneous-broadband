#include "gw_stats.h"

// API to initialize IPv6 monitoring statistics
void initialize_ipv6_monitoring_stats(IPv6MonitoringStats *stats) {
    memset(stats, 0, sizeof(IPv6MonitoringStats));
    strncpy(stats->global_ipv6_address, "N/A", sizeof(stats->global_ipv6_address));
    strncpy(stats->link_local_ipv6_address, "N/A", sizeof(stats->link_local_ipv6_address));
    strncpy(stats->ipv6_reachability, "N/A", sizeof(stats->ipv6_reachability));
    stats->ipv4_latency = -1.0;
    stats->ipv6_latency = -1.0;
    stats->ipv4_packet_loss = -1.0;
    stats->ipv6_packet_loss = -1.0;
}

// Updated API to check IPv6 Address Assignment (Global & Link-Local)
void check_ipv6_address_assignment(char *global_address, size_t global_size, char *link_local_address, size_t link_local_size) {
    // Fetch Global IPv6 Address
    execute_command("ip -6 addr show erouter0 | grep 'inet6' | grep 'global' | awk '{print $2}' | cut -d'/' -f1", global_address, global_size);

    // Fetch Link-Local IPv6 Address
    execute_command("ip -6 addr show erouter0 | grep 'inet6' | grep 'link' | awk '{print $2}' | cut -d'/' -f1", link_local_address, link_local_size);
}

// Updated API to check IPv6 Routing & Reachability
void check_ipv6_routing_reachability(const char *ipv6_site, char *status, size_t size) {
    char command[256];
    snprintf(command, sizeof(command), "ip -6 route | grep default > /dev/null && ping6 -c 1 %s > /dev/null && echo 'reachable' || echo 'unreachable'", ipv6_site);
    execute_command(command, status, size);
}

// Updated API to compare Dual-Stack Performance (IPv4 vs IPv6 latency & packet loss)
void compare_dual_stack_performance(const char *ipv4_site, const char *ipv6_site, double *ipv4_latency, double *ipv6_latency, double *ipv4_packet_loss, double *ipv6_packet_loss) {
    char command[256];
    char output[64];

    // IPv4 Latency
    snprintf(command, sizeof(command), "ping -c 1 %s | grep 'time=' | awk -F'time=' '{print $2}' | awk '{print $1}'", ipv4_site);
    execute_command(command, output, sizeof(output));
    *ipv4_latency = atof(output);

    // IPv6 Latency
    snprintf(command, sizeof(command), "ping6 -c 1 %s | grep 'time=' | awk -F'time=' '{print $2}' | awk '{print $1}'", ipv6_site);
    execute_command(command, output, sizeof(output));
    *ipv6_latency = atof(output);

    // IPv4 Packet Loss
    snprintf(command, sizeof(command), "ping -c 10 %s | grep 'packet loss' | awk '{print $6}'", ipv4_site);
    execute_command(command, output, sizeof(output));
    *ipv4_packet_loss = atof(output);

    // IPv6 Packet Loss
    snprintf(command, sizeof(command), "ping6 -c 10 %s | grep 'packet loss' | awk '{print $6}'", ipv6_site);
    execute_command(command, output, sizeof(output));
    *ipv6_packet_loss = atof(output);
}

// Updated API to collect IPv6 monitoring statistics using the IPv6MonitoringStats structure
void collect_ipv6_monitoring_stats(IPv6MonitoringStats *stats, const char *ipv4_site, const char *ipv6_site) {
    // Collect IPv6 Address Assignment
    check_ipv6_address_assignment(stats->global_ipv6_address, sizeof(stats->global_ipv6_address),
                                   stats->link_local_ipv6_address, sizeof(stats->link_local_ipv6_address));

    // Collect IPv6 Routing & Reachability
    check_ipv6_routing_reachability(ipv6_site, stats->ipv6_reachability, sizeof(stats->ipv6_reachability));

    // Compare Dual-Stack Performance
    compare_dual_stack_performance(ipv4_site, ipv6_site, &stats->ipv4_latency, &stats->ipv6_latency,
                                   &stats->ipv4_packet_loss, &stats->ipv6_packet_loss);
}
