#include "gw_stats.h"
#include <pthread.h>
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define LAN_INTERFACE "brlan0"
#define LEASES_FILE "/nvram/dnsmasq.leases"

void initialize_lan_stats(lan_stats_t *stats) {
    memset(stats, 0, sizeof(lan_stats_t));
    stats->timestamp_ms = 0;
    strncpy(stats->ipv4_address, "N/A", sizeof(stats->ipv4_address));
    strncpy(stats->ipv6_address, "N/A", sizeof(stats->ipv6_address));
    strncpy(stats->rx_bytes, "", sizeof(stats->rx_bytes));
    strncpy(stats->tx_bytes, "", sizeof(stats->tx_bytes));
    strncpy(stats->rx_dropped, "", sizeof(stats->rx_dropped));
    strncpy(stats->tx_dropped, "", sizeof(stats->tx_dropped));
    stats->next = NULL;
}

void get_lan_ipv4_address(char *ipv4_address, size_t size) {
    FILE *fp = popen("ifconfig " LAN_INTERFACE " | awk '/inet addr:/ {print $2}' | cut -d: -f2", "r");
    if (fp) {
        if (fgets(ipv4_address, size, fp)) {
            ipv4_address[strcspn(ipv4_address, "\n")] = '\0';
        } else {
            strncpy(ipv4_address, "N/A", size);
        }
        pclose(fp);
    } else {
        strncpy(ipv4_address, "N/A", size);
    }
}

void get_lan_ipv6_address(char *ipv6_address, size_t size) {
    FILE *fp = popen("ifconfig " LAN_INTERFACE " | awk '/inet6 addr:/ && /Scope:Global/ {print $3}' | cut -d'/' -f1", "r");
    if (fp) {
        if (fgets(ipv6_address, size, fp)) {
            ipv6_address[strcspn(ipv6_address, "\n")] = '\0';
        } else {
            strncpy(ipv6_address, "N/A", size);
        }
        pclose(fp);
    } else {
        strncpy(ipv6_address, "N/A", size);
    }
}

void collect_lan_stats(lan_stats_t *stats) {
    stats->timestamp_ms = get_timestamp_ms();
    char rx_bytes[64] = {0}, tx_bytes[64] = {0}, rx_dropped[64] = {0}, tx_dropped[64] = {0};
    get_lan_ipv4_address(stats->ipv4_address, sizeof(stats->ipv4_address));
    get_lan_ipv6_address(stats->ipv6_address, sizeof(stats->ipv6_address));
    collect_interface_stats(LAN_INTERFACE, rx_bytes, tx_bytes, rx_dropped, tx_dropped);
    strncpy(stats->rx_bytes, rx_bytes, sizeof(stats->rx_bytes));
    strncpy(stats->tx_bytes, tx_bytes, sizeof(stats->tx_bytes));
    strncpy(stats->rx_dropped, rx_dropped, sizeof(stats->rx_dropped));
    strncpy(stats->tx_dropped, tx_dropped, sizeof(stats->tx_dropped));
}