#ifndef GATEWAY_STATS_H
#define GATEWAY_STATS_H


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <errno.h>

#include "gw_stats.h"

#define SAMPLING_INTERVAL   300 // 5 minutes
#define REPORTING_INTERVAL  900 // 15 minutes

typedef struct
{
    uint64_t timestamp;
    size_t n_system_stats;
    SystemStats *system_stats;
    size_t n_wan_stats;
    WanStats *wan_stats;
    size_t n_lan_stats;
    LanStats *lan_stats;
    size_t n_ipv6_stats;
    IPv6MonitoringStats *ipv6_stats;
    size_t n_tcp_stats;
    TcpStats *tcp_stats;
    RestartCountStats *restart_count_stats;
} gw_stats_report;


int gw_stats_init();
int gw_stats_collect();
int gw_stats_save();
int gw_stats_deInit();

#endif //GATEWAY_STATS_H