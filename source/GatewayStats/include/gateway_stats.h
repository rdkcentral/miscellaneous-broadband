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
#include "ansc_platform.h"

#include "gw_stats.h"

// #define SAMPLING_INTERVAL   300 // 5 minutes
// #define REPORTING_INTERVAL  900 // 15 minutes

#define SAMPLING_INTERVAL   90
#define REPORTING_INTERVAL  180


#define SAFE_FREE(pptr) \
    do { \
        if ((pptr) != NULL && *(pptr) != NULL) { \
            free(*(pptr)); \
            *(pptr) = NULL; \
        } \
    } while (0)

typedef struct
{
    uint64_t timestamp;
    size_t n_system_stats;
    system_stats_t *system_stats;
    size_t n_wan_stats;
    wan_stats_t *wan_stats;
    size_t n_lan_stats;
    lan_stats_t *lan_stats;
    size_t n_ipv6_stats;
    ipv6_mon_stats_t *ipv6_stats;
    size_t n_tcp_stats;
    tcp_stats_t *tcp_stats;
    size_t n_client_stats;
    client_stats_t *client_stats;
    size_t n_pid_stats;
    pid_stats_t *pid_stats;
    restart_count_stats_t *restart_count_stats;
} gw_stats_report;


int gw_stats_init();
int gw_stats_collect();
int gw_stats_save();
int gw_stats_reset();
int RestartCountStats_StartThread();
int RestartCountStats_StopThread();
int gw_stats_free_buffer(gw_stats_report *report);
bool gw_stats_publish_data(void *data, long data_len);

#endif //GATEWAY_STATS_H