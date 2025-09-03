#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ev.h> 

#include "gateway_stats.h"

gw_stats_report g_report;
uint32_t sampling_interval;
uint32_t reporting_interval;

pthread_mutex_t g_report_lock = PTHREAD_MUTEX_INITIALIZER;

// Event loop callback for periodic sampling
static void collect_cb(EV_P_ ev_timer *w, int revents) {
    (void)loop;  // unused
    (void)w;     // unused
    (void)revents;

    log_message("Collecting Gateway stats...\n");
    pthread_mutex_lock(&g_report_lock);
    gw_stats_collect();
    pthread_mutex_unlock(&g_report_lock);
}

// Callback for Reporting stats
static void report_cb(EV_P_ ev_timer *w, int revents) {
    (void)loop;
    (void)w;
    (void)revents;
    log_message("Reporting stats...\n");

    pthread_mutex_lock(&g_report_lock);
    gw_stats_save();
    gw_stats_reset();
    pthread_mutex_unlock(&g_report_lock);
}

int main() {
    log_message("Starting Gateway statistics App...\n");

    gw_stats_init();

    // Initialize event loop
    struct ev_loop *loop = EV_DEFAULT;

    // Timer watcher for periodic collection
    ev_timer collect_timer;
    ev_timer_init(&collect_timer, collect_cb, 0.0, sampling_interval);
    ev_timer_start(loop, &collect_timer);

    // Timer for periodic reporting
    ev_timer report_timer;
    ev_timer_init(&report_timer, report_cb, reporting_interval, reporting_interval);
    ev_timer_start(loop, &report_timer);

    // Start event loop
    ev_run(loop, 0);

    pthread_mutex_lock(&g_report_lock);
    gw_stats_free_buffer(&g_report);
    pthread_mutex_unlock(&g_report_lock);

    pthread_mutex_destroy(&g_report_lock);
    printf("Gateway statistics collection completed.\n");
    return 0;
}
