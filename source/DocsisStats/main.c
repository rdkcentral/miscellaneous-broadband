#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ev.h> 

#include "docsisStats.h"

docsis_stats_report g_docsis_report;
char* encoded_data;
size_t encoded_data_len;

uint32_t sampling_interval;
uint32_t reporting_interval;

pthread_mutex_t g_report_lock = PTHREAD_MUTEX_INITIALIZER;

// Event loop callback for periodic sampling
static void collect_cb(EV_P_ ev_timer *w, int revents) {
    (void)loop;  // unused
    (void)w;     // unused
    (void)revents;

    log_message("Collecting Docsis stats...\n");
    pthread_mutex_lock(&g_report_lock);
    docsis_stats_collect();
    pthread_mutex_unlock(&g_report_lock);
}

// Callback for Reporting stats
static void report_cb(EV_P_ ev_timer *w, int revents) {
    (void)loop;
    (void)w;
    (void)revents;
    bool res = false;
    log_message("Reporting Docsis stats...\n");

    pthread_mutex_lock(&g_report_lock);
    docsis_stats_save();

    //Encode the collected data to protobuf format
    encoded_data =  (char *)encode_report(&g_docsis_report, &encoded_data_len);
    if (!encoded_data) {
        log_message("report_cb: encode_report failed\n");
    }
    log_message("Encoded report size: %zu bytes\n", encoded_data_len);

    //Publish the encoded data to MQTT broker
    res = docsis_stats_publish_data((void *)encoded_data, encoded_data_len);
    if (res) {
        log_message("report_cb: docsis_stats_publish_data SUCCESS\n");

        //Reset g_docsis_report after successful publish
        //Don't reset g_docsis_report if publish fails, to avoid data loss
        docsis_stats_reset();
    }
    else {
        log_message("report_cb: docsis_stats_publish_data FAILED\n");
    }

    pthread_mutex_unlock(&g_report_lock);
}


int main() {
    log_message("Starting Docsis Stats Collection\n");

    docsis_stats_init();

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
    docsis_stats_cleanup(&g_docsis_report);
    pthread_mutex_unlock(&g_report_lock);

    ev_loop_destroy(loop);
    pthread_mutex_destroy(&g_report_lock);

    log_message("Docsis Stats Collection Finished\n");
    return 0;
}