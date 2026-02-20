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

#include <systemstats_apis.h>
#include "system_stats.h"
#include "helper.h"

SystemStats *system_stats = NULL;

// static int collection_interval = 120;
static int collection_interval = DEFAULT_INTERVAL;

static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t stats_cond = PTHREAD_COND_INITIALIZER;
static pthread_t stats_thread;
static bool stop_thread = false;

// Function to save statistics to a text file
void save_to_text(const SystemStats *system_stats) {

    FILE *file = fopen("/rdklogs/logs/system_stats_data.txt", "a");
    if (!file) {
        fprintf(stderr, "Failed to open file for writing\n");
        return;
    }

    char timestamp[64];
    get_current_timestamp(timestamp, sizeof(timestamp));

    // Write system_params
    fprintf(file, "system_params: %s|%s|%s|%s|%s|%.3f|%.3f|%.3f|%.3f|%.3f|%.3f|%.3f|%.3f|%.3f|[",
            timestamp, system_stats->model, system_stats->firmware, system_stats->cmac,
            system_stats->uptime, system_stats->cpu_usage, system_stats->free_memory, system_stats->slab_memory,
            system_stats->avail_memory, system_stats->cached_mem, system_stats->slab_unreclaim,
            system_stats->loadavg_1min, system_stats->loadavg_5min, system_stats->loadavg_15min);

    fclose(file);
}

// Function to initialize System Statistics
int SystemStats_Init() {
    log_message("Initializing System Statistics...\n");

    system_stats = (SystemStats *)malloc(sizeof(SystemStats));
    if (system_stats == NULL) {
        log_message("Failed to allocate memory for SystemStats.\n");
        return -1;
    }

    initialize_system_stats(system_stats);

    log_message("System Statistics Initialization completed.\n");
    return 0;
}

// Function to collect System Statistics
int SystemStats_Collect() {
    collect_system_stats(system_stats);
    return 0;
}

// Function to save System Statistics
int SystemStats_Save() {
    save_to_text(system_stats);
    return 0;
}

// Function to deinitialize System Statistics
int SystemStats_DeInit() {
    log_message("Deinitializing System Statistics...\n");

    free(system_stats);

    log_message("System Statistics deinitialization completed.\n");
    return 0;
}

static void *stats_thread_func(void *arg) {
    UNREFERENCED_PARAMETER(arg);
    log_message("Collect System Statistics for every %d minutes.\n", collection_interval / 60);

    // Collect data immediately on startup
    SystemStats_Collect();
    SystemStats_Save();

    while (1) {
        pthread_mutex_lock(&stats_mutex);

        if (stop_thread) {
            pthread_mutex_unlock(&stats_mutex);
            break;
        }

        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += collection_interval;

        pthread_cond_timedwait(&stats_cond, &stats_mutex, &ts);

        if (stop_thread) {
            pthread_mutex_unlock(&stats_mutex);
            break;
        }

        pthread_mutex_unlock(&stats_mutex);

        // Collect and save data
        log_message("Starting SystemStats collection..\n");
        SystemStats_Collect();
        SystemStats_Save();
        log_message("SystemStats collection and save completed.\n");
    }

    return NULL;
}

int SystemStats_StartThread() {
    // Create the stats collection thread
    if (pthread_create(&stats_thread, NULL, stats_thread_func, NULL) != 0) {
        log_message("Failed to create stats collection thread.\n");
        return -1;
    }
    pthread_detach(stats_thread);

    return 0;
}

void SystemStats_StopThread() {
    pthread_mutex_lock(&stats_mutex);
    stop_thread = true;
    pthread_cond_signal(&stats_cond); // Wake up the thread to exit
    pthread_mutex_unlock(&stats_mutex);
}
