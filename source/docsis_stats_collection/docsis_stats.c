#include "docsis_stats.h"

#define LOG_FILE "/rdklogs/logs/docsis_stats_logs.txt"

// Function to log messages to a file
void log_message(const char *format, ...) {
    FILE *logfp = fopen(LOG_FILE, "a+");
    if (logfp) {
        char timestamp[64];
        struct timespec ts;
        struct tm *tm_info;

        clock_gettime(CLOCK_REALTIME, &ts);
        tm_info = localtime(&ts.tv_sec);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
        snprintf(timestamp + strlen(timestamp), sizeof(timestamp) - strlen(timestamp), ".%03ld", ts.tv_nsec / 1000000);
        fprintf(logfp, "[%s] ", timestamp);

        // Write the log message
        va_list args;
        va_start(args, format);
        vfprintf(logfp, format, args);
        va_end(args);

        fclose(logfp);
    }
}

dsChannelStats_t* initialize_dsChannel_stats(int channel_count)
{
    log_message("Initializing dsChannelStats with channel_count: %d\n", channel_count);
    dsChannelStats_t *stats = (dsChannelStats_t *)calloc(1, sizeof(dsChannelStats_t));
    if (!stats) {
        return NULL;
    }
    stats->ds_channel_count = channel_count;
    stats->timestamp_ms = 0;
    stats->ds_channel_stats = (PCMMGMT_CM_DS_CHANNEL)calloc(channel_count, sizeof(*stats->ds_channel_stats));
    if (!stats->ds_channel_stats) {
        free(stats);
        return NULL;
    }
    stats->next = NULL;
    return stats;
}

usChannelStats_t* initialize_usChannel_stats(int channel_count)
{
    log_message("Initializing usChannelStats with channel_count: %d\n", channel_count);
    usChannelStats_t *stats = (usChannelStats_t *)calloc(1, sizeof(usChannelStats_t));
    if (!stats) {
        return NULL;
    }
    stats->us_channel_count = channel_count;
    stats->timestamp_ms = 0;
    stats->us_channel_stats = (PCMMGMT_CM_US_CHANNEL)calloc(channel_count, sizeof(*stats->us_channel_stats));
    if (!stats->us_channel_stats) {
        free(stats);
        return NULL;
    }
    stats->next = NULL;
    return stats;
}

void free_dsChannel_stats(dsChannelStats_t *head)
{
    log_message("Freeing dsChannelStats\n");
    dsChannelStats_t *current = head;
    dsChannelStats_t *next;

    while (current != NULL) {
        next = current->next;
        if (current->ds_channel_stats) {
            free(current->ds_channel_stats);
            current->ds_channel_stats = NULL;
        }
        free(current);
        current = next;
    }
}

void free_usChannel_stats(usChannelStats_t *head)
{
    log_message("Freeing usChannelStats\n");
    usChannelStats_t *current = head;
    usChannelStats_t *next;

    while (current != NULL) {
        next = current->next;
        if (current->us_channel_stats) {
            free(current->us_channel_stats);
            current->us_channel_stats = NULL;
        }
        free(current);
        current = next;
    }
}

int get_ds_channel_stats(dsChannelStats_t *dsChannelStats)
{
    int res;

    log_message("Getting DS Channel Stats\n");
    if (!dsChannelStats || !dsChannelStats->ds_channel_stats) {
        log_message("Invalid dsChannelStats pointer\n");
        return -1;
    }
    dsChannelStats->timestamp_ms = get_timestamp_ms();

    res = docsis_GetDSChannel(&(dsChannelStats->ds_channel_stats));

    if (res != 0) {
        log_message("docsis_GetDSChannel failed with error code: %d\n", res);
        return res;
    }
    log_message("Successfully retrieved DS Channel Stats\n");
    log_message("freq: %s\n", dsChannelStats->ds_channel_stats[0].Frequency);

    return 0;
}

int get_us_channel_stats(usChannelStats_t *usChannelStats)
{
    int res;

    log_message("Getting US Channel Stats\n");
    if (!usChannelStats || !usChannelStats->us_channel_stats) {
        log_message("Invalid usChannelStats pointer\n");
        return -1;
    }
    usChannelStats->timestamp_ms = get_timestamp_ms();

    res = docsis_GetUSChannel(&(usChannelStats->us_channel_stats));

    if (res != 0) {
        log_message("docsis_GetUSChannel failed with error code: %d\n", res);
        return res;
    }
    log_message("Successfully retrieved US Channel Stats\n");
    log_message("freq: %s\n", usChannelStats->us_channel_stats[0].Frequency);

    return 0;
}