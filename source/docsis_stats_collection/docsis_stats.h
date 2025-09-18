#ifndef DOCSIS_STATS_COLLECTION_H
#define DOCSIS_STATS_COLLECTION_H

#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "cm_hal.h"

#define TIME_NSEC_IN_SEC   1000000000
#define TIME_USEC_IN_SEC   1000000
#define TIME_MSEC_IN_SEC   1000
#define TIME_NSEC_PER_MSEC (TIME_NSEC_IN_SEC / TIME_MSEC_IN_SEC)

static inline uint64_t timespec_to_timestamp(const struct timespec *ts)
{
    return (uint64_t)ts->tv_sec * TIME_MSEC_IN_SEC + ts->tv_nsec / TIME_NSEC_PER_MSEC;
}

static inline uint64_t get_timestamp_ms(void)
{
    struct timespec              ts;

    memset (&ts, 0, sizeof (ts));
    if(clock_gettime(CLOCK_REALTIME, &ts) != 0)
    {
        return 0;
    }
    else
        return timespec_to_timestamp(&ts);
}

typedef struct dsChannelStats {
    int ds_channel_count;
    uint64_t timestamp_ms;
    PCMMGMT_CM_DS_CHANNEL ds_channel_stats;
    struct dsChannelStats *next;
} dsChannelStats_t;

typedef struct usChannelStats {
    int us_channel_count;
    uint64_t timestamp_ms;
    PCMMGMT_CM_US_CHANNEL us_channel_stats;
    struct usChannelStats *next;
} usChannelStats_t;

void log_message(const char *format, ...);

dsChannelStats_t* initialize_dsChannel_stats(int channel_count);
usChannelStats_t* initialize_usChannel_stats(int channel_count);
void free_dsChannel_stats(dsChannelStats_t *head);
void free_usChannel_stats(usChannelStats_t *head);
int get_ds_channel_stats(dsChannelStats_t *dsChannelStats);
int get_us_channel_stats(usChannelStats_t *usChannelStats);

#endif //DOCSIS_STATS_COLLECTION_H