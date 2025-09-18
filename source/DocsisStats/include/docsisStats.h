#ifndef DOCSISSTATS_H
#define DOCSISSTATS_H

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

#include "docsis_stats.h"


// #define SAMPLING_INTERVAL   300 // 5 minutes
// #define REPORTING_INTERVAL  900 // 15 minutes

#define SAMPLING_INTERVAL   20
#define REPORTING_INTERVAL  60

#define SAFE_FREE(pptr) \
    do { \
        if ((pptr) != NULL && *(pptr) != NULL) { \
            free(*(pptr)); \
            *(pptr) = NULL; \
        } \
    } while (0)


typedef struct {
    size_t n_ds_channel_stats;
    dsChannelStats_t *ds_channel_stats;
    size_t n_us_channel_stats;
    usChannelStats_t *us_channel_stats;
} docsis_stats_report;

int docsis_stats_init();
int docsis_stats_collect();
int docsis_stats_save();
int docsis_stats_reset();
int docsis_stats_cleanup(docsis_stats_report *report);

void* encode_report(docsis_stats_report *rpt, size_t *buff_len);
bool docsis_stats_publish_data(void *data, long data_len);

#endif // DOCSISSTATS_H