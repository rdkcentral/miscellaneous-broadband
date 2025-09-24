#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "docsis_stats.pb-c.h"
#include "docsisStats.h"


static Report* report_struct_create()
{
    Report *report = calloc(1, sizeof(Report));
    if (!report) {
        log_message("%s: calloc failed\n", __FUNCTION__);
        return NULL;
    }
    report__init(report);
    return report;
}

static DsChannelStats** dsChannelStats_struct_create(dsChannelStats_t *ds_stats, size_t count, size_t *out_count)
{
    if (!ds_stats || count == 0) {
        return NULL;
    }

    int ind = 0;

    int total_cnt = 0;
    dsChannelStats_t *current = ds_stats;
    for (size_t i=0; i < count; i++) {
        total_cnt += current->ds_channel_count;
        current = current->next;
    }

    DsChannelStats **dsChannelStatsArray = calloc(total_cnt, sizeof(DsChannelStats*));
    if (!dsChannelStatsArray) {
        log_message("%s: calloc failed\n", __FUNCTION__);
        return NULL;
    }

    for (size_t i = 0, ind = 0; i < count; i++) {
       for (int j = 0; j < ds_stats->ds_channel_count; j++) {
            dsChannelStatsArray[ind] = calloc(1, sizeof(DsChannelStats));
            if (!dsChannelStatsArray[ind]) {
                log_message("%s: calloc failed\n", __FUNCTION__);
                // Free previously allocated memory
                for (size_t k = 0; k < ind; k++) {
                    free(dsChannelStatsArray[k]);
                }
                free(dsChannelStatsArray);
                return NULL;
            }
            ds_channel_stats__init(dsChannelStatsArray[ind]);

            dsChannelStatsArray[ind]->timestamp_ms = ds_stats->timestamp_ms;
            dsChannelStatsArray[ind]->ds_channel_count = ds_stats->ds_channel_count;

            PCMMGMT_CM_DS_CHANNEL ds_channel = &ds_stats->ds_channel_stats[j];

            dsChannelStatsArray[ind]->channel_id = ds_channel->ChannelID;
            dsChannelStatsArray[ind]->frequency = strdup(ds_channel->Frequency);
            dsChannelStatsArray[ind]->power_level = strdup(ds_channel->PowerLevel);
            dsChannelStatsArray[ind]->snr_level = strdup(ds_channel->SNRLevel);    
            dsChannelStatsArray[ind]->modulation = strdup(ds_channel->Modulation);
            dsChannelStatsArray[ind]->octets = ds_channel->Octets;
            dsChannelStatsArray[ind]->correcteds = ds_channel->Correcteds;
            dsChannelStatsArray[ind]->uncorrectables = ds_channel->Uncorrectables;
            dsChannelStatsArray[ind]->lock_status = strdup(ds_channel->LockStatus);

            ind++;
        }
        ds_stats = ds_stats->next;
    }

    *out_count = total_cnt;
    return dsChannelStatsArray;
}

static UsChannelStats** usChannelStats_struct_create(usChannelStats_t *us_stats, size_t count, size_t *out_count)
{
    if (!us_stats || count == 0) {
        return NULL;
    }

    int ind = 0;

    int total_cnt = 0;
    usChannelStats_t *current = us_stats;
    for (size_t i=0; i < count; i++) {
        total_cnt += current->us_channel_count;
        current = current->next;
    }

    UsChannelStats **usChannelStatsArray = calloc(total_cnt, sizeof(UsChannelStats*));
    if (!usChannelStatsArray) {
        log_message("%s: calloc failed\n", __FUNCTION__);
        return NULL;
    }

    for (size_t i = 0, ind = 0; i < count; i++) {
       for (int j = 0; j < us_stats->us_channel_count; j++) {
            usChannelStatsArray[ind] = calloc(1, sizeof(UsChannelStats));
            if (!usChannelStatsArray[ind]) {
                log_message("%s: calloc failed\n", __FUNCTION__);
                // Free previously allocated memory
                for (size_t k = 0; k < ind; k++) {
                    free(usChannelStatsArray[k]);
                }
                free(usChannelStatsArray);
                return NULL;
            }
            us_channel_stats__init(usChannelStatsArray[ind]);

            usChannelStatsArray[ind]->timestamp_ms = us_stats->timestamp_ms;
            usChannelStatsArray[ind]->us_channel_count = us_stats->us_channel_count;

            PCMMGMT_CM_US_CHANNEL us_channel = &us_stats->us_channel_stats[j];

            usChannelStatsArray[ind]->channel_id = us_channel->ChannelID;
            usChannelStatsArray[ind]->frequency = strdup(us_channel->Frequency);
            usChannelStatsArray[ind]->power_level = strdup(us_channel->PowerLevel);
            usChannelStatsArray[ind]->channel_type = strdup(us_channel->ChannelType);
            usChannelStatsArray[ind]->symbol_rate = strdup(us_channel->SymbolRate);
            usChannelStatsArray[ind]->modulation = strdup(us_channel->Modulation);
            usChannelStatsArray[ind]->lock_status = strdup(us_channel->LockStatus);

            ind++;
        }
        us_stats = us_stats->next;
    }

    *out_count = total_cnt;
    return usChannelStatsArray;
}

static void free_dsChannelStats(DsChannelStats **dsChannelStats, size_t count) {
    if (!dsChannelStats) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        if (dsChannelStats[i]) {
            SAFE_FREE(&dsChannelStats[i]->frequency);
            SAFE_FREE(&dsChannelStats[i]->power_level);
            SAFE_FREE(&dsChannelStats[i]->snr_level);
            SAFE_FREE(&dsChannelStats[i]->modulation);
            SAFE_FREE(&dsChannelStats[i]->lock_status);
            SAFE_FREE(&dsChannelStats[i]);
        }
    }
    SAFE_FREE(&dsChannelStats);
}

static void free_usChannelStats(UsChannelStats **usChannelStats, size_t count) {
    if (!usChannelStats) {
        return;
    }

    for (size_t i = 0; i < count; i++) {
        if (usChannelStats[i]) {
            SAFE_FREE(&usChannelStats[i]->frequency);
            SAFE_FREE(&usChannelStats[i]->power_level);
            SAFE_FREE(&usChannelStats[i]->channel_type);
            SAFE_FREE(&usChannelStats[i]->symbol_rate);
            SAFE_FREE(&usChannelStats[i]->modulation);
            SAFE_FREE(&usChannelStats[i]->lock_status);
            SAFE_FREE(&usChannelStats[i]);
        }
    }
    SAFE_FREE(&usChannelStats);
}

static void free_report_struct(Report *report) {
    if (!report) {
        return;
    }

    free_dsChannelStats(report->dschanneldata, report->n_dschanneldata);
    free_usChannelStats(report->uschanneldata, report->n_uschanneldata);
    SAFE_FREE(&report);
} 

void* encode_report(docsis_stats_report *rpt, size_t *buff_len) {
    Report *report = NULL;
    DsChannelStats **dsChannelStats = NULL;
    UsChannelStats **usChannelStats = NULL;

    size_t len = 0;
    void *buffer = NULL;

    if (!rpt) {
        log_message("%s: rpt is NULL\n", __FUNCTION__);
        return NULL;
    }

    report = report_struct_create();
    if (!report) {
        log_message("%s: report_struct_create failed\n", __FUNCTION__);
        return NULL;
    }

    dsChannelStats = dsChannelStats_struct_create(rpt->ds_channel_stats, rpt->n_ds_channel_stats, &(report->n_dschanneldata));
    if (dsChannelStats) {
        report->dschanneldata = dsChannelStats;
    }

    usChannelStats = usChannelStats_struct_create(rpt->us_channel_stats, rpt->n_us_channel_stats, &(report->n_uschanneldata));
    if (usChannelStats) {
        report->uschanneldata = usChannelStats;
    }

    len = report__get_packed_size(report);
    buffer = (void*) calloc(1, len);
    if (!buffer) {
        log_message("%s: calloc failed for buffer\n", __FUNCTION__);
        goto cleanup;
    }
    report__pack(report, buffer);
    *buff_len = len;
    log_message("%s: Encoded report size: %zu bytes\n", __FUNCTION__, len);

cleanup:
    free_report_struct(report);
    return buffer;
}
