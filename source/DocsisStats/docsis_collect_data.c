#include "docsisStats.h"

extern docsis_stats_report g_docsis_report;
extern char* encoded_data;
extern size_t encoded_data_len;

extern uint32_t sampling_interval;
extern uint32_t reporting_interval;

int docsis_stats_init() {
    log_message("Docsis Stats Init\n");
    memset(&g_docsis_report, 0, sizeof(docsis_stats_report));

    g_docsis_report.n_ds_channel_stats = 0;
    g_docsis_report.ds_channel_stats = NULL;
    g_docsis_report.n_us_channel_stats = 0;
    g_docsis_report.us_channel_stats = NULL;

    sampling_interval = SAMPLING_INTERVAL;
    reporting_interval = REPORTING_INTERVAL;

    return 0;
}

int docsis_stats_collect() {
    log_message("Collecting Docsis Stats\n");
    long unsigned int ds_channel_count = 0;
    long unsigned int us_channel_count = 0;

    docsis_GetNumOfActiveRxChannels(&ds_channel_count);
    docsis_GetNumOfActiveTxChannels(&us_channel_count);


    if (ds_channel_count > 0) {
        dsChannelStats_t *new_ds_stats = NULL;
        new_ds_stats = initialize_dsChannel_stats(ds_channel_count);
        if (!new_ds_stats) {
            log_message("Failed to initialize dsChannelStats\n");
            return -1;
        }
        get_ds_channel_stats(new_ds_stats);

        if (g_docsis_report.n_ds_channel_stats == 0) {
            g_docsis_report.ds_channel_stats = new_ds_stats;
        } else {
            new_ds_stats->next = g_docsis_report.ds_channel_stats;
            g_docsis_report.ds_channel_stats = new_ds_stats;
        }
        g_docsis_report.n_ds_channel_stats++;
    } else {
        log_message("No DS channels to collect\n");
    }

    if (us_channel_count > 0) {
        usChannelStats_t *new_us_stats = NULL;
        new_us_stats = initialize_usChannel_stats(us_channel_count);
        if (!new_us_stats) {
            log_message("Failed to initialize usChannelStats\n");
            return -1;
        }
        get_us_channel_stats(new_us_stats);

        if (g_docsis_report.n_us_channel_stats == 0) {
            g_docsis_report.us_channel_stats = new_us_stats;
        } else {
            new_us_stats->next = g_docsis_report.us_channel_stats;
            g_docsis_report.us_channel_stats = new_us_stats;
        }
        g_docsis_report.n_us_channel_stats++;
    } else {
        log_message("No US channels to collect\n");
    }

    log_message("Collected DS Channels: %d, US Channels: %d\n", ds_channel_count, us_channel_count);

    return 0;
}

int docsis_stats_save() {
    log_message("Saving Docsis Stats\n");

    FILE *file = fopen("/rdklogs/logs/docsis_stats_data.txt", "a");
    if (!file) {
        fprintf(stderr, "Failed to open file for writing\n");
        return -1;
    }
    fprintf(file, "=== Docsis Stats Report ===\n");
    dsChannelStats_t *ds_curr = g_docsis_report.ds_channel_stats;
    while (ds_curr) {
        fprintf(file, "DS Channel Count: %d\n", ds_curr->ds_channel_count);
        if (ds_curr->ds_channel_stats != NULL) {
            for (int i = 0; i < ds_curr->ds_channel_count; i++) {
                fprintf(file, "%llu|%lu|%s|%s|%s|%s|%lu|%lu|%lu|%s\n",
                        ds_curr->timestamp_ms,
                        ds_curr->ds_channel_stats[i].ChannelID,
                        ds_curr->ds_channel_stats[i].Frequency,
                        ds_curr->ds_channel_stats[i].PowerLevel,
                        ds_curr->ds_channel_stats[i].SNRLevel,
                        ds_curr->ds_channel_stats[i].Modulation,
                        ds_curr->ds_channel_stats[i].Octets,
                        ds_curr->ds_channel_stats[i].Correcteds,
                        ds_curr->ds_channel_stats[i].Uncorrectables,
                        ds_curr->ds_channel_stats[i].LockStatus);
            }
        } else if (ds_curr->ds_channel_count > 0) {
            fprintf(file, "Warning: ds_channel_stats is NULL but count > 0\n");
        }
        ds_curr = ds_curr->next;
    }
    fprintf(file, "\n");

    // Print Upstream Channel Stats
    usChannelStats_t *us_curr = g_docsis_report.us_channel_stats;
    while (us_curr) {
        fprintf(file, "US Channel Count: %d\n", us_curr->us_channel_count);
        if (us_curr->us_channel_stats != NULL) {
            for (int i = 0; i < us_curr->us_channel_count; i++) {
                fprintf(file, "%llu|%lu|%s|%s|%s|%s|%s|%s\n",
                        us_curr->timestamp_ms,
                        us_curr->us_channel_stats[i].ChannelID,
                        us_curr->us_channel_stats[i].Frequency,
                        us_curr->us_channel_stats[i].PowerLevel,
                        us_curr->us_channel_stats[i].ChannelType,
                        us_curr->us_channel_stats[i].SymbolRate,
                        us_curr->us_channel_stats[i].Modulation,
                        us_curr->us_channel_stats[i].LockStatus);
            }
        } else if (us_curr->us_channel_count > 0) {
            fprintf(file, "Warning: us_channel_stats is NULL but count > 0\n");
        }
        us_curr = us_curr->next;
    }
    fprintf(file, "\n");

    fclose(file);
    return 0;
}

int docsis_stats_reset() {
    log_message("Resetting Docsis Stats\n");

    free_dsChannel_stats(g_docsis_report.ds_channel_stats);
    free_usChannel_stats(g_docsis_report.us_channel_stats);
    g_docsis_report.ds_channel_stats = NULL;
    g_docsis_report.us_channel_stats = NULL;
    g_docsis_report.n_ds_channel_stats = 0;
    g_docsis_report.n_us_channel_stats = 0;

    SAFE_FREE(&encoded_data);
    encoded_data_len = 0;

    return 0;
}

int docsis_stats_cleanup(docsis_stats_report *report) {
    log_message("Cleaning up Docsis Stats\n");
    if (!report) {
        return -1;
    }
    docsis_stats_reset();
    free(report);

    return 0;
}