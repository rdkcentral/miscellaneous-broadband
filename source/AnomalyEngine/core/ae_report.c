/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_report.c
 * ─────────────────────────────────────────────────────────────────────────────
 * Build and write a JSON analysis report (§6.2 schema) + update summary CSV.
 *
 * UUID generation uses /dev/urandom; falls back to timestamp+pid.
 */

#include "ae_report.h"
#include "ae_rule_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#define REPORT_BUF_SIZE (64 * 1024)

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static void gen_uuid(char *out, size_t size) {
    unsigned char b[16];
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) { fread(b, 1, sizeof(b), f); fclose(f); }
    else {
        time_t t = time(NULL); pid_t p = getpid();
        memcpy(b, &t, sizeof(t)); memcpy(b + sizeof(t), &p, sizeof(p));
    }
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    snprintf(out, size,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7],
             b[8],b[9],b[10],b[11],b[12],b[13],b[14],b[15]);
}

static void iso_now(char *out, size_t size) {
    time_t t = time(NULL);
    struct tm *tm = gmtime(&t);
    strftime(out, size, "%Y-%m-%dT%H:%M:%SZ", tm);
}

static void ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) return;
    mkdir(path, 0755);
}

static const char *subdir_for_type(const char *anomaly_type) {
    if      (strcasecmp(anomaly_type, "CPU")    == 0) return "cpu";
    else if (strcasecmp(anomaly_type, "Memory") == 0) return "memory";
    else if (strcasecmp(anomaly_type, "Both")   == 0) return "both";
    else                                               return "other";
}

/* ── Report building ──────────────────────────────────────────────────────── */

int ae_report_write(const AnomalyEvent  *ev,
                    const char * const  *tiers_executed,
                    int                  num_tiers,
                    const char          *collected_json,
                    const char          *logs_json,
                    const ActionRecord  *actions,
                    int                  num_actions,
                    const char          *thresholds_json) {
    char *buf = (char *)malloc(REPORT_BUF_SIZE);
    if (!buf) return -1;

    char uuid[40], ts_now[64];
    gen_uuid(uuid, sizeof(uuid));
    iso_now(ts_now, sizeof(ts_now));

    int pos = 0;
    pos += snprintf(buf + pos, REPORT_BUF_SIZE - (size_t)pos,
                    "{\n"
                    "  \"report_id\":\"%s\",\n"
                    "  \"timestamp\":\"%s\",\n"
                    "  \"model\":\"%s\",\n"
                    "  \"anomaly_type\":\"%s\",\n"
                    "  \"severity\":\"%s\",\n",
                    uuid, ts_now, ev->model, ev->anomaly_type, ev->severity);

    /* collection_tiers_executed array */
    pos += snprintf(buf + pos, REPORT_BUF_SIZE - (size_t)pos,
                    "  \"collection_tiers_executed\":[");
    for (int i = 0; i < num_tiers; i++) {
        pos += snprintf(buf + pos, REPORT_BUF_SIZE - (size_t)pos,
                        "%s\"%s\"", i > 0 ? "," : "", tiers_executed[i]);
    }
    pos += snprintf(buf + pos, REPORT_BUF_SIZE - (size_t)pos, "],\n");

    /* data object */
    pos += snprintf(buf + pos, REPORT_BUF_SIZE - (size_t)pos,
                    "  \"data\":%s,\n",
                    (collected_json && collected_json[0]) ? collected_json : "{}");

    /* thresholds_exceeded */
    pos += snprintf(buf + pos, REPORT_BUF_SIZE - (size_t)pos,
                    "  \"thresholds_exceeded\":%s,\n",
                    (thresholds_json && thresholds_json[0]) ? thresholds_json : "[]");

    /* corrective_actions */
    pos += snprintf(buf + pos, REPORT_BUF_SIZE - (size_t)pos,
                    "  \"corrective_actions\":[");
    for (int i = 0; i < num_actions; i++) {
        pos += snprintf(buf + pos, REPORT_BUF_SIZE - (size_t)pos,
                        "%s{\"action\":\"%s\",\"target\":\"%s\","
                        "\"result\":\"%s\",\"reason\":\"%s\",\"timestamp\":\"%s\"}",
                        i > 0 ? "," : "",
                        actions[i].action_name, actions[i].target,
                        actions[i].result, actions[i].reason, actions[i].timestamp);
    }
    pos += snprintf(buf + pos, REPORT_BUF_SIZE - (size_t)pos, "],\n");

    /* logs (truncated inline if small, omitted if NULL) */
    if (logs_json && strlen(logs_json) < 4096) {
        pos += snprintf(buf + pos, REPORT_BUF_SIZE - (size_t)pos,
                        "  \"logs\":%s,\n", logs_json);
    } else {
        pos += snprintf(buf + pos, REPORT_BUF_SIZE - (size_t)pos,
                        "  \"logs_available\":true,\n");
    }

    /* recommendations */
    pos += snprintf(buf + pos, REPORT_BUF_SIZE - (size_t)pos,
                    "  \"recommendations\":[]");

    pos += snprintf(buf + pos, REPORT_BUF_SIZE - (size_t)pos, "\n}\n");

    /* ── Write report file ──────────────────────────────────────────────── */
    const char *data_path = ae_rules_data_path();
    ensure_dir(data_path);

    char subdir[512];
    snprintf(subdir, sizeof(subdir), "%s/%s", data_path, subdir_for_type(ev->anomaly_type));
    ensure_dir(subdir);

    /* Filename: YYYYMMDD_HHMMSS_<type>.json */
    char ts_file[32];
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(ts_file, sizeof(ts_file), "%Y%m%d_%H%M%S", tm);

    char filepath[640];
    snprintf(filepath, sizeof(filepath), "%s/%s_%s.json",
             subdir, ts_file, ev->anomaly_type);

    FILE *f = fopen(filepath, "w");
    if (!f) { free(buf); return -1; }
    fputs(buf, f);
    fclose(f);
    free(buf);

    /* ── Append to anomaly_summary.csv ─────────────────────────────────── */
    char summary_path[512];
    snprintf(summary_path, sizeof(summary_path), "%s/../anomaly_summary.csv", data_path);

    f = fopen(summary_path, "a");
    if (f) {
        /* Write header on first entry */
        fseek(f, 0, SEEK_END);
        if (ftell(f) == 0)
            fputs("report_id,timestamp,model,anomaly_type,severity,report_file\n", f);
        fprintf(f, "%s,%s,%s,%s,%s,%s\n",
                uuid, ts_now, ev->model, ev->anomaly_type, ev->severity, filepath);
        fclose(f);
    }

    return 0;
}
