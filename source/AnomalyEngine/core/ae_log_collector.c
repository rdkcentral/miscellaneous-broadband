/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_log_collector.c
 * ─────────────────────────────────────────────────────────────────────────────
 * Read /rdklogs/logs/ files and return lines within a timestamp window.
 * Handles RDK-B format "YYYY-MM-DD-HH:MM:SS" and ISO-8601 variants.
 */

#include "ae_log_collector.h"
#include "ae_rule_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/stat.h>

#define LOG_LINE_MAX   1024
#define LOG_TS_LEN     20   /* "YYYY-MM-DD-HH:MM:SS" */
#define LINES_PER_FILE 1000 /* max lines collected per file */



/* ── Timestamp parsing ────────────────────────────────────────────────────── */

static time_t parse_timestamp(const char *s) {
    struct tm tm;
    memset(&tm, 0, sizeof(tm));
    /* Try "YYYY-MM-DD-HH:MM:SS" (RDK-B device log format) */
    if (sscanf(s, "%d-%d-%d-%d:%d:%d",
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {
        tm.tm_year -= 1900; tm.tm_mon -= 1; tm.tm_isdst = -1;
        return mktime(&tm);
    }
    /* Try ISO-8601 "YYYY-MM-DDTHH:MM:SS" */
    if (sscanf(s, "%d-%d-%dT%d:%d:%d",
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {
        tm.tm_year -= 1900; tm.tm_mon -= 1; tm.tm_isdst = -1;
        return mktime(&tm);
    }
    /* Try "YYYY-MM-DD HH:MM:SS" */
    if (sscanf(s, "%d-%d-%d %d:%d:%d",
               &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
               &tm.tm_hour, &tm.tm_min, &tm.tm_sec) == 6) {
        tm.tm_year -= 1900; tm.tm_mon -= 1; tm.tm_isdst = -1;
        return mktime(&tm);
    }
    return (time_t)-1;
}

/* Escape a string for embedding in JSON (writes to out, returns chars written) */
static int json_escape_str(const char *in, char *out, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j < out_size - 3; i++) {
        unsigned char c = (unsigned char)in[i];
        if      (c == '"')       { out[j++] = '\\'; out[j++] = '"';  }
        else if (c == '\\')      { out[j++] = '\\'; out[j++] = '\\'; }
        else if (c == '\n')      { out[j++] = '\\'; out[j++] = 'n';  }
        else if (c == '\r')      { out[j++] = '\\'; out[j++] = 'r';  }
        else if (c == '\t')      { out[j++] = '\\'; out[j++] = 't';  }
        else if (c >= 0x20)      { out[j++] = (char)c; }
    }
    out[j] = '\0';
    return (int)j;
}

/* ── Collect one log file ─────────────────────────────────────────────────── */

static size_t collect_one_file(const char *filepath, const char *filename,
                                time_t t_start, time_t t_end,
                                char *out, size_t out_size,
                                long *bytes_read_out) {
    FILE *f = fopen(filepath, "r");
    if (!f) return 0;

    size_t pos = 0;
    long   raw_bytes = 0;
    int    line_count = 0;
    int    first_entry = 1;
    char   line[LOG_LINE_MAX];
    char   escaped[LOG_LINE_MAX * 2];
    char   ts_str[LOG_TS_LEN + 1];

    /* Open JSON array for this file */
    pos += (size_t)snprintf(out + pos, out_size - pos,
                            "\"%s\":[", filename);

    while (fgets(line, sizeof(line), f) && line_count < LINES_PER_FILE) {
        /* Strip trailing newline */
        size_t llen = strlen(line);
        while (llen > 0 && (line[llen-1] == '\n' || line[llen-1] == '\r'))
            line[--llen] = '\0';

        raw_bytes += (long)llen;

        /* Extract timestamp: first 19 chars "YYYY-MM-DD-HH:MM:SS" or "YYYY-MM-DDTHH:MM:SS" */
        if (llen < 19) continue;
        strncpy(ts_str, line, LOG_TS_LEN);
        ts_str[LOG_TS_LEN] = '\0';
        /* Replace space separator with '-' so parse_timestamp handles both formats */
        if (ts_str[10] == ' ') ts_str[10] = '-';
        if (ts_str[10] == 'T') ts_str[10] = '-';

        time_t line_ts = parse_timestamp(ts_str);
        if (line_ts == (time_t)-1) continue; /* no recognisable timestamp */
        if (line_ts < t_start || line_ts > t_end) continue;

        json_escape_str(line, escaped, sizeof(escaped));
        if (pos + strlen(escaped) + 64 >= out_size) break; /* guard overflow */

        pos += (size_t)snprintf(out + pos, out_size - pos,
                                "%s{\"ts\":\"%s\",\"line\":\"%s\"}",
                                first_entry ? "" : ",",
                                ts_str, escaped);
        first_entry = 0;
        line_count++;
    }

    pos += (size_t)snprintf(out + pos, out_size - pos, "]");
    fclose(f);

    if (bytes_read_out) *bytes_read_out = raw_bytes;
    return pos;
}

/* ── Public API ───────────────────────────────────────────────────────────── */

LogCollectionResult ae_log_collector_collect(const char *anomaly_timestamp,
                                              int         window_before_sec,
                                              int         window_after_sec) {
    LogCollectionResult res;
    memset(&res, 0, sizeof(res));

    time_t base = parse_timestamp(anomaly_timestamp);
    if (base == (time_t)-1) {
        res.error = -1;
        return res;
    }
    time_t t_start = base - (time_t)window_before_sec;
    time_t t_end   = base + (time_t)window_after_sec;

    char cfg_files[32][64];
    int  num_cfg = ae_rules_log_files(cfg_files, 32);
    const char *logs_dir = ae_rules_logs_directory();
    int  max_kb = ae_rules_max_log_size_kb();

    /* Allocate output buffer: max_kb * 1024 bytes, but cap at 8 MB */
    size_t out_size = (size_t)max_kb * 1024;
    if (out_size > 8 * 1024 * 1024) out_size = 8 * 1024 * 1024;

    char *out = (char *)calloc(out_size, 1);
    if (!out) { res.error = -1; return res; }

    size_t pos = 0;
    pos += (size_t)snprintf(out + pos, out_size - pos, "{");

    int  files_done  = 0;
    long total_bytes = 0;

    /*
     * If log_files list is empty, enumerate every regular file in logs_dir.
     * Otherwise use the explicit list from config.
     */
    if (num_cfg == 0) {
        /* Collect all regular files in the logs directory */
        DIR *d = opendir(logs_dir);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) {
                if (ent->d_name[0] == '.') continue;

                /* Accept only regular files */
                char filepath[512];
                snprintf(filepath, sizeof(filepath), "%s/%s", logs_dir, ent->d_name);
                struct stat st;
                if (stat(filepath, &st) != 0 || !S_ISREG(st.st_mode)) continue;

                size_t avail = (pos < out_size - 2) ? (out_size - pos - 2) : 0;
                if (avail < 1024) break;

                char *file_buf = (char *)calloc(avail, 1);
                if (!file_buf) break;

                long fbytes = 0;
                size_t flen = collect_one_file(filepath, ent->d_name,
                                                t_start, t_end,
                                                file_buf, avail, &fbytes);
                if (flen > 2) {
                    if (files_done > 0) { out[pos++] = ','; }
                    memcpy(out + pos, file_buf, flen);
                    pos += flen;
                    files_done++;
                    total_bytes += fbytes;
                }
                free(file_buf);
            }
            closedir(d);
        }
    } else {
        /* Use the explicit list from config */
        for (int i = 0; i < num_cfg; i++) {
            char filepath[512];
            snprintf(filepath, sizeof(filepath), "%s/%s", logs_dir, cfg_files[i]);

            size_t avail = (pos < out_size - 2) ? (out_size - pos - 2) : 0;
            if (avail < 1024) break;

            char *file_buf = (char *)calloc(avail, 1);
            if (!file_buf) break;

            long fbytes = 0;
            size_t flen = collect_one_file(filepath, cfg_files[i],
                                            t_start, t_end,
                                            file_buf, avail, &fbytes);
            if (flen > 2) {
                if (files_done > 0) { out[pos++] = ','; }
                memcpy(out + pos, file_buf, flen);
                pos += flen;
                files_done++;
                total_bytes += fbytes;
            }
            free(file_buf);
        }
    }

    out[pos++] = '}';
    out[pos]   = '\0';

    res.json           = out;
    res.total_bytes    = total_bytes;
    res.files_collected = files_done;
    return res;
}

void ae_log_collector_free(LogCollectionResult *r) {
    if (r && r->json) { free(r->json); r->json = NULL; }
}
