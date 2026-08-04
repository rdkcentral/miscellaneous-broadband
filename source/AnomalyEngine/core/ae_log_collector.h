/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_log_collector.h
 * ─────────────────────────────────────────────────────────────────────────────
 * Collect /rdklogs/logs/ entries that fall within a time window around an
 * anomaly timestamp.  Output is a JSON object keyed by log file name.
 */

#ifndef AE_LOG_COLLECTOR_H
#define AE_LOG_COLLECTOR_H

typedef struct {
    char *json;           /* heap: {"file.txt":[{"ts":"...","line":"..."},...]} */
    long  total_bytes;    /* total raw bytes read across all files              */
    int   files_collected;
    int   error;          /* 0 on success                                       */
} LogCollectionResult;

/*
 * Collect log lines from all files configured in anomaly_engine_config.json.
 * Lines are selected if their embedded timestamp falls in:
 *   [anomaly_timestamp − window_before_sec .. anomaly_timestamp + window_after_sec]
 *
 * anomaly_timestamp: ISO-8601 or RDK-B "YYYY-MM-DD-HH:MM:SS" string.
 *
 * Caller must release result.json with ae_log_collector_free().
 */
LogCollectionResult ae_log_collector_collect(const char *anomaly_timestamp,
                                              int         window_before_sec,
                                              int         window_after_sec);

void ae_log_collector_free(LogCollectionResult *r);

#endif /* AE_LOG_COLLECTOR_H */
