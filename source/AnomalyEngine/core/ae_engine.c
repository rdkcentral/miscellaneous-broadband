/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_engine.c
 * ─────────────────────────────────────────────────────────────────────────────
 * AnomalyEngine orchestrator: bounded event queue + state-machine thread.
 *
 * State machine (per event):
 *   LOOKUP     → ae_rules_lookup()
 *   COLLECTING → ae_registry_collect_tier() for each tier
 *   EVALUATE   → compare collected data against thresholds
 *   ACTION     → ae_action_evaluate()
 *   REPORT     → ae_report_write() + ae_log_collector_collect()
 */

#include "ae_engine.h"
#include "ae_rule_engine.h"
#include "ae_module_registry.h"
#include "ae_log_collector.h"
#include "ae_action_engine.h"
#include "ae_report.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <time.h>

#define COLLECTED_BUF_SIZE  (32 * 1024)  /* 32 KB for merged tier JSON */
#define TIER_BUF_SIZE       (8 * 1024)   /* 8 KB per individual tier   */
#define THRESH_BUF_SIZE     2048

/* ── Ring-buffer event queue ──────────────────────────────────────────────── */

static AnomalyEvent      s_queue[AE_QUEUE_CAPACITY];
static int               s_q_head  = 0;  /* next write position */
static int               s_q_tail  = 0;  /* next read position  */
static int               s_q_size  = 0;
static pthread_mutex_t   s_q_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t    s_q_cond  = PTHREAD_COND_INITIALIZER;
static volatile int      s_running = 0;
static pthread_t         s_thread;
static EngineState       s_state   = AE_STATE_IDLE;

/* ── Helpers ──────────────────────────────────────────────────────────────── */

/* Safely append src to dst (dst_size includes null terminator) */
static void safe_append(char *dst, const char *src, size_t dst_size) {
    size_t used = strlen(dst);
    if (used >= dst_size - 1) return;
    strncat(dst, src, dst_size - used - 1);
}

/*
 * Extract the first numeric "pid" value from collected JSON.
 * Looks for the pattern  "pid": N  in the tier_key array.
 * Returns -1 if not found.
 */
static int extract_top_pid(const char *json, const char *tier_key) {
    char search[96];
    snprintf(search, sizeof(search), "\"%s\"", tier_key);
    const char *p = strstr(json, search);
    if (!p) return -1;
    p = strstr(p, "\"pid\"");
    if (!p) return -1;
    p = strchr(p, ':');
    if (!p) return -1;
    while (*++p == ' ');
    if (*p < '0' || *p > '9') return -1;
    return atoi(p);
}

/* Extract the first "name" string value after tier_key in collected JSON */
static void extract_top_name(const char *json, const char *tier_key,
                               char *out, size_t out_size) {
    out[0] = '\0';
    char search[96];
    snprintf(search, sizeof(search), "\"%s\"", tier_key);
    const char *p = strstr(json, search);
    if (!p) return;
    p = strstr(p, "\"name\"");
    if (!p) return;
    p = strchr(p, ':');
    if (!p) return;
    while (*++p == ' ');
    if (*p != '"') return;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_size - 1) out[i++] = *p++;
    out[i] = '\0';
}

/*
 * Build a simple thresholds_exceeded JSON array by scanning collected_json
 * for cpu_percent and mem_used_percent keys.
 */
static void build_thresholds_json(const char *collected_json,
                                   const AnomalyEvent *ev,
                                   char *out, size_t out_size) {
    int pos = 0;
    int first = 1;
    pos += snprintf(out + pos, out_size - (size_t)pos, "[");

    /* Check system_cpu_percent */
    const char *p = strstr(collected_json, "\"system_cpu_percent\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            float val = (float)atof(p + 1);
            float thresh = ae_rules_cpu_threshold_high();
            if ((strcmp(ev->anomaly_type, "CPU") == 0 ||
                 strcmp(ev->anomaly_type, "Both") == 0) && val > thresh) {
                pos += snprintf(out + pos, out_size - (size_t)pos,
                    "%s{\"parameter\":\"system_cpu_percent\","
                    "\"value\":%.1f,\"threshold\":%.1f,\"comparison\":\">\"}", 
                    first ? "" : ",", (double)val, (double)thresh);
                first = 0;
            }
        }
    }

    /* Check mem_used_percent */
    p = strstr(collected_json, "\"mem_used_percent\"");
    if (p) {
        p = strchr(p, ':');
        if (p) {
            float val = (float)atof(p + 1);
            float thresh = ae_rules_mem_threshold_high();
            if ((strcmp(ev->anomaly_type, "Memory") == 0 ||
                 strcmp(ev->anomaly_type, "Both") == 0) && val > thresh) {
                pos += snprintf(out + pos, out_size - (size_t)pos,
                    "%s{\"parameter\":\"mem_used_percent\","
                    "\"value\":%.1f,\"threshold\":%.1f,\"comparison\":\">\"}", 
                    first ? "" : ",", (double)val, (double)thresh);
                first = 0;
            }
        }
    }

    snprintf(out + pos, out_size - (size_t)pos, "]");
}

/* ── Core event processing ────────────────────────────────────────────────── */

static void process_event(const AnomalyEvent *ev) {
    /* ── LOOKUP ───────────────────────────────────────────────────────── */
    s_state = AE_STATE_LOOKUP;
    char tiers[AE_MAX_TIERS_PER_RULE][AE_MAX_TIER_NAME_LEN];
    int num_tiers = ae_rules_lookup(ev->model, ev->anomaly_type, ev->severity,
                                     tiers, AE_MAX_TIERS_PER_RULE);
    if (num_tiers <= 0) {
        fprintf(stderr, "[AnomalyEngine] No rules for model=%s type=%s sev=%s\n",
                ev->model, ev->anomaly_type, ev->severity);
        s_state = AE_STATE_IDLE;
        return;
    }

    /* ── COLLECTING ───────────────────────────────────────────────────── */
    s_state = AE_STATE_COLLECTING;
    char *collected = (char *)calloc(COLLECTED_BUF_SIZE, 1);
    char *tier_buf  = (char *)calloc(TIER_BUF_SIZE, 1);
    if (!collected || !tier_buf) {
        free(collected); free(tier_buf);
        s_state = AE_STATE_IDLE;
        return;
    }

    safe_append(collected, "{", COLLECTED_BUF_SIZE);
    for (int i = 0; i < num_tiers; i++) {
        tier_buf[0] = '\0';
        int rc = ae_registry_collect_tier(tiers[i], ev->anomaly_type, ev->severity,
                                           tier_buf, TIER_BUF_SIZE);
        if (rc >= 0 && tier_buf[0] != '\0') {
            if (i > 0) safe_append(collected, ",", COLLECTED_BUF_SIZE);
            safe_append(collected, tier_buf, COLLECTED_BUF_SIZE);
        }
    }
    safe_append(collected, "}", COLLECTED_BUF_SIZE);
    free(tier_buf);

    /* ── EVALUATE ─────────────────────────────────────────────────────── */
    s_state = AE_STATE_EVALUATE;
    char thresholds_json[THRESH_BUF_SIZE];
    build_thresholds_json(collected, ev, thresholds_json, sizeof(thresholds_json));

    /* Extract top process info for action engine */
    int  top_pid = -1;
    char top_name[64] = "";
    if (strcmp(ev->anomaly_type, "CPU") == 0 || strcmp(ev->anomaly_type, "Both") == 0) {
        top_pid = extract_top_pid(collected, "process_cpu");
        extract_top_name(collected, "process_cpu", top_name, sizeof(top_name));
    }
    if (top_pid < 0 && (strcmp(ev->anomaly_type, "Memory") == 0 ||
                         strcmp(ev->anomaly_type, "Both") == 0)) {
        top_pid = extract_top_pid(collected, "process_memory");
        extract_top_name(collected, "process_memory", top_name, sizeof(top_name));
    }

    /* ── ACTION ───────────────────────────────────────────────────────── */
    s_state = AE_STATE_ACTION;
    ActionRecord action;
    memset(&action, 0, sizeof(action));
    ae_action_evaluate(ev->model, ev->anomaly_type, ev->severity,
                       top_pid, top_name[0] ? top_name : NULL, &action);

    /* ── REPORT ───────────────────────────────────────────────────────── */
    s_state = AE_STATE_REPORT;

    /* Collect relevant logs around the anomaly timestamp */
    LogCollectionResult logs = ae_log_collector_collect(
        ev->timestamp,
        ae_rules_log_window_before_sec(),
        ae_rules_log_window_after_sec());

    /* Build tier name pointer array for report */
    const char *tier_ptrs[AE_MAX_TIERS_PER_RULE];
    for (int i = 0; i < num_tiers; i++) tier_ptrs[i] = tiers[i];

    ae_report_write(ev,
                    tier_ptrs, num_tiers,
                    collected,
                    logs.json,
                    &action, 1,
                    thresholds_json);

    ae_log_collector_free(&logs);
    free(collected);
    s_state = AE_STATE_IDLE;
}

/* ── Background thread ────────────────────────────────────────────────────── */

static void *engine_thread(void *arg) {
    (void)arg;
    while (s_running) {
        pthread_mutex_lock(&s_q_mutex);
        while (s_q_size == 0 && s_running)
            pthread_cond_wait(&s_q_cond, &s_q_mutex);
        if (!s_running) { pthread_mutex_unlock(&s_q_mutex); break; }

        AnomalyEvent ev = s_queue[s_q_tail];
        s_q_tail = (s_q_tail + 1) % AE_QUEUE_CAPACITY;
        s_q_size--;
        pthread_mutex_unlock(&s_q_mutex);

        process_event(&ev);
    }
    return NULL;
}

/* ── Public API ───────────────────────────────────────────────────────────── */

int ae_engine_init(const char *config_path) {
    const char *path = config_path ? config_path : AE_ENGINE_CONFIG_DEFAULT;
    if (ae_rules_load(path) != 0) {
        fprintf(stderr, "[AnomalyEngine] Failed to load config: %s\n", path);
        return -1;
    }
    s_running = 1;
    s_state   = AE_STATE_IDLE;
    if (pthread_create(&s_thread, NULL, engine_thread, NULL) != 0) {
        s_running = 0;
        return -1;
    }
    return 0;
}

void ae_engine_submit(const AnomalyEvent *ev) {
    if (!ev) return;
    pthread_mutex_lock(&s_q_mutex);
    if (s_q_size >= AE_QUEUE_CAPACITY) {
        fprintf(stderr, "[AnomalyEngine] Queue full; dropping event model=%s type=%s\n",
                ev->model, ev->anomaly_type);
        pthread_mutex_unlock(&s_q_mutex);
        return;
    }
    s_queue[s_q_head] = *ev;
    s_q_head = (s_q_head + 1) % AE_QUEUE_CAPACITY;
    s_q_size++;
    pthread_cond_signal(&s_q_cond);
    pthread_mutex_unlock(&s_q_mutex);
}

void ae_engine_shutdown(void) {
    pthread_mutex_lock(&s_q_mutex);
    s_running = 0;
    pthread_cond_signal(&s_q_cond);
    pthread_mutex_unlock(&s_q_mutex);
    pthread_join(s_thread, NULL);
}

EngineState ae_engine_state(void) { return s_state; }
