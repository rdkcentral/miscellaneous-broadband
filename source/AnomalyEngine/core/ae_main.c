/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_main.c
 * ─────────────────────────────────────────────────────────────────────────────
 * AnomalyEngine daemon entry point.
 *
 *  1. Daemonise.
 *  2. Register collection modules (cpu, memory; add new ones here).
 *  3. Initialise engine (loads config, starts processing thread).
 *  4. Subscribe to the AnomalyDetected rbus event.
 *  5. Wait for SIGTERM/SIGINT.
 *
 * All anomaly sources (AnomalyService, future NetworkDetector, …) publish to
 * the same rbus event name.  This daemon receives them all and dispatches
 * via the module registry + rule engine.
 */

#include "core/ae_engine.h"
#include "core/ae_event.h"
#include "modules/ae_cpu_module.h"
#include "modules/ae_mem_module.h"

#include <rbus/rbus.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#define AE_RBUS_COMPONENT   "AnomalyEngine"
#define AE_LOG_FILE         "/rdklogs/logs/AnomalyEngine.txt"

static volatile sig_atomic_t g_running = 1;
static rbusHandle_t           g_rbus   = NULL;

/* ── Logging (minimal; no dependency on AnomalyService logging) ──────────── */

static void ae_log(const char *level, const char *fmt, ...) {
    FILE *f = fopen(AE_LOG_FILE, "a");
    if (!f) f = stderr;
    char ts[32] = "";
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    if (tm) strftime(ts, sizeof(ts), "%Y-%m-%d-%H:%M:%S", tm);
    fprintf(f, "[%s] [%s] ", ts, level);
    va_list ap; va_start(ap, fmt); vfprintf(f, fmt, ap); va_end(ap);
    fprintf(f, "\n");
    if (f != stderr) fclose(f);
}

#define AE_INFO(...)  ae_log("INFO",  __VA_ARGS__)
#define AE_WARN(...)  ae_log("WARN",  __VA_ARGS__)
#define AE_ERROR(...) ae_log("ERROR", __VA_ARGS__)

/* ── Signal handler ──────────────────────────────────────────────────────── */

static void sig_handler(int sig) {
    if (sig == SIGTERM || sig == SIGINT) g_running = 0;
    signal(sig, sig_handler);
}

/* ── Daemonise ───────────────────────────────────────────────────────────── */

static void daemonize(void) {
    switch (fork()) {
    case 0:  break;
    case -1: exit(1);
    default: _exit(0);
    }
    if (setsid() < 0) exit(1);
#ifndef _DEBUG
    int fd = open("/dev/null", O_RDONLY);
    if (fd != 0) { dup2(fd, 0); close(fd); }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 1) { dup2(fd, 1); close(fd); }
    fd = open("/dev/null", O_WRONLY);
    if (fd != 2) { dup2(fd, 2); close(fd); }
#endif
}

/* ── rbus event handler ──────────────────────────────────────────────────── */

/*
 * Parse a JSON string value for key from the flat payload string.
 * The AnomalyService encodes the event as a single JSON string in the
 * "value" rbus property.  Format:
 *   {"model":"anomaly","anomaly_type":"CPU","severity":"high","timestamp":"...","details":{...}}
 */
static void extract_json_str(const char *json, const char *key,
                               char *out, size_t out_size) {
    out[0] = '\0';
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return;
    p += strlen(search);
    while (*p == ' ' || *p == ':') p++;
    if (*p == '"') {
        p++;
        size_t i = 0;
        while (*p && *p != '"' && i < out_size - 1) {
            if (*p == '\\' && *(p+1)) { p++; }
            out[i++] = *p++;
        }
        out[i] = '\0';
    }
}

static float extract_json_float(const char *json, const char *key) {
    char search[64];
    snprintf(search, sizeof(search), "\"%s\"", key);
    const char *p = strstr(json, search);
    if (!p) return 0.0f;
    p += strlen(search);
    while (*p == ' ' || *p == ':') p++;
    return (float)atof(p);
}

static void ae_rbus_event_handler(rbusHandle_t handle,
                                   rbusEvent_t const *event,
                                   rbusEventSubscription_t *subscription) {
    (void)handle; (void)subscription;

    /* The publisher stores the whole event as a single JSON string in "value" */
    rbusValue_t v = rbusObject_GetValue(event->data, "value");
    if (!v) { AE_WARN("Received event with no 'value' field"); return; }

    const char *payload = rbusValue_GetString(v, NULL);
    if (!payload || payload[0] == '\0') return;

    AnomalyEvent ev;
    memset(&ev, 0, sizeof(ev));

    extract_json_str(payload, "model",        ev.model,        sizeof(ev.model));
    extract_json_str(payload, "anomaly_type", ev.anomaly_type, sizeof(ev.anomaly_type));
    extract_json_str(payload, "severity",     ev.severity,     sizeof(ev.severity));
    extract_json_str(payload, "timestamp",    ev.timestamp,    sizeof(ev.timestamp));
    ev.confidence = extract_json_float(payload, "confidence");

    /* Capture raw details (if present) */
    const char *det = strstr(payload, "\"details\"");
    if (det) {
        det = strchr(det, ':');
        if (det) strncpy(ev.details_json, det + 1, sizeof(ev.details_json) - 1);
    }

    /* Backward compatibility: if model was omitted, assume "anomaly" */
    if (ev.model[0] == '\0') strncpy(ev.model, AE_MODEL_ANOMALY, sizeof(ev.model) - 1);

    /* Skip "Normal" detections — nothing to collect */
    if (strcmp(ev.anomaly_type, "Normal") == 0) return;

    AE_INFO("Received event: model=%s type=%s severity=%s",
            ev.model, ev.anomaly_type, ev.severity);

    ae_engine_submit(&ev);
}

/* ── main ────────────────────────────────────────────────────────────────── */

int main(int argc, char *argv[]) {
    const char *config_path = AE_ENGINE_CONFIG_DEFAULT;

    /* Allow config path override via -c flag */
    for (int i = 1; i < argc - 1; i++) {
        if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config") == 0)
            config_path = argv[i + 1];
    }

    daemonize();

    AE_INFO("AnomalyEngine starting (config: %s)", config_path);

    /* ── Register modules ───────────────────────────────────────────────── */
    ae_registry_register(&cpu_collection_module);
    ae_registry_register(&mem_collection_module);
    /* Future: ae_registry_register(&network_collection_module); */
    /* Future: ae_registry_register(&docsis_collection_module);  */

    /* ── Start engine ───────────────────────────────────────────────────── */
    if (ae_engine_init(config_path) != 0) {
        AE_ERROR("Engine init failed; exiting");
        return 1;
    }

    /* ── Signal setup ───────────────────────────────────────────────────── */
    signal(SIGTERM, sig_handler);
    signal(SIGINT,  sig_handler);

    /* ── rbus subscribe ─────────────────────────────────────────────────── */
    int rc = rbus_open(&g_rbus, AE_RBUS_COMPONENT);
    if (rc != RBUS_ERROR_SUCCESS) {
        AE_ERROR("rbus_open failed: %d", rc);
        ae_engine_shutdown();
        return 1;
    }

    rc = rbusEvent_Subscribe(g_rbus,
                             AE_RBUS_EVENT_NAME,
                             ae_rbus_event_handler,
                             NULL,   /* user data */
                             0);     /* timeout: block until broker ready */
    if (rc != RBUS_ERROR_SUCCESS) {
        AE_WARN("rbusEvent_Subscribe failed: %d (will retry on next start)", rc);
    } else {
        AE_INFO("Subscribed to %s", AE_RBUS_EVENT_NAME);
    }

    AE_INFO("AnomalyEngine ready");

    /* ── Main loop ──────────────────────────────────────────────────────── */
    while (g_running) {
        sleep(5);
    }

    /* ── Clean shutdown ─────────────────────────────────────────────────── */
    AE_INFO("AnomalyEngine shutting down");
    rbusEvent_Unsubscribe(g_rbus, AE_RBUS_EVENT_NAME);
    rbus_close(g_rbus);
    ae_engine_shutdown();
    AE_INFO("AnomalyEngine stopped");
    return 0;
}
