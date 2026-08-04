/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_event.h
 * ─────────────────────────────────────────────────────────────────────────────
 * Shared AnomalyDetected event contract.
 *
 * All detection daemons publish to the same rbus event name with this payload
 * schema.  AnomalyEngine subscribes and dispatches based on "model".
 *
 * Adding a new detector:
 *   - Publish to AE_RBUS_EVENT_NAME with model set to your identifier string
 *   - No changes needed here unless you add a new known model constant
 */

#ifndef AE_EVENT_H
#define AE_EVENT_H

/* rbus event all detection daemons publish to */
#define AE_RBUS_EVENT_NAME    "Device.X_COMCAST_AnomalyEngine.AnomalyDetected"

/* Field keys inside the rbus event's "value" JSON string */
#define AE_FIELD_MODEL         "model"
#define AE_FIELD_ANOMALY_TYPE  "anomaly_type"
#define AE_FIELD_SEVERITY      "severity"
#define AE_FIELD_CONFIDENCE    "confidence"
#define AE_FIELD_TIMESTAMP     "timestamp"
#define AE_FIELD_DETAILS       "details"

/* Known model identifiers (extend as new detectors are added) */
#define AE_MODEL_ANOMALY          "anomaly"          /* TFLite CPU/Memory model     */
#define AE_MODEL_NETWORK_TRAFFIC  "network_traffic"  /* Future: network detector    */
#define AE_MODEL_DOCSIS           "docsis"            /* Future: DOCSIS detector     */

/* Severity string constants */
#define AE_SEV_LOW       "low"
#define AE_SEV_MEDIUM    "medium"
#define AE_SEV_HIGH      "high"
#define AE_SEV_CRITICAL  "critical"

/*
 * In-process representation of one anomaly event.
 * Populated by ae_main.c's rbus handler and submitted to the engine queue.
 */
typedef struct {
    char  model[32];           /* e.g. "anomaly", "network_traffic" */
    char  anomaly_type[32];    /* model-specific: "CPU", "Memory", "Both" */
    char  severity[16];        /* "low" | "medium" | "high" | "critical" */
    float confidence;          /* 0.0 – 1.0 */
    char  timestamp[64];       /* ISO-8601 from the detector */
    char  details_json[1024];  /* raw details payload from detector */
} AnomalyEvent;

#endif /* AE_EVENT_H */
