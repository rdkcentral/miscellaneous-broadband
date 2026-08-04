/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_engine.h
 * ─────────────────────────────────────────────────────────────────────────────
 * AnomalyEngine orchestrator API.
 *
 * A single background thread processes one AnomalyEvent at a time through
 * the state machine:
 *
 *   IDLE → LOOKUP → COLLECTING → EVALUATE → ACTION → REPORT → IDLE
 *
 * Events submitted concurrently are queued in a bounded ring buffer
 * (AE_QUEUE_CAPACITY slots).  Overflow events are dropped with a warning.
 */

#ifndef AE_ENGINE_H
#define AE_ENGINE_H

#include "ae_event.h"

#define AE_ENGINE_CONFIG_DEFAULT  "/etc/anomaly_engine_config.json"
#define AE_QUEUE_CAPACITY         8

typedef enum {
    AE_STATE_IDLE,
    AE_STATE_LOOKUP,
    AE_STATE_COLLECTING,
    AE_STATE_EVALUATE,
    AE_STATE_ACTION,
    AE_STATE_REPORT,
} EngineState;

/* Initialise engine: load config, start background thread. Returns 0 on success. */
int  ae_engine_init(const char *config_path);

/* Submit an event from any detection source; safe to call from any thread. */
void ae_engine_submit(const AnomalyEvent *ev);

/* Signal engine to stop and join the background thread. */
void ae_engine_shutdown(void);

/* Current state (informational, may change immediately after return). */
EngineState ae_engine_state(void);

#endif /* AE_ENGINE_H */
