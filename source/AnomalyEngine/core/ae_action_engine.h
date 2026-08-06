/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_action_engine.h
 * ─────────────────────────────────────────────────────────────────────────────
 * Corrective action engine: evaluate severity, check cooldown, execute action.
 *
 * Supported actions (driven by anomaly_engine_config.json corrective_actions):
 *   log_and_monitor      — log warning only
 *   kill_runaway_process — SIGTERM to top-CPU process (protected list respected)
 *   reduce_priority      — renice +10 the top process
 *   clear_caches         — write to /proc/sys/vm/drop_caches (level 1 or 3)
 *   restart_service      — fork+exec systemctl restart <service>
 *   system_reboot        — sysevent set reboot_reason + reboot(2)
 */

#ifndef AE_ACTION_ENGINE_H
#define AE_ACTION_ENGINE_H

/* Record of one corrective action attempt (included in the report). */
typedef struct {
    char action_name[64];   /* e.g. "kill_runaway_process"    */
    char target[64];        /* pid string or service name     */
    char result[16];        /* "taken" | "skipped" | "failed" */
    char reason[128];       /* why skipped/failed             */
    char command[256];      /* actual command/syscall executed */
    char timestamp[64];     /* ISO-8601 when attempted        */
} ActionRecord;

/*
 * Evaluate and (if appropriate) execute the corrective action configured for
 * (model, anomaly_type, severity).
 *
 * top_pid:  PID of the highest-resource process extracted from collection
 *           data (-1 if unknown).
 * top_name: process name matching top_pid (may be NULL).
 *
 * Fills *action_out with what was decided.
 * Returns: 0=action taken, 1=no action defined/needed, -1=blocked by
 *          cooldown, pre-conditions, or protected-process list.
 */
int ae_action_evaluate(const char  *model,
                       const char  *anomaly_type,
                       const char  *severity,
                       int          top_pid,
                       const char  *top_process_name,
                       ActionRecord *action_out);

#endif /* AE_ACTION_ENGINE_H */
