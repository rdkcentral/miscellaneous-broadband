/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_rule_engine.h
 * ─────────────────────────────────────────────────────────────────────────────
 * JSON config loader and collection rule lookup.
 *
 * Reads /etc/anomaly_engine_config.json at startup and provides:
 *  - Collection tier lists for (model, anomaly_type, severity)
 *  - Threshold values for severity evaluation
 *  - Log collection parameters
 *  - Action engine parameters
 */

#ifndef AE_RULE_ENGINE_H
#define AE_RULE_ENGINE_H

#define AE_MAX_TIER_NAME_LEN   64
#define AE_MAX_TIERS_PER_RULE  16

/*
 * Load (or reload) config from file.
 * Returns 0 on success, -1 if the file cannot be parsed.
 * May be called again to hot-reload; existing rules are replaced atomically.
 */
int ae_rules_load(const char *config_path);

/*
 * Look up the ordered list of collection tiers for (model, anomaly_type, severity).
 *
 * Mandatory tiers (from the "mandatory" key) are always prepended, regardless
 * of severity.  Duplicate tier names are suppressed.
 *
 * Returns the number of tiers written into tiers[], or -1 if no rule matched.
 * max_tiers must be >= AE_MAX_TIERS_PER_RULE to avoid truncation.
 */
int ae_rules_lookup(const char *model,
                    const char *anomaly_type,
                    const char *severity,
                    char        tiers[][AE_MAX_TIER_NAME_LEN],
                    int         max_tiers);

/* ── Threshold accessors ──────────────────────────────────────────────── */
float ae_rules_cpu_threshold_high(void);
float ae_rules_cpu_threshold_critical(void);
float ae_rules_mem_threshold_high(void);
float ae_rules_mem_threshold_critical(void);
int   ae_rules_top_n_processes(void);

/* ── Log collection config ────────────────────────────────────────────── */
const char *ae_rules_logs_directory(void);
int         ae_rules_log_window_before_sec(void);
int         ae_rules_log_window_after_sec(void);
int         ae_rules_max_log_size_kb(void);
/* Returns number of configured log file names; names written into out[] */
int         ae_rules_log_files(char out[][64], int max);

/* ── Output path config ───────────────────────────────────────────────── */
const char *ae_rules_data_path(void);
const char *ae_rules_log_path(void);

/* ── Action engine config ─────────────────────────────────────────────── */
int ae_rules_actions_enabled(void);
int ae_rules_global_cooldown_sec(void);
int ae_rules_max_actions_per_hour(void);
/* Returns 1 if process name appears in the protected_services list */
int ae_rules_is_protected(const char *process_name);

#endif /* AE_RULE_ENGINE_H */
