/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_report.h
 * ─────────────────────────────────────────────────────────────────────────────
 * Build and persist a JSON analysis report (schema: anomaly_detection_engine.md §6.2).
 *
 * Output locations:
 *   {data_path}/{cpu|memory|both|<type>}/<YYYYMMDD_HHMMSS>_<type>.json
 *   {data_path}/../anomaly_summary.csv   — one-line summary appended
 */

#ifndef AE_REPORT_H
#define AE_REPORT_H

#include "ae_event.h"
#include "ae_action_engine.h"

/*
 * Build and write the full JSON report for one anomaly event.
 *
 * tiers_executed:  NULL-terminated (or num_tiers-limited) list of tier names run.
 * collected_json:  Merged JSON object body: { "tier1":{...}, "tier2":{...}, ... }
 * logs_json:       Output of ae_log_collector_collect() (may be NULL).
 * actions:         Array of ActionRecord written by ae_action_evaluate().
 * num_actions:     Length of actions array.
 * thresholds_json: JSON array of exceeded threshold objects (may be NULL or "[]").
 *
 * Returns 0 on success, -1 on file-write failure.
 */
int ae_report_write(const AnomalyEvent  *ev,
                    const char * const  *tiers_executed,
                    int                  num_tiers,
                    const char          *collected_json,
                    const char          *logs_json,
                    const ActionRecord  *actions,
                    int                  num_actions,
                    const char          *thresholds_json);

#endif /* AE_REPORT_H */
