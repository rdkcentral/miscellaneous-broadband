/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_module_registry.c
 * ─────────────────────────────────────────────────────────────────────────────
 * Plugin registration table and tier dispatcher.
 */

#include "ae_module_registry.h"
#include <stdio.h>
#include <string.h>

static const CollectionModule *s_modules[AE_MAX_MODULES];
static int                     s_num_modules = 0;

void ae_registry_register(const CollectionModule *mod) {
    if (!mod || s_num_modules >= AE_MAX_MODULES) return;
    for (int i = 0; i < s_num_modules; i++) {
        if (strcmp(s_modules[i]->module_name, mod->module_name) == 0) return; /* already registered */
    }
    s_modules[s_num_modules++] = mod;
}

const CollectionModule *ae_registry_find_by_tier(const char *tier_name) {
    for (int m = 0; m < s_num_modules; m++) {
        const TierEntry *te = s_modules[m]->tiers;
        for (; te && te->tier_name; te++) {
            if (strcmp(te->tier_name, tier_name) == 0) return s_modules[m];
        }
    }
    return NULL;
}

int ae_registry_collect_tier(const char *tier_name,
                              const char *anomaly_type,
                              const char *severity,
                              char       *out_buf,
                              size_t      out_size) {
    const CollectionModule *mod = ae_registry_find_by_tier(tier_name);
    if (!mod || !mod->collect) return -1;
    return mod->collect(tier_name, anomaly_type, severity, out_buf, out_size);
}

int ae_registry_execute_actions(const char *model,
                                const char *anomaly_type,
                                const char *severity,
                                int         top_pid,
                                const char *top_process_name) {
    int taken = 0;
    for (int m = 0; m < s_num_modules; m++) {
        if (!s_modules[m]->execute_action) continue;
        if (strcmp(s_modules[m]->handles_model, model) != 0) continue;
        int rc = s_modules[m]->execute_action(anomaly_type, severity,
                                               top_pid, top_process_name);
        if (rc == 0) taken++;
    }
    return taken;
}
