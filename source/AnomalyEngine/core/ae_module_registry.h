/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_module_registry.h
 * ─────────────────────────────────────────────────────────────────────────────
 * Collection module plugin interface.
 *
 * Each detection domain (CPU, memory, network, DOCSIS, …) provides one
 * CollectionModule struct and registers it once at startup.  The engine
 * dispatches collection tiers to the correct module via
 * ae_registry_collect_tier() without knowing which module handles what.
 *
 * ── Adding a new collection module ────────────────────────────────────────
 *
 *  1. Create modules/ae_<name>_module.c implementing CollectionModule.
 *  2. Declare the extern in ae_main.c and call ae_registry_register() once.
 *  3. Add collection tier rules to anomaly_engine_config.json.
 *  4. No changes to core engine code.
 *
 * ── TierEntry ─────────────────────────────────────────────────────────────
 *
 *  A NULL-terminated array mapping tier names to the owning module name.
 *  The registry uses this to dispatch ae_registry_collect_tier() calls.
 *  One module may own multiple tiers; the same tier name must not appear
 *  in more than one module.
 */

#ifndef AE_MODULE_REGISTRY_H
#define AE_MODULE_REGISTRY_H

#include <stddef.h>

#define AE_MAX_MODULES  16

/* Single tier-name → module-name mapping entry; array ends with {NULL,NULL} */
typedef struct {
    const char *tier_name;    /* e.g. "basic_cpu", "process_memory" */
    const char *module_name;  /* owning module e.g. "cpu_module"    */
} TierEntry;

typedef struct {
    const char     *module_name;   /* "cpu_module", "memory_module", … */
    const char     *handles_model; /* "anomaly", "network_traffic", …  */
    const TierEntry *tiers;        /* NULL-terminated list             */

    /*
     * Collect data for one tier.
     * Appends a JSON fragment  "tier_name": { … }  to out_buf.
     * Returns 0 on success, -1 on error (partial output is valid).
     */
    int (*collect)(const char *tier_name,
                   const char *anomaly_type,
                   const char *severity,
                   char       *out_buf,
                   size_t      out_size);

    /*
     * Execute a corrective action for the given anomaly (may be NULL).
     * top_pid:  PID of the highest-resource process, or -1 if unknown.
     * Returns:  0=action taken, 1=no action defined/needed, -1=blocked.
     */
    int (*execute_action)(const char *anomaly_type,
                          const char *severity,
                          int         top_pid,
                          const char *top_process_name);
} CollectionModule;

/* Register a module; idempotent (duplicate module_name is ignored). */
void ae_registry_register(const CollectionModule *mod);

/*
 * Dispatch: find the module owning tier_name and call its collect().
 * out_buf receives a JSON fragment; returns 0 on success, -1 on miss/error.
 */
int ae_registry_collect_tier(const char *tier_name,
                              const char *anomaly_type,
                              const char *severity,
                              char       *out_buf,
                              size_t      out_size);

/*
 * Dispatch: call execute_action on every registered module that handles
 * the given model.  Returns the count of modules that took an action.
 */
int ae_registry_execute_actions(const char *model,
                                const char *anomaly_type,
                                const char *severity,
                                int         top_pid,
                                const char *top_process_name);

/* Lookup: find the module that owns tier_name (for logging). NULL on miss. */
const CollectionModule *ae_registry_find_by_tier(const char *tier_name);

#endif /* AE_MODULE_REGISTRY_H */
