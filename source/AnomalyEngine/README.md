# AnomalyEngine

Model-agnostic data collection, corrective action, and reporting daemon for RDK-B DOCSIS gateways.

---

## Overview

`AnomalyEngine` is a standalone C daemon that subscribes to the
`Device.X_COMCAST_AnomalyEngine.AnomalyDetected` rbus event published by any
detection source and responds by:

1. **Looking up** which diagnostic data to collect (rule engine → config)
2. **Collecting** system data via pluggable collection modules (`/proc`, `/sys`, BusyBox commands)
3. **Collecting logs** from `/rdklogs/logs/` in a configurable time window
4. **Evaluating** collected data against configured thresholds
5. **Executing** a corrective action (if configured and cooldown allows)
6. **Writing** a JSON analysis report to `/rdklogs/logs/anomaly_data/`

The engine is completely decoupled from the detection method.  Adding a new
anomaly source requires no changes to the engine core.

---

## Architecture

```
Detection daemons (publishers)               AnomalyEngine (subscriber)
─────────────────────────────────────────────────────────────────────────
AnomalyService (TFLite CPU/Mem)
NetworkDetector (future)            ──rbus──►  ae_main.c
DocsisDetector  (future)                         │
                                            ae_engine.c  (state machine thread)
                                                 │
                                       ┌─────────┼───────────┐
                                       │         │           │
                                  ae_rule_engine  ae_module_registry
                                  (JSON config)   (plugin table)
                                                 │
                                       ┌─────────┼───────────┐
                                  ae_cpu_module  ae_mem_module  [future modules]
                                  /proc/stat     /proc/meminfo
                                  /proc/<pid>    /proc/<pid>
                                                 │
                              ┌──────────────────┼──────────────────┐
                         ae_log_collector   ae_action_engine    ae_report
                         /rdklogs/logs/     kill/renice/cache   JSON file writer
```

### State machine (one event at a time)

```
IDLE → LOOKUP → COLLECTING → EVALUATE → ACTION → REPORT → IDLE
```

Events from all sources are queued in a bounded ring buffer (8 slots).
One event is processed fully before the next begins.

---

## Directory Structure

```
AnomalyEngine/
├── core/
│   ├── ae_event.h            Shared event type (publisher ↔ subscriber contract)
│   ├── ae_engine.h/.c        Orchestrator: queue, state machine, thread
│   ├── ae_rule_engine.h/.c   JSON config loader and rule/tier lookup
│   ├── ae_module_registry.h/.c  Plugin table and tier dispatcher
│   ├── ae_log_collector.h/.c    /rdklogs/logs/ timestamp-windowed reader
│   ├── ae_action_engine.h/.c    Corrective actions with cooldown enforcement
│   ├── ae_report.h/.c           JSON report builder and file writer
│   └── ae_main.c                Daemon entry point (rbus subscribe + main loop)
├── modules/
│   ├── ae_cpu_module.h/.c    CPU tiers: mandatory/basic/process/extended/system_state
│   └── ae_mem_module.h/.c    Memory tiers: mandatory/basic/process/extended/system_state
├── config/
│   └── anomaly_engine_config.json   Runtime configuration
└── Makefile.am
```

---

## Configuration

Deployed to `/etc/anomaly_engine_config.json`.  Key sections:

| Section | Controls |
|---------|---------|
| `engine` | Output paths, LLM endpoint toggle |
| `log_collection` | Which `/rdklogs/logs/` files to read, time window size |
| `thresholds` | CPU/memory % values that trigger threshold-exceeded alerts |
| `protected_services` | Processes that must never be killed by corrective actions |
| `corrective_actions` | Per-severity actions, cooldown periods, pre-conditions |
| `collection_rules` | Maps `(model, anomaly_type, severity)` → ordered tier list |

---

## Adding a New Detection Module

A new detector (e.g. NetworkDetector) only needs to:

### 1 — Publish the rbus event with the correct payload

```c
/* From the new detector daemon */
snprintf(payload, sizeof(payload),
         "{\"model\":\"network_traffic\","
         "\"anomaly_type\":\"ConntrackExhaustion\","
         "\"severity\":\"high\","
         "\"timestamp\":\"%s\","
         "\"details\":{...}}",
         timestamp);

rbusValue_SetString(value, payload);
rbusObject_SetValue(data, "value", value);
event.name = "Device.X_COMCAST_AnomalyEngine.AnomalyDetected";
rbusEvent_Publish(handle, &event);
```

### 2 — Create a collection module

Create `modules/ae_network_module.c` implementing the `CollectionModule` interface:

```c
/* Tier names this module owns */
static const TierEntry k_net_tiers[] = {
    { "network_mandatory",  "network_module" },
    { "conntrack_summary",  "network_module" },
    { "top_connections",    "network_module" },
    { "socket_states",      "network_module" },
    { "interface_stats",    "network_module" },
    { NULL, NULL }
};

static int net_collect(const char *tier_name,
                       const char *anomaly_type,
                       const char *severity,
                       char *out_buf, size_t out_size) {
    /* Implement per tier, writing JSON to out_buf */
    if (strcmp(tier_name, "conntrack_summary") == 0) {
        /* read /proc/sys/net/netfilter/nf_conntrack_count etc. */
        ...
    }
    ...
}

const CollectionModule network_collection_module = {
    .module_name    = "network_module",
    .handles_model  = "network_traffic",
    .tiers          = k_net_tiers,
    .collect        = net_collect,
    .execute_action = net_execute_action,  /* or NULL */
};
```

### 3 — Register in ae_main.c (one line)

```c
/* In ae_main.c, after existing registrations */
ae_registry_register(&network_collection_module);
```

### 4 — Add rules to anomaly_engine_config.json

```json
"collection_rules": {
    "network_traffic": {
        "ConntrackExhaustion": {
            "mandatory": ["network_mandatory"],
            "medium":    ["conntrack_summary", "top_connections"],
            "high":      ["conntrack_summary", "top_connections", "socket_states"],
            "critical":  ["conntrack_summary", "top_connections", "socket_states", "interface_stats"]
        }
    }
}
```

**No changes to the engine core (`ae_engine.c`, `ae_rule_engine.c`, etc.).**

---

## Adding a New Collection Tier to an Existing Module

1. Add a new `tier_<name>()` function in the module `.c` file.
2. Add a `{ "tier_name", "module_name" }` entry to the module's `TierEntry` array.
3. Handle the new tier name in the module's `collect()` switch.
4. Add the tier name to the appropriate severity rule in `anomaly_engine_config.json`.

---

## Output

Reports are written to:
```
/rdklogs/logs/anomaly_data/
├── cpu/     YYYYMMDD_HHMMSS_CPU.json
├── memory/  YYYYMMDD_HHMMSS_Memory.json
├── both/    YYYYMMDD_HHMMSS_Both.json
└── ../anomaly_summary.csv
```

Report JSON schema follows `anomaly_detection_engine.md §6.2`:
- `report_id`, `timestamp`, `model`, `anomaly_type`, `severity`
- `collection_tiers_executed[]`
- `data{}` — merged output from each tier
- `thresholds_exceeded[]`
- `corrective_actions[]`

---

## Building

```bash
cd miscellaneous-broadband
autoreconf -fi
./configure --prefix=/usr ...
make
make install
```

The `AnomalyEngine` binary is installed to `/usr/bin/AnomalyEngine`.
The config is installed to `/etc/anomaly_engine_config.json`.

---

## Relationship with AnomalyService

| Component | Role |
|-----------|------|
| `AnomalyService` | Detection daemon: runs `anomaly_app` (TFLite inference), watches `anomaly_results.csv`, **publishes** `AnomalyDetected` rbus event |
| `AnomalyEngine` | Collection daemon: **subscribes** to the event, collects diagnostics, executes corrective actions, writes reports |

Both daemons are independent processes connected only via the rbus event bus.
`AnomalyEngine` can run without `AnomalyService` (it simply receives no events)
and vice versa.
