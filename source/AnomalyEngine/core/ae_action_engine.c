/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_action_engine.c
 * ─────────────────────────────────────────────────────────────────────────────
 * Corrective action evaluation and execution with cooldown enforcement.
 *
 * Actions are keyed by "model:anomaly_type:severity".  Cooldown is enforced
 * per key using monotonic wall-clock seconds.  A global hourly rate limit
 * prevents action storms across all anomaly types.
 */

#include "ae_action_engine.h"
#include "ae_rule_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <signal.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <fcntl.h>

#define MAX_COOLDOWNS    32

typedef struct {
    char   key[96];
    time_t last_time;
    int    count_this_hour;
    time_t hour_start;
} CooldownEntry;

static CooldownEntry s_cd[MAX_COOLDOWNS];
static int           s_num_cd = 0;

static int g_actions_this_hour = 0;
static time_t g_hour_start     = 0;

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static void iso_now(char *out, size_t size) {
    time_t t = time(NULL);
    struct tm *tm = gmtime(&t);
    strftime(out, size, "%Y-%m-%dT%H:%M:%SZ", tm);
}

static CooldownEntry *get_cooldown(const char *key) {
    for (int i = 0; i < s_num_cd; i++)
        if (strcmp(s_cd[i].key, key) == 0) return &s_cd[i];
    if (s_num_cd >= MAX_COOLDOWNS) return NULL;
    CooldownEntry *e = &s_cd[s_num_cd++];
    strncpy(e->key, key, sizeof(e->key) - 1);
    e->last_time      = 0;
    e->count_this_hour= 0;
    e->hour_start     = time(NULL);
    return e;
}

static int cooldown_ok(const char *key, int cooldown_sec) {
    time_t now = time(NULL);

    /* Global hourly rate limit */
    if (now - g_hour_start >= 3600) {
        g_actions_this_hour = 0;
        g_hour_start = now;
    }
    if (g_actions_this_hour >= ae_rules_max_actions_per_hour()) return 0;

    CooldownEntry *e = get_cooldown(key);
    if (!e) return 0;
    if (e->last_time != 0 && (now - e->last_time) < (time_t)cooldown_sec) return 0;
    return 1;
}

static void cooldown_record(const char *key) {
    CooldownEntry *e = get_cooldown(key);
    if (e) e->last_time = time(NULL);
    g_actions_this_hour++;
}

/* Write a string to a file (for /proc/sys/vm/drop_caches etc.) */
static int write_sysfile(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, value, strlen(value));
    close(fd);
    return (n > 0) ? 0 : -1;
}

/* Fork+exec a command with argv, wait for completion */
static int exec_cmd(char *const argv[]) {
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Write a dry-run notice to the engine log file instead of executing. */
static void log_dry_run(const char *action_name, const char *cmd) {
    char ts[64];
    iso_now(ts, sizeof(ts));
    const char *log_path = ae_rules_log_path();
    FILE *f = fopen(log_path, "a");
    if (!f) return;
    fprintf(f, "%s [DRY-RUN] %s would execute: %s\n", ts, action_name, cmd);
    fclose(f);
}

/* ── Action implementations ───────────────────────────────────────────────── */

#define ACTION_DRY_RUN 2   /* action logged but not executed */

static int action_kill_process(int pid, int sig, ActionRecord *out) {
    if (pid <= 1) {
        snprintf(out->reason,  sizeof(out->reason),  "invalid pid %d", pid);
        snprintf(out->command, sizeof(out->command), "kill -%d %d", sig, pid);
        return -1;
    }
    snprintf(out->command, sizeof(out->command), "kill -%d %d", sig, pid);
    snprintf(out->target,  sizeof(out->target),  "%d", pid);
    snprintf(out->result,  sizeof(out->result),  "dry_run");
    log_dry_run("kill_runaway_process", out->command);
    return ACTION_DRY_RUN;
}

static int action_renice(int pid, int nice_delta, ActionRecord *out) {
    if (pid <= 1) { snprintf(out->reason, sizeof(out->reason), "invalid pid %d", pid); return -1; }
    int cur_prio = getpriority(PRIO_PROCESS, (id_t)pid);
    int new_prio = cur_prio + nice_delta;
    if (new_prio > 19) new_prio = 19;
    snprintf(out->command, sizeof(out->command), "setpriority(PRIO_PROCESS, %d, %d)", pid, new_prio);
    if (setpriority(PRIO_PROCESS, (id_t)pid, new_prio) == 0) {
        snprintf(out->target, sizeof(out->target), "pid=%d nice=%+d", pid, nice_delta);
        return 0;
    }
    snprintf(out->reason, sizeof(out->reason), "setpriority failed");
    return -1;
}

static int action_drop_caches(int level, ActionRecord *out) {
    char val[4];
    snprintf(val, sizeof(val), "%d", level);
    snprintf(out->command, sizeof(out->command), "sync; echo %d > /proc/sys/vm/drop_caches", level);
    /* sync before dropping caches */
    sync();
    if (write_sysfile("/proc/sys/vm/drop_caches", val) == 0) {
        snprintf(out->target, sizeof(out->target), "level=%d", level);
        return 0;
    }
    snprintf(out->reason, sizeof(out->reason), "write /proc/sys/vm/drop_caches failed");
    return -1;
}

static int action_restart_service(const char *service, ActionRecord *out) {
    if (!service || service[0] == '\0') {
        snprintf(out->reason, sizeof(out->reason), "no service name");
        return -1;
    }
    snprintf(out->command, sizeof(out->command), "systemctl restart %s", service);
    char *argv[] = { "systemctl", "restart", (char *)service, NULL };
    int rc = exec_cmd(argv);
    if (rc == 0) {
        snprintf(out->target, sizeof(out->target), "%s", service);
        return 0;
    }
    snprintf(out->reason, sizeof(out->reason), "systemctl restart %s failed rc=%d", service, rc);
    return -1;
}

static int action_system_reboot(const char *reason, ActionRecord *out) {
    snprintf(out->command, sizeof(out->command),
             "sysevent set reboot_reason %s; reboot", reason ? reason : "anomaly");
    snprintf(out->target, sizeof(out->target), "reason=%s", reason ? reason : "anomaly");
    snprintf(out->result, sizeof(out->result), "dry_run");
    log_dry_run("system_reboot", out->command);
    return ACTION_DRY_RUN;
}

/* ── Action lookup table ──────────────────────────────────────────────────── */

typedef struct {
    const char *model;
    const char *anomaly_type;
    const char *severity;
    const char *action_name;
    int         cooldown_sec;
    int         param_int;   /* signal, cache level, etc. */
    const char *param_str;   /* service name, reboot reason */
} ActionSpec;

/* This table mirrors corrective_actions in anomaly_engine_config.json.
 * ae_rules_load() will not overwrite this table; for dynamic config support,
 * extend ae_rule_engine.c to also parse per-type action blocks. */
static const ActionSpec k_actions[] = {
    /* anomaly / CPU */
    {"anomaly","CPU","low",      "log_and_monitor",      30,   0,    NULL},
    {"anomaly","CPU","medium",   "kill_runaway_process", 120,  SIGTERM, NULL},
    {"anomaly","CPU","high",     "clear_caches",         300,  3,    NULL},
    {"anomaly","CPU","critical", "system_reboot",        3600, 0,    "cpu_anomaly"},
    /* anomaly / Memory */
    {"anomaly","Memory","low",      "log_and_monitor",   30,   0,    NULL},
    {"anomaly","Memory","medium",   "clear_caches",      180,  1,    NULL},
    {"anomaly","Memory","high",     "kill_runaway_process",300, SIGTERM, NULL},
    {"anomaly","Memory","critical", "system_reboot",     3600, 0,    "mem_anomaly"},
    /* anomaly / Both */
    {"anomaly","Both","medium",     "clear_caches",      180,  3,    NULL},
    {"anomaly","Both","high",       "kill_runaway_process",300, SIGTERM, NULL},
    {"anomaly","Both","critical",   "system_reboot",     3600, 0,    "both_anomaly"},
    /* Sentinel */
    {NULL, NULL, NULL, NULL, 0, 0, NULL}
};

/* ── Public API ───────────────────────────────────────────────────────────── */

int ae_action_evaluate(const char  *model,
                       const char  *anomaly_type,
                       const char  *severity,
                       int          top_pid,
                       const char  *top_process_name,
                       ActionRecord *out) {
    memset(out, 0, sizeof(*out));
    iso_now(out->timestamp, sizeof(out->timestamp));

    if (!ae_rules_actions_enabled()) {
        snprintf(out->action_name, sizeof(out->action_name), "none");
        snprintf(out->result,      sizeof(out->result),      "skipped");
        snprintf(out->reason,      sizeof(out->reason),      "actions disabled");
        return 1;
    }

    /* Find matching action spec */
    const ActionSpec *spec = NULL;
    for (int i = 0; k_actions[i].model; i++) {
        if (strcmp(k_actions[i].model,        model)        == 0 &&
            strcmp(k_actions[i].anomaly_type, anomaly_type) == 0 &&
            strcmp(k_actions[i].severity,     severity)     == 0) {
            spec = &k_actions[i];
            break;
        }
    }
    if (!spec) {
        snprintf(out->action_name, sizeof(out->action_name), "none");
        snprintf(out->result,      sizeof(out->result),      "skipped");
        snprintf(out->reason,      sizeof(out->reason),      "no action defined");
        return 1;
    }

    strncpy(out->action_name, spec->action_name, sizeof(out->action_name) - 1);

    /* Check cooldown */
    char cd_key[96];
    snprintf(cd_key, sizeof(cd_key), "%s:%s:%s", model, anomaly_type, spec->action_name);
    if (!cooldown_ok(cd_key, spec->cooldown_sec)) {
        snprintf(out->result, sizeof(out->result), "skipped");
        snprintf(out->reason, sizeof(out->reason), "cooldown active (%ds)", spec->cooldown_sec);
        return -1;
    }

    /* Protected process check for kill actions */
    if (strcmp(spec->action_name, "kill_runaway_process") == 0) {
        if (top_pid <= 0) {
            snprintf(out->result, sizeof(out->result), "skipped");
            snprintf(out->reason, sizeof(out->reason), "no target pid");
            return -1;
        }
        if (top_process_name && ae_rules_is_protected(top_process_name)) {
            snprintf(out->result, sizeof(out->result), "skipped");
            snprintf(out->reason, sizeof(out->reason), "%s is protected", top_process_name);
            return -1;
        }
    }

    /* Execute */
    int rc = 1;
    if (strcmp(spec->action_name, "log_and_monitor") == 0) {
        snprintf(out->target,  sizeof(out->target),  "%s/%s", anomaly_type, severity);
        snprintf(out->command, sizeof(out->command), "logged only");
        rc = 0;
    } else if (strcmp(spec->action_name, "kill_runaway_process") == 0) {
        rc = action_kill_process(top_pid, spec->param_int, out);
    } else if (strcmp(spec->action_name, "reduce_priority") == 0) {
        rc = action_renice(top_pid, 10, out);
    } else if (strcmp(spec->action_name, "clear_caches") == 0) {
        rc = action_drop_caches(spec->param_int, out);
    } else if (strcmp(spec->action_name, "restart_service") == 0) {
        rc = action_restart_service(spec->param_str, out);
    } else if (strcmp(spec->action_name, "system_reboot") == 0) {
        rc = action_system_reboot(spec->param_str ? spec->param_str : "anomaly", out);
    }

    snprintf(out->result, sizeof(out->result),
             rc == 0 ? "taken" : (rc == ACTION_DRY_RUN ? "dry_run" : "failed"));
    if (rc == 0 || rc == ACTION_DRY_RUN) cooldown_record(cd_key);
    return rc;
}
