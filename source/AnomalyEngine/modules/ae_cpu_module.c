/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_cpu_module.c
 * ─────────────────────────────────────────────────────────────────────────────
 * CPU data collection tiers (BusyBox v1.35 compatible).
 *
 * Tiers:
 *   cpu_mandatory  – BusyBox shell commands for quick snapshot
 *   basic_cpu      – /proc/stat delta → percent breakdowns + load avgs
 *   process_cpu    – /proc/<pid>/stat delta → top N processes by CPU%
 *   cpu_extended   – per-top-process context switches, FD count, wait channel
 *   system_state   – interrupt rate, thermal zones, CPU frequency
 */

#include "ae_cpu_module.h"
#include "../core/ae_rule_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define JSON_BUF   8192
#define CMD_BUF    4096
#define TOP_N_MAX  20

/* ── JSON helpers ─────────────────────────────────────────────────────────── */

static int json_escape(const char *in, char *out, size_t out_size) {
    size_t j = 0;
    for (size_t i = 0; in[i] && j < out_size - 3; i++) {
        unsigned char c = (unsigned char)in[i];
        if      (c == '"')  { out[j++] = '\\'; out[j++] = '"'; }
        else if (c == '\\') { out[j++] = '\\'; out[j++] = '\\'; }
        else if (c == '\n') { out[j++] = '\\'; out[j++] = 'n'; }
        else if (c == '\r') { out[j++] = '\\'; out[j++] = 'r'; }
        else if (c == '\t') { out[j++] = '\\'; out[j++] = 't'; }
        else if (c >= 0x20) { out[j++] = (char)c; }
    }
    out[j] = '\0';
    return (int)j;
}

/* Run command, capture up to max_bytes of output, JSON-escape into out. */
static int run_cmd(const char *cmd, char *out, size_t out_size) {
    char raw[CMD_BUF];
    size_t len = 0;
    FILE *fp = popen(cmd, "r");
    if (!fp) { out[0] = '\0'; return -1; }
    while (len < sizeof(raw) - 1) {
        size_t n = fread(raw + len, 1, sizeof(raw) - 1 - len, fp);
        if (n == 0) break;
        len += n;
    }
    raw[len] = '\0';
    pclose(fp);
    return json_escape(raw, out, out_size);
}

/* ── /proc/stat helpers ───────────────────────────────────────────────────── */

typedef struct { unsigned long long user,nice,system,idle,iowait,irq,softirq; } CpuTicks;

static int read_cpu_ticks(CpuTicks *t) {
    FILE *f = fopen("/proc/stat", "r");
    if (!f) return -1;
    int rc = fscanf(f, "cpu %llu %llu %llu %llu %llu %llu %llu",
                    &t->user, &t->nice, &t->system, &t->idle,
                    &t->iowait, &t->irq, &t->softirq);
    fclose(f);
    return (rc == 7) ? 0 : -1;
}

/* ── Process scan helpers ─────────────────────────────────────────────────── */

typedef struct {
    int  pid;
    char name[64];
    char state;
    unsigned long long utime, stime;
    long   priority, nice_val, num_threads;
} ProcStat;

/* Parse /proc/<pid>/stat; returns 0 on success */
static int read_proc_stat(int pid, ProcStat *out) {
    char path[64], buf[512];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    buf[n] = '\0';
    fclose(f);

    /* Process name is in parentheses; find the last ')' */
    char *end_paren = strrchr(buf, ')');
    if (!end_paren) return -1;

    /* Extract name between first '(' and last ')' */
    char *start_paren = strchr(buf, '(');
    if (start_paren && end_paren > start_paren) {
        size_t nlen = (size_t)(end_paren - start_paren - 1);
        if (nlen >= sizeof(out->name)) nlen = sizeof(out->name) - 1;
        memcpy(out->name, start_paren + 1, nlen);
        out->name[nlen] = '\0';
    }

    /* Parse fields after ')': state ppid ... utime stime ... priority nice num_threads */
    char *p = end_paren + 2;
    unsigned long long ut, st;
    long prio, ni, nthreads;
    if (sscanf(p, "%c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %llu %llu %*d %*d %ld %ld %ld",
               &out->state, &ut, &st, &prio, &ni, &nthreads) < 6)
        return -1;

    out->pid         = pid;
    out->utime       = ut;
    out->stime       = st;
    out->priority    = prio;
    out->nice_val    = ni;
    out->num_threads = nthreads;
    return 0;
}

/* Comparison function for qsort: descending total ticks */
static int cmp_proc_ticks(const void *a, const void *b) {
    const ProcStat *pa = (const ProcStat *)a;
    const ProcStat *pb = (const ProcStat *)b;
    unsigned long long ta = pa->utime + pa->stime;
    unsigned long long tb = pb->utime + pb->stime;
    return (tb > ta) ? 1 : (tb < ta) ? -1 : 0;
}

/* Scan /proc for all numeric directories and fill procs[]; return count */
static int scan_all_procs(ProcStat *procs, int max) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && count < max) {
        if (!isdigit((unsigned char)ent->d_name[0])) continue;
        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;
        if (read_proc_stat(pid, &procs[count]) == 0)
            count++;
    }
    closedir(d);
    return count;
}

/* ── Tier: cpu_mandatory ──────────────────────────────────────────────────── */

static int tier_cpu_mandatory(char *out, size_t out_size) {
    char top_esc[CMD_BUF], uptime_esc[256], vmstat_esc[512], stat_esc[1024];
    run_cmd("top -b -n 1 2>/dev/null | head -n 15", top_esc, sizeof(top_esc));
    run_cmd("uptime 2>/dev/null",                    uptime_esc, sizeof(uptime_esc));
    run_cmd("vmstat 2>/dev/null",                    vmstat_esc, sizeof(vmstat_esc));
    run_cmd("cat /proc/stat 2>/dev/null | head -n 5",stat_esc, sizeof(stat_esc));

    return snprintf(out, out_size,
                    "\"cpu_mandatory\":{"
                    "\"top_output\":\"%s\","
                    "\"uptime\":\"%s\","
                    "\"vmstat_snapshot\":\"%s\","
                    "\"proc_stat_head\":\"%s\"}",
                    top_esc, uptime_esc, vmstat_esc, stat_esc);
}

/* ── Tier: basic_cpu ─────────────────────────────────────────────────────── */

static int tier_basic_cpu(char *out, size_t out_size) {
    CpuTicks t1, t2;
    if (read_cpu_ticks(&t1) != 0) {
        snprintf(out, out_size, "\"basic_cpu\":{\"error\":\"proc_stat_unavailable\"}");
        return 0;
    }
    usleep(500000); /* 500ms sample window */
    if (read_cpu_ticks(&t2) != 0) {
        snprintf(out, out_size, "\"basic_cpu\":{\"error\":\"proc_stat_second_read_failed\"}");
        return 0;
    }

    unsigned long long d_user   = t2.user   - t1.user;
    unsigned long long d_nice   = t2.nice   - t1.nice;
    unsigned long long d_sys    = t2.system - t1.system;
    unsigned long long d_idle   = t2.idle   - t1.idle;
    unsigned long long d_iowait = t2.iowait - t1.iowait;
    unsigned long long d_irq    = t2.irq    - t1.irq;
    unsigned long long d_softirq= t2.softirq- t1.softirq;
    unsigned long long total    = d_user + d_nice + d_sys + d_idle + d_iowait
                                  + d_irq + d_softirq;
    if (total == 0) total = 1; /* guard division by zero */

    float user_pct   = (float)(d_user + d_nice) / (float)total * 100.0f;
    float sys_pct    = (float)d_sys    / (float)total * 100.0f;
    float iowait_pct = (float)d_iowait / (float)total * 100.0f;
    float idle_pct   = (float)d_idle   / (float)total * 100.0f;
    float cpu_pct    = 100.0f - idle_pct;

    /* Load averages */
    float la1 = 0, la5 = 0, la15 = 0;
    int   running = 0, total_procs = 0;
    FILE *f = fopen("/proc/loadavg", "r");
    if (f) {
        fscanf(f, "%f %f %f %d/%d", &la1, &la5, &la15, &running, &total_procs);
        fclose(f);
    }

    return snprintf(out, out_size,
                    "\"basic_cpu\":{"
                    "\"system_cpu_percent\":%.2f,"
                    "\"user_percent\":%.2f,"
                    "\"system_percent\":%.2f,"
                    "\"iowait_percent\":%.2f,"
                    "\"idle_percent\":%.2f,"
                    "\"load_avg_1m\":%.2f,"
                    "\"load_avg_5m\":%.2f,"
                    "\"load_avg_15m\":%.2f,"
                    "\"running_processes\":%d,"
                    "\"total_processes\":%d}",
                    (double)cpu_pct, (double)user_pct, (double)sys_pct,
                    (double)iowait_pct, (double)idle_pct,
                    (double)la1, (double)la5, (double)la15,
                    running, total_procs);
}

/* ── Tier: process_cpu ───────────────────────────────────────────────────── */

static int tier_process_cpu(char *out, size_t out_size, int top_n) {
    ProcStat *procs1 = (ProcStat *)calloc(TOP_N_MAX * 4, sizeof(ProcStat));
    ProcStat *procs2 = (ProcStat *)calloc(TOP_N_MAX * 4, sizeof(ProcStat));
    if (!procs1 || !procs2) { free(procs1); free(procs2);
        snprintf(out, out_size, "\"process_cpu\":[]"); return 0; }

    /* Two samples with 200ms gap for delta CPU% */
    CpuTicks ct1, ct2;
    read_cpu_ticks(&ct1);
    int n1 = scan_all_procs(procs1, TOP_N_MAX * 4);
    usleep(200000);
    read_cpu_ticks(&ct2);
    int n2 = scan_all_procs(procs2, TOP_N_MAX * 4);

    unsigned long long total_delta =
        (ct2.user + ct2.nice + ct2.system + ct2.idle + ct2.iowait + ct2.irq + ct2.softirq) -
        (ct1.user + ct1.nice + ct1.system + ct1.idle + ct1.iowait + ct1.irq + ct1.softirq);
    if (total_delta == 0) total_delta = 1;

    /* Match pids and compute delta */
    typedef struct { int pid; float cpu_pct; ProcStat s2; } ProcResult;
    ProcResult *results = (ProcResult *)calloc((size_t)n2, sizeof(ProcResult));
    if (!results) { free(procs1); free(procs2); snprintf(out, out_size, "\"process_cpu\":[]"); return 0; }

    for (int i = 0; i < n2; i++) {
        results[i].s2  = procs2[i];
        unsigned long long delta_proc = procs2[i].utime + procs2[i].stime;
        for (int j = 0; j < n1; j++) {
            if (procs1[j].pid == procs2[i].pid) {
                delta_proc -= (procs1[j].utime + procs1[j].stime);
                break;
            }
        }
        results[i].pid     = procs2[i].pid;
        results[i].cpu_pct = (float)delta_proc / (float)total_delta * 100.0f;
    }

    /* Sort descending by cpu_pct */
    for (int i = 0; i < n2 - 1; i++)
        for (int j = i + 1; j < n2; j++)
            if (results[j].cpu_pct > results[i].cpu_pct) {
                ProcResult tmp = results[i]; results[i] = results[j]; results[j] = tmp;
            }

    if (top_n > n2) top_n = n2;

    int pos = snprintf(out, out_size, "\"process_cpu\":[");
    for (int i = 0; i < top_n && (size_t)pos < out_size - 200; i++) {
        ProcStat *s = &results[i].s2;
        pos += snprintf(out + pos, out_size - (size_t)pos,
                        "%s{\"pid\":%d,\"name\":\"%s\",\"state\":\"%c\","
                        "\"cpu_percent\":%.2f,\"priority\":%ld,\"nice\":%ld,"
                        "\"num_threads\":%ld}",
                        i > 0 ? "," : "",
                        s->pid, s->name, s->state,
                        (double)results[i].cpu_pct,
                        s->priority, s->nice_val, s->num_threads);
    }
    pos += snprintf(out + pos, out_size - (size_t)pos, "]");

    free(procs1); free(procs2); free(results);
    return pos;
}

/* ── Tier: cpu_extended ──────────────────────────────────────────────────── */

static int tier_cpu_extended(char *out, size_t out_size, int top_n) {
    ProcStat procs[TOP_N_MAX * 4];
    int n = scan_all_procs(procs, TOP_N_MAX * 4);
    qsort(procs, (size_t)n, sizeof(ProcStat), cmp_proc_ticks);
    if (top_n > n) top_n = n;

    int pos = snprintf(out, out_size, "\"cpu_extended\":[");
    for (int i = 0; i < top_n && (size_t)pos < out_size - 512; i++) {
        int pid = procs[i].pid;
        char path[64], buf[256];
        long vol_ctxt = 0, nonvol_ctxt = 0, fd_count = 0;

        /* Voluntary/non-voluntary context switches from /proc/<pid>/status */
        snprintf(path, sizeof(path), "/proc/%d/status", pid);
        FILE *f = fopen(path, "r");
        if (f) {
            char key[64]; long val;
            while (fscanf(f, "%63s %ld", key, &val) == 2) {
                if (strcmp(key, "voluntary_ctxt_switches:") == 0)    vol_ctxt = val;
                if (strcmp(key, "nonvoluntary_ctxt_switches:") == 0) nonvol_ctxt = val;
            }
            fclose(f);
        }

        /* Open FD count */
        snprintf(path, sizeof(path), "/proc/%d/fd", pid);
        DIR *d = opendir(path);
        if (d) {
            struct dirent *ent;
            while ((ent = readdir(d)) != NULL) fd_count++;
            fd_count -= 2; /* subtract . and .. */
            closedir(d);
        }

        /* Wait channel */
        buf[0] = '\0';
        snprintf(path, sizeof(path), "/proc/%d/wchan", pid);
        FILE *wf = fopen(path, "r");
        if (wf) { fscanf(wf, "%255s", buf); fclose(wf); }

        pos += snprintf(out + pos, out_size - (size_t)pos,
                        "%s{\"pid\":%d,\"name\":\"%s\","
                        "\"voluntary_ctxt_switches\":%ld,"
                        "\"nonvoluntary_ctxt_switches\":%ld,"
                        "\"open_fd_count\":%ld,"
                        "\"wchan\":\"%s\"}",
                        i > 0 ? "," : "",
                        pid, procs[i].name,
                        vol_ctxt, nonvol_ctxt, fd_count, buf);
    }
    pos += snprintf(out + pos, out_size - (size_t)pos, "]");
    return pos;
}

/* ── Tier: system_state ──────────────────────────────────────────────────── */

static int tier_system_state(char *out, size_t out_size) {
    /* Interrupt count (one sample; actual rate requires two samples) */
    long irq_total = 0;
    FILE *f = fopen("/proc/interrupts", "r");
    if (f) {
        char line[256];
        fgets(line, sizeof(line), f); /* skip header */
        while (fgets(line, sizeof(line), f)) {
            char *p = line;
            while (*p == ' ') p++;
            if (!isdigit((unsigned char)*p)) continue;
            strtol(p, &p, 10); /* IRQ number */
            long cnt;
            while (sscanf(p, " %ld", &cnt) == 1) { irq_total += cnt; p += strspn(p, " "); while (*p && *p != ' ') p++; while (*p == ' ') p++; if (!isdigit((unsigned char)*p)) break; }
        }
        fclose(f);
    }

    /* Thermal zones */
    char thermal_json[512] = "[";
    int  tz_first = 1;
    for (int z = 0; z < 8; z++) {
        char path[128], temp_str[32];
        snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/temp", z);
        FILE *tf = fopen(path, "r");
        if (!tf) break;
        if (fgets(temp_str, sizeof(temp_str), tf)) {
            long millideg = atol(temp_str);
            size_t tlen = strlen(thermal_json);
            if (tlen + 32 < sizeof(thermal_json))
                tlen += (size_t)snprintf(thermal_json + tlen, sizeof(thermal_json) - tlen,
                                          "%s{\"zone\":%d,\"temp_c\":%.1f}",
                                          tz_first ? "" : ",", z, (double)millideg / 1000.0);
            tz_first = 0;
        }
        fclose(tf);
    }
    strncat(thermal_json, "]", sizeof(thermal_json) - strlen(thermal_json) - 1);

    /* CPU frequency (first core) */
    long cpu_freq_khz = 0;
    f = fopen("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", "r");
    if (f) { fscanf(f, "%ld", &cpu_freq_khz); fclose(f); }

    /* Blocked processes */
    long procs_blocked = 0;
    f = fopen("/proc/stat", "r");
    if (f) {
        char key[32]; long val;
        while (fscanf(f, "%31s %ld", key, &val) == 2)
            if (strcmp(key, "procs_blocked") == 0) { procs_blocked = val; break; }
        fclose(f);
    }

    return snprintf(out, out_size,
                    "\"system_state\":{"
                    "\"irq_total_count\":%ld,"
                    "\"procs_blocked\":%ld,"
                    "\"cpu_freq_mhz\":%.0f,"
                    "\"thermal_zones\":%s}",
                    irq_total, procs_blocked,
                    (double)cpu_freq_khz / 1000.0,
                    thermal_json);
}

/* ── CollectionModule interface ───────────────────────────────────────────── */

static int cpu_collect(const char *tier_name,
                       const char *anomaly_type,
                       const char *severity,
                       char       *out_buf,
                       size_t      out_size) {
    (void)anomaly_type; (void)severity;

    int top_n = ae_rules_top_n_processes();
    if (top_n > TOP_N_MAX) top_n = TOP_N_MAX;

    if      (strcmp(tier_name, "cpu_mandatory") == 0) return tier_cpu_mandatory(out_buf, out_size);
    else if (strcmp(tier_name, "basic_cpu")     == 0) return tier_basic_cpu(out_buf, out_size);
    else if (strcmp(tier_name, "process_cpu")   == 0) return tier_process_cpu(out_buf, out_size, top_n);
    else if (strcmp(tier_name, "cpu_extended")  == 0) return tier_cpu_extended(out_buf, out_size, top_n);
    else if (strcmp(tier_name, "system_state")  == 0) return tier_system_state(out_buf, out_size);

    snprintf(out_buf, out_size, "\"%s\":{\"error\":\"unknown tier\"}", tier_name);
    return -1;
}

static const TierEntry k_cpu_tiers[] = {
    { "cpu_mandatory", "cpu_module" },
    { "basic_cpu",     "cpu_module" },
    { "process_cpu",   "cpu_module" },
    { "cpu_extended",  "cpu_module" },
    { "system_state",  "cpu_module" },
    { NULL, NULL }
};

const CollectionModule cpu_collection_module = {
    .module_name    = "cpu_module",
    .handles_model  = "anomaly",
    .tiers          = k_cpu_tiers,
    .collect        = cpu_collect,
    .execute_action = NULL,   /* action handled by ae_action_engine.c */
};
