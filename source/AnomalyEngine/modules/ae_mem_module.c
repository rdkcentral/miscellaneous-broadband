/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_mem_module.c
 * ─────────────────────────────────────────────────────────────────────────────
 * Memory data collection tiers (BusyBox v1.35 compatible).
 *
 * Tiers:
 *   memory_mandatory    – BusyBox free/vmstat + OOM dmesg
 *   basic_memory        – /proc/meminfo key fields
 *   process_memory      – /proc/<pid>/statm top N by RSS
 *   memory_extended     – /proc/<pid>/smaps_rollup, page faults, cgroups
 *   memory_system_state – slab, vmstat counters, zram
 */

#include "ae_mem_module.h"
#include "../core/ae_rule_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>

#define JSON_BUF   8192
#define CMD_BUF    2048
#define TOP_N_MAX  20

/* ── JSON helpers (duplicated locally to keep modules self-contained) ─────── */

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

static int run_cmd(const char *cmd, char *out, size_t out_size) {
    char raw[CMD_BUF]; size_t len = 0;
    FILE *fp = popen(cmd, "r");
    if (!fp) { out[0] = '\0'; return -1; }
    while (len < sizeof(raw) - 1) {
        size_t n = fread(raw + len, 1, sizeof(raw) - 1 - len, fp);
        if (n == 0) break;
        len += n;
    }
    raw[len] = '\0'; pclose(fp);
    return json_escape(raw, out, out_size);
}

/* ── /proc/meminfo helpers ────────────────────────────────────────────────── */

typedef struct {
    long long mem_total, mem_free, mem_available;
    long long buffers, cached;
    long long swap_total, swap_free;
    long long dirty, writeback;
    long long slab_total, slab_reclaimable, slab_unreclaimable;
    long long page_tables, kernel_stack, vmalloc_used;
    long long hugepages_total, hugepages_free;
} MemInfo;

static int read_meminfo(MemInfo *m) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return -1;
    memset(m, 0, sizeof(*m));
    char key[64]; long long val;
    while (fscanf(f, "%63s %lld %*s", key, &val) >= 2) {
        if      (strcmp(key, "MemTotal:")     == 0) m->mem_total      = val;
        else if (strcmp(key, "MemFree:")      == 0) m->mem_free       = val;
        else if (strcmp(key, "MemAvailable:") == 0) m->mem_available  = val;
        else if (strcmp(key, "Buffers:")      == 0) m->buffers        = val;
        else if (strcmp(key, "Cached:")       == 0) m->cached         = val;
        else if (strcmp(key, "SwapTotal:")    == 0) m->swap_total     = val;
        else if (strcmp(key, "SwapFree:")     == 0) m->swap_free      = val;
        else if (strcmp(key, "Dirty:")        == 0) m->dirty          = val;
        else if (strcmp(key, "Writeback:")    == 0) m->writeback      = val;
        else if (strcmp(key, "Slab:")         == 0) m->slab_total     = val;
        else if (strcmp(key, "SReclaimable:") == 0) m->slab_reclaimable   = val;
        else if (strcmp(key, "SUnreclaim:")   == 0) m->slab_unreclaimable = val;
        else if (strcmp(key, "PageTables:")   == 0) m->page_tables    = val;
        else if (strcmp(key, "KernelStack:")  == 0) m->kernel_stack   = val;
        else if (strcmp(key, "VmallocUsed:")  == 0) m->vmalloc_used   = val;
        else if (strcmp(key, "HugePages_Total:") == 0) m->hugepages_total = val;
        else if (strcmp(key, "HugePages_Free:")  == 0) m->hugepages_free  = val;
    }
    fclose(f);
    return 0;
}

/* ── Process memory scan ──────────────────────────────────────────────────── */

typedef struct {
    int       pid;
    char      name[64];
    long long rss_bytes;     /* pages * page_size */
    long long vsz_bytes;
    long long shared_bytes;
    int       oom_score;
    int       oom_score_adj;
} MemProcEntry;

static long s_page_size = 0;

static int read_mem_proc(int pid, MemProcEntry *out) {
    char path[64];
    if (s_page_size == 0) s_page_size = sysconf(_SC_PAGESIZE);

    /* Name from /proc/<pid>/comm */
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    if (!fgets(out->name, sizeof(out->name), f)) out->name[0] = '\0';
    size_t nl = strlen(out->name);
    if (nl > 0 && out->name[nl-1] == '\n') out->name[--nl] = '\0';
    fclose(f);
    out->pid = pid;

    /* /proc/<pid>/statm: size resident shared text lib data dirty */
    snprintf(path, sizeof(path), "/proc/%d/statm", pid);
    f = fopen(path, "r");
    if (!f) return -1;
    long long size_pg, rss_pg, shared_pg;
    int rc = fscanf(f, "%lld %lld %lld", &size_pg, &rss_pg, &shared_pg);
    fclose(f);
    if (rc < 2) return -1;
    out->vsz_bytes    = size_pg   * s_page_size;
    out->rss_bytes    = rss_pg    * s_page_size;
    out->shared_bytes = shared_pg * s_page_size;

    /* OOM score */
    snprintf(path, sizeof(path), "/proc/%d/oom_score", pid);
    f = fopen(path, "r");
    if (f) { fscanf(f, "%d", &out->oom_score); fclose(f); }

    snprintf(path, sizeof(path), "/proc/%d/oom_score_adj", pid);
    f = fopen(path, "r");
    if (f) { fscanf(f, "%d", &out->oom_score_adj); fclose(f); }

    return 0;
}

static int scan_mem_procs(MemProcEntry *procs, int max) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && count < max) {
        if (!isdigit((unsigned char)ent->d_name[0])) continue;
        int pid = atoi(ent->d_name);
        if (pid <= 0) continue;
        if (read_mem_proc(pid, &procs[count]) == 0) count++;
    }
    closedir(d);
    return count;
}

/* Count all numeric entries in /proc to size allocations before scanning. */
static int count_proc_pids(void) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    int count = 0;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL)
        if (isdigit((unsigned char)ent->d_name[0])) count++;
    closedir(d);
    return count;
}

static int cmp_rss_desc(const void *a, const void *b) {
    long long ra = ((const MemProcEntry *)a)->rss_bytes;
    long long rb = ((const MemProcEntry *)b)->rss_bytes;
    return (rb > ra) ? 1 : (rb < ra) ? -1 : 0;
}

/* ── Tier: memory_mandatory ───────────────────────────────────────────────── */

static int tier_memory_mandatory(char *out, size_t out_size) {
    char free_esc[512], vmstat_esc[512], oom_esc[1024], meminfo_esc[2048];
    run_cmd("free 2>/dev/null",                        free_esc,    sizeof(free_esc));
    run_cmd("vmstat 2>/dev/null",                      vmstat_esc,  sizeof(vmstat_esc));
    run_cmd("dmesg 2>/dev/null | grep -i oom | tail -n 20",
                                                       oom_esc,     sizeof(oom_esc));
    run_cmd("cat /proc/meminfo 2>/dev/null",           meminfo_esc, sizeof(meminfo_esc));

    return snprintf(out, out_size,
                    "\"memory_mandatory\":{"
                    "\"free_output\":\"%s\","
                    "\"vmstat_snapshot\":\"%s\","
                    "\"dmesg_oom\":\"%s\","
                    "\"cat_meminfo\":\"%s\"}",
                    free_esc, vmstat_esc, oom_esc, meminfo_esc);
}

/* ── Tier: basic_memory ───────────────────────────────────────────────────── */

static int tier_basic_memory(char *out, size_t out_size) {
    MemInfo m;
    if (read_meminfo(&m) != 0) {
        snprintf(out, out_size, "\"basic_memory\":{\"error\":\"meminfo_unavailable\"}");
        return 0;
    }
    float used_pct = 0.0f, swap_pct = 0.0f;
    if (m.mem_total > 0)
        used_pct = (float)(m.mem_total - m.mem_available) / (float)m.mem_total * 100.0f;
    if (m.swap_total > 0)
        swap_pct = (float)(m.swap_total - m.swap_free) / (float)m.swap_total * 100.0f;

    return snprintf(out, out_size,
                    "\"basic_memory\":{"
                    "\"mem_total_kb\":%lld,"
                    "\"mem_free_kb\":%lld,"
                    "\"mem_available_kb\":%lld,"
                    "\"mem_used_percent\":%.2f,"
                    "\"buffers_kb\":%lld,"
                    "\"cached_kb\":%lld,"
                    "\"swap_total_kb\":%lld,"
                    "\"swap_free_kb\":%lld,"
                    "\"swap_used_percent\":%.2f,"
                    "\"dirty_kb\":%lld,"
                    "\"writeback_kb\":%lld}",
                    m.mem_total, m.mem_free, m.mem_available,
                    (double)used_pct, m.buffers, m.cached,
                    m.swap_total, m.swap_free, (double)swap_pct,
                    m.dirty, m.writeback);
}

/* ── Tier: process_memory ─────────────────────────────────────────────────── */

static int tier_process_memory(char *out, size_t out_size, int top_n) {
    int total = count_proc_pids();
    if (total < TOP_N_MAX) total = TOP_N_MAX;
    MemProcEntry *procs = (MemProcEntry *)calloc((size_t)total, sizeof(MemProcEntry));
    if (!procs) { snprintf(out, out_size, "\"process_memory\":[]"); return 0; }

    int n = scan_mem_procs(procs, total);
    qsort(procs, (size_t)n, sizeof(MemProcEntry), cmp_rss_desc);
    if (top_n > n) top_n = n;

    int pos = snprintf(out, out_size, "\"process_memory\":[");
    for (int i = 0; i < top_n && (size_t)pos < out_size - 200; i++) {
        MemProcEntry *p = &procs[i];
        double rss_mb = (double)p->rss_bytes / (1024.0 * 1024.0);
        pos += snprintf(out + pos, out_size - (size_t)pos,
                        "%s{\"pid\":%d,\"name\":\"%s\","
                        "\"rss_bytes\":%lld,\"rss_mb\":%.2f,"
                        "\"vsz_bytes\":%lld,\"shared_bytes\":%lld,"
                        "\"oom_score\":%d,\"oom_score_adj\":%d}",
                        i > 0 ? "," : "",
                        p->pid, p->name,
                        p->rss_bytes, rss_mb,
                        p->vsz_bytes, p->shared_bytes,
                        p->oom_score, p->oom_score_adj);
    }
    pos += snprintf(out + pos, out_size - (size_t)pos, "]");
    free(procs);
    return pos;
}

/* ── Tier: memory_extended ────────────────────────────────────────────────── */

static int tier_memory_extended(char *out, size_t out_size, int top_n) {
    int total = count_proc_pids();
    if (total < TOP_N_MAX) total = TOP_N_MAX;
    MemProcEntry *procs = (MemProcEntry *)calloc((size_t)total, sizeof(MemProcEntry));
    if (!procs) { snprintf(out, out_size, "\"memory_extended\":[]"); return 0; }

    int n = scan_mem_procs(procs, total);
    qsort(procs, (size_t)n, sizeof(MemProcEntry), cmp_rss_desc);
    if (top_n > n) top_n = n;

    int pos = snprintf(out, out_size, "\"memory_extended\":[");
    for (int i = 0; i < top_n && (size_t)pos < out_size - 512; i++) {
        int pid = procs[i].pid;
        char path[64];
        long long pss_kb = 0, swap_kb = 0, anon_kb = 0;
        long long major_faults = 0, minor_faults = 0;

        /* smaps_rollup */
        snprintf(path, sizeof(path), "/proc/%d/smaps_rollup", pid);
        FILE *f = fopen(path, "r");
        if (f) {
            char key[64]; long long val;
            while (fscanf(f, "%63s %lld %*s", key, &val) >= 2) {
                if      (strcmp(key, "Pss:")       == 0) pss_kb = val;
                else if (strcmp(key, "Swap:")      == 0) swap_kb = val;
                else if (strcmp(key, "Anonymous:") == 0) anon_kb = val;
            }
            fclose(f);
        }

        /* page faults from /proc/<pid>/stat fields 10 (minflt) and 12 (majflt) */
        snprintf(path, sizeof(path), "/proc/%d/stat", pid);
        f = fopen(path, "r");
        if (f) {
            char buf[512]; size_t nr = fread(buf, 1, sizeof(buf)-1, f); buf[nr] = '\0';
            char *ep = strrchr(buf, ')');
            if (ep) {
                unsigned long minflt, majflt;
                /* fields after ')': state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt */
                if (sscanf(ep + 2, "%*c %*d %*d %*d %*d %*d %*u %lu %*u %lu",
                           &minflt, &majflt) == 2) {
                    minor_faults = (long long)minflt;
                    major_faults = (long long)majflt;
                }
            }
            fclose(f);
        }

        pos += snprintf(out + pos, out_size - (size_t)pos,
                        "%s{\"pid\":%d,\"name\":\"%s\","
                        "\"pss_kb\":%lld,\"swap_kb\":%lld,\"anonymous_kb\":%lld,"
                        "\"major_faults\":%lld,\"minor_faults\":%lld}",
                        i > 0 ? "," : "",
                        pid, procs[i].name,
                        pss_kb, swap_kb, anon_kb,
                        major_faults, minor_faults);
    }
    pos += snprintf(out + pos, out_size - (size_t)pos, "]");
    free(procs);
    return pos;
}

/* ── Tier: memory_system_state ────────────────────────────────────────────── */

static int tier_memory_system_state(char *out, size_t out_size) {
    MemInfo m;
    read_meminfo(&m);

    /* vmstat counters */
    long long oom_kill = 0, pgfault = 0, pgmajfault = 0, pswpin = 0, pswpout = 0;
    FILE *f = fopen("/proc/vmstat", "r");
    if (f) {
        char key[64]; long long val;
        while (fscanf(f, "%63s %lld", key, &val) == 2) {
            if      (strcmp(key, "oom_kill")    == 0) oom_kill    = val;
            else if (strcmp(key, "pgfault")     == 0) pgfault     = val;
            else if (strcmp(key, "pgmajfault")  == 0) pgmajfault  = val;
            else if (strcmp(key, "pswpin")      == 0) pswpin      = val;
            else if (strcmp(key, "pswpout")     == 0) pswpout     = val;
        }
        fclose(f);
    }

    /* zram (first device) */
    long long zram_orig = 0, zram_compr = 0;
    f = fopen("/sys/block/zram0/mm_stat", "r");
    if (f) { fscanf(f, "%lld %lld", &zram_orig, &zram_compr); fclose(f); }

    return snprintf(out, out_size,
                    "\"memory_system_state\":{"
                    "\"slab_total_kb\":%lld,"
                    "\"slab_reclaimable_kb\":%lld,"
                    "\"slab_unreclaimable_kb\":%lld,"
                    "\"page_tables_kb\":%lld,"
                    "\"kernel_stack_kb\":%lld,"
                    "\"vmalloc_used_kb\":%lld,"
                    "\"hugepages_total\":%lld,"
                    "\"hugepages_free\":%lld,"
                    "\"oom_kill_count\":%lld,"
                    "\"pgfault\":%lld,"
                    "\"pgmajfault\":%lld,"
                    "\"pswpin\":%lld,"
                    "\"pswpout\":%lld,"
                    "\"zram_orig_bytes\":%lld,"
                    "\"zram_compr_bytes\":%lld}",
                    m.slab_total, m.slab_reclaimable, m.slab_unreclaimable,
                    m.page_tables, m.kernel_stack, m.vmalloc_used,
                    m.hugepages_total, m.hugepages_free,
                    oom_kill, pgfault, pgmajfault, pswpin, pswpout,
                    zram_orig, zram_compr);
}

/* ── CollectionModule interface ───────────────────────────────────────────── */

static int mem_collect(const char *tier_name,
                       const char *anomaly_type,
                       const char *severity,
                       char       *out_buf,
                       size_t      out_size) {
    (void)anomaly_type; (void)severity;

    int top_n = ae_rules_top_n_processes();
    if (top_n > TOP_N_MAX) top_n = TOP_N_MAX;

    if      (strcmp(tier_name, "memory_mandatory")    == 0) return tier_memory_mandatory(out_buf, out_size);
    else if (strcmp(tier_name, "basic_memory")        == 0) return tier_basic_memory(out_buf, out_size);
    else if (strcmp(tier_name, "process_memory")      == 0) return tier_process_memory(out_buf, out_size, top_n);
    else if (strcmp(tier_name, "memory_extended")     == 0) return tier_memory_extended(out_buf, out_size, top_n);
    else if (strcmp(tier_name, "memory_system_state") == 0) return tier_memory_system_state(out_buf, out_size);

    snprintf(out_buf, out_size, "\"%s\":{\"error\":\"unknown tier\"}", tier_name);
    return -1;
}

static const TierEntry k_mem_tiers[] = {
    { "memory_mandatory",    "memory_module" },
    { "basic_memory",        "memory_module" },
    { "process_memory",      "memory_module" },
    { "memory_extended",     "memory_module" },
    { "memory_system_state", "memory_module" },
    { NULL, NULL }
};

const CollectionModule mem_collection_module = {
    .module_name    = "memory_module",
    .handles_model  = "anomaly",
    .tiers          = k_mem_tiers,
    .collect        = mem_collect,
    .execute_action = NULL,
};
