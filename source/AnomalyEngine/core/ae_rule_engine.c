/*
 * Copyright 2026 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * ae_rule_engine.c
 * ─────────────────────────────────────────────────────────────────────────────
 * Minimal recursive-descent JSON parser targeting anomaly_engine_config.json.
 * Builds an in-memory lookup table of (model, anomaly_type, severity) → tiers[].
 */

#include "ae_rule_engine.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/* ── Internal storage ─────────────────────────────────────────────────────── */

#define MAX_RULES          128
#define MAX_TIERS_PER_KEY  AE_MAX_TIERS_PER_RULE
#define MAX_LOG_FILES      32
#define MAX_PROTECTED      32

typedef struct {
    char model[32];
    char anomaly_type[32];
    char severity[16];   /* "mandatory" | "low" | "medium" | "high" | "critical" */
    char tiers[MAX_TIERS_PER_KEY][AE_MAX_TIER_NAME_LEN];
    int  num_tiers;
} RuleKey;

static RuleKey s_rules[MAX_RULES];
static int     s_num_rules = 0;

static struct {
    float cpu_high;
    float cpu_critical;
    float mem_high;
    float mem_critical;
    int   top_n_processes;
    char  logs_dir[256];
    int   log_before_sec;
    int   log_after_sec;
    int   max_log_size_kb;
    char  log_files[MAX_LOG_FILES][64];
    int   num_log_files;
    char  data_path[256];
    char  log_path[256];
    int   actions_enabled;
    int   global_cooldown_sec;
    int   max_actions_per_hour;
    char  protected[MAX_PROTECTED][64];
    int   num_protected;
} s_cfg = {
    .cpu_high             = 80.0f,
    .cpu_critical         = 90.0f,
    .mem_high             = 75.0f,
    .mem_critical         = 85.0f,
    .top_n_processes      = 10,
    .logs_dir             = "/rdklogs/logs",
    .log_before_sec       = 300,
    .log_after_sec        = 60,
    .max_log_size_kb      = 5120,
    .data_path            = "/rdklogs/logs/anomaly_data",
    .log_path             = "/rdklogs/logs/anomaly_analysis.txt",
    .actions_enabled      = 1,
    .global_cooldown_sec  = 60,
    .max_actions_per_hour = 10,
};

/* ── Minimal JSON tokenizer ───────────────────────────────────────────────── */

typedef enum {
    JT_NONE, JT_LBRACE, JT_RBRACE, JT_LBRACKET, JT_RBRACKET,
    JT_COLON, JT_COMMA, JT_STRING, JT_NUMBER, JT_BOOL, JT_NULL, JT_EOF, JT_ERROR
} JTok;

typedef struct {
    const char *src;
    size_t      pos;
    size_t      len;
    char        str[256];
} JLex;

static void jl_init(JLex *l, const char *src, size_t len) {
    l->src = src; l->pos = 0; l->len = len; l->str[0] = '\0';
}

static void jl_skip_ws(JLex *l) {
    while (l->pos < l->len) {
        char c = l->src[l->pos];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') { l->pos++; continue; }
        /* Skip // line comments (present in config _comment fields already, but safe) */
        if (c == '/' && l->pos + 1 < l->len && l->src[l->pos + 1] == '/') {
            while (l->pos < l->len && l->src[l->pos] != '\n') l->pos++;
            continue;
        }
        break;
    }
}

static JTok jl_next(JLex *l) {
    jl_skip_ws(l);
    l->str[0] = '\0';
    if (l->pos >= l->len) return JT_EOF;

    char c = l->src[l->pos++];
    switch (c) {
    case '{': return JT_LBRACE;
    case '}': return JT_RBRACE;
    case '[': return JT_LBRACKET;
    case ']': return JT_RBRACKET;
    case ':': return JT_COLON;
    case ',': return JT_COMMA;
    case '"': {
        size_t i = 0;
        while (l->pos < l->len && l->src[l->pos] != '"') {
            if (l->src[l->pos] == '\\' && l->pos + 1 < l->len) {
                char esc = l->src[++l->pos]; l->pos++;
                if (i < sizeof(l->str) - 1) {
                    switch (esc) {
                    case 'n': l->str[i++] = '\n'; break;
                    case 't': l->str[i++] = '\t'; break;
                    default:  l->str[i++] = esc;  break;
                    }
                }
            } else {
                if (i < sizeof(l->str) - 1) l->str[i++] = l->src[l->pos];
                l->pos++;
            }
        }
        l->str[i] = '\0';
        if (l->pos < l->len) l->pos++; /* closing " */
        return JT_STRING;
    }
    default:
        if (c == 't' || c == 'f' || c == 'n') {
            l->str[0] = c; size_t i = 1;
            while (l->pos < l->len && isalpha((unsigned char)l->src[l->pos]) && i < sizeof(l->str)-1)
                l->str[i++] = l->src[l->pos++];
            l->str[i] = '\0';
            return (strcmp(l->str, "null") == 0) ? JT_NULL : JT_BOOL;
        }
        if (isdigit((unsigned char)c) || c == '-') {
            l->str[0] = c; size_t i = 1;
            while (l->pos < l->len && i < sizeof(l->str)-1) {
                char n = l->src[l->pos];
                if (isdigit((unsigned char)n) || n == '.' || n == 'e' || n == 'E' || n == '+' || n == '-')
                    l->str[i++] = l->src[l->pos++];
                else break;
            }
            l->str[i] = '\0';
            return JT_NUMBER;
        }
        return JT_ERROR;
    }
}

/* ── Recursive descent parser state ─────────────────────────────────────── */

static JLex s_lex;
static JTok s_tok;

static void advance(void)            { s_tok = jl_next(&s_lex); }
static void expect_tok(JTok t)       { if (s_tok == t) advance(); }
static const char *tok_str(void)     { return s_lex.str; }

/* Skip one complete JSON value (any type, any depth) */
static void skip_value(void) {
    if (s_tok == JT_LBRACE) {
        advance();
        while (s_tok != JT_RBRACE && s_tok != JT_EOF && s_tok != JT_ERROR) {
            if (s_tok == JT_STRING) { advance(); } /* key */
            if (s_tok == JT_COLON) { advance(); skip_value(); }
            else                   { skip_value(); }
            if (s_tok == JT_COMMA) advance();
        }
        if (s_tok == JT_RBRACE) advance();
    } else if (s_tok == JT_LBRACKET) {
        advance();
        while (s_tok != JT_RBRACKET && s_tok != JT_EOF && s_tok != JT_ERROR) {
            skip_value();
            if (s_tok == JT_COMMA) advance();
        }
        if (s_tok == JT_RBRACKET) advance();
    } else {
        advance(); /* STRING, NUMBER, BOOL, NULL */
    }
}

/* Parse a JSON string array ["a","b",...] → out[][]; returns count */
static int parse_string_array(char out[][AE_MAX_TIER_NAME_LEN], int max) {
    if (s_tok != JT_LBRACKET) { skip_value(); return 0; }
    advance();
    int count = 0;
    while (s_tok != JT_RBRACKET && s_tok != JT_EOF && s_tok != JT_ERROR) {
        if (s_tok == JT_STRING) {
            if (count < max) {
                strncpy(out[count], tok_str(), AE_MAX_TIER_NAME_LEN - 1);
                out[count][AE_MAX_TIER_NAME_LEN - 1] = '\0';
                count++;
            }
            advance();
        } else if (s_tok == JT_COMMA) {
            advance();
        } else {
            skip_value();
        }
    }
    if (s_tok == JT_RBRACKET) advance();
    return count;
}

/* ── Section parsers ──────────────────────────────────────────────────── */

static void parse_thresholds(void) {
    if (s_tok != JT_LBRACE) { skip_value(); return; }
    advance();
    while (s_tok != JT_RBRACE && s_tok != JT_EOF) {
        if (s_tok != JT_STRING) { skip_value(); if (s_tok == JT_COMMA) advance(); continue; }
        char section[32];
        strncpy(section, tok_str(), sizeof(section)-1); section[sizeof(section)-1] = '\0';
        advance(); expect_tok(JT_COLON);

        if (strcmp(section, "cpu") == 0 || strcmp(section, "memory") == 0) {
            if (s_tok != JT_LBRACE) { skip_value(); if (s_tok == JT_COMMA) advance(); continue; }
            advance();
            while (s_tok != JT_RBRACE && s_tok != JT_EOF) {
                if (s_tok != JT_STRING) { skip_value(); if (s_tok == JT_COMMA) advance(); continue; }
                char key[64];
                strncpy(key, tok_str(), sizeof(key)-1); key[sizeof(key)-1] = '\0';
                advance(); expect_tok(JT_COLON);
                if (s_tok == JT_NUMBER) {
                    float v = (float)atof(tok_str()); advance();
                    if      (strcmp(key, "system_cpu_high")      == 0) s_cfg.cpu_high      = v;
                    else if (strcmp(key, "system_cpu_critical")  == 0) s_cfg.cpu_critical   = v;
                    else if (strcmp(key, "mem_used_high")        == 0) s_cfg.mem_high       = v;
                    else if (strcmp(key, "mem_used_critical")    == 0) s_cfg.mem_critical   = v;
                } else { skip_value(); }
                if (s_tok == JT_COMMA) advance();
            }
            if (s_tok == JT_RBRACE) advance();
        } else {
            skip_value();
        }
        if (s_tok == JT_COMMA) advance();
    }
    if (s_tok == JT_RBRACE) advance();
}

static void parse_log_collection(void) {
    if (s_tok != JT_LBRACE) { skip_value(); return; }
    advance();
    while (s_tok != JT_RBRACE && s_tok != JT_EOF) {
        if (s_tok != JT_STRING) { skip_value(); if (s_tok == JT_COMMA) advance(); continue; }
        char key[64];
        strncpy(key, tok_str(), sizeof(key)-1); key[sizeof(key)-1] = '\0';
        advance(); expect_tok(JT_COLON);

        if (strcmp(key, "logs_directory") == 0 && s_tok == JT_STRING) {
            strncpy(s_cfg.logs_dir, tok_str(), sizeof(s_cfg.logs_dir)-1); advance();
        } else if (strcmp(key, "time_window_before_sec") == 0 && s_tok == JT_NUMBER) {
            s_cfg.log_before_sec = atoi(tok_str()); advance();
        } else if (strcmp(key, "time_window_after_sec") == 0 && s_tok == JT_NUMBER) {
            s_cfg.log_after_sec = atoi(tok_str()); advance();
        } else if (strcmp(key, "max_total_size_kb") == 0 && s_tok == JT_NUMBER) {
            s_cfg.max_log_size_kb = atoi(tok_str()); advance();
        } else if (strcmp(key, "log_files") == 0) {
            s_cfg.num_log_files = parse_string_array(s_cfg.log_files, MAX_LOG_FILES);
        } else {
            skip_value();
        }
        if (s_tok == JT_COMMA) advance();
    }
    if (s_tok == JT_RBRACE) advance();
}

static void parse_engine_section(void) {
    if (s_tok != JT_LBRACE) { skip_value(); return; }
    advance();
    while (s_tok != JT_RBRACE && s_tok != JT_EOF) {
        if (s_tok != JT_STRING) { skip_value(); if (s_tok == JT_COMMA) advance(); continue; }
        char key[64];
        strncpy(key, tok_str(), sizeof(key)-1); key[sizeof(key)-1] = '\0';
        advance(); expect_tok(JT_COLON);
        if (strcmp(key, "data_path") == 0 && s_tok == JT_STRING) {
            strncpy(s_cfg.data_path, tok_str(), sizeof(s_cfg.data_path)-1); advance();
        } else if (strcmp(key, "log_path") == 0 && s_tok == JT_STRING) {
            strncpy(s_cfg.log_path, tok_str(), sizeof(s_cfg.log_path)-1); advance();
        } else if (strcmp(key, "enable_corrective_actions") == 0 && s_tok == JT_BOOL) {
            s_cfg.actions_enabled = (strncmp(tok_str(), "true", 4) == 0) ? 1 : 0; advance();
        } else {
            skip_value();
        }
        if (s_tok == JT_COMMA) advance();
    }
    if (s_tok == JT_RBRACE) advance();
}

static void parse_protected_services(void) {
    if (s_tok != JT_LBRACKET) { skip_value(); return; }
    advance();
    while (s_tok != JT_RBRACKET && s_tok != JT_EOF) {
        if (s_tok == JT_STRING && s_cfg.num_protected < MAX_PROTECTED) {
            strncpy(s_cfg.protected[s_cfg.num_protected], tok_str(),
                    sizeof(s_cfg.protected[0]) - 1);
            s_cfg.num_protected++;
            advance();
        } else if (s_tok == JT_COMMA) {
            advance();
        } else {
            skip_value();
        }
    }
    if (s_tok == JT_RBRACKET) advance();
}

static void parse_corrective_actions(void) {
    /* Parse only the top-level enabled/global_cooldown/max_actions fields */
    if (s_tok != JT_LBRACE) { skip_value(); return; }
    advance();
    while (s_tok != JT_RBRACE && s_tok != JT_EOF) {
        if (s_tok != JT_STRING) { skip_value(); if (s_tok == JT_COMMA) advance(); continue; }
        char key[64];
        strncpy(key, tok_str(), sizeof(key)-1); key[sizeof(key)-1] = '\0';
        advance(); expect_tok(JT_COLON);
        if (strcmp(key, "enabled") == 0 && s_tok == JT_BOOL) {
            s_cfg.actions_enabled = (strncmp(tok_str(),"true",4) == 0) ? 1 : 0; advance();
        } else if (strcmp(key, "global_cooldown_seconds") == 0 && s_tok == JT_NUMBER) {
            s_cfg.global_cooldown_sec = atoi(tok_str()); advance();
        } else if (strcmp(key, "max_actions_per_hour") == 0 && s_tok == JT_NUMBER) {
            s_cfg.max_actions_per_hour = atoi(tok_str()); advance();
        } else {
            skip_value(); /* skip per-type action blocks */
        }
        if (s_tok == JT_COMMA) advance();
    }
    if (s_tok == JT_RBRACE) advance();
}

/*
 * Parse collection_rules section.
 * Structure: { MODEL: { TYPE: { "mandatory"|SEVERITY: [...], ... } } }
 */
static void parse_collection_rules(void) {
    if (s_tok != JT_LBRACE) { skip_value(); return; }
    advance(); /* enter collection_rules object */

    while (s_tok != JT_RBRACE && s_tok != JT_EOF) {
        if (s_tok != JT_STRING) { skip_value(); if (s_tok == JT_COMMA) advance(); continue; }
        char model[32];
        strncpy(model, tok_str(), sizeof(model)-1); model[sizeof(model)-1] = '\0';
        advance(); expect_tok(JT_COLON);
        if (s_tok != JT_LBRACE) { skip_value(); if (s_tok == JT_COMMA) advance(); continue; }
        advance(); /* enter model object */

        while (s_tok != JT_RBRACE && s_tok != JT_EOF) {
            if (s_tok != JT_STRING) { skip_value(); if (s_tok == JT_COMMA) advance(); continue; }
            char atype[32];
            strncpy(atype, tok_str(), sizeof(atype)-1); atype[sizeof(atype)-1] = '\0';
            advance(); expect_tok(JT_COLON);
            if (s_tok != JT_LBRACE) { skip_value(); if (s_tok == JT_COMMA) advance(); continue; }
            advance(); /* enter anomaly_type object */

            while (s_tok != JT_RBRACE && s_tok != JT_EOF) {
                if (s_tok != JT_STRING) { skip_value(); if (s_tok == JT_COMMA) advance(); continue; }
                char severity[32];
                strncpy(severity, tok_str(), sizeof(severity)-1); severity[sizeof(severity)-1] = '\0';
                advance(); expect_tok(JT_COLON);

                if (s_num_rules < MAX_RULES) {
                    RuleKey *rk = &s_rules[s_num_rules];
                    strncpy(rk->model,        model,    sizeof(rk->model)-1);
                    strncpy(rk->anomaly_type, atype,    sizeof(rk->anomaly_type)-1);
                    strncpy(rk->severity,     severity, sizeof(rk->severity)-1);
                    rk->num_tiers = parse_string_array(rk->tiers, MAX_TIERS_PER_KEY);
                    s_num_rules++;
                } else {
                    skip_value();
                }
                if (s_tok == JT_COMMA) advance();
            }
            if (s_tok == JT_RBRACE) advance(); /* exit type object */
            if (s_tok == JT_COMMA) advance();
        }
        if (s_tok == JT_RBRACE) advance(); /* exit model object */
        if (s_tok == JT_COMMA) advance();
    }
    if (s_tok == JT_RBRACE) advance(); /* exit collection_rules */
}

/* ── Public API ───────────────────────────────────────────────────────────── */

int ae_rules_load(const char *config_path) {
    FILE *f = fopen(config_path, "r");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);
    if (fsize <= 0 || fsize > 256 * 1024) { fclose(f); return -1; }

    char *buf = (char *)malloc((size_t)fsize + 1);
    if (!buf) { fclose(f); return -1; }
    size_t n = fread(buf, 1, (size_t)fsize, f);
    buf[n] = '\0';
    fclose(f);

    /* Reset rule table */
    s_num_rules = 0;
    s_cfg.num_protected  = 0;
    s_cfg.num_log_files  = 0;

    jl_init(&s_lex, buf, n);
    s_tok = jl_next(&s_lex);

    if (s_tok != JT_LBRACE) { free(buf); return -1; }
    advance(); /* enter top-level object */

    while (s_tok != JT_RBRACE && s_tok != JT_EOF && s_tok != JT_ERROR) {
        if (s_tok != JT_STRING) { skip_value(); if (s_tok == JT_COMMA) advance(); continue; }
        char key[64];
        strncpy(key, tok_str(), sizeof(key)-1); key[sizeof(key)-1] = '\0';
        advance(); expect_tok(JT_COLON);

        if      (strcmp(key, "engine")              == 0) parse_engine_section();
        else if (strcmp(key, "log_collection")       == 0) parse_log_collection();
        else if (strcmp(key, "thresholds")           == 0) parse_thresholds();
        else if (strcmp(key, "protected_services")   == 0) parse_protected_services();
        else if (strcmp(key, "corrective_actions")   == 0) parse_corrective_actions();
        else if (strcmp(key, "collection_rules")     == 0) parse_collection_rules();
        else                                               skip_value();

        if (s_tok == JT_COMMA) advance();
    }

    free(buf);
    return 0;
}

int ae_rules_lookup(const char *model, const char *anomaly_type,
                    const char *severity,
                    char tiers[][AE_MAX_TIER_NAME_LEN], int max_tiers) {
    int count = 0;

    /* Mandatory tiers first (deduplicated) */
    for (int i = 0; i < s_num_rules && count < max_tiers; i++) {
        if (strcmp(s_rules[i].model, model) != 0 ||
            strcmp(s_rules[i].anomaly_type, anomaly_type) != 0 ||
            strcmp(s_rules[i].severity, "mandatory") != 0) continue;
        for (int j = 0; j < s_rules[i].num_tiers && count < max_tiers; j++)
            strncpy(tiers[count++], s_rules[i].tiers[j], AE_MAX_TIER_NAME_LEN - 1);
    }

    /* Severity-specific tiers (skip duplicates already in mandatory) */
    for (int i = 0; i < s_num_rules && count < max_tiers; i++) {
        if (strcmp(s_rules[i].model, model) != 0 ||
            strcmp(s_rules[i].anomaly_type, anomaly_type) != 0 ||
            strcmp(s_rules[i].severity, severity) != 0) continue;
        for (int j = 0; j < s_rules[i].num_tiers && count < max_tiers; j++) {
            int dup = 0;
            for (int k = 0; k < count; k++)
                if (strcmp(tiers[k], s_rules[i].tiers[j]) == 0) { dup = 1; break; }
            if (!dup) strncpy(tiers[count++], s_rules[i].tiers[j], AE_MAX_TIER_NAME_LEN - 1);
        }
    }

    return (count > 0) ? count : -1;
}

float ae_rules_cpu_threshold_high(void)      { return s_cfg.cpu_high; }
float ae_rules_cpu_threshold_critical(void)  { return s_cfg.cpu_critical; }
float ae_rules_mem_threshold_high(void)      { return s_cfg.mem_high; }
float ae_rules_mem_threshold_critical(void)  { return s_cfg.mem_critical; }
int   ae_rules_top_n_processes(void)         { return s_cfg.top_n_processes; }
const char *ae_rules_logs_directory(void)    { return s_cfg.logs_dir; }
int   ae_rules_log_window_before_sec(void)   { return s_cfg.log_before_sec; }
int   ae_rules_log_window_after_sec(void)    { return s_cfg.log_after_sec; }
int   ae_rules_max_log_size_kb(void)         { return s_cfg.max_log_size_kb; }
const char *ae_rules_data_path(void)         { return s_cfg.data_path; }
const char *ae_rules_log_path(void)          { return s_cfg.log_path; }
int   ae_rules_actions_enabled(void)         { return s_cfg.actions_enabled; }
int   ae_rules_global_cooldown_sec(void)     { return s_cfg.global_cooldown_sec; }
int   ae_rules_max_actions_per_hour(void)    { return s_cfg.max_actions_per_hour; }

int ae_rules_log_files(char out[][64], int max) {
    int n = s_cfg.num_log_files < max ? s_cfg.num_log_files : max;
    for (int i = 0; i < n; i++) strncpy(out[i], s_cfg.log_files[i], 63);
    return n;
}

int ae_rules_is_protected(const char *process_name) {
    if (!process_name) return 0;
    for (int i = 0; i < s_cfg.num_protected; i++)
        if (strcmp(s_cfg.protected[i], process_name) == 0) return 1;
    return 0;
}
