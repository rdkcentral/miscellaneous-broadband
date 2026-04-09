/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

/*
 * psmcli — PSM command-line interface (SQLite-direct).
 *
 * Replaces the old RBUS-based psmcli.  Operates directly on the SQLite
 * PSM database so it works after the PSM daemon has exited (oneshot boot).
 *
 * Interface preserved for script compatibility:
 *   psmcli [subsys <prefix> | nosubsys] get <key> ...
 *   psmcli [subsys <prefix> | nosubsys] getdetail <key> ...
 *   psmcli [subsys <prefix> | nosubsys] get -e <env_var> <key> ...
 *   psmcli [subsys <prefix> | nosubsys] getdetail -e <env_var> <key> ...
 *   psmcli [subsys <prefix> | nosubsys] set <key> <value> ...
 *   psmcli [subsys <prefix> | nosubsys] setdetail <type> <key> <value> ...
 *   psmcli [subsys <prefix> | nosubsys] del <key> ...
 *   psmcli [subsys <prefix> | nosubsys] getallinst <key>
 *   psmcli [subsys <prefix> | nosubsys] getinstcnt <key> ...
 *
 * The subsys prefix option is accepted for backward compatibility but
 * ignored — the SQLite PSM implementation does not use subsystem prefixes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sqlite3.h>

#ifndef PSM_DB_PATH
#define PSM_DB_PATH "/nvram/psm.db"
#endif

/* Return codes matching legacy CCSP/psmcli values used by scripts */
#define CCSP_SUCCESS                    0
#define CCSP_FAILURE                    100
#define CCSP_ERR_INVALID_ARGUMENTS      191
#define CCSP_CR_ERR_INVALID_PARAM       204

/* -----------------------------------------------------------------------
 * Type table — must match ccsp dataType_e in ccsp_base_api.h
 * --------------------------------------------------------------------- */
typedef struct { const char *name; int type_id; } type_entry_t;

static const type_entry_t type_table[] = {
    { "int",          1 },  /* ccsp_int          */
    { "string",       0 },  /* ccsp_string       */
    { "uint",         2 },  /* ccsp_unsignedInt  */
    { "bool",         3 },  /* ccsp_boolean      */
    { "datetime",     4 },  /* ccsp_dateTime     */
    { "ccsp_base64",  5 },  /* ccsp_base64       */
    { "long",         6 },  /* ccsp_long         */
    { "ulong",        7 },  /* ccsp_unsignedLong */
    { "float",        8 },  /* ccsp_float        */
    { "double",       9 },  /* ccsp_double       */
    { "byte",        10 },  /* ccsp_byte         */
};

#define TYPE_TABLE_SIZE  ((int)(sizeof(type_table) / sizeof(type_table[0])))

static const char *type_name(int type_id)
{
    int i;
    for (i = 0; i < TYPE_TABLE_SIZE; i++)
        if (type_table[i].type_id == type_id)
            return type_table[i].name;
    return "string";
}

static int type_id_from_name(const char *name)
{
    int i;
    if (!name) return 0;
    for (i = 0; i < TYPE_TABLE_SIZE; i++)
        if (strcasecmp(type_table[i].name, name) == 0)
            return type_table[i].type_id;
    return -1; /* unrecognised */
}

/* -----------------------------------------------------------------------
 * Database connection helper
 * --------------------------------------------------------------------- */
static sqlite3 *open_db(int flags)
{
    sqlite3 *db = NULL;
    int rc = sqlite3_open_v2(PSM_DB_PATH, &db,
                             flags | SQLITE_OPEN_FULLMUTEX, NULL);
    if (rc != SQLITE_OK) {
        fprintf(stderr, "psmcli: cannot open %s: %s\n",
                PSM_DB_PATH, db ? sqlite3_errmsg(db) : "unknown");
        if (db) sqlite3_close(db);
        return NULL;
    }
    sqlite3_busy_timeout(db, 5000);
    return db;
}

/* -----------------------------------------------------------------------
 * Commands
 *
 * All functions receive the adjusted (argc, argv) where:
 *   argv[1] = command name ("get", "set", etc.)
 *   argv[2] = first argument (a key, value, type, or "-e")
 * --------------------------------------------------------------------- */

/* get <key> ... — print value for each key */
static int process_get(int argc, char * const argv[])
{
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int ret = CCSP_SUCCESS;
    int i;

    if (argc < 3) {
        fprintf(stderr, "psmcli get: missing key\n");
        return CCSP_ERR_INVALID_ARGUMENTS;
    }

    db = open_db(SQLITE_OPEN_READONLY);
    if (!db) return CCSP_FAILURE;

    sqlite3_prepare_v2(db,
        "SELECT value FROM psm_records WHERE name=?1 LIMIT 1;",
        -1, &stmt, NULL);

    for (i = 2; i < argc; i++) {
        sqlite3_bind_text(stmt, 1, argv[i], -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *val = (const char *)sqlite3_column_text(stmt, 0);
            printf("%s\n", val ? val : "");
        } else {
            ret = CCSP_CR_ERR_INVALID_PARAM;
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ret;
}

/* getdetail <key> ... — print type-name then value on separate lines */
static int process_getdetail(int argc, char * const argv[])
{
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int ret = CCSP_SUCCESS;
    int i;

    if (argc < 3) {
        fprintf(stderr, "psmcli getdetail: missing key\n");
        return CCSP_ERR_INVALID_ARGUMENTS;
    }

    db = open_db(SQLITE_OPEN_READONLY);
    if (!db) return CCSP_FAILURE;

    sqlite3_prepare_v2(db,
        "SELECT type, value FROM psm_records WHERE name=?1 LIMIT 1;",
        -1, &stmt, NULL);

    for (i = 2; i < argc; i++) {
        sqlite3_bind_text(stmt, 1, argv[i], -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int         type_id = sqlite3_column_int(stmt, 0);
            const char *val     = (const char *)sqlite3_column_text(stmt, 1);
            printf("%s\n", type_name(type_id));
            printf("%s\n", val ? val : "");
        } else {
            ret = CCSP_CR_ERR_INVALID_PARAM;
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ret;
}

/* get -e <env_var1> <key1> <env_var2> <key2> ...
 * Pairs (ENV_VAR, KEY) start at argv[3].
 * Prints: ENV_VAR="value"  */
static int process_get_e(int argc, char * const argv[])
{
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int ret = CCSP_SUCCESS;
    int cmd_cnt = argc - 3;
    int i;

    if (cmd_cnt <= 0 || (cmd_cnt % 2) != 0) {
        fprintf(stderr,
            "psmcli get -e: argument count must be even pairs of ENV_VAR KEY\n");
        return CCSP_ERR_INVALID_ARGUMENTS;
    }

    db = open_db(SQLITE_OPEN_READONLY);
    if (!db) return CCSP_FAILURE;

    sqlite3_prepare_v2(db,
        "SELECT value FROM psm_records WHERE name=?1 LIMIT 1;",
        -1, &stmt, NULL);

    for (i = 3; i + 1 < argc; i += 2) {
        const char *env_var = argv[i];
        const char *key     = argv[i + 1];

        sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *val = (const char *)sqlite3_column_text(stmt, 0);
            printf("%s=\"%s\"\n", env_var, val ? val : "");
        } else {
            ret = CCSP_CR_ERR_INVALID_PARAM;
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ret;
}

/* getdetail -e <env_var1> <key1> ...
 * Pairs (ENV_VAR, KEY) start at argv[3].
 * Prints: ENV_VAR_TYPE="type_name" then ENV_VAR="value"  */
static int process_getdetail_e(int argc, char * const argv[])
{
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int ret = CCSP_SUCCESS;
    int cmd_cnt = argc - 3;
    int i;

    if (cmd_cnt <= 0 || (cmd_cnt % 2) != 0) {
        fprintf(stderr,
            "psmcli getdetail -e: argument count must be even pairs of ENV_VAR KEY\n");
        return CCSP_ERR_INVALID_ARGUMENTS;
    }

    db = open_db(SQLITE_OPEN_READONLY);
    if (!db) return CCSP_FAILURE;

    sqlite3_prepare_v2(db,
        "SELECT type, value FROM psm_records WHERE name=?1 LIMIT 1;",
        -1, &stmt, NULL);

    for (i = 3; i + 1 < argc; i += 2) {
        const char *env_var = argv[i];
        const char *key     = argv[i + 1];

        sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int         type_id = sqlite3_column_int(stmt, 0);
            const char *val     = (const char *)sqlite3_column_text(stmt, 1);
            printf("%s_TYPE=\"%s\"\n", env_var, type_name(type_id));
            printf("%s=\"%s\"\n",      env_var, val ? val : "");
        } else {
            ret = CCSP_CR_ERR_INVALID_PARAM;
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ret;
}

/* set <key1> <value1> <key2> <value2> ...
 * Pairs (KEY, VALUE) at argv[2..].
 * Preserves the existing type; defaults to ccsp_string for new keys.  */
static int process_set(int argc, char * const argv[])
{
    sqlite3 *db;
    sqlite3_stmt *get_type_stmt = NULL;
    sqlite3_stmt *set_stmt      = NULL;
    int ret = CCSP_SUCCESS;
    int cmd_cnt = argc - 2;
    int i;

    if (cmd_cnt <= 0 || (cmd_cnt % 2) != 0) {
        fprintf(stderr,
            "psmcli set: argument count must be even pairs of KEY VALUE\n");
        return CCSP_ERR_INVALID_ARGUMENTS;
    }

    db = open_db(SQLITE_OPEN_READWRITE);
    if (!db) return CCSP_FAILURE;

    sqlite3_prepare_v2(db,
        "SELECT type FROM psm_records WHERE name=?1 LIMIT 1;",
        -1, &get_type_stmt, NULL);
    sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO psm_records (name, type, value)"
        " VALUES (?1, ?2, ?3);",
        -1, &set_stmt, NULL);

    for (i = 2; i + 1 < argc; i += 2) {
        const char *key   = argv[i];
        const char *value = argv[i + 1];
        int type_id = 0; /* default: ccsp_string */

        /* Preserve existing type if the key already exists */
        sqlite3_bind_text(get_type_stmt, 1, key, -1, SQLITE_STATIC);
        if (sqlite3_step(get_type_stmt) == SQLITE_ROW)
            type_id = sqlite3_column_int(get_type_stmt, 0);
        sqlite3_reset(get_type_stmt);
        sqlite3_clear_bindings(get_type_stmt);

        sqlite3_bind_text(set_stmt, 1, key,     -1, SQLITE_STATIC);
        sqlite3_bind_int (set_stmt, 2, type_id);
        sqlite3_bind_text(set_stmt, 3, value,   -1, SQLITE_STATIC);
        if (sqlite3_step(set_stmt) == SQLITE_DONE) {
            printf("%d\n", CCSP_SUCCESS);
        } else {
            fprintf(stderr, "psmcli set: failed for '%s': %s\n",
                    key, sqlite3_errmsg(db));
            ret = CCSP_FAILURE;
        }
        sqlite3_reset(set_stmt);
        sqlite3_clear_bindings(set_stmt);
    }

    sqlite3_finalize(get_type_stmt);
    sqlite3_finalize(set_stmt);
    sqlite3_close(db);
    return ret;
}

/* setdetail <type1> <key1> <value1> <type2> <key2> <value2> ...
 * Triples (TYPE, KEY, VALUE) at argv[2..].
 * Uses the caller-supplied type; ignores any existing type.  */
static int process_setdetail(int argc, char * const argv[])
{
    sqlite3 *db;
    sqlite3_stmt *stmt = NULL;
    int ret = CCSP_SUCCESS;
    int cmd_cnt = argc - 2;
    int i;

    if (cmd_cnt <= 0 || (cmd_cnt % 3) != 0) {
        fprintf(stderr,
            "psmcli setdetail: argument count must be a multiple of 3"
            " (type key value triples)\n");
        return CCSP_ERR_INVALID_ARGUMENTS;
    }

    db = open_db(SQLITE_OPEN_READWRITE);
    if (!db) return CCSP_FAILURE;

    sqlite3_prepare_v2(db,
        "INSERT OR REPLACE INTO psm_records (name, type, value)"
        " VALUES (?1, ?2, ?3);",
        -1, &stmt, NULL);

    for (i = 2; i + 2 < argc; i += 3) {
        const char *type_str = argv[i];
        const char *key      = argv[i + 1];
        const char *value    = argv[i + 2];
        int type_id = type_id_from_name(type_str);

        if (type_id < 0) {
            fprintf(stderr, "psmcli setdetail: unrecognised type '%s'\n",
                    type_str);
            ret = CCSP_CR_ERR_INVALID_PARAM;
            continue;
        }

        sqlite3_bind_text(stmt, 1, key,     -1, SQLITE_STATIC);
        sqlite3_bind_int (stmt, 2, type_id);
        sqlite3_bind_text(stmt, 3, value,   -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_DONE) {
            printf("%d\n", CCSP_SUCCESS);
        } else {
            fprintf(stderr, "psmcli setdetail: failed for '%s': %s\n",
                    key, sqlite3_errmsg(db));
            ret = CCSP_FAILURE;
        }
        sqlite3_reset(stmt);
        sqlite3_clear_bindings(stmt);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return ret;
}

/* del <key> ...
 * Deletes each key exactly; if the key ends with '.' treats it as a
 * prefix and deletes all matching records (same behaviour as PSM_Del_Record).  */
static int process_del(int argc, char * const argv[])
{
    sqlite3 *db;
    sqlite3_stmt *exact_stmt  = NULL;
    sqlite3_stmt *prefix_stmt = NULL;
    int ret = CCSP_SUCCESS;
    int i;

    if (argc < 3) {
        fprintf(stderr, "psmcli del: missing key\n");
        return CCSP_ERR_INVALID_ARGUMENTS;
    }

    db = open_db(SQLITE_OPEN_READWRITE);
    if (!db) return CCSP_FAILURE;

    sqlite3_prepare_v2(db, "DELETE FROM psm_records WHERE name=?1;",
                       -1, &exact_stmt, NULL);
    sqlite3_prepare_v2(db, "DELETE FROM psm_records WHERE name LIKE ?1;",
                       -1, &prefix_stmt, NULL);

    for (i = 2; i < argc; i++) {
        const char *key = argv[i];
        size_t klen = strlen(key);
        int is_prefix = (klen > 0 && key[klen - 1] == '.');

        if (is_prefix) {
            char pattern[512];
            snprintf(pattern, sizeof(pattern), "%s%%", key);
            sqlite3_bind_text(prefix_stmt, 1, pattern, -1, SQLITE_TRANSIENT);
            if (sqlite3_step(prefix_stmt) == SQLITE_DONE)
                printf("%d", CCSP_SUCCESS);
            else {
                fprintf(stderr, "psmcli del: failed for '%s': %s\n",
                        key, sqlite3_errmsg(db));
                ret = CCSP_FAILURE;
            }
            sqlite3_reset(prefix_stmt);
            sqlite3_clear_bindings(prefix_stmt);
        } else {
            sqlite3_bind_text(exact_stmt, 1, key, -1, SQLITE_STATIC);
            if (sqlite3_step(exact_stmt) == SQLITE_DONE)
                printf("%d", CCSP_SUCCESS);
            else {
                fprintf(stderr, "psmcli del: failed for '%s': %s\n",
                        key, sqlite3_errmsg(db));
                ret = CCSP_FAILURE;
            }
            sqlite3_reset(exact_stmt);
            sqlite3_clear_bindings(exact_stmt);
        }
    }

    sqlite3_finalize(exact_stmt);
    sqlite3_finalize(prefix_stmt);
    sqlite3_close(db);
    return ret;
}

/* Shared helper: collect next-level numeric instance IDs under parent_path.
 * Implements the same logic as PsmGetNextLevelInstances in ccsp_base_api.c.
 * Caller must free(*out_arr).  */
static int get_instances(sqlite3 *db, const char *parent_path,
                         unsigned int **out_arr, unsigned int *out_count)
{
    sqlite3_stmt *stmt   = NULL;
    unsigned int  cap    = 16;
    unsigned int  count  = 0;
    unsigned int *arr;
    char pattern[512];
    int parent_len;
    int rc;

    snprintf(pattern, sizeof(pattern), "%s%%", parent_path);
    parent_len = (int)strlen(parent_path);

    rc = sqlite3_prepare_v2(db,
             "SELECT DISTINCT CAST(SUBSTR(name, ?1) AS INTEGER) AS inst"
             " FROM psm_records"
             " WHERE name LIKE ?2"
             "   AND CAST(SUBSTR(name, ?1) AS INTEGER) > 0"
             " ORDER BY inst;",
             -1, &stmt, NULL);
    if (rc != SQLITE_OK)
        return -1;

    sqlite3_bind_int (stmt, 1, parent_len + 1);
    sqlite3_bind_text(stmt, 2, pattern, -1, SQLITE_TRANSIENT);

    arr = malloc(cap * sizeof(unsigned int));
    if (!arr) { sqlite3_finalize(stmt); return -1; }

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        unsigned int inst = (unsigned int)sqlite3_column_int(stmt, 0);
        if (inst == 0) continue;
        if (count == cap) {
            unsigned int *tmp = realloc(arr, (cap * 2) * sizeof(unsigned int));
            if (!tmp) break;
            arr = tmp;
            cap *= 2;
        }
        arr[count++] = inst;
    }
    sqlite3_finalize(stmt);

    *out_arr   = arr;
    *out_count = count;
    return 0;
}

/* getallinst <key>
 * Accepts exactly one key argument.  Prints each next-level instance number.  */
static int process_getallinst(int argc, char * const argv[])
{
    sqlite3      *db;
    unsigned int *arr = NULL;
    unsigned int  count = 0;
    unsigned int  i;

    if (argc != 3) {
        fprintf(stderr,
            "psmcli getallinst: expected exactly one key argument\n");
        return CCSP_ERR_INVALID_ARGUMENTS;
    }

    db = open_db(SQLITE_OPEN_READONLY);
    if (!db) return CCSP_FAILURE;

    if (get_instances(db, argv[2], &arr, &count) != 0) {
        sqlite3_close(db);
        return CCSP_FAILURE;
    }

    for (i = 0; i < count; i++)
        printf("%u\n", arr[i]);

    free(arr);
    sqlite3_close(db);
    return CCSP_SUCCESS;
}

/* getinstcnt <key> ...
 * Prints the count of next-level instances for each key.  */
static int process_getinstcnt(int argc, char * const argv[])
{
    sqlite3 *db;
    int ret = CCSP_SUCCESS;
    int i;

    if (argc < 3) {
        fprintf(stderr, "psmcli getinstcnt: missing key\n");
        return CCSP_ERR_INVALID_ARGUMENTS;
    }

    db = open_db(SQLITE_OPEN_READONLY);
    if (!db) return CCSP_FAILURE;

    for (i = 2; i < argc; i++) {
        unsigned int *arr   = NULL;
        unsigned int  count = 0;
        if (get_instances(db, argv[i], &arr, &count) == 0) {
            printf("%u\n", count);
            free(arr);
        } else {
            fprintf(stderr, "psmcli getinstcnt: query failed for '%s'\n",
                    argv[i]);
            ret = CCSP_FAILURE;
        }
    }

    sqlite3_close(db);
    return ret;
}

/* -----------------------------------------------------------------------
 * Usage
 * --------------------------------------------------------------------- */
static void print_usage(void)
{
    fprintf(stderr,
        "Usage:\n"
        "  psmcli [subsys <prefix> | nosubsys] get <key> ...\n"
        "  psmcli [subsys <prefix> | nosubsys] getdetail <key> ...\n"
        "  psmcli [subsys <prefix> | nosubsys] get -e <env_var> <key> ...\n"
        "  psmcli [subsys <prefix> | nosubsys] getdetail -e <env_var> <key> ...\n"
        "  psmcli [subsys <prefix> | nosubsys] set <key> <value> ...\n"
        "  psmcli [subsys <prefix> | nosubsys] setdetail <type> <key> <value> ...\n"
        "  psmcli [subsys <prefix> | nosubsys] del <key> ...\n"
        "  psmcli [subsys <prefix> | nosubsys] getallinst <key>\n"
        "  psmcli [subsys <prefix> | nosubsys] getinstcnt <key> ...\n"
        "\n"
        "Types for setdetail: int string uint bool datetime ccsp_base64"
        " long ulong float double byte\n"
        "\n"
        "Note: the subsys prefix option is accepted for backward compatibility\n"
        "      but ignored. PSM database: " PSM_DB_PATH "\n");
}

/* -----------------------------------------------------------------------
 * main
 * --------------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    int    local_argc = argc;
    char **local_argv = argv;
    const char *cmd;
    int is_e;

    if (argc < 2) {
        print_usage();
        return CCSP_ERR_INVALID_ARGUMENTS;
    }

    /* ------------------------------------------------------------------
     * Parse optional subsys prefix — adjust local_argc / local_argv so
     * that local_argv[1] is always the command name.
     *
     * nosubsys: shift by 1 (drop "nosubsys")
     * subsys <prefix>: shift by 2 (drop "subsys" and the prefix string)
     *
     * The prefix itself is not stored or used — the SQLite API ignores it.
     * ------------------------------------------------------------------ */
    if (strcmp(argv[1], "nosubsys") == 0) {
        if (argc < 4) { print_usage(); return CCSP_ERR_INVALID_ARGUMENTS; }
        local_argv = argv + 1;
        local_argc = argc - 1;
    } else if (strcmp(argv[1], "subsys") == 0) {
        if (argc < 5) { print_usage(); return CCSP_ERR_INVALID_ARGUMENTS; }
        local_argv = argv + 2;
        local_argc = argc - 2;
    }
    /* else: no subsys option — use argv as-is */

    cmd = local_argv[1];

    /* Handle "psmcli help" (no key argument required) */
    if (strcmp(cmd, "help") == 0) {
        print_usage();
        return CCSP_SUCCESS;
    }

    if (local_argc < 3) {
        print_usage();
        return CCSP_ERR_INVALID_ARGUMENTS;
    }

    /* Dispatch "get -e" / "getdetail -e" when argv[2] == "-e" */
    is_e = (strcmp(local_argv[2], "-e") == 0);

    if (strcmp(cmd, "get") == 0 && is_e)
        return process_get_e(local_argc, local_argv);
    if (strcmp(cmd, "getdetail") == 0 && is_e)
        return process_getdetail_e(local_argc, local_argv);
    if (strcmp(cmd, "get") == 0)
        return process_get(local_argc, local_argv);
    if (strcmp(cmd, "getdetail") == 0)
        return process_getdetail(local_argc, local_argv);
    if (strcmp(cmd, "set") == 0)
        return process_set(local_argc, local_argv);
    if (strcmp(cmd, "setdetail") == 0)
        return process_setdetail(local_argc, local_argv);
    if (strcmp(cmd, "del") == 0)
        return process_del(local_argc, local_argv);
    if (strcmp(cmd, "getallinst") == 0)
        return process_getallinst(local_argc, local_argv);
    if (strcmp(cmd, "getinstcnt") == 0)
