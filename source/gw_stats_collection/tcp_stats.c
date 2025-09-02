#include "gw_stats.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void initialize_tcp_stats(TcpStats *stats) {
    stats->timestamp_ms = 0;
    memset(stats->TCPLostRetransmit, 0, sizeof(stats->TCPLostRetransmit));
    memset(stats->TCPRetransFail, 0, sizeof(stats->TCPRetransFail));
    memset(stats->TCPSackFailures, 0, sizeof(stats->TCPSackFailures));
    memset(stats->TCPTimeouts, 0, sizeof(stats->TCPTimeouts));
    memset(stats->TCPAbortOnTimeout, 0, sizeof(stats->TCPAbortOnTimeout));
    memset(stats->ListenOverflows, 0, sizeof(stats->ListenOverflows));
    memset(stats->TCPOrigDataSent, 0, sizeof(stats->TCPOrigDataSent));
    stats->next = NULL;
}

//High TCPTimeouts or TCPAbortOnTimeout may indicate poor connectivity, especially for external WAN routes.
//High TCPLostRetransmit, TCPRetransFail, or TCPSackFailures = packet loss or network instability.

void get_tcp_params(TcpStats *stats) {
    FILE *fp = fopen("/proc/net/netstat", "r");
    if (!fp) {
        memset(stats, 0, sizeof(TcpStats));
        return;
    }
    char line[4096]; // Increased buffer size for long lines
    char *fields = NULL;
    char *values = NULL;
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "TcpExt:", 7) == 0) {
            // Save the fields line
            if (fields) free(fields);
            fields = strdup(line);
            // Read the next line for values
            if (fgets(line, sizeof(line), fp)) {
                if (values) free(values);
                values = strdup(line);
            }
        }
    }
    fclose(fp);
    if (!fields || !values) {
        if (fields) free(fields);
        if (values) free(values);
        memset(stats, 0, sizeof(TcpStats));
        return;
    }
    // Tokenize fields and values
    char *field_saveptr, *value_saveptr;
    char *field = strtok_r(fields, " \t\n", &field_saveptr);
    char *value = strtok_r(values, " \t\n", &value_saveptr);

    // Skip the first token ("TcpExt:") in both fields and values
    if (field && value && strcmp(field, "TcpExt:") == 0) {
        field = strtok_r(NULL, " \t\n", &field_saveptr);
        value = strtok_r(NULL, " \t\n", &value_saveptr);
    }

    while (field && value) {
        if (strcmp(field, "TCPLostRetransmit") == 0) {
            strncpy(stats->TCPLostRetransmit, value, sizeof(stats->TCPLostRetransmit) - 1);
            stats->TCPLostRetransmit[sizeof(stats->TCPLostRetransmit) - 1] = '\0';
        } else if (strcmp(field, "TCPRetransFail") == 0) {
            strncpy(stats->TCPRetransFail, value, sizeof(stats->TCPRetransFail) - 1);
            stats->TCPRetransFail[sizeof(stats->TCPRetransFail) - 1] = '\0';
        } else if (strcmp(field, "TCPSackFailures") == 0) {
            strncpy(stats->TCPSackFailures, value, sizeof(stats->TCPSackFailures) - 1);
            stats->TCPSackFailures[sizeof(stats->TCPSackFailures) - 1] = '\0';
        } else if (strcmp(field, "TCPTimeouts") == 0) {
            strncpy(stats->TCPTimeouts, value, sizeof(stats->TCPTimeouts) - 1);
            stats->TCPTimeouts[sizeof(stats->TCPTimeouts) - 1] = '\0';
        } else if (strcmp(field, "TCPAbortOnTimeout") == 0) {
            strncpy(stats->TCPAbortOnTimeout, value, sizeof(stats->TCPAbortOnTimeout) - 1);
            stats->TCPAbortOnTimeout[sizeof(stats->TCPAbortOnTimeout) - 1] = '\0';
        } else if (strcmp(field, "ListenOverflows") == 0) {
            strncpy(stats->ListenOverflows, value, sizeof(stats->ListenOverflows) - 1);
            stats->ListenOverflows[sizeof(stats->ListenOverflows) - 1] = '\0';
        } else if (strcmp(field, "TCPOrigDataSent") == 0) {
            strncpy(stats->TCPOrigDataSent, value, sizeof(stats->TCPOrigDataSent) - 1);
            stats->TCPOrigDataSent[sizeof(stats->TCPOrigDataSent) - 1] = '\0';
        }
        field = strtok_r(NULL, " \t\n", &field_saveptr);
        value = strtok_r(NULL, " \t\n", &value_saveptr);
    }
    free(fields);
    free(values);
}

void collect_tcp_stats(TcpStats *stats) {
    get_tcp_params(stats);
}