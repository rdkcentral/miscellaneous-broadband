#include "gw_stats.h"

// Function to log messages to a file
void log_message(const char *format, ...) {
    FILE *logfp = fopen(LOG_FILE, "a+");
    if (logfp) {
        char timestamp[64];
        struct timespec ts;
        struct tm *tm_info;

        clock_gettime(CLOCK_REALTIME, &ts);
        tm_info = localtime(&ts.tv_sec);
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
        snprintf(timestamp + strlen(timestamp), sizeof(timestamp) - strlen(timestamp), ".%03ld", ts.tv_nsec / 1000000);
        fprintf(logfp, "[%s] ", timestamp);

        // Write the log message
        va_list args;
        va_start(args, format);
        vfprintf(logfp, format, args);
        va_end(args);

        fclose(logfp);
    }
}

// Common helper function to execute a command and fetch its output
void execute_command(const char *command, char *output, size_t size) {
    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        fprintf(stderr, "Failed to run command: %s\n", command);
        strncpy(output, "N/A", size);
        return;
    }
    fgets(output, size, fp);
    output[strcspn(output, "\n")] = '\0';
    pclose(fp);
}

// Function to get the current timestamp in the required format
void get_current_timestamp(char *timestamp, size_t size) {
    struct timespec ts;
    struct tm *tm_info;

    clock_gettime(CLOCK_REALTIME, &ts);
    tm_info = localtime(&ts.tv_sec);
    strftime(timestamp, size, "%Y-%m-%d-%H:%M:%S", tm_info); // Format: yyyy-mm-dd-hh:mm:ss
    snprintf(timestamp + strlen(timestamp), size - strlen(timestamp), ".%03ld", ts.tv_nsec / 1000000); // Append milliseconds
}
