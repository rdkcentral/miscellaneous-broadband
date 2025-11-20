#ifndef SPECTRUM_ANALYZER_H
#define SPECTRUM_ANALYZER_H


#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <pthread.h>
#include <stdarg.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <limits.h>
#include <math.h>
#include "cm_hal.h"
#include "secure_wrapper.h"

#define LOG_FILE "/rdklogs/logs/specAnalyzer_logs.txt"

typedef enum
{
    UPSTREAM,
    DOWNSTREAM
} FrequencyScope;

typedef struct
{
    uint64_t startFreq;
    uint64_t endFreq;
    uint64_t freqSpan;
    uint32_t fftSize;
} specAnalyzer_config_t;

typedef struct {
    float noise_floor;      // Minimum dB value (10th percentile)
    float avg_noise_power;  // Average of lower 25% values
    float peak_signal;      // Maximum dB value
    float snr;              // Signal-to-Noise Ratio
} NoiseStats;


void log_message(const char *format, ...);

int init_spec_analyzer(specAnalyzer_config_t* config, FrequencyScope scope);
int collect_and_parse_spec_analyzer_data();

// Noise calculation functions
int compare_floats(const void *a, const void *b);
NoiseStats calculate_noise_stats(float *amplitude_data, uint32_t num_bins);


#endif //SPECTRUM_ANALYZER_H