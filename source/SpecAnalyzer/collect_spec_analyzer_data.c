#include "specAnalyzer.h"

#define OUTPUT_FILE "/rdklogs/logs/specAnalyzer_data.txt"
#define MAX_LINE_LEN 8192
#define MAX_HEX_BLOCK 200000
#define MAX_POWER_ENTRIES 100

typedef struct {
    uint32_t freq;
    float power;
} PowerEntry;

specAnalyzer_config_t *g_config;

// Helper functions for parsing
int16_t read_int16_be(uint8_t *data) {
    return (int16_t)((data[0] << 8) | data[1]);
}

uint32_t read_uint32_be(uint8_t *data) {
    return ((uint32_t)data[0] << 24) |
           ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8)  |
           ((uint32_t)data[3]);
}

void parse_hex_string(const char *hex, uint8_t *bytes, size_t *byte_count) {
    size_t len = strlen(hex);
    size_t count = 0;
    for (size_t i = 0; i < len;) {
        while (i < len && (hex[i] == ' ' || hex[i] == '\n' || hex[i] == '\t')) i++;
        if (i + 1 >= len) break;
        unsigned int byte;
        if (sscanf(&hex[i], "%2x", &byte) == 1) {
            bytes[count++] = (uint8_t)byte;
            i += 2;
        } else {
            i++;
        }
    }
    *byte_count = count;
}

// Comparison function for qsort
int compare_floats(const void *a, const void *b) {
    float fa = *(const float*)a;
    float fb = *(const float*)b;
    return (fa > fb) - (fa < fb);
}

/*
Lower noise floor = cleaner spectrum
Higher SNR = better signal quality (typically want SNR > 20 dB)
Average noise power shows typical noise level across the band

calculate_noise_stats() - Analyzes amplitude data and returns:
  Noise Floor: 10th percentile (the baseline noise level)
  Average Noise Power: Average of the lowest 25% of values
  Peak Signal: Maximum amplitude value
  SNR (Signal-to-Noise Ratio): Peak signal minus noise floor
*/

// Calculate noise statistics for amplitude data
NoiseStats calculate_noise_stats(float *amplitude_data, uint32_t num_bins) {
    NoiseStats stats = {0};
    
    if (num_bins == 0) {
        return stats;
    }
    
    // Create a sorted copy of amplitude data
    float *sorted_data = (float *)malloc(num_bins * sizeof(float));
    if (sorted_data == NULL) {
        return stats;
    }
    
    memcpy(sorted_data, amplitude_data, num_bins * sizeof(float));
    qsort(sorted_data, num_bins, sizeof(float), compare_floats);
    
    // Noise floor: 10th percentile (lower values = more noise)
    uint32_t percentile_10_idx = (uint32_t)(num_bins * 0.10);
    stats.noise_floor = sorted_data[percentile_10_idx];
    
    // Average noise power: average of lowest 25% values
    uint32_t noise_sample_count = (uint32_t)(num_bins * 0.25);
    float noise_sum = 0.0f;
    for (uint32_t i = 0; i < noise_sample_count; i++) {
        noise_sum += sorted_data[i];
    }
    stats.avg_noise_power = noise_sum / noise_sample_count;
    
    // Peak signal: maximum value
    stats.peak_signal = sorted_data[num_bins - 1];
    
    // SNR: difference between peak and noise floor
    stats.snr = stats.peak_signal - stats.noise_floor;
    
    free(sorted_data);
    return stats;
}

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

// Function to initialize spec analyzer
int init_spec_analyzer(specAnalyzer_config_t* config, FrequencyScope scope) {
    log_message("Initializing spec analyzer config...\n");
    
    if (config == NULL) {
        log_message("Error: config is NULL\n");
        return -1;
    }

    int res = 0;
    long unsigned int channel_count = 0;
    PCMMGMT_CM_DS_CHANNEL ds_channel_stats = NULL;
    PCMMGMT_CM_US_CHANNEL us_channel_stats = NULL;

    if (scope == UPSTREAM) {
        docsis_GetNumOfActiveTxChannels(&channel_count);
        us_channel_stats = (PCMMGMT_CM_US_CHANNEL)malloc(sizeof(CMMGMT_CM_US_CHANNEL) * channel_count);
        memset(us_channel_stats, 0, sizeof(CMMGMT_CM_US_CHANNEL) * channel_count);
        res = docsis_GetUSChannel(&us_channel_stats);
        if (res != 0) {
            log_message("docsis_GetUSChannel failed with error code: %d\n", res);
            free(us_channel_stats);
            return -1;
        }
        
        // Find min and max frequencies from upstream channels
        unsigned long min_freq = ULONG_MAX;
        unsigned long max_freq = 0;
        
        for (unsigned long i = 0; i < channel_count; i++) {
            unsigned long freq = atol(us_channel_stats[i].Frequency);
            if (freq > 0) {  // Only consider valid frequencies
                if (freq < min_freq) {
                    min_freq = freq;
                }
                if (freq > max_freq) {
                    max_freq = freq;
                }
            }
        }
        
        config->startFreq = min_freq * 1000000;  // Convert MHz to Hz
        config->endFreq = max_freq * 1000000;    // Convert MHz to Hz
        log_message("Upstream frequency range: %llu - %llu Hz\n", config->startFreq, config->endFreq);
        
        free(us_channel_stats);
    } else if (scope == DOWNSTREAM) {
        docsis_GetNumOfActiveRxChannels(&channel_count);
        ds_channel_stats = (PCMMGMT_CM_DS_CHANNEL)malloc(sizeof(CMMGMT_CM_DS_CHANNEL) * channel_count);
        memset(ds_channel_stats, 0, sizeof(CMMGMT_CM_DS_CHANNEL) * channel_count);
        res = docsis_GetDSChannel(&ds_channel_stats);
        if (res != 0) {
            log_message("docsis_GetDSChannel failed with error code: %d\n", res);
            free(ds_channel_stats);
            return -1;
        }
        
        // Find min and max frequencies from downstream channels
        unsigned long min_freq = ULONG_MAX;
        unsigned long max_freq = 0;
        
        for (unsigned long i = 0; i < channel_count; i++) {
            unsigned long freq = atol(ds_channel_stats[i].Frequency);
            if (freq > 0) {  // Only consider valid frequencies
                if (freq < min_freq) {
                    min_freq = freq;
                }
                if (freq > max_freq) {
                    max_freq = freq;
                }
            }
        }
        
        config->startFreq = min_freq * 1000000;  // Convert MHz to Hz
        config->endFreq = max_freq * 1000000;    // Convert MHz to Hz
        log_message("Downstream frequency range: %llu - %llu Hz\n", config->startFreq, config->endFreq);
        
        free(ds_channel_stats);
    } else {
        log_message("Error: Invalid FrequencyScope\n");
        return -1;
    }
    
    config->freqSpan = 7.5 * 1000000; // Default freqSpan of 7.5 MHz in Hz
    config->fftSize = 256;

    log_message("Spec analyzer initialized successfully\n");
    
    return 0;
}

int collect_and_parse_spec_analyzer_data() {

    log_message("Setting Spec Analyzer parameters via SNMP...\n");
    v_secure_system("snmpset -v2c -c private  -m +DOCS-IF3-MIB 172.31.255.45 1.3.6.1.4.1.4491.2.1.20.1.34.3.0 u %llu", g_config->startFreq);
    v_secure_system("snmpset -v2c -c private  -m +DOCS-IF3-MIB 172.31.255.45 1.3.6.1.4.1.4491.2.1.20.1.34.4.0 u %llu", g_config->endFreq);
    v_secure_system("snmpset -v2c -c private  -m +DOCS-IF3-MIB 172.31.255.45 1.3.6.1.4.1.4491.2.1.20.1.34.5.0 u %llu", g_config->freqSpan);
    v_secure_system("snmpset -v2c -c private  -m +DOCS-IF3-MIB 172.31.255.45 1.3.6.1.4.1.4491.2.1.20.1.34.6.0 u %u", g_config->fftSize);


    log_message("Collecting Spec Analyzer data via SNMP...\n");
    v_secure_system("snmpset -v2c -c private  -m +DOCS-IF3-MIB 172.31.255.45 1.3.6.1.4.1.4491.2.1.20.1.34.1.0 i 1");
    
    // Use popen to capture snmpwalk output and parse on-the-fly
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "snmpwalk -v2c -c tpMupUaF5qqzrb4U -m +DOCS-IF3-MIB 172.31.255.45 1.3.6.1.4.1.4491.2.1.20.1.35");
    
    FILE *pipe = popen(cmd, "r");
    if (pipe == NULL) {
        log_message("Failed to execute snmpwalk command\n");
        return -1;
    }
    
    FILE *outfile = fopen(OUTPUT_FILE, "w");
    if (outfile == NULL) {
        log_message("Failed to open output file %s\n", OUTPUT_FILE);
        pclose(pipe);
        return -1;
    }
    
    char line[MAX_LINE_LEN];
    char *hex_block = (char *)malloc(MAX_HEX_BLOCK);
    if (hex_block == NULL) {
        log_message("Failed to allocate memory for hex_block\n");
        fclose(outfile);
        pclose(pipe);
        return -1;
    }
    
    int inside_hex = 0;
    hex_block[0] = '\0';
    
    PowerEntry power_entries[MAX_POWER_ENTRIES];
    int power_count = 0;
    int amplitude_count = 0;
    
    while (fgets(line, sizeof(line), pipe) != NULL) {
        // Parse TotalSegmentPower lines
        if (strstr(line, "docsIf3CmSpectrumAnalysisMeasTotalSegmentPower.")) {
            uint32_t freq;
            float power;
            if (sscanf(line, "DOCS-IF3-MIB::docsIf3CmSpectrumAnalysisMeasTotalSegmentPower.%u = INTEGER: %f", &freq, &power) == 2) {
                if (power_count < MAX_POWER_ENTRIES) {
                    power_entries[power_count].freq = freq;
                    power_entries[power_count].power = power;
                    power_count++;
                }
            }
        }
        
        if (strstr(line, "Hex-STRING:")) {
            // New Hex-STRING block found - parse previous block first
            if (inside_hex && strlen(hex_block) > 0) {
                uint8_t *bytes = (uint8_t *)malloc(100000);
                if (bytes != NULL) {
                    size_t byte_count = 0;
                    parse_hex_string(hex_block, bytes, &byte_count);

                    if (byte_count >= 20) {
                        uint32_t ChCenterFreq = read_uint32_be(&bytes[0]);
                        uint32_t FreqSpan     = read_uint32_be(&bytes[4]);
                        uint32_t NumberOfBins = read_uint32_be(&bytes[8]);
                        uint32_t BinSpacing   = read_uint32_be(&bytes[12]);
                        uint32_t ResolutionBW = read_uint32_be(&bytes[16]);

                        // Collect amplitude data
                        float *amplitude_data = (float *)malloc(NumberOfBins * sizeof(float));
                        if (amplitude_data != NULL) {
                            for (uint32_t i = 0; i < NumberOfBins && 20 + i * 2 + 1 < byte_count; i++) {
                                int16_t raw = read_int16_be(&bytes[20 + i * 2]);
                                amplitude_data[i] = raw / 100.0f;
                            }
                            
                            // Calculate noise statistics
                            NoiseStats noise_stats = calculate_noise_stats(amplitude_data, NumberOfBins);

                            fprintf(outfile, "%u,%u,%u,%u,%u:", ChCenterFreq, FreqSpan, NumberOfBins, BinSpacing, ResolutionBW);

                            for (uint32_t i = 0; i < NumberOfBins && 20 + i * 2 + 1 < byte_count; i++) {
                                fprintf(outfile, "%.2f", amplitude_data[i]);
                                if (i < NumberOfBins - 1 && 20 + (i + 1) * 2 + 1 < byte_count) {
                                    fprintf(outfile, ",");
                                }
                            }
                            fprintf(outfile, "\n");
                            
                            // Write noise statistics on separate line
                            fprintf(outfile, "NoiseStats:%u,NoiseFloor=%.2f,AvgNoise=%.2f,PeakSignal=%.2f,SNR=%.2f\n",
                                    ChCenterFreq, noise_stats.noise_floor, noise_stats.avg_noise_power,
                                    noise_stats.peak_signal, noise_stats.snr);
                            
                            free(amplitude_data);
                            amplitude_count++;
                        }
                    }
                    free(bytes);
                }
                hex_block[0] = '\0';
            }

            inside_hex = 1;
            char *start = strstr(line, "Hex-STRING:") + strlen("Hex-STRING:");
            strcat(hex_block, start);
        }
        else if (inside_hex && strstr(line, "DOCS-IF3-MIB::docsIf3CmSpectrumAnalysisMeasAmplitudeData.") == NULL) {
            strcat(hex_block, line);
        }
    }

    // Parse last block
    if (inside_hex && strlen(hex_block) > 0) {
        uint8_t *bytes = (uint8_t *)malloc(100000);
        if (bytes != NULL) {
            size_t byte_count = 0;
            parse_hex_string(hex_block, bytes, &byte_count);

            if (byte_count >= 20) {
                uint32_t ChCenterFreq = read_uint32_be(&bytes[0]);
                uint32_t FreqSpan     = read_uint32_be(&bytes[4]);
                uint32_t NumberOfBins = read_uint32_be(&bytes[8]);
                uint32_t BinSpacing   = read_uint32_be(&bytes[12]);
                uint32_t ResolutionBW = read_uint32_be(&bytes[16]);

                // Collect amplitude data
                float *amplitude_data = (float *)malloc(NumberOfBins * sizeof(float));
                if (amplitude_data != NULL) {
                    for (uint32_t i = 0; i < NumberOfBins && 20 + i * 2 + 1 < byte_count; i++) {
                        int16_t raw = read_int16_be(&bytes[20 + i * 2]);
                        amplitude_data[i] = raw / 100.0f;
                    }
                    
                    // Calculate noise statistics
                    NoiseStats noise_stats = calculate_noise_stats(amplitude_data, NumberOfBins);

                    fprintf(outfile, "%u,%u,%u,%u,%u:", ChCenterFreq, FreqSpan, NumberOfBins, BinSpacing, ResolutionBW);

                    for (uint32_t i = 0; i < NumberOfBins && 20 + i * 2 + 1 < byte_count; i++) {
                        fprintf(outfile, "%.2f", amplitude_data[i]);
                        if (i < NumberOfBins - 1 && 20 + (i + 1) * 2 + 1 < byte_count) {
                            fprintf(outfile, ",");
                        }
                    }
                    fprintf(outfile, "\n");
                    
                    // Write noise statistics on separate line
                    fprintf(outfile, "NoiseStats:%u,NoiseFloor=%.2f,AvgNoise=%.2f,PeakSignal=%.2f,SNR=%.2f\n",
                            ChCenterFreq, noise_stats.noise_floor, noise_stats.avg_noise_power,
                            noise_stats.peak_signal, noise_stats.snr);
                    
                    free(amplitude_data);
                    amplitude_count++;
                }
            }
            free(bytes);
        }
    }
    
    // Write TotalSegmentPower data
    if (power_count > 0) {
        fprintf(outfile, "\nTotalSegmentPower:\n");
        for (int i = 0; i < power_count; i++) {
            fprintf(outfile, "%u,%.1f\n", power_entries[i].freq, power_entries[i].power);
        }
    }
    
    free(hex_block);
    fclose(outfile);
    int status = pclose(pipe);
    
    if (status != 0) {
        log_message("snmpwalk command failed with status %d\n", status);
        return -1;
    }

    log_message("Parsed %d amplitude entries and %d power entries\n", amplitude_count, power_count);
    log_message("Spectrum Analyzer data stored in %s\n", OUTPUT_FILE);

    return 0;
}

int main() {
    
    log_message("Spec Analyzer initialized successfully.\n");
    log_message("Initializing Spec Analyzer data...\n");

    g_config = (specAnalyzer_config_t *)malloc(sizeof(specAnalyzer_config_t));
    if (g_config == NULL) {
        log_message("Failed to allocate memory for config\n");
        return -1;
    }
    
    memset(g_config, 0, sizeof(specAnalyzer_config_t));
    
    if (init_spec_analyzer(g_config, DOWNSTREAM) != 0) {
        log_message("Failed to initialize spec analyzer\n");
        free(g_config);
        return -1;
    }

    if (collect_and_parse_spec_analyzer_data() != 0) {
        log_message("Failed to collect spec analyzer data\n");
        free(g_config);
        return -1;
    }
    
    log_message("Spec Analyzer configuration: StartFreq=%llu Hz, EndFreq=%llu Hz,  FreqSpan=%llu Hz, FFTSize=%u\n",
                (unsigned long long)g_config->startFreq, (unsigned long long)g_config->endFreq, (unsigned long long)g_config->freqSpan, g_config->fftSize);
    free(g_config);

    return 0;
}