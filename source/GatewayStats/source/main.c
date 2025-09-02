#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "cJSON.h"

#include "gateway_stats.h"

int main() {
    printf("Starting Gateway statistics collection...\n");

    gw_stats_init();
    gw_stats_collect();
    gw_stats_save();

    gw_stats_deInit();
    printf("Gateway statistics collection completed.\n");
    return 0;
}
