#ifndef GW_STATS_MQTT_ENCODER_H_
#define GW_STATS_MQTT_ENCODER_H_

#include "gateway_stats.h"

void* encode_report(gw_stats_report *rpt, size_t *buff_len);


#endif /* GW_STATS_MQTT_ENCODER_H_ */
