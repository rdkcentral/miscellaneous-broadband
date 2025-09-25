#include <stdio.h>
#include <mosquitto.h>
#include "gateway_stats.h"
#include "gateway_stats.pb-c.h"

#define MQTT_LOCAL_MQTT_BROKER_IP_ADDR "192.168.245.254"
#define MQTT_LOCAL_MQTT_BROKER_PORT_VAL 1883
// #define MQTT_GATEWAY_STATS_TOPIC  "local/device_optimizer_stats"
#define MQTT_GATEWAY_STATS_TOPIC "local/gateway_stats"

bool gw_stats_publish_data(void *data, long data_len) {
    int rc, mid;
    struct mosquitto *mosq = NULL;

    log_message("[MQTT] %s: Initializing MQTT library\n", __FUNCTION__);
    mosquitto_lib_init();

    mosq = mosquitto_new(NULL, true, NULL);
    if (!mosq) {
        log_message("[MQTT] %s: Error in creating mosquitto object\n", __FUNCTION__);
        return false;
    }

    rc = mosquitto_connect(mosq, MQTT_LOCAL_MQTT_BROKER_IP_ADDR, MQTT_LOCAL_MQTT_BROKER_PORT_VAL, 60);
    if(rc != MOSQ_ERR_SUCCESS){
        log_message("[MQTT] %s: Could not connect to broker[%s:%d], Error: %s\n", __FUNCTION__, MQTT_LOCAL_MQTT_BROKER_IP_ADDR, MQTT_LOCAL_MQTT_BROKER_PORT_VAL, mosquitto_strerror(rc));
        mosquitto_destroy(mosq);
        mosquitto_lib_cleanup();
        return false;
    }
    log_message("[MQTT] %s: Connected to MQTT broker[%s:%d]\n", __FUNCTION__, MQTT_LOCAL_MQTT_BROKER_IP_ADDR, MQTT_LOCAL_MQTT_BROKER_PORT_VAL);

    if (mosquitto_publish(mosq, &mid, MQTT_GATEWAY_STATS_TOPIC, data_len, data, 0, false) != MOSQ_ERR_SUCCESS)
    {
        log_message("[MQTT] %s: MQTT stats publish failed to local broker\n", __FUNCTION__);
    }
    log_message("[MQTT] %s: Published %ld bytes to topic: %s\n", __FUNCTION__, data_len, MQTT_GATEWAY_STATS_TOPIC);

    // Give some time to ensure message is sent
    mosquitto_loop(mosq, -1, 1);

    // Cleanup
    mosquitto_disconnect(mosq);
    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();

    return true;
}
