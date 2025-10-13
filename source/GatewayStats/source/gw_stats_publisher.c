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

    // Debug: Log data being published
    log_message("[MQTT] %s: About to publish %ld bytes\n", __FUNCTION__, data_len);
    if (data && data_len > 0) {
        uint8_t *debug_buf = (uint8_t*)data;
        log_message("[MQTT] %s: First 16 bytes being published: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x\n",
                    __FUNCTION__,
                    debug_buf[0], debug_buf[1], debug_buf[2], debug_buf[3],
                    debug_buf[4], debug_buf[5], debug_buf[6], debug_buf[7],
                    debug_buf[8], debug_buf[9], debug_buf[10], debug_buf[11],
                    debug_buf[12], debug_buf[13], debug_buf[14], debug_buf[15]);

        // Debug: Analyze protobuf structure being published
        unsigned int field_number = (debug_buf[0]) >> 3;
        unsigned int wire_type = (debug_buf[0]) & 0x07;
        log_message("[MQTT] %s: Publishing - First field number: %u, wire type: %u\n", __FUNCTION__, field_number, wire_type);
    } else {
        log_message("[MQTT] %s: ERROR - Invalid data pointer or length: data=%p, data_len=%ld\n", __FUNCTION__, data, data_len);
    }

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
