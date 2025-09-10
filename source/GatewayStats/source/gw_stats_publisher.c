#include <limits.h>
#include <stdio.h>
#include <zlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "mosqev.h"

#include "gateway_stats.h"
#include "gateway_stats.pb-c.h"
#include <openssl_config_lib.h>

#define HOST_NAME_MAX 64 

#define STATS_MQTT_PORT         8883
#define STATS_MQTT_QOS          0
#define STATS_MQTT_INTERVAL     60  /* Report interval in seconds */
#define STATS_MQTT_RECONNECT    60  /* Reconnect interval -- seconds */

static mosqev_t         gw_stats_mqtt;
static bool             gw_stats_mosquitto_init = false;
static bool             gw_stats_mosqev_init = false;


// static int64_t          gw_stats_mqtt_reconnect_ts = 0;
// static char             gw_stats_mqtt_broker[HOST_NAME_MAX];
// static char             gw_stats_mqtt_topic[HOST_NAME_MAX];
// static int              gw_stats_mqtt_port = STATS_MQTT_PORT;
// static int              gw_stats_mqtt_qos = STATS_MQTT_QOS;

struct mqtt_local_client {
    struct mosquitto *mosq;
    bool is_connected;
    struct ev_timer mosq_loop_timer;
    ev_tstamp mosq_loop_wake_interval;
} g_local_mqtt_client;

#define MQTT_LOCAL_MQTT_CLIENT_LOOP_WAKE_MIN_TIME 3
#define MQTT_LOCAL_MQTT_CLIENT_LOOP_WAKE_MAX_TIME 60
#define MQTT_LOCAL_MQTT_BROKER_IP_ADDR "192.168.245.254"
#define MQTT_LOCAL_MQTT_BROKER_PORT_VAL 1883
#define MQTT_LOCAL_MQTT_BROKER_KEEPALIVE 3600
#define MQTT_LOCAL_MQTT_CLIENT_LOOP_TIMEOUT_MS 1000
#define MQTT_GATEWAY_STATS_TOPIC "local/gateway_stats"
#define MQTT_FILE_PATH "/tmp/mqtt_broker"
#define DEFAULT_CA_CERT "/etc/ssl/certs/ca-certificates.crt"
#define MAX_IP_LENGTH 16
char mqtt_broker_ip[MAX_IP_LENGTH] = MQTT_LOCAL_MQTT_BROKER_IP_ADDR;
int mqtt_port = MQTT_LOCAL_MQTT_BROKER_PORT_VAL;

bool gw_stats_mqtt_is_connected()
{
    return mosqev_is_connected(&gw_stats_mqtt);
}

void gw_stats_mqtt_local_cleanup()
{
    struct mosquitto *mosq = g_local_mqtt_client.mosq;

    if (mosq != NULL)
    {
        mosquitto_disconnect(mosq);
        mosquitto_destroy(mosq);
    }
}
void gw_stats_mqtt_stop(void)
{
    if (gw_stats_mosqev_init) mosqev_del(&gw_stats_mqtt);
    gw_stats_mqtt_local_cleanup();

    if (gw_stats_mosquitto_init) mosquitto_lib_cleanup();

    gw_stats_mosqev_init = gw_stats_mosquitto_init = false;

    log_message("[MQTT] %s: Closing MQTT connection\n", __FUNCTION__);
}

void gw_stats_mqtt_local_publish(struct mosquitto *mosq, void *userdata, int mid)
{
    UNREFERENCED_PARAMETER(mosq);
    UNREFERENCED_PARAMETER(userdata);
    UNREFERENCED_PARAMETER(mid);
    log_message("[MQTT] %s: Message published\n", __FUNCTION__);
}

void  gw_stats_mqtt_local_publish_data(long mlen,void *mbuf)
{
    log_message("[MQTT] %s: Published %ld bytes - before compressing\n", __FUNCTION__, mlen);

    int mid;
    log_message("[MQTT] %s: About to publish to local broker\n", __FUNCTION__);
    if (mosquitto_publish(g_local_mqtt_client.mosq, &mid, MQTT_GATEWAY_STATS_TOPIC, mlen, mbuf, 0, false) != MOSQ_ERR_SUCCESS)
    {
        log_message("[MQTT] %s: MQTT stats publish failed to local broker\n", __FUNCTION__);
    }
}

void gw_stats_mqtt_client_loop_timer_handler(struct ev_loop *loop, ev_timer *timer, int revents)
{
    (void)revents;
    UNREFERENCED_PARAMETER(loop);

    int rc = 1;
    struct mqtt_local_client *local_mqtt_client = (struct mqtt_local_client *) timer->data;

    log_message("[MQTT] %s: Timer fired\n", __FUNCTION__);

    rc = mosquitto_loop(local_mqtt_client->mosq, MQTT_LOCAL_MQTT_CLIENT_LOOP_TIMEOUT_MS, 1);
    if (rc != MOSQ_ERR_SUCCESS)
    {
        log_message("[MQTT] %s: mosquitto_loop error\n", __FUNCTION__);
        if (rc == MOSQ_ERR_NO_CONN || rc == MOSQ_ERR_CONN_LOST)
        {
            log_message("[MQTT] %s: Trying reconnecting to mosquitto local broker[%s:%d]\n",
                __FUNCTION__, mqtt_broker_ip, mqtt_port);

            rc = mosquitto_reconnect(local_mqtt_client->mosq);
            if (rc != MOSQ_ERR_SUCCESS)
            {
                if (local_mqtt_client->mosq_loop_wake_interval * 2 > MQTT_LOCAL_MQTT_CLIENT_LOOP_WAKE_MAX_TIME)
                    local_mqtt_client->mosq_loop_wake_interval = MQTT_LOCAL_MQTT_CLIENT_LOOP_WAKE_MAX_TIME;
                else
                    local_mqtt_client->mosq_loop_wake_interval *= 2;

                log_message("[MQTT] %s: Failed to connect to local MQTT broker[%s:%d], error: %s; Will try again in %f seconds\n",
                    __FUNCTION__, mqtt_broker_ip, mqtt_port,
                    (rc == MOSQ_ERR_ERRNO) ? strerror(rc) : mosquitto_strerror(rc),
                    local_mqtt_client->mosq_loop_wake_interval);
                g_local_mqtt_client.is_connected = false;
            }
            else
                g_local_mqtt_client.is_connected = true;
        }
    } else {
        local_mqtt_client->mosq_loop_wake_interval = MQTT_LOCAL_MQTT_CLIENT_LOOP_WAKE_MIN_TIME;
    }

    local_mqtt_client->mosq_loop_timer.repeat = local_mqtt_client->mosq_loop_wake_interval;
    ev_timer_again(EV_DEFAULT, &local_mqtt_client->mosq_loop_timer);
}

bool gw_stats_local_mqtt_client_init()
{
    bool clean_session = true;
    struct mosquitto *mosq = NULL;
    struct ev_timer *mosq_loop_timer = &g_local_mqtt_client.mosq_loop_timer;
    ev_tstamp mosq_loop_wake_interval = 0;

    mosq = mosquitto_new(NULL, clean_session, NULL);
    if (!mosq) {
        log_message("[MQTT] %s: Error in creating mosquitto object\n", __FUNCTION__);
        return false;
    }

    g_local_mqtt_client.mosq = mosq;

    log_message("[MQTT] %s: Created mosquitto object\n", __FUNCTION__);

    if (mosquitto_connect(mosq, mqtt_broker_ip, mqtt_port, MQTT_LOCAL_MQTT_BROKER_KEEPALIVE) != MOSQ_ERR_SUCCESS) {
        log_message("[MQTT] %s: Unable to connect to MQTT broker[%s:%d]", __FUNCTION__, mqtt_broker_ip, mqtt_port);
        g_local_mqtt_client.is_connected = false;
    }
    else {
        log_message("[MQTT] %s: Connected to MQTT broker[%s:%d]", __FUNCTION__, mqtt_broker_ip, mqtt_port);
        g_local_mqtt_client.is_connected = true;
    }

    mosquitto_publish_callback_set(mosq, gw_stats_mqtt_local_publish);

    g_local_mqtt_client.mosq_loop_wake_interval = MQTT_LOCAL_MQTT_CLIENT_LOOP_WAKE_MIN_TIME;
    mosq_loop_wake_interval = g_local_mqtt_client.mosq_loop_wake_interval;

    ev_timer_init(mosq_loop_timer, gw_stats_mqtt_client_loop_timer_handler, mosq_loop_wake_interval, mosq_loop_wake_interval);
    mosq_loop_timer->data = &g_local_mqtt_client;
    ev_timer_start(EV_DEFAULT, mosq_loop_timer);

    return true;
}

bool gw_stats_mqtt_init(void)
{
    mosquitto_lib_init();
    gw_stats_mosquitto_init = true;

    log_message("[MQTT] %s: Initializing MQTT library\n", __FUNCTION__);

    char cmac[64];
    get_cmac_address(cmac, sizeof(cmac));

    if (!mosqev_init(&gw_stats_mqtt, cmac, EV_DEFAULT, NULL))
    {
        log_message("[MQTT] %s: Error in mosqev_init\n", __FUNCTION__);
        goto error;
    }

    if (!gw_stats_local_mqtt_client_init())
    {
        log_message("[MQTT] %s: Failed to init gw_stats_local_mqtt_client_init\n", __FUNCTION__);
        goto error;
    }

    gw_stats_mosqev_init = true;

    return true;

error:
    gw_stats_mqtt_stop();

    return false;
}