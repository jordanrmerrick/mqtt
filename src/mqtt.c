#include <stdlib.h>
#include <string.h>

#include "mqtt.h"
#include "pack.h"

// #define MAX_LEN_BYTES 4;
static const int MAX_LEN_BYTES = 4;

static size_t unpack_mqtt_connect(const unsigned char*, union mqtt_header*, union mqtt_packet*);
static size_t unpack_mqtt_publish(const unsigned char*, union mqtt_header*, union mqtt_packet*);
static size_t unpack_mqtt_subscribe(const unsigned char*, union mqtt_header*, union mqtt_packet*);
static size_t unpack_mqtt_unsubscribe(const unsigned char*, union mqtt_header*, union mqtt_packet*);
static size_t unpack_mqtt_ack(const unsigned char*, union mqtt_header*, union mqtt_packet*);

static unsigned char *pack_mqtt_header(const union mqtt_header*);
static unsigned char *pack_mqtt_ack(const union mqtt_packet*);
static unsigned char *pack_mqtt_connack(const union mqtt_packet*);
static unsigned char *pack_mqtt_suback(const union mqtt_packet*);
static unsigned char *pack_mqtt_publish(const union mqtt_packet*);

int mqtt_encode_length(unsigned char *buf, size_t len) {
    int bytes = 0;
    do {
        if (bytes + 1 > MAX_LEN_BYTES)
            return bytes;

        short rem = len % 128;
        len /= 128;

        if (len > 0)
            rem |= 128;

        buf[bytes++] = rem;
    } while (len > 0);

    return bytes;
}

unsigned long long mqtt_decode_length(const unsigned char **buf) {
    char c;
    int multiplier = 1;
    unsigned long long value = 0LL;

    do {
        c = **buf;
        value += (c & 127) * multiplier;
        multiplier *= 128;
        (*buf)++;
    } while ((c & 128) != 0);

    return value;
}

static size_t unpack_mqtt_connect(unsigned char *buf, union mqtt_header *header, union mqtt_packet *packet) {
    struct mqtt_connect connect = { .header = *header};
    packet->connect = connect;
    const unsigned char *init = buf;

    size_t len = mqtt_decode_length(&buf);

    buf = init + 8;

    packet->connect.byte = unpack_u8((const uint8_t**) &buf);
    packet->connect.payload.keep_alive = unpack_u16((const uint8_t**) &buf);

    uint16_t cid_len = unpack_u16((const uint8_t**) &buf);

    // Client ID
    if (cid_len > 0) {
        packet->connect.payload.client_id = malloc(cid_len + 1);
        unpack_bytes((const uint8_t**) &buf, cid_len, packet->connect.payload.client_id);
    }

    // Topic & Msg IF will topic set in flags
    if (packet->connect.bits.will == 1) {
        unpack_string16(&buf, &packet->connect.payload.will_topic);
        unpack_string16(&buf, &packet->connect.payload.will_message);
    }

    // Username IF username set in flags
    if (packet->connect.bits.username == 1)
        unpack_string16(&buf, &packet->connect.payload.username);

    // Password IF password set in flags
    if (packet->connect.bits.password == 1)
        unpack_string16(&buf, &packet->connect.payload.password);

    return len;
}

static size_t unpack_mqtt_publish(const unsigned char *buf, union mqtt_header *header, union mqtt_header *packet) {

    struct mqtt_publish publish = { .header = *header};
    packet->publish = publish;

    size_t len = mqtt_decode_length(&buf);

    packet->publish.topiclen = unpack_string16(&buf, &packet->publish.topic);

    uint16_t message_len = len;

    if (publish.header.bits.qos > AT_MOST_ONCE) {
        packet->publish.pkt_id = unpack_u16((const uint8_t**) &buf);
        message_len -= sizeof(uint16_t);
    }

    message_len -= (sizeof(uint16_t) + topic_len);
    packet->publish.payloadlen = message_len;
    packet->publish.payload = malloc(message_len + 1);

    unpack_bytes((const uint8_t**) &buf, message_len, packet->publish.payload);
    return len;
}

static size_t unpack_mqtt_subscribe(const unsigned char *buf, union mqtt_header *header, union mqtt_header *packet) {
    struct mqtt_subscribe subscribe { .header = *header };

    size_t len = mqtt_decode_length(&buf);

    size_t remaining_bytes = len;

    subscribe.pkt_id = unpack_u16((const uint8_t**) &buf);
    remaining_bytes -= sizeof(uint16_t);

    int i=0;
    while (remaining_bytes > 0) {
        remaining_bytes -= sizeof(uint16_t);

        // More tuples will come in, allocate more memory
        subscribe.tuples = realloc(subscribe.tuples, (i+1) * sizeof(*subscribe.tuples));

        subscribe.tuples[i].topic_len = unpack_string16(&buf, &subscribe.tuples[i].topic);
        remaining_bytes -= subscribe.tuples[i].topic_len;

        subscribe.tuples[i].qos = unpack_u8((const uint8_t**) &buf);
        len -= sizeof(uint8_t);
        i++;
    }

    subscribe.tuples_len = i;
    packet->subscribe = subscribe;
    return len;
}