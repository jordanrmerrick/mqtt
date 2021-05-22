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

static size_t unpack_mqtt_unsubscribe(const unsigned char *buf, union mqtt_header *header, union mqtt_packet *packet) {
    struct mqtt_unsubscribe unsubscribe = { .header = *header };

    size_t len = mqtt_decode_length(&buf);
    size_t remaining_bytes = len;

    unsubscribe.pkt_id = unpack_u16((const uint8_t**) &buf);
    remaining_bytes -= sizeof(uint16_t);

    int i = 0;
    while (remaining_bytes > 0) {
        remaining_bytes -= sizeof(uint16_t);

        unsubscribe.tuples = realloc(unsubscribe.tuples, (i + 1) * sizeof(*unsubscribe.tuples));

        unsubscribe.tuples[i].topic_len = unpack_u16(&buf, &unsubscribe.tuples[i].topic);
        remaining_bytes -= unsubscribe.tuples[i].topic_len;

        i++;
    }
    unsubscribe.tuples_len = i;

    packet->unsubscribe = unsubscribe;
    return len;
}

static size_t unpack_mqtt_ack(const unsigned char *buf, union mqtt_header *header, union mqtt_packet *packet) {
    struct mqtt_ack ack = { .header = *header };

    size_t len = mqtt_decode_length(&buf);
    ack.pkt_id = unpack_u16((const uint8_t**) &buf);
    packet->ack = ack;

    return len;
}

typedef size_t mqtt_unpack_handler(const unsigned char *, union mqtt_header, union mqtt_packet);

static mqtt_unpack_handler *unpack_handlers[11] = {
        NULL,
        unpack_mqtt_connect,
        NULL,
        unpack_mqtt_publish,
        unpack_mqtt_ack,
        unpack_mqtt_ack,
        unpack_mqtt_ack,
        unpack_mqtt_ack,
        unpack_mqtt_subscribe,
        NULL,
        unpack_mqtt_unsubscribe
};

int unpack_mqtt_packet(const unsigned char *buf, union mqtt_packet *packet) {
    int r = 0;

    unsigned char type = *buf;
    union mqtt_header header = { .byte = type };

    if (header.bits.type == DISCONNECT || header.bits.type == PINGREQ || header.bits.type == PINGRESP)
        packet->header = header;
    else
        r = unpack_handlers[header.bits.type](++buf, &header, packet);

    return r;
}

union mqtt_header *mqtt_packet_header(unsigned char byte) {
    static union mqtt_header header;

    header.byte = byte;
    return &header;
}

struct mqtt_ack *mqtt_packet_ack(unsigned char byte, unsigned short packet_id) {
    static struct mqtt_ack ack;
    ack.header.byte = byte;
    ack.pkt_id = packet_id;

    return &ack;
}

struct mqtt_connack *mqtt_packet_connack(unsigned char byte, unsigned char cflags, unsigned char rc) {
    static struct mqtt_connack connack;
    connack.header.byte = byte;
    connack.byte = cflags;
    connack.rc = rc;

    return &connack;
}

struct mqtt_suback *mqtt_packet_suback(unsigned char byte, unsigned short packet_id, unsigned char *rcs, unsigned short rcslen) {
    struct mqtt_suback *suback = malloc(sizeof(*suback));

    suback->header.byte = byte;
    suback->pkt_id = packet_id;

    suback->rcslen = rcslen;

    suback->rcs = malloc(rcslen);
    memcpy(suback->rcs, rcs, rcslen);

    return suback;
}

struct mqtt_publish *mqtt_packet_publish(unsigned char byte, unsigned short packet_id, size_t topic_len, unsigned char *topic, size_t payload_len, unsigned char *payload) {
    struct mqtt_publish *publish = malloc(sizeof(*publish));

    publish->header.byte = byte;
    publish->pkt_id = packet_id;

    publish->topic_len = topic_len;
    publish->payload_len = payload_len;

    publish->topic = topic;
    publish->payload = payload;
}

