#include <stdlib.h>
#include <string.h>
#include "pack.h"

#ifdef _WIN32
#include <winsock.h>
#endif

#ifdef linux
#include <arpa/inet.h>
#endif



uint8_t unpack_u8(const uint8_t **buf) {
    uint8_t val = **buf;
    (*buf)++;
    return val;
}

uint16_t unpack_u16(const uint8_t **buf) {
    uint16_t val;
    memcpy(&val, *buf, sizeof(uint16_t));
    (*buf) += sizeof(uint16_t);
    return ntohs(val);
}

uint32_t unpack_u32(const uint8_t **buf) {
    uint32_t val;
    memcpy(&val, *buf, sizeof(uint32_t));
    (*buf) += sizeof(uint32_t);
    return ntohl(val);
}

uint8_t *unpack_bytes(const uint8_t **buf, size_t len, uint8_t *str) {
    memcpy(str, *buf, len);
    str[len] = '\0';
    (*buf) += len;
    return str;
}

uint16_t unpack_string16(uint8_t **buf, uint8_t **dest) {
    uint16_t len = unpack_u16(buf);
    *dest = malloc(len + 1);
    *dest = unpack_bytes(buf, len, *dest);
    return len;
}

