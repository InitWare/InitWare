/* SPDX-License-Identifier: LGPL-2.1-or-later */

#pragma once

#include <stddef.h>
#include <stdint.h>

#include "string-util.h"

#define SHA256_DIGEST_SIZE 32

struct sha256_ctx {
        uint32_t H[8];

        union {
                uint64_t total64;
#define TOTAL64_low (1 - (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__))
#define TOTAL64_high (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
                uint32_t total[2];
        };

        uint32_t buflen;

        union {
                uint8_t  buffer[128]; /* NB: always correctly aligned for UINT32.  */
                uint32_t buffer32[32];
                uint64_t buffer64[16];
        };
};

void sha256_init_ctx(struct sha256_ctx *ctx);
uint8_t *sha256_finish_ctx(struct sha256_ctx *ctx, uint8_t resbuf[static SHA256_DIGEST_SIZE]);
void sha256_process_bytes(const void *buffer, size_t len, struct sha256_ctx *ctx);

static inline void sha256_process_bytes_and_size(const void *buffer, size_t len, struct sha256_ctx *ctx) {
        sha256_process_bytes(&len, sizeof(len), ctx);
        sha256_process_bytes(buffer, len, ctx);
}

uint8_t* sha256_direct(const void *buffer, size_t sz, uint8_t result[static SHA256_DIGEST_SIZE]);

#define SHA256_DIRECT(buffer, sz) sha256_direct(buffer, sz, (uint8_t[SHA256_DIGEST_SIZE]) {})

int sha256_fd(int fd, uint64_t max_size, uint8_t ret[static SHA256_DIGEST_SIZE]);

int parse_sha256(const char *s, uint8_t res[static SHA256_DIGEST_SIZE]);

static inline bool sha256_is_valid(const char *s) {
        return s && in_charset(s, HEXDIGITS) && (strlen(s) == SHA256_DIGEST_SIZE * 2);
}
