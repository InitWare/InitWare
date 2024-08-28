#pragma once

/***
  This file is part of systemd.

  Copyright 2014 Tom Gundersen

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <stdint.h>

static inline uint16_t unaligned_read_ne16(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) { uint16_t x; } *u = _u;

        return u->x;
}

static inline uint32_t unaligned_read_ne32(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) { uint32_t x; } *u = _u;

        return u->x;
}

static inline uint64_t unaligned_read_ne64(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) { uint64_t x; } *u = _u;

        return u->x;
}

static inline void unaligned_write_ne16(void *_u, uint16_t a) {
        struct __attribute__((__packed__, __may_alias__)) { uint16_t x; } *u = _u;

        u->x = a;
}

static inline void unaligned_write_ne32(void *_u, uint32_t a) {
        struct __attribute__((__packed__, __may_alias__)) { uint32_t x; } *u = _u;

        u->x = a;
}

static inline void unaligned_write_ne64(void *_u, uint64_t a) {
        struct __attribute__((__packed__, __may_alias__)) { uint64_t x; } *u = _u;

        u->x = a;
}

static inline uint16_t
unaligned_read_be16(const void *_u)
{
	const uint8_t *u = _u;

	return (((uint16_t)u[0]) << 8) | ((uint16_t)u[1]);
}

static inline uint32_t
unaligned_read_be32(const void *_u)
{
	const uint8_t *u = _u;

	return (((uint32_t)unaligned_read_be16(u)) << 16) |
		((uint32_t)unaligned_read_be16(u + 2));
}

static inline uint64_t
unaligned_read_be64(const void *_u)
{
	const uint8_t *u = _u;

	return (((uint64_t)unaligned_read_be32(u)) << 32) |
		((uint64_t)unaligned_read_be32(u + 4));
}

static inline void
unaligned_write_be16(void *_u, uint16_t a)
{
	uint8_t *u = _u;

	u[0] = (uint8_t)(a >> 8);
	u[1] = (uint8_t)a;
}

static inline void
unaligned_write_be32(void *_u, uint32_t a)
{
	uint8_t *u = _u;

	unaligned_write_be16(u, (uint16_t)(a >> 16));
	unaligned_write_be16(u + 2, (uint16_t)a);
}

static inline void
unaligned_write_be64(void *_u, uint64_t a)
{
	uint8_t *u = _u;

	unaligned_write_be32(u, (uint32_t)(a >> 32));
	unaligned_write_be32(u + 4, (uint32_t)a);
}

static inline uint16_t unaligned_read_le16(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) { uint16_t x; } *u = _u;

        return le16toh(u->x);
}

static inline uint32_t unaligned_read_le32(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) { uint32_t x; } *u = _u;

        return le32toh(u->x);
}

static inline uint64_t unaligned_read_le64(const void *_u) {
        const struct __attribute__((__packed__, __may_alias__)) { uint64_t x; } *u = _u;

        return le64toh(u->x);
}

static inline void unaligned_write_le16(void *_u, uint16_t a) {
        struct __attribute__((__packed__, __may_alias__)) { uint16_t x; } *u = _u;

        u->x = le16toh(a);
}

static inline void unaligned_write_le32(void *_u, uint32_t a) {
        struct __attribute__((__packed__, __may_alias__)) { uint32_t x; } *u = _u;

        u->x = le32toh(a);
}

static inline void unaligned_write_le64(void *_u, uint64_t a) {
        struct __attribute__((__packed__, __may_alias__)) { uint64_t x; } *u = _u;

        u->x = le64toh(a);
}
