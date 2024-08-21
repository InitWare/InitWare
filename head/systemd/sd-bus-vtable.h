#ifndef foosdbusvtablehfoo
#define foosdbusvtablehfoo

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

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

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

typedef struct sd_bus_vtable sd_bus_vtable;

#include "sd-bus.h"

enum {
	_SD_BUS_VTABLE_START = '<',
	_SD_BUS_VTABLE_END = '>',
	_SD_BUS_VTABLE_METHOD = 'M',
	_SD_BUS_VTABLE_SIGNAL = 'S',
	_SD_BUS_VTABLE_PROPERTY = 'P',
	_SD_BUS_VTABLE_WRITABLE_PROPERTY = 'W',
};

__extension__ enum {
        SD_BUS_VTABLE_DEPRECATED                   = 1ULL << 0,
        SD_BUS_VTABLE_HIDDEN                       = 1ULL << 1,
        SD_BUS_VTABLE_UNPRIVILEGED                 = 1ULL << 2,
        SD_BUS_VTABLE_METHOD_NO_REPLY              = 1ULL << 3,
        SD_BUS_VTABLE_PROPERTY_CONST               = 1ULL << 4,
        SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE        = 1ULL << 5,
        SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION  = 1ULL << 6,
        SD_BUS_VTABLE_PROPERTY_EXPLICIT            = 1ULL << 7,
        SD_BUS_VTABLE_SENSITIVE                    = 1ULL << 8, /* covers both directions: method call + reply */
        SD_BUS_VTABLE_ABSOLUTE_OFFSET              = 1ULL << 9,
        _SD_BUS_VTABLE_CAPABILITY_MASK             = 0xFFFFULL << 40
};

#define SD_BUS_VTABLE_CAPABILITY(x) ((uint64_t)(((x) + 1) & 0xFFFF) << 40)

/* Note: unused areas in the sd_bus_vtable[] array must be initialized to 0. The structure contains an embedded
 * union, and the compiler is NOT required to initialize the unused areas of the union when the rest of the
 * structure is initialized. Normally the array is defined as read-only data, in which case the linker places
 * it in the BSS section, which is always fully initialized, so this is not a concern. But if the array is
 * created on the stack or on the heap, care must be taken to initialize the unused areas, for examply by
 * first memsetting the whole region to zero before filling the data in. */

struct sd_bus_vtable {
        /* Please do not initialize this structure directly, use the
         * macros below instead */

        __extension__ uint8_t type:8;
        __extension__ uint64_t flags:56;
        union {
                struct {
                        size_t element_size;
                        uint64_t features;
                        const unsigned *vtable_format_reference;
                } start;
                struct {
                        /* This field exists only to make sure we have something to initialize in
                         * SD_BUS_VTABLE_END in a way that is both compatible with pedantic versions of C and
                         * C++. It's unused otherwise. */
                        size_t _reserved;
                } end;
                struct {
                        const char *member;
                        const char *signature;
                        const char *result;
                        sd_bus_message_handler_t handler;
                        size_t offset;
                        const char *names;
                } method;
                struct {
                        const char *member;
                        const char *signature;
                        const char *names;
                } signal;
                struct {
                        const char *member;
                        const char *signature;
                        sd_bus_property_get_t get;
                        sd_bus_property_set_t set;
                        size_t offset;
                } property;
        } x;
};;

#define SD_BUS_VTABLE_START(_flags)                                     \
        {                                                               \
                .type = _SD_BUS_VTABLE_START,                           \
                .flags = _flags,                                        \
                .x = {                                                  \
                        .start = {                                      \
                                .element_size = sizeof(sd_bus_vtable),  \
                                .features = _SD_BUS_VTABLE_PARAM_NAMES, \
                                .vtable_format_reference = &sd_bus_object_vtable_format, \
                        },                                              \
                },                                                      \
        }

/* helper macro to format method and signal parameters, one at a time */
#define SD_BUS_PARAM(x) #x "\0"

#define SD_BUS_METHOD_WITH_NAMES_OFFSET(_member, _signature, _in_names, _result, _out_names, _handler, _offset, _flags)  \
        {                                                               \
                .type = _SD_BUS_VTABLE_METHOD,                          \
                .flags = _flags,                                        \
                .x = {                                                  \
                        .method = {                                     \
                                .member = _member,                      \
                                .signature = _signature,                \
                                .result = _result,                      \
                                .handler = _handler,                    \
                                .offset = _offset,                      \
                                .names = _in_names _out_names,          \
                        },                                              \
                },                                                      \
        }
#define SD_BUS_METHOD_WITH_OFFSET(_member, _signature, _result, _handler, _offset, _flags)   \
        SD_BUS_METHOD_WITH_NAMES_OFFSET(_member, _signature, "", _result, "", _handler, _offset, _flags)
#define SD_BUS_METHOD_WITH_NAMES(_member, _signature, _in_names, _result, _out_names, _handler, _flags)   \
        SD_BUS_METHOD_WITH_NAMES_OFFSET(_member, _signature, _in_names, _result, _out_names, _handler, 0, _flags)
#define SD_BUS_METHOD(_member, _signature, _result, _handler, _flags)   \
        SD_BUS_METHOD_WITH_NAMES_OFFSET(_member, _signature, "", _result, "", _handler, 0, _flags)

#define SD_BUS_SIGNAL_WITH_NAMES(_member, _signature, _out_names, _flags)                      \
        {                                                               \
                .type = _SD_BUS_VTABLE_SIGNAL,                          \
                .flags = _flags,                                        \
                .x = {                                                  \
                        .signal = {                                     \
                                .member = _member,                      \
                                .signature = _signature,                \
                                .names = _out_names,                    \
                        },                                              \
                },                                                      \
                        }
#define SD_BUS_SIGNAL(_member, _signature, _flags)                      \
        SD_BUS_SIGNAL_WITH_NAMES(_member, _signature, "", _flags)

#define SD_BUS_PROPERTY(_member, _signature, _get, _offset, _flags)     \
        {                                                               \
                .type = _SD_BUS_VTABLE_PROPERTY,                        \
                .flags = _flags,                                        \
                .x = {                                                  \
                        .property = {                                   \
                                .member = _member,                      \
                                .signature = _signature,                \
                                .get = _get,                            \
                                .set = NULL,                            \
                                .offset = _offset,                      \
                        },                                              \
                },                                                      \
        }

#define SD_BUS_WRITABLE_PROPERTY(_member, _signature, _get, _set, _offset, _flags) \
        {                                                               \
                .type = _SD_BUS_VTABLE_WRITABLE_PROPERTY,               \
                .flags = _flags,                                        \
                .x = {                                                  \
                        .property = {                                   \
                                .member = _member,                      \
                                .signature = _signature,                \
                                .get = _get,                            \
                                .set = _set,                            \
                                .offset = _offset,                      \
                        },                                              \
                },                                                      \
        }

#define SD_BUS_VTABLE_END                                               \
        {                                                               \
                .type = _SD_BUS_VTABLE_END,                             \
                .flags = 0,                                             \
                .x = {                                                  \
                        .end = {                                        \
                                ._reserved = 0,                         \
                        },                                              \
                },                                                      \
        }

_SD_END_DECLARATIONS;

#endif
