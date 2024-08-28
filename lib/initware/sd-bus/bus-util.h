#pragma once

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

#include "hashmap.h"
#include "install.h"
#include "pidref.h"
#include "sd-bus.h"
#include "sd-event.h"
#include "time-util.h"
#include "util.h"

typedef enum BusTransport {
        BUS_TRANSPORT_LOCAL,
        BUS_TRANSPORT_REMOTE,
        BUS_TRANSPORT_MACHINE,
        BUS_TRANSPORT_CAPSULE,
        _BUS_TRANSPORT_MAX,
        _BUS_TRANSPORT_INVALID = -EINVAL,
} BusTransport;

typedef int (*bus_property_set_t)(sd_bus *bus, const char *member,
	sd_bus_message *m, sd_bus_error *error, void *userdata);

struct bus_properties_map {
	const char *member;
	const char *signature;
	bus_property_set_t set;
	size_t offset;
};

int bus_map_id128(sd_bus *bus, const char *member, sd_bus_message *m,
	sd_bus_error *error, void *userdata);

// int bus_message_map_all_properties(sd_bus *bus, sd_bus_message *m,
// 	const struct bus_properties_map *map, void *userdata);
// int bus_message_map_properties_changed(sd_bus *bus, sd_bus_message *m,
// 	const struct bus_properties_map *map, void *userdata);
// int bus_map_all_properties(sd_bus *bus, const char *destination,
// 	const char *path, const struct bus_properties_map *map, void *userdata);

int bus_async_unregister_and_exit(sd_event *e, sd_bus *bus, const char *name);

typedef bool (*check_idle_t)(void *userdata);

int bus_event_loop_with_idle(sd_event *e, sd_bus *bus, const char *name,
	usec_t timeout, check_idle_t check_idle, void *userdata);

int bus_name_has_owner(sd_bus *c, const char *name, sd_bus_error *error);

int bus_check_peercred(sd_bus *c);

int bus_set_address_capsule_bus(sd_bus *bus, const char *capsule, int *ret_pin_fd);

int bus_verify_polkit(sd_bus_message *call, int capability, const char *action,
	bool interactive, bool *_challenge, sd_bus_error *e);

typedef enum PolkitFLags {
        POLKIT_ALLOW_INTERACTIVE = 1 << 0, /* Allow interactive auth (typically not required, because can be derived from bus message/link automatically) */
        POLKIT_ALWAYS_QUERY      = 1 << 1, /* Query polkit even if client is privileged */
        POLKIT_DEFAULT_ALLOW     = 1 << 2, /* If polkit is not around, assume "allow" rather than the usual "deny" */
        POLKIT_DONT_REPLY        = 1 << 3, /* Varlink: don't immediately propagate polkit error to the Varlink client */
} PolkitFlags;

int bus_verify_polkit_async_full(sd_bus_message *call, const char *action, const char **details, uid_t good_user, PolkitFlags flags, Hashmap **registry, sd_bus_error *error);
static inline int bus_verify_polkit_async(sd_bus_message *call, const char *action, const char **details, Hashmap **registry, sd_bus_error *error) {
        return bus_verify_polkit_async_full(call, action, details, UID_INVALID, 0, registry, error);
}
void bus_verify_polkit_async_registry_free(Hashmap *registry);

// int bus_open_system_systemd(sd_bus **_bus);
// int bus_open_user_systemd(sd_bus **_bus);

int bus_open_transport(BusTransport transport, const char *host, bool user,
	sd_bus **bus);
// int bus_open_transport_systemd(BusTransport transport, const char *host,
// 	bool user, sd_bus **bus);

int bus_print_property(const char *name, sd_bus_message *property, bool all);
// int bus_print_all_properties(sd_bus *bus, const char *dest, const char *path,
// 	char **filter, bool all);

int bus_property_get_bool(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error);

int bus_log_address_error(int r, BusTransport transport);
int bus_log_connect_error(int r, BusTransport transport);

#define bus_property_get_usec ((sd_bus_property_get_t)NULL)
#define bus_property_set_usec ((sd_bus_property_set_t)NULL)

assert_cc(sizeof(int) == sizeof(int32_t));
#define bus_property_get_int ((sd_bus_property_get_t)NULL)

assert_cc(sizeof(unsigned) == sizeof(unsigned));
#define bus_property_get_unsigned ((sd_bus_property_get_t)NULL)

/* On 64bit machines we can use the default serializer for size_t and
 * friends, otherwise we need to cast this manually */
#if __SIZEOF_SIZE_T__ == 8
#define bus_property_get_size ((sd_bus_property_get_t)NULL)
#else
int bus_property_get_size(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error);
#endif

#if __SIZEOF_LONG__ == 8
#define bus_property_get_long ((sd_bus_property_get_t)NULL)
#define bus_property_get_ulong ((sd_bus_property_get_t)NULL)
#else
int bus_property_get_long(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error);
int bus_property_get_ulong(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error);
#endif

/* uid_t and friends on Linux 32 bit. This means we can just use the
 * default serializer for 32bit unsigned, for serializing it, and map
 * it to NULL here */
assert_cc(sizeof(uid_t) == sizeof(uint32_t));
#define bus_property_get_uid ((sd_bus_property_get_t)NULL)

assert_cc(sizeof(gid_t) == sizeof(uint32_t));
#define bus_property_get_gid ((sd_bus_property_get_t)NULL)

assert_cc(sizeof(pid_t) == sizeof(uint32_t));
#define bus_property_get_pid ((sd_bus_property_get_t)NULL)

#if SVC_SIZEOF_MODE_T == 4
assert_cc(sizeof(mode_t) == sizeof(uint32_t));
#define bus_property_get_mode ((sd_bus_property_get_t)NULL)
#elif SVC_SIZEOF_MODE_T == 2
int bus_property_get_mode(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error);
#else
#error Odd mode_t size
#endif

int bus_log_parse_error(int r);
int bus_log_create_error(int r);

typedef struct UnitInfo {
	const char *machine;
	const char *id;
	const char *description;
	const char *load_state;
	const char *active_state;
	const char *sub_state;
	const char *following;
	const char *unit_path;
	uint32_t job_id;
	const char *job_type;
	const char *job_path;
} UnitInfo;

int bus_parse_unit_info(sd_bus_message *message, UnitInfo *u);

#define BUS_DEFINE_PROPERTY_GET_ENUM(function, name, type)                     \
	int function(sd_bus *bus, const char *path, const char *interface,     \
		const char *property, sd_bus_message *reply, void *userdata,   \
		sd_bus_error *error)                                           \
	{                                                                      \
		const char *value;                                             \
		type *field = userdata;                                        \
		int r;                                                         \
                                                                               \
		assert(bus);                                                   \
		assert(reply);                                                 \
		assert(field);                                                 \
                                                                               \
		value = strempty(name##_to_string(*field));                    \
                                                                               \
		r = sd_bus_message_append_basic(reply, 's', value);            \
		if (r < 0)                                                     \
			return r;                                              \
                                                                               \
		return 1;                                                      \
	}                                                                      \
	struct __useless_struct_to_allow_trailing_semicolon__

#define BUS_PROPERTY_DUAL_TIMESTAMP(name, offset, flags)                       \
	SD_BUS_PROPERTY(name, "t", bus_property_get_usec,                      \
		(offset) + offsetof(struct dual_timestamp, realtime),          \
		(flags)),                                                      \
		SD_BUS_PROPERTY(name "Monotonic", "t", bus_property_get_usec,  \
			(offset) + offsetof(struct dual_timestamp, monotonic), \
			(flags))

int bus_maybe_reply_error(sd_bus_message *m, int r, sd_bus_error *error);

int bus_append_unit_property_assignment(sd_bus_message *m,
	const char *assignment);

typedef struct BusWaitForJobs BusWaitForJobs;

// int bus_wait_for_jobs_new(sd_bus *bus, BusWaitForJobs **ret);
void bus_wait_for_jobs_free(BusWaitForJobs *d);
// int bus_wait_for_jobs_add(BusWaitForJobs *d, const char *path);
int bus_wait_for_jobs(BusWaitForJobs *d, bool quiet);
// int bus_wait_for_jobs_one(BusWaitForJobs *d, const char *path, bool quiet);

// DEFINE_TRIVIAL_CLEANUP_FUNC(BusWaitForJobs *, bus_wait_for_jobs_free);

int bus_property_get_rlimit(sd_bus *bus, const char *path,
	const char *interface, const char *property, sd_bus_message *reply,
	void *userdata, sd_bus_error *error);

/* Listen to GetMallocInfo() calls to 'destination' and return malloc_info() via FD */
int bus_register_malloc_status(sd_bus *bus, const char *destination);

int bus_query_sender_pidref(sd_bus_message *m, PidRef *ret);
