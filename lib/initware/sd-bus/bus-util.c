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

#include <sys/socket.h>

#include "sd-bus.h"
#include "sd-daemon.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "bsdglibc.h"
#include "bus-error.h"
#include "bus-internal.h"
#include "bus-label.h"
#include "bus-message.h"
#include "capsule-util.h"
#include "cgroup-util.h"
#include "chase.h"
#include "def.h"
#include "fd-util.h"
#include "macro.h"
#include "missing.h"
#include "parse-util.h"
#include "path-util.h"
#include "set.h"
#include "socket-util.h"
#include "strv.h"
#include "uid-classification.h"
#include "unit-name.h"
#include "util.h"

#include "bus-util.h"

static int name_owner_change_callback(sd_bus_message *m, void *userdata, sd_bus_error *ret_error) {
        sd_event *e = ASSERT_PTR(userdata);

        assert(m);

        sd_bus_close(sd_bus_message_get_bus(m));
        sd_event_exit(e, 0);

        return 1;
}

int bus_log_address_error(int r, BusTransport transport) {
        bool hint = transport == BUS_TRANSPORT_LOCAL && r == -ENOMEDIUM;

        return log_error_errno(r,
                               hint ? "Failed to set bus address: $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR not defined (consider using --machine=<user>@.host --user to connect to bus of other user)" :
                                      "Failed to set bus address: %m");
}

int bus_log_connect_error(int r, BusTransport transport) {
        bool hint_vars = transport == BUS_TRANSPORT_LOCAL && r == -ENOMEDIUM,
             hint_addr = transport == BUS_TRANSPORT_LOCAL && ERRNO_IS_PRIVILEGE(r);

        return log_error_errno(r,
                               r == hint_vars ? "Failed to connect to bus: $DBUS_SESSION_BUS_ADDRESS and $XDG_RUNTIME_DIR not defined (consider using --machine=<user>@.host --user to connect to bus of other user)" :
                               r == hint_addr ? "Failed to connect to bus: Operation not permitted (consider using --machine=<user>@.host --user to connect to bus of other user)" :
                                                "Failed to connect to bus: %m");
}

int
bus_async_unregister_and_exit(sd_event *e, sd_bus *bus, const char *name)
{
	_cleanup_free_ char *match = NULL;
	const char *unique;
	int r;

	assert(e);
	assert(bus);
	assert(name);

	/* We unregister the name here and then wait for the
         * NameOwnerChanged signal for this event to arrive before we
         * quit. We do this in order to make sure that any queued
         * requests are still processed before we really exit. */

	r = sd_bus_get_unique_name(bus, &unique);
	if (r < 0)
		return r;

	r = asprintf(&match,
		"sender='org.freedesktop.DBus',"
		"type='signal',"
		"interface='org.freedesktop.DBus',"
		"member='NameOwnerChanged',"
		"path='/org/freedesktop/DBus',"
		"arg0='%s',"
		"arg1='%s',"
		"arg2=''",
		name, unique);
	if (r < 0)
		return -ENOMEM;

	r = sd_bus_add_match(bus, NULL, match, name_owner_change_callback, e);
	if (r < 0)
		return r;

	r = sd_bus_release_name(bus, name);
	if (r < 0)
		return r;

	return 0;
}

int
bus_event_loop_with_idle(sd_event *e, sd_bus *bus, const char *name,
	usec_t timeout, check_idle_t check_idle, void *userdata)
{
	bool exiting = false;
	int r, code;

	assert(e);
	assert(bus);
	assert(name);

	for (;;) {
		bool idle;

		r = sd_event_get_state(e);
		if (r < 0)
			return r;
		if (r == SD_EVENT_FINISHED)
			break;

		if (check_idle)
			idle = check_idle(userdata);
		else
			idle = true;

		r = sd_event_run(e, exiting || !idle ? (uint64_t)-1 : timeout);
		if (r < 0)
			return r;

		if (r == 0 && !exiting && idle) {
			r = sd_bus_try_close(bus);
			if (r == -EBUSY)
				continue;

			/* Fallback for dbus1 connections: we
                         * unregister the name and wait for the
                         * response to come through for it */
			if (r == -ENOTSUP) {
				/* Inform the service manager that we
                                 * are going down, so that it will
                                 * queue all further start requests,
                                 * instead of assuming we are already
                                 * running. */
				sd_notify(false, "STOPPING=1");

				r = bus_async_unregister_and_exit(e, bus, name);
				if (r < 0)
					return r;

				exiting = true;
				continue;
			}

			if (r < 0)
				return r;

			sd_event_exit(e, 0);
			break;
		}
	}

	r = sd_event_get_exit_code(e, &code);
	if (r < 0)
		return r;

	return code;
}

int bus_name_has_owner(sd_bus *c, const char *name, sd_bus_error *error) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *rep = NULL;
        int r, has_owner = 0;

        assert(c);
        assert(name);

        r = sd_bus_call_method(c,
                               "org.freedesktop.DBus",
                               "/org/freedesktop/dbus",
                               "org.freedesktop.DBus",
                               "NameHasOwner",
                               error,
                               &rep,
                               "s",
                               name);
        if (r < 0)
                return r;

        r = sd_bus_message_read_basic(rep, 'b', &has_owner);
        if (r < 0)
                return sd_bus_error_set_errno(error, r);

        return has_owner;
}

int
bus_verify_polkit(sd_bus_message *call, int capability, const char *action,
	bool interactive, bool *_challenge, sd_bus_error *e)
{
	int r;

	assert(call);
	assert(action);

	r = sd_bus_query_sender_privilege(call, capability);
	if (r < 0)
		return r;
	else if (r > 0)
		return 1;
#ifdef ENABLE_POLKIT
	else {
		_cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
		int authorized = false, challenge = false, c;
		const char *sender;

		sender = sd_bus_message_get_sender(call);
		if (!sender)
			return -EBADMSG;

		c = sd_bus_message_get_allow_interactive_authorization(call);
		if (c < 0)
			return c;
		if (c > 0)
			interactive = true;

		r = sd_bus_call_method(call->bus, "org.freedesktop.PolicyKit1",
			"/org/freedesktop/PolicyKit1/Authority",
			"org.freedesktop.PolicyKit1.Authority",
			"CheckAuthorization", e, &reply, "(sa{sv})sa{ss}us",
			"system-bus-name", 1, "name", "s", sender, action, 0,
			!!interactive, "");

		if (r < 0) {
			/* Treat no PK available as access denied */
			if (sd_bus_error_has_name(e,
				    SD_BUS_ERROR_SERVICE_UNKNOWN)) {
				sd_bus_error_free(e);
				return -EACCES;
			}

			return r;
		}

		r = sd_bus_message_enter_container(reply, 'r', "bba{ss}");
		if (r < 0)
			return r;

		r = sd_bus_message_read(reply, "bb", &authorized, &challenge);
		if (r < 0)
			return r;

		if (authorized)
			return 1;

		if (_challenge) {
			*_challenge = challenge;
			return 0;
		}
	}
#endif

	return -EACCES;
}

#ifdef ENABLE_POLKIT

typedef struct AsyncPolkitQuery {
	sd_bus_message *request, *reply;
	sd_bus_message_handler_t callback;
	void *userdata;
	sd_bus_slot *slot;
	Hashmap *registry;
} AsyncPolkitQuery;

static void
async_polkit_query_free(AsyncPolkitQuery *q)
{
	if (!q)
		return;

	sd_bus_slot_unref(q->slot);

	if (q->registry && q->request)
		hashmap_remove(q->registry, q->request);

	sd_bus_message_unref(q->request);
	sd_bus_message_unref(q->reply);

	free(q);
}

static int
async_polkit_callback(sd_bus *bus, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	_cleanup_bus_error_free_ sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
	AsyncPolkitQuery *q = userdata;
	int r;

	assert(bus);
	assert(reply);
	assert(q);

	q->slot = sd_bus_slot_unref(q->slot);
	q->reply = sd_bus_message_ref(reply);

	r = sd_bus_message_rewind(q->request, true);
	if (r < 0) {
		r = sd_bus_reply_method_errno(q->request, r, NULL);
		goto finish;
	}

	r = q->callback(bus, q->request, q->userdata, &error_buffer);
	r = bus_maybe_reply_error(q->request, r, &error_buffer);

finish:
	async_polkit_query_free(q);

	return r;
}

#endif

// int
// bus_verify_polkit_async(sd_bus_message *call, int capability,
// 	const char *action, bool interactive, Hashmap **registry,
// 	sd_bus_error *error)
// {
// #ifdef ENABLE_POLKIT
// 	_cleanup_bus_message_unref_ sd_bus_message *pk = NULL;
// 	AsyncPolkitQuery *q;
// 	const char *sender;
// 	sd_bus_message_handler_t callback;
// 	void *userdata;
// 	int c;
// #endif
// 	int r;

// 	assert(call);
// 	assert(action);
// 	assert(registry);

// #ifdef ENABLE_POLKIT
// 	q = hashmap_get(*registry, call);
// 	if (q) {
// 		int authorized, challenge;

// 		/* This is the second invocation of this function, and
//                  * there's already a response from polkit, let's
//                  * process it */
// 		assert(q->reply);

// 		if (sd_bus_message_is_method_error(q->reply, NULL)) {
// 			const sd_bus_error *e;

// 			/* Copy error from polkit reply */
// 			e = sd_bus_message_get_error(q->reply);
// 			sd_bus_error_copy(error, e);

// 			/* Treat no PK available as access denied */
// 			if (sd_bus_error_has_name(e,
// 				    SD_BUS_ERROR_SERVICE_UNKNOWN))
// 				return -EACCES;

// 			return -sd_bus_error_get_errno(e);
// 		}

// 		r = sd_bus_message_enter_container(q->reply, 'r', "bba{ss}");
// 		if (r >= 0)
// 			r = sd_bus_message_read(q->reply, "bb", &authorized,
// 				&challenge);

// 		if (r < 0)
// 			return r;

// 		if (authorized)
// 			return 1;

// 		if (challenge)
// 			return sd_bus_error_set(error,
// 				SD_BUS_ERROR_INTERACTIVE_AUTHORIZATION_REQUIRED,
// 				"Interactive authentication required.");

// 		return -EACCES;
// 	}
// #endif

// 	r = sd_bus_query_sender_privilege(call, capability);
// 	if (r < 0)
// 		return r;
// 	else if (r > 0)
// 		return 1;

// #ifdef ENABLE_POLKIT
// 	if (sd_bus_get_current_message(call->bus) != call)
// 		return -EINVAL;

// 	callback = sd_bus_get_current_handler(call->bus);
// 	if (!callback)
// 		return -EINVAL;

// 	userdata = sd_bus_get_current_userdata(call->bus);

// 	sender = sd_bus_message_get_sender(call);
// 	if (!sender)
// 		return -EBADMSG;

// 	c = sd_bus_message_get_allow_interactive_authorization(call);
// 	if (c < 0)
// 		return c;
// 	if (c > 0)
// 		interactive = true;

// 	r = hashmap_ensure_allocated(registry, NULL);
// 	if (r < 0)
// 		return r;

// 	r = sd_bus_message_new_method_call(call->bus, &pk,
// 		"org.freedesktop.PolicyKit1",
// 		"/org/freedesktop/PolicyKit1/Authority",
// 		"org.freedesktop.PolicyKit1.Authority", "CheckAuthorization");
// 	if (r < 0)
// 		return r;

// 	r = sd_bus_message_append(pk, "(sa{sv})sa{ss}us", "system-bus-name", 1,
// 		"name", "s", sender, action, 0, !!interactive, NULL);
// 	if (r < 0)
// 		return r;

// 	q = new0(AsyncPolkitQuery, 1);
// 	if (!q)
// 		return -ENOMEM;

// 	q->request = sd_bus_message_ref(call);
// 	q->callback = callback;
// 	q->userdata = userdata;

// 	r = hashmap_put(*registry, call, q);
// 	if (r < 0) {
// 		async_polkit_query_free(q);
// 		return r;
// 	}

// 	q->registry = *registry;

// 	r = sd_bus_call_async(call->bus, &q->slot, pk, async_polkit_callback, q,
// 		0);
// 	if (r < 0) {
// 		async_polkit_query_free(q);
// 		return r;
// 	}

// 	return 0;
// #endif

// 	return -EACCES;
// }

static int bus_message_check_good_user(sd_bus_message *m, uid_t good_user) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        uid_t sender_uid;
        int r;

        assert(m);

        if (good_user == UID_INVALID)
                return false;

        r = sd_bus_query_sender_creds(m, SD_BUS_CREDS_EUID, &creds);
        if (r < 0)
                return r;

        /* Don't trust augmented credentials for authorization */
        assert_return((sd_bus_creds_get_augmented_mask(creds) & SD_BUS_CREDS_EUID) == 0, -EPERM);

        r = sd_bus_creds_get_euid(creds, &sender_uid);
        if (r < 0)
                return r;

        return sender_uid == good_user;
}

/* bus_verify_polkit_async() handles verification of D-Bus calls with polkit. Because the polkit API
 * is asynchronous, the whole thing is a bit complex and requires some support in the code that uses
 * it. It relies on sd-bus's support for interrupting the processing of a message.
 *
 * Requirements:
 *
 * * bus_verify_polkit_async() must be called before any changes to internal state.
 * * If bus_verify_polkit_async() has made a new polkit query (signaled by return value 0),
 *   processing of the message should be interrupted. This is done by returning 1--which sd-bus
 *   handles specially--and is usually accompanied by a comment. (The message will be queued for
 *   processing again later when a reply from polkit is received.)
 * * The code needs to keep a hashmap, here called registry, in which bus_verify_polkit_async()
 *   stores active queries. This hashmap's lifetime must be larger than the method handler's;
 *   e.g., it can be a member of some "manager" object or a global variable.
 *
 * Return value:
 *
 * * 0 - a new polkit call has been made, which means the processing of the message should be
 *   interrupted;
 * * 1 - the action has been allowed;
 * * -EACCES - the action has been denied;
 * * < 0 - an unspecified error.
 *
 * A step-by-step description of how it works:
 *
 * 1.  A D-Bus method handler calls bus_verify_polkit_async(), passing it the D-Bus message being
 *     processed and the polkit action to verify.
 * 2.  bus_verify_polkit_async() checks the registry for an existing query object associated with the
 *     message. Let's assume this is the first call, so it finds nothing.
 * 3.  A new AsyncPolkitQuery object is created and an async. D-Bus call to polkit is made. The
 *     function then returns 0. The method handler returns 1 to tell sd-bus that the processing of
 *    the message has been interrupted.
 * 4.  (Later) A reply from polkit is received and async_polkit_callback() is called.
 * 5.  async_polkit_callback() reads the reply and stores its result in the passed query.
 * 6.  async_polkit_callback() enqueues the original message again.
 * 7.  (Later) The same D-Bus method handler is called for the same message. It calls
 *     bus_verify_polkit_async() again.
 * 8.  bus_verify_polkit_async() checks the registry for an existing query object associated with the
 *     message. It finds one and returns the result for the action.
 * 9.  The method handler continues processing of the message. If there's another action that needs
 *     to be verified:
 * 10. bus_verify_polkit_async() is called again for the new action. The registry already contains a
 *     query for the message, but the new action hasn't been seen yet, hence steps 4-8 are repeated.
 * 11. (In the method handler again.) bus_verify_polkit_async() returns query results for both
 *     actions and the processing continues as in step 9.
 *
 * Memory handling:
 *
 * async_polkit_callback() registers a deferred call of async_polkit_defer() for the query, which
 * causes the query to be removed from the registry and freed. Deferred events are run with idle
 * priority, so this will happen after processing of the D-Bus message, when the query is no longer
 * needed.
 *
 * Schematically:
 *
 * (m - D-Bus message, a - polkit action, q - polkit query)
 *
 * -> foo_method(m)
 *    -> bus_verify_polkit_async(m, a)
 *       -> async_polkit_query_ref(q)
 *       -> bus_call_method_async(q)
 *    <- bus_verify_polkit_async(m, a) = 0
 * <- foo_method(m) = 1
 * ...
 * -> async_polkit_callback(q)
 *    -> sd_event_add_defer(async_polkit_defer, q)
 *    -> sd_bus_enqueue_for_read(m)
 * <- async_polkit_callback(q)
 * ...
 * -> foo_method(m)
 *    -> bus_verify_polkit_async(m, a)
 *    <- bus_verify_polkit_async(m, a) = 1/-EACCES/error
 *    ...
 *    // possibly another call to bus_verify_polkit_async with action a2
 * <- foo_method(m)
 * ...
 * -> async_polkit_defer(q)
 *    -> async_polkit_query_unref(q)
 * <- async_polkit_defer(q)
 */

int bus_verify_polkit_async_full(
                sd_bus_message *call,
                const char *action,
                const char **details,
                uid_t good_user,
                PolkitFlags flags,
                Hashmap **registry,
                sd_bus_error *error) {

        int r;

        assert(call);
        assert(action);
        assert(registry);

        log_debug("Trying to acquire polkit authentication for '%s'.", action);

        r = bus_message_check_good_user(call, good_user);
        if (r != 0)
                return r;

#if ENABLE_POLKIT
        _cleanup_(async_polkit_query_unrefp) AsyncPolkitQuery *q = NULL;

        q = async_polkit_query_ref(hashmap_get(*registry, call));
        /* This is a repeated invocation of this function, hence let's check if we've already got
         * a response from polkit for this action */
        if (q) {
                r = async_polkit_query_check_action(q, action, details, flags, error);
                if (r != 0) {
                        log_debug("Found matching previous polkit authentication for '%s'.", action);
                        return r;
                }
        }
#endif

        if (!FLAGS_SET(flags, POLKIT_ALWAYS_QUERY)) {
                /* Don't query PK if client is privileged */
                r = sd_bus_query_sender_privilege(call, /* capability= */ -1);
                if (r < 0)
                        return r;
                if (r > 0)
                        return 1;
        }

#if ENABLE_POLKIT
        bool interactive = FLAGS_SET(flags, POLKIT_ALLOW_INTERACTIVE);

        int c = sd_bus_message_get_allow_interactive_authorization(call);
        if (c < 0)
                return c;
        if (c > 0)
                interactive = true;

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *pk = NULL;
        r = bus_message_new_polkit_auth_call_for_bus(call, action, details, interactive, &pk);
        if (r < 0)
                return r;

        if (!q) {
                q = new(AsyncPolkitQuery, 1);
                if (!q)
                        return -ENOMEM;

                *q = (AsyncPolkitQuery) {
                        .n_ref = 1,
                        .request = sd_bus_message_ref(call),
                        .bus = sd_bus_ref(sd_bus_message_get_bus(call)),
                };
        }

        assert(!q->action);
        q->action = new(AsyncPolkitQueryAction, 1);
        if (!q->action)
                return -ENOMEM;

        *q->action = (AsyncPolkitQueryAction) {
                .action = strdup(action),
                .details = strv_copy((char**) details),
        };
        if (!q->action->action || !q->action->details)
                return -ENOMEM;

        if (!q->registry) {
                r = hashmap_ensure_put(registry, &async_polkit_query_hash_ops, call, q);
                if (r < 0)
                        return r;

                q->registry = *registry;
        }

        r = sd_bus_call_async(call->bus, &q->slot, pk, async_polkit_callback, q, 0);
        if (r < 0)
                return r;

        TAKE_PTR(q);

        return 0;
#else
        return FLAGS_SET(flags, POLKIT_DEFAULT_ALLOW) ? 1 : -EACCES;
#endif
}

void
bus_verify_polkit_async_registry_free(Hashmap *registry)
{
#ifdef ENABLE_POLKIT
	AsyncPolkitQuery *q;

	while ((q = hashmap_steal_first(registry)))
		async_polkit_query_free(q);

	hashmap_free(registry);
#endif
}

int
bus_check_peercred(sd_bus *c)
{
	struct socket_ucred ucred;
	int fd;

	assert(c);

	fd = sd_bus_get_fd(c);
	if (fd < 0)
		return fd;

	if (getpeercred(fd, &ucred) < 0)
		return -errno;

	if (ucred.uid != 0 && ucred.uid != geteuid())
		return -EPERM;

	return 1;
}

// int
// bus_open_system_systemd(sd_bus **_bus)
// {
// 	_cleanup_bus_unref_ sd_bus *bus = NULL;
// 	int r;

// 	assert(_bus);

// 	if (geteuid() != 0)
// 		return sd_bus_open_system(_bus);

// 	/* If we are root and kdbus is not available, then let's talk
//          * directly to the system instance, instead of going via the
//          * bus */

// 	r = sd_bus_new(&bus);
// 	if (r < 0)
// 		return r;

// 	r = sd_bus_set_address(bus, "unix:path=" SVC_PKGRUNSTATEDIR "/private");
// 	if (r < 0)
// 		return r;

// 	r = sd_bus_start(bus);
// 	if (r < 0)
// 		return sd_bus_open_system(_bus);

// 	r = bus_check_peercred(bus);
// 	if (r < 0)
// 		return r;

// 	*_bus = bus;
// 	bus = NULL;

// 	return 0;
// }

// int
// bus_open_user_systemd(sd_bus **_bus)
// {
// 	_cleanup_bus_unref_ sd_bus *bus = NULL;
// 	_cleanup_free_ char *ee = NULL;
// 	const char *e;
// 	int r;

// 	/* Try via kdbus first, and then directly */

// 	assert(_bus);

// 	e = secure_getenv("XDG_RUNTIME_DIR");
// 	if (!e)
// 		return sd_bus_open_user(_bus);

// 	ee = bus_address_escape(e);
// 	if (!ee)
// 		return -ENOMEM;

// 	r = sd_bus_new(&bus);
// 	if (r < 0)
// 		return r;

// 	bus->address = strjoin("unix:path=", ee, "/" SVC_PKGDIRNAME "/private", NULL);
// 	if (!bus->address)
// 		return -ENOMEM;

// 	r = sd_bus_start(bus);
// 	if (r < 0)
// 		return sd_bus_open_user(_bus);

// 	r = bus_check_peercred(bus);
// 	if (r < 0)
// 		return r;

// 	*_bus = bus;
// 	bus = NULL;

// 	return 0;
// }

int
bus_print_property(const char *name, sd_bus_message *property, bool all)
{
	char type;
	const char *contents;
	int r;

	assert(name);
	assert(property);

	r = sd_bus_message_peek_type(property, &type, &contents);
	if (r < 0)
		return r;

	switch (type) {
	case SD_BUS_TYPE_STRING: {
		const char *s;

		r = sd_bus_message_read_basic(property, type, &s);
		if (r < 0)
			return r;

		if (all || !isempty(s))
			printf("%s=%s\n", name, s);

		return 1;
	}

	case SD_BUS_TYPE_BOOLEAN: {
		int b;

		r = sd_bus_message_read_basic(property, type, &b);
		if (r < 0)
			return r;

		printf("%s=%s\n", name, yes_no(b));

		return 1;
	}

	case SD_BUS_TYPE_UINT64: {
		uint64_t u;

		r = sd_bus_message_read_basic(property, type, &u);
		if (r < 0)
			return r;

		/* Yes, heuristics! But we can change this check
                 * should it turn out to not be sufficient */

		if (endswith(name, "Timestamp")) {
			char timestamp[FORMAT_TIMESTAMP_MAX], *t;

			t = format_timestamp(timestamp, sizeof(timestamp), u);
			if (t || all)
				printf("%s=%s\n", name, strempty(t));

		} else if (strstr(name, "USec")) {
			char timespan[FORMAT_TIMESPAN_MAX];

			printf("%s=%s\n", name,
				format_timespan(timespan, sizeof(timespan), u,
					0));
		} else
			printf("%s=%llu\n", name, (unsigned long long)u);

		return 1;
	}

	case SD_BUS_TYPE_UINT32: {
		uint32_t u;

		r = sd_bus_message_read_basic(property, type, &u);
		if (r < 0)
			return r;

		if (strstr(name, "UMask") || strstr(name, "Mode"))
			printf("%s=%04o\n", name, u);
		else
			printf("%s=%u\n", name, (unsigned)u);

		return 1;
	}

	case SD_BUS_TYPE_INT32: {
		int32_t i;

		r = sd_bus_message_read_basic(property, type, &i);
		if (r < 0)
			return r;

		printf("%s=%i\n", name, (int)i);
		return 1;
	}

	case SD_BUS_TYPE_DOUBLE: {
		double d;

		r = sd_bus_message_read_basic(property, type, &d);
		if (r < 0)
			return r;

		printf("%s=%g\n", name, d);
		return 1;
	}

	case SD_BUS_TYPE_ARRAY:
		if (streq(contents, "s")) {
			bool first = true;
			const char *str;

			r = sd_bus_message_enter_container(property,
				SD_BUS_TYPE_ARRAY, contents);
			if (r < 0)
				return r;

			while ((r = sd_bus_message_read_basic(property,
					SD_BUS_TYPE_STRING, &str)) > 0) {
				if (first)
					printf("%s=", name);

				printf("%s%s", first ? "" : " ", str);

				first = false;
			}
			if (r < 0)
				return r;

			if (first && all)
				printf("%s=", name);
			if (!first || all)
				puts("");

			r = sd_bus_message_exit_container(property);
			if (r < 0)
				return r;

			return 1;

		} else if (streq(contents, "y")) {
			const uint8_t *u;
			size_t n;

			r = sd_bus_message_read_array(property,
				SD_BUS_TYPE_BYTE, (const void **)&u, &n);
			if (r < 0)
				return r;

			if (all || n > 0) {
				unsigned int i;

				printf("%s=", name);

				for (i = 0; i < n; i++)
					printf("%02x", u[i]);

				puts("");
			}

			return 1;

		} else if (streq(contents, "u")) {
			uint32_t *u;
			size_t n;

			r = sd_bus_message_read_array(property,
				SD_BUS_TYPE_UINT32, (const void **)&u, &n);
			if (r < 0)
				return r;

			if (all || n > 0) {
				unsigned int i;

				printf("%s=", name);

				for (i = 0; i < n; i++)
					printf("%08x", u[i]);

				puts("");
			}

			return 1;
		}

		break;
	}

	return 0;
}

// int
// bus_print_all_properties(sd_bus *bus, const char *dest, const char *path,
// 	char **filter, bool all)
// {
// 	_cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
// 	_cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
// 	int r;

// 	assert(bus);
// 	assert(path);

// 	r = sd_bus_call_method(bus, dest, path,
// 		"org.freedesktop.DBus.Properties", "GetAll", &error, &reply,
// 		"s", "");
// 	if (r < 0)
// 		return r;

// 	r = sd_bus_message_enter_container(reply, SD_BUS_TYPE_ARRAY, "{sv}");
// 	if (r < 0)
// 		return r;

// 	while ((r = sd_bus_message_enter_container(reply,
// 			SD_BUS_TYPE_DICT_ENTRY, "sv")) > 0) {
// 		const char *name;
// 		const char *contents;

// 		r = sd_bus_message_read_basic(reply, SD_BUS_TYPE_STRING, &name);
// 		if (r < 0)
// 			return r;

// 		if (!filter || strv_find(filter, name)) {
// 			r = sd_bus_message_peek_type(reply, NULL, &contents);
// 			if (r < 0)
// 				return r;

// 			r = sd_bus_message_enter_container(reply,
// 				SD_BUS_TYPE_VARIANT, contents);
// 			if (r < 0)
// 				return r;

// 			r = bus_print_property(name, reply, all);
// 			if (r < 0)
// 				return r;
// 			if (r == 0) {
// 				if (all)
// 					printf("%s=[unprintable]\n", name);
// 				/* skip what we didn't read */
// 				r = sd_bus_message_skip(reply, contents);
// 				if (r < 0)
// 					return r;
// 			}

// 			r = sd_bus_message_exit_container(reply);
// 			if (r < 0)
// 				return r;
// 		} else {
// 			r = sd_bus_message_skip(reply, "v");
// 			if (r < 0)
// 				return r;
// 		}

// 		r = sd_bus_message_exit_container(reply);
// 		if (r < 0)
// 			return r;
// 	}
// 	if (r < 0)
// 		return r;

// 	r = sd_bus_message_exit_container(reply);
// 	if (r < 0)
// 		return r;

// 	return 0;
// }

int
bus_map_id128(sd_bus *bus, const char *member, sd_bus_message *m,
	sd_bus_error *error, void *userdata)
{
	sd_id128_t *p = userdata;
	const void *v;
	size_t n;
	int r;

	r = sd_bus_message_read_array(m, SD_BUS_TYPE_BYTE, &v, &n);
	if (r < 0)
		return r;

	if (n == 0)
		*p = SD_ID128_NULL;
	else if (n == 16)
		memcpy((*p).bytes, v, n);
	else
		return -EINVAL;

	return 0;
}

static int
map_basic(sd_bus *bus, const char *member, sd_bus_message *m,
	sd_bus_error *error, void *userdata)
{
	char type;
	int r;

	r = sd_bus_message_peek_type(m, &type, NULL);
	if (r < 0)
		return r;

	switch (type) {
	case SD_BUS_TYPE_STRING: {
		const char *s;
		char *str;
		char **p = userdata;

		r = sd_bus_message_read_basic(m, type, &s);
		if (r < 0)
			break;

		if (isempty(s))
			break;

		str = strdup(s);
		if (!str) {
			r = -ENOMEM;
			break;
		}
		free(*p);
		*p = str;

		break;
	}

	case SD_BUS_TYPE_ARRAY: {
		_cleanup_strv_free_ char **l = NULL;
		char ***p = userdata;

		r = bus_message_read_strv_extend(m, &l);
		if (r < 0)
			break;

		strv_free(*p);
		*p = l;
		l = NULL;

		break;
	}

	case SD_BUS_TYPE_BOOLEAN: {
		unsigned b;
		bool *p = userdata;

		r = sd_bus_message_read_basic(m, type, &b);
		if (r < 0)
			break;

		*p = b;

		break;
	}

	case SD_BUS_TYPE_UINT32: {
		uint64_t u;
		uint32_t *p = userdata;

		r = sd_bus_message_read_basic(m, type, &u);
		if (r < 0)
			break;

		*p = u;

		break;
	}

	case SD_BUS_TYPE_UINT64: {
		uint64_t t;
		uint64_t *p = userdata;

		r = sd_bus_message_read_basic(m, type, &t);
		if (r < 0)
			break;

		*p = t;

		break;
	}

	default:
		break;
	}

	return r;
}

// int
// bus_message_map_all_properties(sd_bus *bus, sd_bus_message *m,
// 	const struct bus_properties_map *map, void *userdata)
// {
// 	_cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
// 	int r;

// 	assert(bus);
// 	assert(m);
// 	assert(map);

// 	r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "{sv}");
// 	if (r < 0)
// 		return r;

// 	while ((r = sd_bus_message_enter_container(m, SD_BUS_TYPE_DICT_ENTRY,
// 			"sv")) > 0) {
// 		const struct bus_properties_map *prop;
// 		const char *member;
// 		const char *contents;
// 		void *v;
// 		unsigned i;

// 		r = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &member);
// 		if (r < 0)
// 			return r;

// 		for (i = 0, prop = NULL; map[i].member; i++)
// 			if (streq(map[i].member, member)) {
// 				prop = &map[i];
// 				break;
// 			}

// 		if (prop) {
// 			r = sd_bus_message_peek_type(m, NULL, &contents);
// 			if (r < 0)
// 				return r;

// 			r = sd_bus_message_enter_container(m,
// 				SD_BUS_TYPE_VARIANT, contents);
// 			if (r < 0)
// 				return r;

// 			v = (uint8_t *)userdata + prop->offset;
// 			if (map[i].set)
// 				r = prop->set(bus, member, m, &error, v);
// 			else
// 				r = map_basic(bus, member, m, &error, v);
// 			if (r < 0)
// 				return r;

// 			r = sd_bus_message_exit_container(m);
// 			if (r < 0)
// 				return r;
// 		} else {
// 			r = sd_bus_message_skip(m, "v");
// 			if (r < 0)
// 				return r;
// 		}

// 		r = sd_bus_message_exit_container(m);
// 		if (r < 0)
// 			return r;
// 	}

// 	return sd_bus_message_exit_container(m);
// }

// int
// bus_message_map_properties_changed(sd_bus *bus, sd_bus_message *m,
// 	const struct bus_properties_map *map, void *userdata)
// {
// 	const char *member;
// 	int r, invalidated, i;

// 	assert(bus);
// 	assert(m);
// 	assert(map);

// 	r = bus_message_map_all_properties(bus, m, map, userdata);
// 	if (r < 0)
// 		return r;

// 	r = sd_bus_message_enter_container(m, SD_BUS_TYPE_ARRAY, "s");
// 	if (r < 0)
// 		return r;

// 	invalidated = 0;
// 	while ((r = sd_bus_message_read_basic(m, SD_BUS_TYPE_STRING, &member)) >
// 		0)
// 		for (i = 0; map[i].member; i++)
// 			if (streq(map[i].member, member)) {
// 				++invalidated;
// 				break;
// 			}

// 	r = sd_bus_message_exit_container(m);
// 	if (r < 0)
// 		return r;

// 	return invalidated;
// }

// int
// bus_map_all_properties(sd_bus *bus, const char *destination, const char *path,
// 	const struct bus_properties_map *map, void *userdata)
// {
// 	_cleanup_bus_message_unref_ sd_bus_message *m = NULL;
// 	_cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
// 	int r;

// 	assert(bus);
// 	assert(destination);
// 	assert(path);
// 	assert(map);

// 	r = sd_bus_call_method(bus, destination, path,
// 		"org.freedesktop.DBus.Properties", "GetAll", &error, &m, "s",
// 		"");
// 	if (r < 0)
// 		return r;

// 	return bus_message_map_all_properties(bus, m, map, userdata);
// }

int
bus_open_transport(BusTransport transport, const char *host, bool user,
	sd_bus **bus)
{
	int r;

	assert(transport >= 0);
	assert(transport < _BUS_TRANSPORT_MAX);
	assert(bus);

	assert_return((transport == BUS_TRANSPORT_LOCAL) == !host, -EINVAL);
	assert_return(transport == BUS_TRANSPORT_LOCAL || !user, -ENOTSUP);

	switch (transport) {
	case BUS_TRANSPORT_LOCAL:
		if (user)
			r = sd_bus_default_user(bus);
		else
			r = sd_bus_default_system(bus);

		break;

	case BUS_TRANSPORT_REMOTE:
		r = sd_bus_open_system_remote(bus, host);
		break;

	case BUS_TRANSPORT_MACHINE:
		r = sd_bus_open_system_machine(bus, host);
		break;

	default:
		assert_not_reached();
	}

	return r;
}

// int
// bus_open_transport_systemd(BusTransport transport, const char *host, bool user,
// 	sd_bus **bus)
// {
// 	int r;

// 	assert(transport >= 0);
// 	assert(transport < _BUS_TRANSPORT_MAX);
// 	assert(bus);

// 	assert_return((transport == BUS_TRANSPORT_LOCAL) == !host, -EINVAL);
// 	assert_return(transport == BUS_TRANSPORT_LOCAL || !user, -ENOTSUP);

// 	switch (transport) {
// 	case BUS_TRANSPORT_LOCAL:
// 		if (user)
// 			r = bus_open_user_systemd(bus);
// 		else
// 			r = bus_open_system_systemd(bus);

// 		break;

// 	case BUS_TRANSPORT_REMOTE:
// 		r = sd_bus_open_system_remote(bus, host);
// 		break;

// 	case BUS_TRANSPORT_MACHINE:
// 		r = sd_bus_open_system_machine(bus, host);
// 		break;

// 	default:
// 		assert_not_reached();
// 	}

// 	return r;
// }

int
bus_property_get_bool(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	int b = *(bool *)userdata;

	return sd_bus_message_append_basic(reply, 'b', &b);
}

#if __SIZEOF_SIZE_T__ != 8
int
bus_property_get_size(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	uint64_t sz = *(size_t *)userdata;

	return sd_bus_message_append_basic(reply, 't', &sz);
}
#endif

#if __SIZEOF_LONG__ != 8
int
bus_property_get_long(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	int64_t l = *(long *)userdata;

	return sd_bus_message_append_basic(reply, 'x', &l);
}

int
bus_property_get_ulong(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	uint64_t ul = *(unsigned long *)userdata;

	return sd_bus_message_append_basic(reply, 't', &ul);
}
#endif

#if SVC_SIZEOF_MODE_T != 4
int
bus_property_get_mode(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	uint32_t ul = *(mode_t *)userdata;

	return sd_bus_message_append_basic(reply, 'u', &ul);
}
#endif

int
bus_log_parse_error(int r)
{
	return log_error_errno(r, "Failed to parse bus message: %m");
}

int
bus_log_create_error(int r)
{
	return log_error_errno(r, "Failed to create bus message: %m");
}

int
bus_parse_unit_info(sd_bus_message *message, UnitInfo *u)
{
	assert(message);
	assert(u);

	u->machine = NULL;

	return sd_bus_message_read(message, "(ssssssouso)", &u->id,
		&u->description, &u->load_state, &u->active_state,
		&u->sub_state, &u->following, &u->unit_path, &u->job_id,
		&u->job_type, &u->job_path);
}

int
bus_maybe_reply_error(sd_bus_message *m, int r, sd_bus_error *error)
{
	assert(m);

	if (r < 0) {
		if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL)
			sd_bus_reply_method_errno(m, r, error);

	} else if (sd_bus_error_is_set(error)) {
		if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL)
			sd_bus_reply_method_error(m, error);
	} else
		return r;

	log_debug(
		"Failed to process message [type=%s sender=%s path=%s interface=%s member=%s signature=%s]: %s",
		bus_message_type_to_string(m->header->type), strna(m->sender),
		strna(m->path), strna(m->interface), strna(m->member),
		strna(m->root_container.signature),
		bus_error_message(error, r));

	return 1;
}

int
bus_append_unit_property_assignment(sd_bus_message *m, const char *assignment)
{
	const char *eq, *field;
	int r;

	assert(m);
	assert(assignment);

	eq = strchr(assignment, '=');
	if (!eq) {
		log_error("Not an assignment: %s", assignment);
		return -EINVAL;
	}

	field = strndupa(assignment, eq - assignment);
	eq++;

	if (streq(field, "CPUQuota")) {
		if (isempty(eq)) {
			r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING,
				"CPUQuotaPerSecUSec");
			if (r < 0)
				return bus_log_create_error(r);

			r = sd_bus_message_append(m, "v", "t", USEC_INFINITY);

		} else if (endswith(eq, "%")) {
			double percent;

			if (sscanf(eq, "%lf%%", &percent) != 1 ||
				percent <= 0) {
				log_error("CPU quota '%s' invalid.", eq);
				return -EINVAL;
			}

			r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING,
				"CPUQuotaPerSecUSec");
			if (r < 0)
				return bus_log_create_error(r);

			r = sd_bus_message_append(m, "v", "t",
				(usec_t)percent * USEC_PER_SEC / 100);
		} else {
			log_error("CPU quota needs to be in percent.");
			return -EINVAL;
		}

		if (r < 0)
			return bus_log_create_error(r);

		return 0;
	} else if (streq(field, "RandomizedDelaySec")) {
		usec_t t;

		r = parse_sec(eq, &t);
		if (r < 0)
			return log_error_errno(r,
				"Failed to parse RandomizedDelaySec= parameter: %s",
				eq);

		r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING,
			"RandomizedDelayUSec");
		if (r < 0)
			return bus_log_create_error(r);

		r = sd_bus_message_append(m, "v", "t", t);
		if (r < 0)
			return bus_log_create_error(r);

		return 0;
	}

	r = sd_bus_message_append_basic(m, SD_BUS_TYPE_STRING, field);
	if (r < 0)
		return bus_log_create_error(r);

	if (STR_IN_SET(field, "CPUAccounting", "MemoryAccounting",
		    "BlockIOAccounting", "SendSIGHUP", "SendSIGKILL",
		    "WakeSystem", "DefaultDependencies", "Delegate")) {
		r = parse_boolean(eq);
		if (r < 0) {
			log_error("Failed to parse boolean assignment %s.",
				assignment);
			return -EINVAL;
		}

		r = sd_bus_message_append(m, "v", "b", r);

	} else if (streq(field, "MemoryLimit")) {
		off_t bytes;

		r = parse_size(eq, 1024, &bytes);
		if (r < 0) {
			log_error("Failed to parse bytes specification %s",
				assignment);
			return -EINVAL;
		}

		r = sd_bus_message_append(m, "v", "t", (uint64_t)bytes);
	} else if (streq(field, "TasksMax")) {
		uint64_t t;

		if (isempty(eq) || streq(eq, "infinity"))
			t = (uint64_t)-1;
		else {
			r = safe_atou64(eq, &t);
			if (r < 0)
				return log_error_errno(r,
					"Failed to parse maximum tasks specification %s",
					assignment);
		}

		r = sd_bus_message_append(m, "v", "t", t);

	} else if (STR_IN_SET(field, "CPUShares", "StartupCPUShares")) {
		uint64_t u;

		r = cg_cpu_shares_parse(eq, &u);
		if (r < 0) {
			log_error("Failed to parse %s value %s.", field, eq);
			return -EINVAL;
		}

		r = sd_bus_message_append(m, "v", "t", u);

	} else if (STR_IN_SET(field, "BlockIOWeight", "StartupBlockIOWeight")) {
		uint64_t u;

		r = cg_blkio_weight_parse(eq, &u);
		if (r < 0) {
			log_error("Failed to parse %s value %s.", field, eq);
			return -EINVAL;
		}

		r = sd_bus_message_append(m, "v", "t", u);

	} else if (STR_IN_SET(field, "User", "Group", "DevicePolicy",
			   "KillMode"))
		r = sd_bus_message_append(m, "v", "s", eq);

	else if (streq(field, "DeviceAllow")) {
		if (isempty(eq))
			r = sd_bus_message_append(m, "v", "a(ss)", 0);
		else {
			const char *path, *rwm, *e;

			e = strchr(eq, ' ');
			if (e) {
				path = strndupa(eq, e - eq);
				rwm = e + 1;
			} else {
				path = eq;
				rwm = "";
			}

			if (!path_startswith(path, "/dev")) {
				log_error("%s is not a device file in /dev.",
					path);
				return -EINVAL;
			}

			r = sd_bus_message_append(m, "v", "a(ss)", 1, path,
				rwm);
		}

	} else if (STR_IN_SET(field, "BlockIOReadBandwidth",
			   "BlockIOWriteBandwidth")) {
		if (isempty(eq))
			r = sd_bus_message_append(m, "v", "a(st)", 0);
		else {
			const char *path, *bandwidth, *e;
			off_t bytes;

			e = strchr(eq, ' ');
			if (e) {
				path = strndupa(eq, e - eq);
				bandwidth = e + 1;
			} else {
				log_error("Failed to parse %s value %s.", field,
					eq);
				return -EINVAL;
			}

			if (!path_startswith(path, "/dev")) {
				log_error("%s is not a device file in /dev.",
					path);
				return -EINVAL;
			}

			r = parse_size(bandwidth, 1000, &bytes);
			if (r < 0) {
				log_error("Failed to parse byte value %s.",
					bandwidth);
				return -EINVAL;
			}

			r = sd_bus_message_append(m, "v", "a(st)", 1, path,
				(uint64_t)bytes);
		}

	} else if (streq(field, "BlockIODeviceWeight")) {
		if (isempty(eq))
			r = sd_bus_message_append(m, "v", "a(st)", 0);
		else {
			const char *path, *weight, *e;
			uint64_t u;

			e = strchr(eq, ' ');
			if (e) {
				path = strndupa(eq, e - eq);
				weight = e + 1;
			} else {
				log_error("Failed to parse %s value %s.", field,
					eq);
				return -EINVAL;
			}

			if (!path_startswith(path, "/dev")) {
				log_error("%s is not a device file in /dev.",
					path);
				return -EINVAL;
			}

			r = safe_atou64(weight, &u);
			if (r < 0) {
				log_error("Failed to parse %s value %s.", field,
					weight);
				return -EINVAL;
			}
			r = sd_bus_message_append(m, "v", "a(st)", path, u);
		}

	} else if (rlimit_from_string(field) >= 0) {
		uint64_t rl;

		if (streq(eq, "infinity"))
			rl = (uint64_t)-1;
		else {
			r = safe_atou64(eq, &rl);
			if (r < 0) {
				log_error("Invalid resource limit: %s", eq);
				return -EINVAL;
			}
		}

		r = sd_bus_message_append(m, "v", "t", rl);

	} else if (streq(field, "Nice")) {
		int32_t i;

		r = safe_atoi32(eq, &i);
		if (r < 0) {
			log_error("Failed to parse %s value %s.", field, eq);
			return -EINVAL;
		}

		r = sd_bus_message_append(m, "v", "i", i);

	} else if (STR_IN_SET(field, "Environment", "PassEnvironment")) {
		r = sd_bus_message_append(m, "v", "as", 1, eq);

	} else if (streq(field, "KillSignal")) {
		int sig;

		sig = signal_from_string_try_harder(eq);
		if (sig < 0) {
			log_error("Failed to parse %s value %s.", field, eq);
			return -EINVAL;
		}

		r = sd_bus_message_append(m, "v", "i", sig);

	} else if (streq(field, "AccuracySec")) {
		usec_t u;

		r = parse_sec(eq, &u);
		if (r < 0) {
			log_error("Failed to parse %s value %s", field, eq);
			return -EINVAL;
		}

		r = sd_bus_message_append(m, "v", "t", u);

	} else {
		log_error("Unknown assignment %s.", assignment);
		return -EINVAL;
	}

	if (r < 0)
		return bus_log_create_error(r);

	return 0;
}

typedef struct BusWaitForJobs {
	sd_bus *bus;
	Set *jobs;

	char *name;
	char *result;

	sd_bus_slot *slot_job_removed;
	sd_bus_slot *slot_disconnected;
} BusWaitForJobs;

static int
match_disconnected(sd_bus *bus, sd_bus_message *m, void *userdata,
	sd_bus_error *error)
{
	assert(bus);
	assert(m);

	log_error("Warning! D-Bus connection terminated.");
	sd_bus_close(bus);

	return 0;
}

static int
match_job_removed(sd_bus *bus, sd_bus_message *m, void *userdata,
	sd_bus_error *error)
{
	const char *path, *unit, *result;
	BusWaitForJobs *d = userdata;
	uint32_t id;
	char *found;
	int r;

	assert(bus);
	assert(m);
	assert(d);

	r = sd_bus_message_read(m, "uoss", &id, &path, &unit, &result);
	if (r < 0) {
		bus_log_parse_error(r);
		return 0;
	}

	found = set_remove(d->jobs, (char *)path);
	if (!found)
		return 0;

	free(found);

	if (!isempty(result))
		d->result = strdup(result);

	if (!isempty(unit))
		d->name = strdup(unit);

	return 0;
}

void
bus_wait_for_jobs_free(BusWaitForJobs *d)
{
	if (!d)
		return;

	set_free_free(d->jobs);

	sd_bus_slot_unref(d->slot_disconnected);
	sd_bus_slot_unref(d->slot_job_removed);

	sd_bus_unref(d->bus);

	free(d->name);
	free(d->result);

	free(d);
}

// int
// bus_wait_for_jobs_new(sd_bus *bus, BusWaitForJobs **ret)
// {
// 	_cleanup_(bus_wait_for_jobs_freep) BusWaitForJobs *d = NULL;
// 	int r;

// 	assert(bus);
// 	assert(ret);

// 	d = new0(BusWaitForJobs, 1);
// 	if (!d)
// 		return -ENOMEM;

// 	d->bus = sd_bus_ref(bus);

// 	/* When we are a bus client we match by sender. Direct
//          * connections OTOH have no initialized sender field, and
//          * hence we ignore the sender then */
// 	r = sd_bus_add_match(bus, &d->slot_job_removed,
// 		bus->bus_client ? "type='signal',"
// 				  "interface='" SVC_DBUS_BUSNAME "',"
// 				  "interface='" SVC_DBUS_INTERFACE ".Manager',"
// 				  "member='JobRemoved',"
// 				  "path='/org/freedesktop/systemd1'" :
// 					"type='signal',"
// 				  "interface='" SVC_DBUS_INTERFACE ".Manager',"
// 				  "member='JobRemoved',"
// 				  "path='/org/freedesktop/systemd1'",
// 		match_job_removed, d);
// 	if (r < 0)
// 		return r;

// 	r = sd_bus_add_match(bus, &d->slot_disconnected,
// 		"type='signal',"
// 		"sender='org.freedesktop.DBus.Local',"
// 		"interface='org.freedesktop.DBus.Local',"
// 		"member='Disconnected'",
// 		match_disconnected, d);
// 	if (r < 0)
// 		return r;

// 	*ret = d;
// 	d = NULL;

// 	return 0;
// }

static int
bus_process_wait(sd_bus *bus)
{
	int r;

	for (;;) {
		r = sd_bus_process(bus, NULL);
		if (r < 0)
			return r;
		if (r > 0)
			return 0;

		r = sd_bus_wait(bus, (uint64_t)-1);
		if (r < 0)
			return r;
	}
}

static int
bus_job_get_service_result(BusWaitForJobs *d, char **result)
{
	_cleanup_free_ char *dbus_path = NULL;

	assert(d);
	assert(d->name);
	assert(result);

	dbus_path = unit_dbus_path_from_name(d->name);
	if (!dbus_path)
		return -ENOMEM;

	return sd_bus_get_property_string(d->bus, SVC_DBUS_BUSNAME, dbus_path,
		SVC_DBUS_INTERFACE ".Service", "Result", NULL, result);
}

static const struct {
	const char *result, *explanation;
} explanations[] = { { "resources",
			     "a configured resource limit was exceeded" },
	{ "timeout", "a timeout was exceeded" },
	{ "exit-code", "the control process exited with error code" },
	{ "signal", "a fatal signal was delivered to the control process" },
	{ "core-dump",
		"a fatal signal was delivered causing the control process to dump core" },
	{ "watchdog", "the service failed to send watchdog ping" },
	{ "start-limit", "start of the service was attempted too often" } };

static void
log_job_error_with_service_result(const char *service, const char *result)
{
	_cleanup_free_ char *service_shell_quoted = NULL;

	assert(service);

	service_shell_quoted = shell_maybe_quote(service);

	if (!isempty(result)) {
		unsigned i;

		for (i = 0; i < ELEMENTSOF(explanations); ++i)
			if (streq(result, explanations[i].result))
				break;

		if (i < ELEMENTSOF(explanations)) {
			log_error(
				"Job for %s failed because %s. See \"systemctl status %s\" and \"journalctl -xe\" for details.\n",
				service, explanations[i].explanation,
				strna(service_shell_quoted));

			goto finish;
		}
	}

	log_error(
		"Job for %s failed. See \"systemctl status %s\" and \"journalctl -xe\" for details.\n",
		service, strna(service_shell_quoted));

finish:
	/* For some results maybe additional explanation is required */
	if (streq_ptr(result, "start-limit"))
		log_info(
			"To force a start use \"systemctl reset-failed %1$s\" followed by \"systemctl start %1$s\" again.",
			strna(service_shell_quoted));
}

static int
check_wait_response(BusWaitForJobs *d, bool quiet)
{
	int r = 0;

	assert(d->result);

	if (!quiet) {
		if (streq(d->result, "canceled"))
			log_error("Job for %s canceled.", strna(d->name));
		else if (streq(d->result, "timeout"))
			log_error("Job for %s timed out.", strna(d->name));
		else if (streq(d->result, "dependency"))
			log_error(
				"A dependency job for %s failed. See 'journalctl -xe' for details.",
				strna(d->name));
		else if (streq(d->result, "invalid"))
			log_error("Job for %s invalid.", strna(d->name));
		else if (streq(d->result, "assert"))
			log_error("Assertion failed on job for %s.",
				strna(d->name));
		else if (streq(d->result, "unsupported"))
			log_error(
				"Operation on or unit type of %s not supported on this system.",
				strna(d->name));
		else if (!streq(d->result, "done") &&
			!streq(d->result, "skipped")) {
			if (d->name) {
				int q;
				_cleanup_free_ char *result = NULL;

				q = bus_job_get_service_result(d, &result);
				if (q < 0)
					log_debug_errno(q,
						"Failed to get Result property of service %s: %m",
						d->name);

				log_job_error_with_service_result(d->name,
					result);
			} else
				log_error(
					"Job failed. See \"journalctl -xe\" for details.");
		}
	}

	if (streq(d->result, "canceled"))
		r = -ECANCELED;
	else if (streq(d->result, "timeout"))
		r = -ETIME;
	else if (streq(d->result, "dependency"))
		r = -EIO;
	else if (streq(d->result, "invalid"))
		r = -ENOEXEC;
	else if (streq(d->result, "assert"))
		r = -EPROTO;
	else if (streq(d->result, "unsupported"))
		r = -ENOTSUP;
	else if (!streq(d->result, "done") && !streq(d->result, "skipped"))
		r = -EIO;

	return r;
}

int
bus_wait_for_jobs(BusWaitForJobs *d, bool quiet)
{
	int r = 0;

	assert(d);

	while (!set_isempty(d->jobs)) {
		int q;

		q = bus_process_wait(d->bus);
		if (q < 0)
			return log_error_errno(q,
				"Failed to wait for response: %m");

		if (d->result) {
			q = check_wait_response(d, quiet);
			/* Return the first error as it is most likely to be
                         * meaningful. */
			if (q < 0 && r == 0)
				r = q;

			errno = 0;
			log_debug_errno(q, "Got result %s/%m for job %s",
				strna(d->result), strna(d->name));
		}

		free(d->name);
		d->name = NULL;

		free(d->result);
		d->result = NULL;
	}

	return r;
}

// int
// bus_wait_for_jobs_add(BusWaitForJobs *d, const char *path)
// {
// 	int r;

// 	assert(d);

// 	r = set_ensure_allocated(&d->jobs, &string_hash_ops);
// 	if (r < 0)
// 		return r;

// 	return set_put_strdup(d->jobs, path);
// }

// int
// bus_wait_for_jobs_one(BusWaitForJobs *d, const char *path, bool quiet)
// {
// 	int r;

// 	r = bus_wait_for_jobs_add(d, path);
// 	if (r < 0)
// 		return log_oom();

// 	return bus_wait_for_jobs(d, quiet);
// }

int
bus_property_get_rlimit(sd_bus *bus, const char *path, const char *interface,
	const char *property, sd_bus_message *reply, void *userdata,
	sd_bus_error *error)
{
	struct rlimit *rl;
	uint64_t u;
	rlim_t x;

	assert(bus);
	assert(reply);
	assert(userdata);

	rl = *(struct rlimit **)userdata;
	if (rl)
		x = rl->rlim_max;
	else {
		struct rlimit buf = {};
		int z;

		z = rlimit_from_string(startswith(property, "Default") ?
				      property + 7 :
				      property);
		assert(z >= 0);

		getrlimit(z, &buf);
		x = buf.rlim_max;
	}

	/* rlim_t might have different sizes, let's map
         * RLIMIT_INFINITY to (uint64_t) -1, so that it is the same on
         * all archs */
	u = x == RLIM_INFINITY ? (uint64_t)-1 : (uint64_t)x;

	return sd_bus_message_append(reply, "t", u);
}

static int pin_capsule_socket(const char *capsule, const char *suffix, uid_t *ret_uid, gid_t *ret_gid) {
        _cleanup_close_ int inode_fd = -EBADF;
        _cleanup_free_ char *p = NULL;
        struct stat st;
        int r;

        assert(capsule);
        assert(suffix);
        assert(ret_uid);
        assert(ret_gid);

        p = path_join("/run/capsules", capsule, suffix);
        if (!p)
                return -ENOMEM;

        /* We enter territory owned by the user, hence let's be paranoid about symlinks and ownership */
        r = chase(p, /* root= */ NULL, CHASE_SAFE|CHASE_PROHIBIT_SYMLINKS, /* ret_path= */ NULL, &inode_fd);
        if (r < 0)
                return r;

        if (fstat(inode_fd, &st) < 0)
                return negative_errno();

        /* Paranoid safety check */
        if (uid_is_system(st.st_uid) || gid_is_system(st.st_gid))
                return -EPERM;

        *ret_uid = st.st_uid;
        *ret_gid = st.st_gid;

        return TAKE_FD(inode_fd);
}

static int bus_set_address_capsule(sd_bus *bus, const char *capsule, const char *suffix, int *ret_pin_fd) {
        _cleanup_close_ int inode_fd = -EBADF;
        _cleanup_free_ char *pp = NULL;
        uid_t uid;
        gid_t gid;
        int r;

        assert(bus);
        assert(capsule);
        assert(suffix);
        assert(ret_pin_fd);

        /* Connects to a capsule's user bus. We need to do so under the capsule's UID/GID, otherwise
         * the service manager might refuse our connection. Hence fake it. */

        r = capsule_name_is_valid(capsule);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        inode_fd = pin_capsule_socket(capsule, suffix, &uid, &gid);
        if (inode_fd < 0)
                return inode_fd;

        pp = bus_address_escape(FORMAT_PROC_FD_PATH(inode_fd));
        if (!pp)
                return -ENOMEM;

        if (asprintf(&bus->address, "unix:path=%s,uid=" UID_FMT ",gid=" GID_FMT, pp, uid, gid) < 0)
                return -ENOMEM;

        *ret_pin_fd = TAKE_FD(inode_fd); /* This fd must be kept pinned until the connection has been established */
        return 0;
}

int bus_set_address_capsule_bus(sd_bus *bus, const char *capsule, int *ret_pin_fd) {
        return bus_set_address_capsule(bus, capsule, "bus", ret_pin_fd);
}
