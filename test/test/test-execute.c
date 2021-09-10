/***
  This file is part of systemd.

  Copyright 2014 Ronny Chevalier

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

#include <grp.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/types.h>

#include "unit.h"
#include "manager.h"
#include "util.h"
#include "macro.h"
#include "strv.h"
#include "mkdir.h"
#include "path-util.h"

typedef void (*test_function_t)(Manager *m);

static void check(Manager *m, Unit *unit, int status_expected, int code_expected) {
        Service *service = NULL;
        usec_t ts;
        usec_t timeout = 2 * USEC_PER_SEC;

        assert_se(m);
        assert_se(unit);

        service = SERVICE(unit);
        printf("%s\n", unit->id);
        exec_context_dump(&service->exec_context, stdout, "\t");
        ts = now(CLOCK_MONOTONIC);
        while (service->state != SERVICE_DEAD && service->state != SERVICE_FAILED) {
                int r;
                usec_t n;

                r = sd_event_run(m->event, 100 * USEC_PER_MSEC);
                assert_se(r >= 0);

                n = now(CLOCK_MONOTONIC);
                if (ts + timeout < n) {
                        log_error("Test timeout when testing %s", unit->id);
                        exit(EXIT_FAILURE);
                }
        }
        exec_status_dump(&service->main_exec_status, stdout, "\t");
        assert_se(service->main_exec_status.status == status_expected);
        assert_se(service->main_exec_status.code == code_expected);
}

static void test(Manager *m, const char *unit_name, int status_expected, int code_expected) {
        Unit *unit;

        assert_se(unit_name);

        assert_se(manager_load_unit(m, unit_name, NULL, NULL, &unit) >= 0);
        assert_se(UNIT_VTABLE(unit)->start(unit) >= 0);
        check(m, unit, status_expected, code_expected);
}

static void test_exec_workingdirectory(Manager *m) {
        assert_se(mkdir_p("/tmp/test-exec_workingdirectory", 0755) >= 0);

        test(m, "exec-workingdirectory.service", 0, CLD_EXITED);

        rm_rf_dangerous("/tmp/test-exec_workingdirectory", false, true, false);
}

static void test_exec_personality(Manager *m) {
#if defined(__x86_64__)
        test(m, "exec-personality-x86-64.service", 0, CLD_EXITED);

#elif defined(__s390__)
        test(m, "exec-personality-s390.service", 0, CLD_EXITED);

#elif defined(__powerpc64__)
        test(m, "exec-personality-ppc64.service", 0, CLD_EXITED);

#elif defined(__aarch64__)
        test(m, "exec-personality-aarch64.service", 0, CLD_EXITED);

#else
        test(m, "exec-personality-x86.service", 0, CLD_EXITED);
#endif
}

static void test_exec_ignoresigpipe(Manager *m) {
        test(m, "exec-ignoresigpipe-yes.service", 0, CLD_EXITED);
        test(m, "exec-ignoresigpipe-no.service", SIGPIPE, CLD_KILLED);
}

static void test_exec_privatetmp(Manager *m) {
        assert_se(touch("/tmp/test-exec_privatetmp") >= 0);

        test(m, "exec-privatetmp-yes.service", 0, CLD_EXITED);
        test(m, "exec-privatetmp-no.service", 0, CLD_EXITED);

        unlink("/tmp/test-exec_privatetmp");
}

static void test_exec_privatedevices(Manager *m) {
        test(m, "exec-privatedevices-yes.service", 0, CLD_EXITED);
        test(m, "exec-privatedevices-no.service", 0, CLD_EXITED);
}

static void test_exec_systemcallfilter(Manager *m) {
#ifdef HAVE_SECCOMP
        test(m, "exec-systemcallfilter-not-failing.service", 0, CLD_EXITED);
        test(m, "exec-systemcallfilter-not-failing2.service", 0, CLD_EXITED);
        test(m, "exec-systemcallfilter-failing.service", SIGSYS, CLD_KILLED);
        test(m, "exec-systemcallfilter-failing2.service", SIGSYS, CLD_KILLED);
#endif
}

static void test_exec_systemcallerrornumber(Manager *m) {
#ifdef HAVE_SECCOMP
        test(m, "exec-systemcallerrornumber.service", 1, CLD_EXITED);
#endif
}

static void test_exec_user(Manager *m) {
        test(m, "exec-user.service", 0, CLD_EXITED);
}

static void test_exec_group(Manager *m) {
        test(m, "exec-group.service", 0, CLD_EXITED);
}

static void test_exec_environment(Manager *m) {
        test(m, "exec-environment.service", 0, CLD_EXITED);
        test(m, "exec-environment-multiple.service", 0, CLD_EXITED);
        test(m, "exec-environment-empty.service", 0, CLD_EXITED);
}

static void test_exec_passenvironment(Manager *m) {
        /* test-execute runs under MANAGER_USER which, by default, forwards all
         * variables present in the environment, but only those that are
         * present _at the time it is created_!
         *
         * So these PassEnvironment checks are still expected to work, since we
         * are ensuring the variables are not present at manager creation (they
         * are unset explicitly in main) and are only set here.
         *
         * This is still a good approximation of how a test for MANAGER_SYSTEM
         * would work.
         */
        assert_se(setenv("VAR1", "word1 word2", 1) == 0);
        assert_se(setenv("VAR2", "word3", 1) == 0);
        assert_se(setenv("VAR3", "$word 5 6", 1) == 0);
        test(m, "exec-passenvironment.service", 0, CLD_EXITED);
        test(m, "exec-passenvironment-repeated.service", 0, CLD_EXITED);
        test(m, "exec-passenvironment-empty.service", 0, CLD_EXITED);
        assert_se(unsetenv("VAR1") == 0);
        assert_se(unsetenv("VAR2") == 0);
        assert_se(unsetenv("VAR3") == 0);
        test(m, "exec-passenvironment-absent.service", 0, CLD_EXITED);
}

static void test_exec_umask(Manager *m) {
        test(m, "exec-umask-default.service", 0, CLD_EXITED);
        test(m, "exec-umask-0177.service", 0, CLD_EXITED);
}

static void test_exec_runtimedirectory(Manager *m) {
        test(m, "exec-runtimedirectory.service", 0, CLD_EXITED);
        test(m, "exec-runtimedirectory-mode.service", 0, CLD_EXITED);
        test(m, "exec-runtimedirectory-owner.service", 0, CLD_EXITED);
}

static void test_exec_capabilityboundingset(Manager *m) {
        int r;

        r = find_binary("capsh", true, NULL);
        if (r < 0) {
                log_error_errno(r, "Skipping %s, could not find capsh binary: %m", __func__);
                return;
        }

        test(m, "exec-capabilityboundingset-simple.service", 0, CLD_EXITED);
        test(m, "exec-capabilityboundingset-reset.service", 0, CLD_EXITED);
        test(m, "exec-capabilityboundingset-merge.service", 0, CLD_EXITED);
        test(m, "exec-capabilityboundingset-invert.service", 0, CLD_EXITED);
}

static void test_exec_capabilityambientset(Manager *m) {
        int r;

        /* Check if the kernel has support for ambient capabilities. Run
         * the tests only if that's the case. Clearing all ambient
         * capabilities is fine, since we are expecting them to be unset
         * in the first place for the tests. */
        r = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
        if (r >= 0 || errno != EINVAL) {
                if (getpwnam("nobody")) {
                        test(m, "exec-capabilityambientset.service", 0, CLD_EXITED);
                        test(m, "exec-capabilityambientset-merge.service", 0, CLD_EXITED);
                } else if (getpwnam("nfsnobody")) {
                        test(m, "exec-capabilityambientset-nfsnobody.service", 0, CLD_EXITED);
                        test(m, "exec-capabilityambientset-merge-nfsnobody.service", 0, CLD_EXITED);
                } else
                        log_error_errno(errno, "Skipping %s, could not find nobody/nfsnobody user: %m", __func__);
        } else
                log_error_errno(errno, "Skipping %s, the kernel does not support ambient capabilities: %m", __func__);
}

int main(int argc, char *argv[]) {
        test_function_t tests[] = {
                test_exec_workingdirectory,
                test_exec_personality,
                test_exec_ignoresigpipe,
                test_exec_privatetmp,
                test_exec_privatedevices,
                test_exec_systemcallfilter,
                test_exec_systemcallerrornumber,
                test_exec_user,
                test_exec_group,
                test_exec_environment,
                test_exec_passenvironment,
                test_exec_umask,
                test_exec_runtimedirectory,
                test_exec_capabilityboundingset,
                test_exec_capabilityambientset,
                NULL,
        };
        test_function_t *test = NULL;
        Manager *m = NULL;
        int r;

        log_parse_environment();
        log_open();

        /* It is needed otherwise cgroup creation fails */
        if (getuid() != 0) {
                printf("Skipping test: not root\n");
                return EXIT_TEST_SKIP;
        }

        assert_se(setenv("XDG_RUNTIME_DIR", "/tmp/", 1) == 0);
        assert_se(set_unit_path(TEST_DIR ":") >= 0);

        /* Unset VAR1, VAR2 and VAR3 which are used in the PassEnvironment test
         * cases, otherwise (and if they are present in the environment),
         * `manager_default_environment` will copy them into the default
         * environment which is passed to each created job, which will make the
         * tests that expect those not to be present to fail.
         */
        assert_se(unsetenv("VAR1") == 0);
        assert_se(unsetenv("VAR2") == 0);
        assert_se(unsetenv("VAR3") == 0);

        r = manager_new(SYSTEMD_USER, true, &m);
        if (IN_SET(r, -EPERM, -EACCES, -EADDRINUSE, -EHOSTDOWN, -ENOENT)) {
                printf("Skipping test: manager_new: %s", strerror(-r));
                return EXIT_TEST_SKIP;
        }
        assert_se(r >= 0);
        assert_se(manager_startup(m, NULL, NULL) >= 0);
        m->default_cpu_accounting =
                m->default_memory_accounting =
                m->default_blockio_accounting =
                m->default_tasks_accounting = false;
        m->default_tasks_max = (uint64_t) -1;

        for (test = tests; test && *test; test++)
                (*test)(m);

        manager_free(m);

        return 0;
}
