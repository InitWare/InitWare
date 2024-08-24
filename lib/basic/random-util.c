/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include "svc-config.h"

#include "errno-util.h"
#include "io-util.h"
#include "process-util.h"
#include "random-util.h"
#include "sha256.h"

#ifdef SVC_PLATFORM_Linux
#include <linux/random.h>
#endif

#if HAVE_SYS_AUXV_H
#  include <sys/auxv.h>
#endif

/* This is a "best effort" kind of thing, but has no real security value.  So, this should only be used by
 * random_bytes(), which is not meant for crypto. This could be made better, but we're *not* trying to roll a
 * userspace prng here, or even have forward secrecy, but rather just do the shortest thing that is at least
 * better than libc rand(). */
static void fallback_random_bytes(void *p, size_t n) {
        static thread_local uint64_t fallback_counter = 0;
        struct {
                char label[32];
                uint64_t call_id, block_id;
                usec_t stamp_mono, stamp_real;
                pid_t pid, tid;
                uint8_t auxval[16];
        } state = {
                /* Arbitrary domain separation to prevent other usage of AT_RANDOM from clashing. */
                .label = "systemd fallback random bytes v1",
                .call_id = fallback_counter++,
                .stamp_mono = now(CLOCK_MONOTONIC),
                .stamp_real = now(CLOCK_REALTIME),
                .pid = getpid_cached(),
                .tid = gettid(),
        };

#if HAVE_SYS_AUXV_H
        memcpy(state.auxval, ULONG_TO_PTR(getauxval(AT_RANDOM)), sizeof(state.auxval));
#endif

        while (n > 0) {
                struct sha256_ctx ctx;

                sha256_init_ctx(&ctx);
                sha256_process_bytes(&state, sizeof(state), &ctx);
                if (n < SHA256_DIGEST_SIZE) {
                        uint8_t partial[SHA256_DIGEST_SIZE];
                        sha256_finish_ctx(&ctx, partial);
                        memcpy(p, partial, n);
                        break;
                }
                sha256_finish_ctx(&ctx, p);
                p = (uint8_t *) p + SHA256_DIGEST_SIZE;
                n -= SHA256_DIGEST_SIZE;
                ++state.block_id;
        }
}

void random_bytes(void *p, size_t n) {
        static bool have_getrandom = true, have_grndinsecure = true;
        _cleanup_close_ int fd = -EBADF;

        if (n == 0)
                return;

        for (;;) {
                ssize_t l;

                if (!have_getrandom)
                        break;

                l = getrandom(p, n, have_grndinsecure ? GRND_INSECURE : GRND_NONBLOCK);
                if (l > 0) {
                        if ((size_t) l == n)
                                return; /* Done reading, success. */
                        p = (uint8_t *) p + l;
                        n -= l;
                        continue; /* Interrupted by a signal; keep going. */
                } else if (l == 0)
                        break; /* Weird, so fallback to /dev/urandom. */
                else if (ERRNO_IS_NOT_SUPPORTED(errno)) {
                        have_getrandom = false;
                        break; /* No syscall, so fallback to /dev/urandom. */
                } else if (errno == EINVAL && have_grndinsecure) {
                        have_grndinsecure = false;
                        continue; /* No GRND_INSECURE; fallback to GRND_NONBLOCK. */
                } else if (errno == EAGAIN && !have_grndinsecure)
                        break; /* Will block, but no GRND_INSECURE, so fallback to /dev/urandom. */

                break; /* Unexpected, so just give up and fallback to /dev/urandom. */
        }

        fd = open("/dev/urandom", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd >= 0 && loop_read_exact(fd, p, n, false) == 0)
                return;

        /* This is a terrible fallback. Oh well. */
        fallback_random_bytes(p, n);
}
