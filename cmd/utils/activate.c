/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

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

#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <getopt.h>

#include <systemd/sd-daemon.h>

#include "socket-util.h"
#include "build.h"
#include "log.h"
#include "strv.h"
#include "macro.h"

static char** arg_listen = NULL;
static bool arg_accept = false;
static char** arg_args = NULL;
static char** arg_environ = NULL;

static int add_epoll(int epoll_fd, int fd) {
        int r;
        struct epoll_event ev = {EPOLLIN};
        ev.data.fd = fd;

        assert(epoll_fd >= 0);
        assert(fd >= 0);

        r = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
        if (r < 0)
                log_error("Failed to add event on epoll fd:%d for fd:%d: %s",
                          epoll_fd, fd, strerror(-r));
        return r;
}

static int set_nocloexec(int fd) {
        int flags;

        flags = fcntl(fd, F_GETFD);
        if (flags < 0) {
                log_error("Querying flags for fd:%d: %m", fd);
                return -errno;
        }

        if (!(flags & FD_CLOEXEC))
                return 0;

        if (fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC) < 0) {
                log_error("Settings flags for fd:%d: %m", fd);
                return -errno;
        }

        return 0;
}

static int print_socket(const char* desc, int fd) {
        int r;
        SocketAddress addr = {
                .size = sizeof(union sockaddr_union),
                .type = SOCK_STREAM,
        };
        int family;

        r = getsockname(fd, &addr.sockaddr.sa, &addr.size);
        if (r < 0) {
                log_warning("Failed to query socket on fd:%d: %m", fd);
                return 0;
        }

        family = socket_address_family(&addr);
        switch(family) {
        case AF_INET:
        case AF_INET6: {
                char* _cleanup_free_ a = NULL;
                r = socket_address_print(&addr, &a);
                if (r < 0)
                        log_warning("socket_address_print(): %s", strerror(-r));
                else
                        log_info("%s %s address %s",
                                 desc,
                                 family == AF_INET ? "IP" : "IPv6",
                                 a);
                break;
        }
        default:
                log_warning("Connection with unknown family %d", family);
        }

        return 0;
}

static int open_sockets(int *epoll_fd, bool accept) {
        int n, fd;
        int count = 0;
        char **address;

        n = sd_listen_fds(true);
        if (n < 0) {
                log_error("Failed to read listening file descriptors from environment: %s",
                          strerror(-n));
                return n;
        }
        log_info("Received %d descriptors", n);

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
                log_debug("Received descriptor fd:%d", fd);
                print_socket("Listening on", fd);

                if (!arg_accept) {
                        int r = set_nocloexec(fd);
                        if (r < 0)
                                return r;
                }

                count ++;
        }

        /* Close logging and all other descriptors */
        if (arg_listen) {
                int except[3 + n];

                for (fd = 0; fd < SD_LISTEN_FDS_START + n; fd++)
                        except[fd] = fd;

                log_close();
                close_all_fds(except, 3 + n);
        }

        /** Note: we leak some fd's on error here. I doesn't matter
         *  much, since the program will exit immediately anyway, but
         *  would be a pain to fix.
         */

        STRV_FOREACH(address, arg_listen) {
                log_info("Opening address %s", *address);

                fd = make_socket_fd(*address, SOCK_STREAM);
                if (fd < 0) {
                        log_open();
                        log_error("Failed to open '%s': %s", *address, strerror(-fd));
                        return fd;
                }

		if (arg_accept) {
			r = fd_cloexec(fd, true);

			if (r < 0) {
				log_error_errno(-r, "Failed to set cloexec or nonblock: %m");
				close(fd);
				return r;
			}
		}

		count ++;
        }

        if (arg_listen)
                log_open();

        *epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (*epoll_fd < 0) {
                log_error("Failed to create epoll object: %m");
                return -errno;
        }

        for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + count; fd++) {
                int r = add_epoll(*epoll_fd, fd);
                if (r < 0)
                        return r;
        }

        return count;
}

static int launch(char* name, char **argv, char **env, int fds) {
        unsigned n_env = 0, length;
        _cleanup_strv_free_ char **envp = NULL;
        char **s;
        static const char* tocopy[] = {"TERM=", "PATH=", "USER=", "HOME="};
        _cleanup_free_ char *tmp = NULL;
        unsigned i;

        length = strv_length(arg_environ);
        /* PATH, TERM, HOME, USER, LISTEN_FDS, LISTEN_PID, NULL */
        envp = new(char *, length + 7);

        STRV_FOREACH(s, arg_environ) {
                if (strchr(*s, '='))
                        envp[n_env++] = *s;
                else {
                        _cleanup_free_ char *p = strappend(*s, "=");
                        if (!p)
                                return log_oom();
                        envp[n_env] = strv_find_prefix(env, p);
                        if (envp[n_env])
                                n_env ++;
                }
        }

        for (i = 0; i < ELEMENTSOF(tocopy); i++) {
                envp[n_env] = strv_find_prefix(env, tocopy[i]);
                if (envp[n_env])
                        n_env ++;
        }

        if ((asprintf((char**)(envp + n_env++), "LISTEN_FDS=%d", fds) < 0) ||
            (asprintf((char**)(envp + n_env++), "LISTEN_PID=%d", getpid()) < 0))
                return log_oom();

        tmp = strv_join(argv, " ");
        if (!tmp)
                return log_oom();

        log_info("Execing %s (%s)", name, tmp);
        execvpe(name, argv, envp);
        log_error("Failed to execp %s (%s): %m", name, tmp);
        return -errno;
}

static int launch1(const char* child, char** argv, char **env, int fd) {
        pid_t parent_pid, child_pid;
        int r;

        _cleanup_free_ char *tmp = NULL;
        tmp = strv_join(argv, " ");
        if (!tmp)
                return log_oom();

        parent_pid = getpid();

        child_pid = fork();
        if (child_pid < 0) {
                log_error("Failed to fork: %m");
                return -errno;
        }

        /* In the child */
        if (child_pid == 0) {
                r = dup2(fd, STDIN_FILENO);
                if (r < 0) {
                        log_error("Failed to dup connection to stdin: %m");
                        _exit(EXIT_FAILURE);
                }

                r = dup2(fd, STDOUT_FILENO);
                if (r < 0) {
                        log_error("Failed to dup connection to stdout: %m");
                        _exit(EXIT_FAILURE);
                }

                r = close(fd);
                if (r < 0) {
                        log_error("Failed to close dupped connection: %m");
                        _exit(EXIT_FAILURE);
                }

                /* Make sure the child goes away when the parent dies */
                if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
                        _exit(EXIT_FAILURE);

                /* Check whether our parent died before we were able
                 * to set the death signal */
                if (getppid() != parent_pid)
                        _exit(EXIT_SUCCESS);

                execvp(child, argv);
                log_error("Failed to exec child %s: %m", child);
                _exit(EXIT_FAILURE);
        }

        log_info("Spawned %s (%s) as PID %d", child, tmp, child_pid);

        return 0;
}

static int do_accept(const char* name, char **argv, char **envp, int fd) {
        SocketAddress addr = {
                .size = sizeof(union sockaddr_union),
                .type = SOCK_STREAM,
        };
        int fd2, r;

        fd2 = accept(fd, &addr.sockaddr.sa, &addr.size);
        if (fd2 < 0) {
                log_error("Failed to accept connection on fd:%d: %m", fd);
                return fd2;
        }

        print_socket("Connection from", fd2);

        r = launch1(name, argv, envp, fd2);
        return r;
}

/* SIGCHLD handler. */
static void sigchld_hdl(int sig, siginfo_t *t, void *data) {
        log_info("Child %d died with code %d", t->si_pid, t->si_status);
        /* Wait for a dead child. */
        waitpid(t->si_pid, NULL, 0);
}

static int install_chld_handler(void) {
        int r;
        struct sigaction act = {
                .sa_flags = SA_SIGINFO,
                .sa_sigaction = sigchld_hdl,
        };

        r = sigaction(SIGCHLD, &act, 0);
        if (r < 0)
                log_error("Failed to install SIGCHLD handler: %m");
        return r;
}

static int help(void) {
        printf("%s [OPTIONS...]\n\n"
               "Listen on sockets and launch child on connection.\n\n"
               "Options:\n"
               "  -l --listen=ADDR     Listen for raw connections at ADDR\n"
               "  -a --accept          Spawn separate child for each connection\n"
               "  -h --help            Show this help and exit\n"
               "  -E --environment=NAME[=VALUE]\n"
               "                       Pass an environment variable to children\n"
               "  --version            Print version string and exit\n"
               "\n"
               "Note: file descriptors from sd_listen_fds() will be passed through.\n"
               , program_invocation_short_name
               );

        return 0;
}

static int parse_argv(int argc, char *argv[]) {
        enum {
                ARG_VERSION = 0x100,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'           },
                { "version",      no_argument,       NULL, ARG_VERSION   },
                { "listen",       required_argument, NULL, 'l'           },
                { "accept",       no_argument,       NULL, 'a'           },
                { "environment",  required_argument, NULL, 'E'           },
                { NULL,           0,                 NULL, 0             }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hl:aE:", options, NULL)) >= 0)
                switch(c) {
                case 'h':
                        help();
                        return 0 /* done */;

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0 /* done */;

                case 'l': {
                        int r = strv_extend(&arg_listen, optarg);
                        if (r < 0)
                                return r;

                        break;
                }

                case 'a':
                        arg_accept = true;
                        break;

                case 'E': {
                        int r = strv_extend(&arg_environ, optarg);
                        if (r < 0)
                                return r;

                        break;
                }

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }

        if (optind == argc) {
                log_error("Usage: %s [OPTION...] PROGRAM [OPTION...]",
                          program_invocation_short_name);
                return -EINVAL;
        }

        arg_args = argv + optind;

        return 1 /* work to do */;
}

int main(int argc, char **argv, char **envp) {
        int r, n;
        int epoll_fd = -1;

        log_set_max_level(LOG_DEBUG);
        log_show_color(true);
        log_parse_environment();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r == 0 ? EXIT_SUCCESS : EXIT_FAILURE;

        r = install_chld_handler();
        if (r < 0)
                return EXIT_FAILURE;

        n = open_sockets(&epoll_fd, arg_accept);
        if (n < 0)
                return EXIT_FAILURE;

        while (true) {
                struct epoll_event event;

                r = epoll_wait(epoll_fd, &event, 1, -1);
                if (r < 0) {
                        if (errno == EINTR)
                                continue;

                        log_error("epoll_wait() failed: %m");
                        return EXIT_FAILURE;
                }

                log_info("Communication attempt on fd:%d", event.data.fd);
                if (arg_accept) {
                        r = do_accept(argv[optind], argv + optind, envp,
                                      event.data.fd);
                        if (r < 0)
                                return EXIT_FAILURE;
                } else
                        break;
        }

        launch(argv[optind], argv + optind, envp, n);

        return EXIT_SUCCESS;
}
