#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <sys/types.h>
#include <sys/inotify.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "bsdglob.h"
#include "bsdstatfs.h"
#include "bsducred.h"
#include "def.h"
#include "log.h"
#include "terminal-util.h"

#ifdef HAVE_alloca_h
#include <alloca.h>
#endif

#ifdef HAVE_mntent_h
#include <mntent.h>
#endif

#ifdef HAVE_sys_sysmacros_h
#include <sys/sysmacros.h>
#endif

#if SVC_SIZEOF_PID_T == 4
#define PID_PRI PRIi32
#elif SVC_SIZEOF_PID_T == 2
#define PID_PRI PRIi16
#else
#error Unknown pid_t size
#endif
#define PID_FMT "%" PID_PRI

#if SVC_SIZEOF_UID_T == 4
#define UID_FMT "%" PRIu32
#elif SVC_SIZEOF_UID_T == 2
#define UID_FMT "%" PRIu16
#else
#error Unknown uid_t size
#endif

#if SVC_SIZEOF_GID_T == 4
#define GID_FMT "%" PRIu32
#elif SVC_SIZEOF_GID_T == 2
#define GID_FMT "%" PRIu16
#else
#error Unknown gid_t size
#endif

#if SVC_SIZEOF_TIME_T == 8
#define PRI_TIME PRIi64
#elif SVC_SIZEOF_TIME_T == 4
#define PRI_TIME "li"
#else
#error Unknown time_t size
#endif

#define RLIM_FMT "%" PRIuMAX
static inline uintmax_t
rlim_to_uintmax(rlim_t rlim)
{
	return (uintmax_t)rlim;
}

#include "macro.h"
#include "missing.h"
#include "time-util.h"

#define ANSI_HIGHLIGHT_ON "\x1B[1;39m"
#define ANSI_RED_ON "\x1B[31m"
#define ANSI_HIGHLIGHT_RED_ON "\x1B[1;31m"
#define ANSI_GREEN_ON "\x1B[32m"
#define ANSI_HIGHLIGHT_GREEN_ON "\x1B[1;32m"
#define ANSI_HIGHLIGHT_YELLOW_ON "\x1B[1;33m"
#define ANSI_HIGHLIGHT_BLUE_ON "\x1B[1;34m"
#define ANSI_HIGHLIGHT_OFF "\x1B[0m"
#define ANSI_ERASE_TO_END_OF_LINE "\x1B[K"

/* fdset.c */
#define MAKE_SET(s) ((Set *)s)
#define MAKE_FDSET(s) ((FDSet *)s)

static inline void *
mfree(void *memory)
{
	free(memory);
	return NULL;
}

static inline char *
startswith(const char *s, const char *prefix)
{
	size_t l;

	l = strlen(prefix);
	if (strncmp(s, prefix, l) == 0)
		return (char *)s + l;

	return NULL;
}

static inline char *
startswith_no_case(const char *s, const char *prefix)
{
	size_t l;

	l = strlen(prefix);
	if (strncasecmp(s, prefix, l) == 0)
		return (char *)s + l;

	return NULL;
}

char *endswith(const char *s, const char *postfix) _pure_;

int close_nointr(int fd);
int safe_close(int fd);
void safe_close_pair(int p[]);

void close_many(const int fds[], unsigned n_fd);

int parse_size(const char *t, off_t base, off_t *size);
int parse_range(const char *t, unsigned *lower, unsigned *upper);

int parse_uid(const char *s, uid_t *ret_uid);
#define parse_gid(s, ret_uid) parse_uid(s, ret_uid)

int safe_atou(const char *s, unsigned *ret_u);
int safe_atoi(const char *s, int *ret_i);

int safe_atollu(const char *s, unsigned long long *ret_u);
int safe_atolli(const char *s, long long int *ret_i);

int safe_atod(const char *s, double *ret_d);

int safe_atou8(const char *s, uint8_t *ret);

#if LONG_MAX == INT_MAX
static inline int
safe_atolu(const char *s, unsigned long *ret_u)
{
	assert_cc(sizeof(unsigned long) == sizeof(unsigned));
	return safe_atou(s, (unsigned *)ret_u);
}
static inline int
safe_atoli(const char *s, long int *ret_u)
{
	assert_cc(sizeof(long int) == sizeof(int));
	return safe_atoi(s, (int *)ret_u);
}
#else
static inline int
safe_atolu(const char *s, unsigned long *ret_u)
{
	assert_cc(sizeof(unsigned long) == sizeof(unsigned long long));
	return safe_atollu(s, (unsigned long long *)ret_u);
}
static inline int
safe_atoli(const char *s, long int *ret_u)
{
	assert_cc(sizeof(long int) == sizeof(long long int));
	return safe_atolli(s, (long long int *)ret_u);
}
#endif

static inline int
safe_atou32(const char *s, uint32_t *ret_u)
{
	assert_cc(sizeof(uint32_t) == sizeof(unsigned));
	return safe_atou(s, (unsigned *)ret_u);
}

static inline int
safe_atoi32(const char *s, int32_t *ret_i)
{
	assert_cc(sizeof(int32_t) == sizeof(int));
	return safe_atoi(s, (int *)ret_i);
}

static inline int
safe_atou64(const char *s, uint64_t *ret_u)
{
	assert_cc(sizeof(uint64_t) == sizeof(unsigned long long));
	return safe_atollu(s, (unsigned long long *)ret_u);
}

static inline int
safe_atoi64(const char *s, int64_t *ret_i)
{
	assert_cc(sizeof(int64_t) == sizeof(long long int));
	return safe_atolli(s, (long long int *)ret_i);
}

int safe_atou16(const char *s, uint16_t *ret);
int safe_atoi16(const char *s, int16_t *ret);

const char *split(const char **state, size_t *l, const char *separator,
	bool quoted);

#define FOREACH_WORD(word, length, s, state)                                   \
	_FOREACH_WORD(word, length, s, WHITESPACE, false, state)

#define FOREACH_WORD_SEPARATOR(word, length, s, separator, state)              \
	_FOREACH_WORD(word, length, s, separator, false, state)

#define FOREACH_WORD_QUOTED(word, length, s, state)                            \
	_FOREACH_WORD(word, length, s, WHITESPACE, true, state)

#define _FOREACH_WORD(word, length, s, separator, quoted, state)               \
	for ((state) = (s),                                                    \
	    (word) = split(&(state), &(length), (separator), (quoted));        \
		(word);                                                        \
		(word) = split(&(state), &(length), (separator), (quoted)))

pid_t get_parent_of_pid(pid_t pid, pid_t *ppid);
int pid_is_my_child(pid_t pid);

char *strappend(const char *s, const char *suffix);

char *replace_env(const char *format, char **env);
char **replace_env_argv(char **argv, char **env);

int readlinkat_malloc(int fd, const char *p, char **ret);
int readlink_malloc(const char *p, char **r);
int readlink_value(const char *p, char **ret);
int readlink_and_make_absolute(const char *p, char **r);
int readlink_and_canonicalize(const char *p, char **r);
int readlink_and_make_absolute_root(const char *root, const char *path,
	char **ret);

int reset_all_signal_handlers(void);
int reset_signal_mask(void);

char *strstrip(char *s);
char *delete_chars(char *s, const char *bad);
char *truncate_nl(char *s);

char *file_in_same_dir(const char *path, const char *filename);

int rmdir_parents(const char *path, const char *stop);

int get_process_state(pid_t pid);
int get_process_comm(pid_t pid, char **name);
int get_process_cmdline(pid_t pid, size_t max_length, bool comm_fallback,
	char **line);
int get_process_exe(pid_t pid, char **name);
int get_process_uid(pid_t pid, uid_t *uid);
int get_process_gid(pid_t pid, gid_t *gid);
int get_process_capeff(pid_t pid, char **capeff);
int get_process_cwd(pid_t pid, char **cwd);
int get_process_root(pid_t pid, char **root);
int get_process_environ(pid_t pid, char **environ);

char *xescape(const char *s, const char *bad);

char *ascii_strlower(char *path);

bool dirent_is_file(const struct dirent *de) _pure_;
bool dirent_is_file_with_suffix(const struct dirent *de,
	const char *suffix) _pure_;

bool hidden_file(const char *filename) _pure_;

bool chars_intersect(const char *a, const char *b) _pure_;

int make_stdio(int fd);
int make_null_stdio(void);
int make_console_stdio(void);

// int dev_urandom(void *p, size_t n);
// void random_bytes(void *p, size_t n);
// void initialize_srand(void);

// static inline uint64_t
// random_u64(void)
// {
// 	uint64_t u;
// 	random_bytes(&u, sizeof(u));
// 	return u;
// }

// static inline uint32_t
// random_u32(void)
// {
// 	uint32_t u;
// 	random_bytes(&u, sizeof(u));
// 	return u;
// }

int fd_nonblock(int fd, bool nonblock);
int fd_cloexec(int fd, bool cloexec);

/* Returns true if \p fd is present in the FD array. */
_pure_ bool fd_in_set(int fd, const int fdset[], unsigned n_fdset);
int close_all_fds(const int except[], unsigned n_except);

bool fstype_is_network(const char *fstype);

int chvt(int vt);

int read_one_char(FILE *f, char *ret, usec_t timeout, bool *need_nl);
int ask_char(char *ret, const char *replies, const char *text, ...)
	_printf_(3, 4);
int ask_string(char **ret, const char *text, ...) _printf_(2, 3);

int reset_terminal_fd(int fd, bool switch_to_text);
int reset_terminal(const char *name);

int open_terminal(const char *name, int mode);
int acquire_terminal(const char *name, bool fail, bool force,
	bool ignore_tiocstty_eperm, usec_t timeout);
int release_terminal(void);

int flush_fd(int fd);

int ignore_signals(int sig, ...);
int default_signals(int sig, ...);
int sigaction_many(const struct sigaction *sa, ...);

bool is_device_path(const char *path);

char *dirname_malloc(const char *path);

void rename_process(const char name[8]);

void sigset_add_many(sigset_t *ss, ...);
int sigprocmask_many(int how, ...);

bool hostname_is_set(void);

char *lookup_uid(uid_t uid);
char *getlogname_malloc(void);
char *getusername_malloc(void);

int getttyname_malloc(int fd, char **r);
int getttyname_harder(int fd, char **r);

int get_ctty_devnr(pid_t pid, dev_t *d);
int get_ctty(pid_t, dev_t *_devnr, char **r);

int chmod_and_chown(const char *path, mode_t mode, uid_t uid, gid_t gid);
int fchmod_and_fchown(int fd, mode_t mode, uid_t uid, gid_t gid);

int is_fd_on_temporary_fs(int fd);

// int rm_rf_children(int fd, bool only_dirs, bool honour_sticky,
// 	struct stat *root_dev);
// int rm_rf_children_dangerous(int fd, bool only_dirs, bool honour_sticky,
// 	struct stat *root_dev);
// int rm_rf(const char *path, bool only_dirs, bool delete_root,
// 	bool honour_sticky);
// int rm_rf_dangerous(const char *path, bool only_dirs, bool delete_root,
// 	bool honour_sticky);

/**
 * Check if EOF has been reached on the FD using poll() checking for POLLHUP.
 *
 * @retval 1 if EOF reached
 * @retval 0 if EOF not reached
 * @retval -errno if an error occurred
 */
int pipe_eof(int fd);

#ifdef SVC_PLATFORM_Linux
cpu_set_t *cpu_set_malloc(unsigned *ncpus);
// int parse_cpu_set_and_warn(const char *rvalue, cpu_set_t **cpu_set,
// 	const char *unit, const char *filename, unsigned line,
// 	const char *lvalue);
#endif

int status_vprintf(const char *status, bool ellipse, bool ephemeral,
	const char *format, va_list ap) _printf_(4, 0);
int status_printf(const char *status, bool ellipse, bool ephemeral,
	const char *format, ...) _printf_(4, 5);

#define xsprintf(buf, fmt, ...)                                                \
	assert_se((size_t)snprintf(buf, ELEMENTSOF(buf), fmt, __VA_ARGS__) <   \
		ELEMENTSOF(buf))

int fd_columns(int fd);
unsigned columns(void);
int fd_lines(int fd);
unsigned lines(void);
void columns_lines_cache_reset(int _unused_ signum);

bool on_tty(void);

// static inline const char *
// ansi_highlight(void)
// {
// 	return colors_enabled() ? ANSI_HIGHLIGHT_ON : "";
// }

// static inline const char *
// ansi_highlight_red(void)
// {
// 	return colors_enabled() ? ANSI_HIGHLIGHT_RED_ON : "";
// }

// static inline const char *
// ansi_highlight_green(void)
// {
// 	return colors_enabled() ? ANSI_HIGHLIGHT_GREEN_ON : "";
// }

// static inline const char *
// ansi_highlight_yellow(void)
// {
// 	return colors_enabled() ? ANSI_HIGHLIGHT_YELLOW_ON : "";
// }

// static inline const char *
// ansi_highlight_blue(void)
// {
// 	return colors_enabled() ? ANSI_HIGHLIGHT_BLUE_ON : "";
// }

// static inline const char *
// ansi_highlight_off(void)
// {
// 	return colors_enabled() ? ANSI_HIGHLIGHT_OFF : "";
// }

int files_same(const char *filea, const char *fileb);

int running_in_chroot(void);

int touch_file(const char *path, bool parents, usec_t stamp, uid_t uid,
	gid_t gid, mode_t mode);
int touch(const char *path);

char *unquote(const char *s, const char *quotes);
char *normalize_env_assignment(const char *s);

int wait_for_terminate(pid_t pid, siginfo_t *status);
int wait_for_terminate_and_warn(const char *name, pid_t pid,
	bool check_exit_code);

noreturn void freeze(void);

int null_or_empty_path(const char *fn);
int null_or_empty_fd(int fd);

DIR *xopendirat(int dirfd, const char *name, int flags);

char *fstab_node_to_udev_node(const char *p);

char *resolve_dev_console(char **active);
bool tty_is_vc(const char *tty);
bool tty_is_vc_resolve(const char *tty);
bool tty_is_console(const char *tty) _pure_;
int vtnr_from_tty(const char *tty);
const char *default_term_for_tty(const char *tty);

int kill_and_sigcont(pid_t pid, int sig);

bool nulstr_contains(const char *nulstr, const char *needle);

bool plymouth_running(void);

bool machine_name_is_valid(const char *s) _pure_;

char *strshorten(char *s, size_t l);

int terminal_vhangup_fd(int fd);
int terminal_vhangup(const char *name);

// int vt_disallocate(const char *name);

int fchmod_umask(int fd, mode_t mode);

bool display_is_local(const char *display) _pure_;
int socket_from_display(const char *display, char **path);

int get_user_creds(const char **username, uid_t *uid, gid_t *gid,
	const char **home, const char **shell);
int get_group_creds(const char **groupname, gid_t *gid);

int in_gid(gid_t gid);
int in_group(const char *name);

char *uid_to_name(uid_t uid);
char *gid_to_name(gid_t gid);

int glob_exists(const char *path);
int glob_extend(char ***strv, const char *path);
int safe_glob(const char *path, int flags, glob_t *pglob);

char *strjoin(const char *x, ...) _sentinel_;

bool is_main_thread(void);

static inline bool _pure_
in_charset(const char *s, const char *charset)
{
	assert(s);
	assert(charset);
	return s[strspn(s, charset)] == '\0';
}

int block_get_whole_disk(dev_t d, dev_t *ret);

int ioprio_class_to_string_alloc(int i, char **s);
int ioprio_class_from_string(const char *s);

const char *sigchld_code_to_string(int i) _const_;
int sigchld_code_from_string(const char *s) _pure_;

int log_facility_unshifted_to_string_alloc(int i, char **s);
int log_facility_unshifted_from_string(const char *s);

int log_level_to_string_alloc(int i, char **s);
int log_level_from_string(const char *s);

int sched_policy_to_string_alloc(int i, char **s);
int sched_policy_from_string(const char *s);

const char *rlimit_to_string(int i) _const_;
int rlimit_from_string(const char *s) _pure_;

int ip_tos_to_string_alloc(int i, char **s);
int ip_tos_from_string(const char *s);

const char *signal_to_string(int i) _const_;
int signal_from_string(const char *s) _pure_;

int signal_from_string_try_harder(const char *s);

bool kexec_loaded(void);

int prot_from_flags(int flags) _const_;

int fd_wait_for_event(int fd, int event, usec_t timeout);

int is_kernel_thread(pid_t pid);

int fork_agent(pid_t *pid, const int except[], unsigned n_except,
	const char *path, ...);

int setrlimit_closest(int resource, const struct rlimit *rlim);

int getenv_for_pid(pid_t pid, const char *field, char **_value);

bool http_url_is_valid(const char *url) _pure_;
bool documentation_url_is_valid(const char *url) _pure_;

bool http_etag_is_valid(const char *etag);

bool in_initrd(void);

void warn_melody(void);

int get_home_dir(char **ret);
int get_shell(char **_ret);

static inline void
closep(int *fd)
{
	safe_close(*fd);
}

static inline void
close_pairp(int (*p)[2])
{
	safe_close_pair(*p);
}

DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(FILE *, fclose, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(FILE*, pclose, NULL);
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(DIR*, closedir, NULL);
#ifdef SVC_PLATFORM_Linux
DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(FILE *, endmntent, NULL);
// REPLACED IN cpu-set-util. steal if needed?
// DEFINE_TRIVIAL_CLEANUP_FUNC_FULL(cpu_set_t *, CPU_FREE, NULL);
#endif

#define _cleanup_free_ _cleanup_(freep)
#define _cleanup_close_ _cleanup_(closep)
#define _cleanup_globfree_ _cleanup_(globfree)
#define _cleanup_fclose_ _cleanup_(fclosep)
#define _cleanup_pclose_ _cleanup_(pclosep)
#define _cleanup_closedir_ _cleanup_(closedirp)
#define _cleanup_close_pair_ _cleanup_(close_pairp)
#ifdef SVC_PLATFORM_Linux
#define _cleanup_endmntent_ _cleanup_(endmntentp)
#define _cleanup_cpu_free_ _cleanup_(CPU_FREEp)
#endif

_alloc_(2, 3) static inline void *realloc_multiply(void *p, size_t a, size_t b)
{
	if (_unlikely_(b != 0 && a > ((size_t)-1) / b))
		return NULL;

	return realloc(p, a * b);
}

bool string_is_safe(const char *p) _pure_;
bool string_has_cc(const char *p, const char *ok) _pure_;

void *xbsearch_r(const void *key, const void *base, size_t nmemb, size_t size,
	int (*compar)(const void *, const void *, void *), void *arg);

bool is_locale_utf8(void);

typedef enum DrawSpecialChar {
	DRAW_TREE_VERTICAL,
	DRAW_TREE_BRANCH,
	DRAW_TREE_RIGHT,
	DRAW_TREE_SPACE,
	DRAW_TRIANGULAR_BULLET,
	DRAW_BLACK_CIRCLE,
	DRAW_ARROW,
	DRAW_DASH,
	_DRAW_SPECIAL_CHAR_MAX
} DrawSpecialChar;

const char *draw_special_char(DrawSpecialChar ch);

char *strip_tab_ansi(char **p, size_t *l);

int on_ac_power(void);

int search_and_fopen(const char *path, const char *mode, const char *root,
	const char **search, FILE **_f);
int search_and_fopen_nulstr(const char *path, const char *mode,
	const char *root, const char *search, FILE **_f);

#define FOREACH_LINE(line, f, on_error)                                        \
	for (;;)                                                               \
		if (!fgets(line, sizeof(line), f)) {                           \
			if (ferror(f)) {                                       \
				on_error;                                      \
			}                                                      \
			break;                                                 \
		} else

// #define FOREACH_DIRENT(de, d, on_error)                                        \
// 	for (errno = 0, de = readdir(d);; errno = 0, de = readdir(d))          \
// 		if (!de) {                                                     \
// 			if (errno > 0) {                                       \
// 				on_error;                                      \
// 			}                                                      \
// 			break;                                                 \
// 		} else if (hidden_file((de)->d_name))                          \
// 			continue;                                              \
// 		else

// #define FOREACH_DIRENT_ALL(de, d, on_error)                                    \
// 	for (errno = 0, de = readdir(d);; errno = 0, de = readdir(d))          \
// 		if (!de) {                                                     \
// 			if (errno > 0) {                                       \
// 				on_error;                                      \
// 			}                                                      \
// 			break;                                                 \
// 		} else

char *strextend(char **x, ...) _sentinel_;
char *strrep(const char *s, unsigned n);

struct _umask_struct_ {
	mode_t mask;
	bool quit;
};

static inline void
_reset_umask_(struct _umask_struct_ *s)
{
	umask(s->mask);
};

#define RUN_WITH_UMASK(mask)                                                   \
	for (_cleanup_(_reset_umask_) struct _umask_struct_                    \
			_saved_umask_ = { umask(mask), false };                \
		!_saved_umask_.quit; _saved_umask_.quit = true)

static inline unsigned
u64log2(uint64_t n)
{
#if __SIZEOF_LONG_LONG__ == 8
	return (n > 1) ? (unsigned)__builtin_clzll(n) ^ 63U : 0;
#else
#error "Wut?"
#endif
}

static inline bool
logind_running(void)
{
	return access(SVC_PKGRUNSTATEDIR "/seats/", F_OK) >= 0;
}

#define DECIMAL_STR_WIDTH(x)                                                   \
	({                                                                     \
		typeof(x) _x_ = (x);                                           \
		unsigned ans = 1;                                              \
		while (_x_ /= 10)                                              \
			ans++;                                                 \
		ans;                                                           \
	})

int unlink_noerrno(const char *path);

#define strjoina(a, ...)                                                       \
	({                                                                     \
		const char *_appendees_[] = { a, __VA_ARGS__ };                \
		char *_d_, *_p_;                                               \
		int _len_ = 0;                                                 \
		unsigned _i_;                                                  \
		for (_i_ = 0;                                                  \
			_i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_];     \
			_i_++)                                                 \
			_len_ += strlen(_appendees_[_i_]);                     \
		_p_ = _d_ = alloca(_len_ + 1);                                 \
		for (_i_ = 0;                                                  \
			_i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_];     \
			_i_++)                                                 \
			_p_ = stpcpy(_p_, _appendees_[_i_]);                   \
		*_p_ = 0;                                                      \
		_d_;                                                           \
	})

#define procfs_file_alloca(pid, field)                                         \
	({                                                                     \
		pid_t _pid_ = (pid);                                           \
		const char *_r_;                                               \
		if (_pid_ == 0) {                                              \
			_r_ = ("/proc/self/" field);                           \
		} else {                                                       \
			_r_ = alloca(strlen("/proc/") +                        \
				DECIMAL_STR_MAX(pid_t) + 1 + sizeof(field));   \
			sprintf((char *)_r_, "/proc/" PID_FMT "/" field,       \
				_pid_);                                        \
		}                                                              \
		_r_;                                                           \
	})

bool id128_is_valid(const char *s) _pure_;

int split_pair(const char *s, const char *sep, char **l, char **r);

int shall_restore_state(void);

/**
 * Normal qsort requires base to be nonnull. Here were require
 * that only if nmemb > 0.
 */
static inline void
qsort_safe(void *base, size_t nmemb, size_t size,
	int (*compar)(const void *, const void *))
{
	if (nmemb) {
		assert(base);
		qsort(base, nmemb, size, compar);
	}
}

int proc_cmdline(char **ret);
int parse_proc_cmdline(int (*parse_word)(const char *key, const char *value));
int get_proc_cmdline_key(const char *parameter, char **value);

// int container_get_leader(const char *machine, pid_t *pid);

int namespace_open(pid_t pid, int *pidns_fd, int *mntns_fd, int *netns_fd,
	int *root_fd);
int namespace_enter(int pidns_fd, int mntns_fd, int netns_fd, int root_fd);

bool pid_is_alive(pid_t pid);
bool pid_is_unwaited(pid_t pid);

int getpeercred(int fd, struct socket_ucred *ucred);
int getpeersec(int fd, char **ret);

int writev_safe(int fd, const struct iovec *w, int j);

int open_tmpfile(const char *path, int flags);

int fd_warn_permissions(const char *path, int fd);

unsigned long personality_from_string(const char *p);
const char *personality_to_string(unsigned long);

uint64_t physical_memory(void);

void hexprint(FILE *f, const void *p, size_t s);

#ifdef SVC_PLATFORM_Linux
union file_handle_union {
	struct file_handle handle;
	char padding[sizeof(struct file_handle) + MAX_HANDLE_SZ];
};
#define FILE_HANDLE_INIT                                                       \
	{                                                                      \
		.handle.handle_bytes = MAX_HANDLE_SZ                           \
	}
#endif

int update_reboot_param_file(const char *param);

// int umount_recursive(const char *target, int flags);

// int bind_remount_recursive(const char *prefix, bool ro);

int fflush_and_check(FILE *f);

bool is_localhost(const char *hostname);

int take_password_lock(const char *root);

int is_symlink(const char *path);
int is_dir(const char *path, bool follow);

int unquote_first_word(const char **p, char **ret, bool relax);
int unquote_many_words(const char **p, ...) _sentinel_;

int sethostname_idempotent(const char *s);

#if defined(SVC_PLATFORM_NetBSD) || defined(SVC_PLATFORM_Linux)
#define laccess(path, mode)                                                    \
	faccessat(AT_FDCWD, (path), (mode), AT_SYMLINK_NOFOLLOW)
#else
/* AT_SYMLINK_NOFOLLOW doesn't work with faccessat() on at least FreeBSD */
#define laccess(path, mode) faccessat(AT_FDCWD, (path), (mode), 0)
#endif

int ptsname_malloc(int fd, char **ret);

int openpt_in_namespace(pid_t pid, int flags);

ssize_t fgetxattrat_fake(int dirfd, const char *filename, const char *attribute,
	void *value, size_t size, int flags);

int fd_setcrtime(int fd, usec_t usec);
int fd_getcrtime(int fd, usec_t *usec);
int path_getcrtime(const char *p, usec_t *usec);
int fd_getcrtime_at(int dirfd, const char *name, usec_t *usec, int flags);

int same_fd(int a, int b);

int chattr_fd(int fd, bool b, unsigned mask);
int chattr_path(const char *p, bool b, unsigned mask);

int read_attr_fd(int fd, unsigned *ret);
int read_attr_path(const char *p, unsigned *ret);

#define _cleanup_release_lock_file_ _cleanup_(release_lock_file)

#define LOCK_FILE_INIT                                                         \
	{                                                                      \
		.fd = -1, .path = NULL                                         \
	}

#define RLIMIT_MAKE_CONST(lim) ((struct rlimit){ lim, lim })

ssize_t sparse_write(int fd, const void *p, size_t sz, size_t run_length);

void sigkill_wait(pid_t *pid);
#define _cleanup_sigkill_wait_ _cleanup_(sigkill_wait)

int syslog_parse_priority(const char **p, int *priority, bool with_facility);

void cmsg_close_all(struct msghdr *mh);

char *shell_maybe_quote(const char *s);

int parse_percent_unbounded(const char *p);
int parse_percent(const char *p);

uint64_t system_tasks_max(void);
uint64_t system_tasks_max_scale(uint64_t v, uint64_t max);

int wait_for_terminate_with_timeout(pid_t pid, usec_t timeout);

static inline void
block_signals_reset(sigset_t *ss)
{
	assert_se(sigprocmask(SIG_SETMASK, ss, NULL) >= 0);
}

#define BLOCK_SIGNALS(...)                                                     \
	_cleanup_(block_signals_reset) _unused_ sigset_t _saved_sigset = ({    \
		sigset_t _t;                                                   \
		assert_se(sigprocmask(SIG_SETMASK, NULL, &_t) == 0);           \
		assert_se(sigprocmask_many(SIG_BLOCK, __VA_ARGS__, -1) >= 0);  \
		_t;                                                            \
	})

#define IOVEC_INIT(base, len)                                                  \
	{                                                                      \
		.iov_base = (base), .iov_len = (len)                           \
	}
#define IOVEC_MAKE(base, len) (struct iovec) IOVEC_INIT(base, len)
#define IOVEC_INIT_STRING(string) IOVEC_INIT((char *)string, strlen(string))
#define IOVEC_MAKE_STRING(string) (struct iovec) IOVEC_INIT_STRING(string)

char *set_iovec_string_field(struct iovec *iovec, unsigned int *n_iovec,
	const char *field, const char *value);
char *set_iovec_field_free(struct iovec *iovec, unsigned int *n_iovec,
	const char *field, char *value);
