#pragma once

/***
  This file is part of systemd.

  Copyright 2010-2012 Lennart Poettering

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

#include <stdbool.h>

#include "macro.h"
#include "string-util.h"
#include "time-util.h"

#define PATH_SPLIT_BIN(x) x "sbin:" x "bin"
#define PATH_SPLIT_BIN_NULSTR(x) x "sbin\0" x "bin\0"

#define PATH_MERGED_BIN(x) x "bin"
#define PATH_MERGED_BIN_NULSTR(x) x "bin\0"

#define DEFAULT_PATH_WITH_SBIN PATH_SPLIT_BIN("/usr/local/") ":" PATH_SPLIT_BIN("/usr/")
#define DEFAULT_PATH_WITHOUT_SBIN PATH_MERGED_BIN("/usr/local/") ":" PATH_MERGED_BIN("/usr/")

#define DEFAULT_PATH_COMPAT PATH_SPLIT_BIN("/usr/local/") ":" PATH_SPLIT_BIN("/usr/") ":" PATH_SPLIT_BIN("/")

const char* default_PATH(void);

static inline const char* default_user_PATH(void) {
#ifdef DEFAULT_USER_PATH
        return DEFAULT_USER_PATH;
#else
        return default_PATH();
#endif
}

bool is_path(const char *p) _pure_;
int path_split_and_make_absolute(const char *p, char ***ret);
int path_get_parent(const char *path, char **parent);
bool path_is_absolute(const char *p) _pure_;
char *path_make_absolute(const char *p, const char *prefix);
int safe_getcwd(char **ret);
int path_make_absolute_cwd(const char *p, char **ret);
int path_make_relative(const char *from_dir, const char *to_path, char **_r);
char *path_kill_slashes(char *path);
char *path_startswith(const char *path, const char *prefix) _pure_;
int path_compare(const char *a, const char *b) _pure_;
static inline bool path_equal(const char *a, const char *b) {
        return path_compare(a, b) == 0;
}

int path_compare_filename(const char *a, const char *b);
static inline bool path_equal_filename(const char *a, const char *b) {
        return path_compare_filename(a, b) == 0;
}

int path_equal_or_inode_same_full(const char *a, const char *b, int flags);
static inline bool path_equal_or_inode_same(const char *a, const char *b, int flags) {
        return path_equal_or_inode_same_full(a, b, flags) > 0;
}

char* path_extend_internal(char **x, ...);
#define path_extend(x, ...) path_extend_internal(x, __VA_ARGS__, POINTER_MAX)
#define path_join(...) path_extend_internal(NULL, __VA_ARGS__, POINTER_MAX)

int path_strv_make_absolute_cwd(char **l);
char **path_strv_resolve(char **l, const char *prefix);
char **path_strv_resolve_uniq(char **l, const char *prefix);

int path_is_read_only_fs(const char *path);
int path_is_os_tree(const char *path);

int path_find_first_component(const char **p, bool accept_dot_dot, const char **ret);
int path_find_last_component(const char *path, bool accept_dot_dot, const char **next, const char **ret);
const char* last_path_component(const char *path);
int path_extract_filename(const char *path, char **ret);
int path_extract_directory(const char *path, char **ret);

static inline char* skip_leading_slash(const char *p) {
        return skip_leading_chars(p, "/");
}

typedef enum PathSimplifyFlags {
        PATH_SIMPLIFY_KEEP_TRAILING_SLASH = 1 << 0,
} PathSimplifyFlags;

char* path_simplify_full(char *path, PathSimplifyFlags flags);
static inline char* path_simplify(char *path) {
        return path_simplify_full(path, 0);
}

static inline int path_simplify_alloc(const char *path, char **ret) {
        assert(ret);

        if (!path) {
                *ret = NULL;
                return 0;
        }

        char *t = strdup(path);
        if (!t)
                return -ENOMEM;

        *ret = path_simplify(t);
        return 0;
}

/* Note: the search terminates on the first NULL item. */
#define PATH_IN_SET(p, ...) path_strv_contains(STRV_MAKE(__VA_ARGS__), p)

char* path_startswith_strv(const char *p, char * const *strv);
#define PATH_STARTSWITH_SET(p, ...) path_startswith_strv(p, STRV_MAKE(__VA_ARGS__))

bool path_strv_contains(char * const *l, const char *path);
bool prefixed_path_strv_contains(char * const *l, const char *path);

bool dot_or_dot_dot(const char *path);

bool hidden_or_backup_file(const char *filename) _pure_;

int find_executable_full(const char *name, const char *root, char **exec_search_path, bool use_path_envvar, char **ret_filename, int *ret_fd);
static inline int find_executable(const char *name, char **ret_filename) {
        return find_executable_full(name, /* root= */ NULL, NULL, true, ret_filename, NULL);
}

bool paths_check_timestamp(const char *const *paths, usec_t *paths_ts_usec,
	bool update);

int fsck_exists(void);
int fsck_exists_for_fstype(const char *fstype);

char *prefix_root(const char *root, const char *path);

bool empty_or_root(const char *path);
static inline const char* empty_to_root(const char *path) {
        return isempty(path) ? "/" : path;
}

bool filename_part_is_valid(const char *p) _pure_;
bool filename_is_valid(const char *p) _pure_;
bool path_is_valid_full(const char *p, bool accept_dot_dot) _pure_;
static inline bool path_is_valid(const char *p) {
        return path_is_valid_full(p, /* accept_dot_dot= */ true);
}
static inline bool path_is_safe(const char *p) {
        return path_is_valid_full(p, /* accept_dot_dot= */ false);
}

bool path_is_normalized(const char *p) _pure_;

/* Similar to prefix_root(), but returns an alloca() buffer, or
 * possibly a const pointer into the path parameter */
#define prefix_roota(root, path)                                               \
	({                                                                     \
		const char *_path = (path), *_root = (root), *_ret;            \
		char *_p, *_n;                                                 \
		size_t _l;                                                     \
		while (_path[0] == '/' && _path[1] == '/')                     \
			_path++;                                               \
		if (isempty(_root) || path_equal(_root, "/"))                  \
			_ret = _path;                                          \
		else {                                                         \
			_l = strlen(_root) + 1 + strlen(_path) + 1;            \
			_n = alloca(_l);                                       \
			_p = stpcpy(_n, _root);                                \
			while (_p > _n && _p[-1] == '/')                       \
				_p--;                                          \
			if (_path[0] != '/')                                   \
				*(_p++) = '/';                                 \
			strcpy(_p, _path);                                     \
			_ret = _n;                                             \
		}                                                              \
		_ret;                                                          \
	})

/* Iterates through the path prefixes of the specified path, going up
 * the tree, to root. Also returns "" (and not "/"!) for the root
 * directory. Excludes the specified directory itself */
#define PATH_FOREACH_PREFIX(prefix, path)                                      \
	for (char *_slash = ({                                                 \
		     path_kill_slashes(strcpy(prefix, path));                  \
		     streq(prefix, "/") ? NULL : strrchr(prefix, '/');         \
	     });                                                               \
		_slash && ((*_slash = 0), true);                               \
		_slash = strrchr((prefix), '/'))

/* Same as PATH_FOREACH_PREFIX but also includes the specified path itself */
#define PATH_FOREACH_PREFIX_MORE(prefix, path)                                 \
	for (char *_slash = ({                                                 \
		     path_kill_slashes(strcpy(prefix, path));                  \
		     if (streq(prefix, "/"))                                   \
			     prefix[0] = 0;                                    \
		     strrchr(prefix, 0);                                       \
	     });                                                               \
		_slash && ((*_slash = 0), true);                               \
		_slash = strrchr((prefix), '/'))
