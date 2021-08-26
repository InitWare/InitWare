#include <libproc.h>

#include "fdset.h"
#include "util.h"

int close_all_fds(const int except[], unsigned n_except)
{
	struct proc_fdinfo fdinfo[1023];
	int fdcnt;
	int r = 0;

	fdcnt = proc_pidinfo(getpid(), PROC_PIDLISTFDS, 0, fdinfo, sizeof fdinfo);
	if (fdcnt < 0)
		log_error("Failed to get process FD info: %m\n");
	fdcnt = fdcnt / PROC_PIDLISTFD_SIZE;

	for (int i = 0; i < fdcnt; i++) {
		int fd = fdinfo[i].proc_fd;

		if (fd_in_set(fd, except, n_except))
			continue;
		else if (close_nointr(fd) < 0)
			if (errno != EBADF && r == 0)
				r = -errno;
	}

	return r;
}

int get_parent_of_pid(pid_t pid, pid_t *_ppid)
{
	return -ENOTSUP;
}

int get_process_state(pid_t pid)
{
	return -ENOTSUP;
}

int get_process_comm(pid_t pid, char **name)
{
	return -ENOTSUP;
}

int get_process_cmdline(pid_t pid, size_t max_length, bool comm_fallback, char **line)
{
	return -ENOTSUP;
}

int get_process_exe(pid_t pid, char **line)
{
	return -ENOTSUP;
}

int get_process_uid(pid_t pid, uid_t *uid)
{
	return -ENOTSUP;
}

int get_process_gid(pid_t pid, gid_t *gid)
{
	return -ENOTSUP;
}

int fdset_new_fill(FDSet **_s)
{
	return -ENOTSUP;
}