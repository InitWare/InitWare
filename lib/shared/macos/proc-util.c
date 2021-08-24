#include "fdset.h"
#include "util.h"

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