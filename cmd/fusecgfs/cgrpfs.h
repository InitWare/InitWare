#ifndef CG_H_
#define CG_H_

#include <sys/queue.h>
#include <sys/stat.h>

typedef struct Hashmap Hashmap;

/* kind of CGroupFS inode */
typedef enum cg_nodetype {
	CGN_INVALID = -1,
	CGN_PROCS, /* cgroup.procs file */
	CGN_RELEASE_AGENT, /* release_agent file */
	CGN_NOTIFY_ON_RELEASE, /* notify_on_release file */
	CGN_CG_DIR, /* cgroup directory */
	CGN_PID_ROOT_DIR, /* cgroup.meta root dir */
	CGN_PID_DIR, /* cgroup.meta/$pid directory */
	CGN_PID_CGROUP /* cgroup.meta/$pid/cgroup */
} cg_nodetype_t;

/* inode for all entries in the CGroupFS */
typedef struct cg_node {
	LIST_ENTRY(cg_node) entries;

	char *name;
	cg_nodetype_t type;
	struct cg_node *parent;
	struct stat attr;

	/* for PID dirs */
	pid_t pid;

	/* for all dirs */
	LIST_HEAD(cg_node_list, cg_node) subnodes;

	/* for cgroup dirs */
	bool notify;
	char *agent;
} cg_node_t;

/* the cgfs manager singleton */
typedef struct cgmgr {
	struct fuse *fuse;
	char *mountpoint;
	int mt;
	int kq;

	Hashmap *pid_to_cg;

	cg_node_t *rootnode, *metanode;
} cgmgr_t;

/* an open file description */
typedef struct cgn_filedesc {
	cg_node_t *node;

	char *buf; /* file contents - pre-filled on open() for consistency */
} cg_filedesc_t;

cg_node_t *newnode(cg_node_t *parent, const char *name, cg_nodetype_t type);
cg_node_t *newcgdir(cg_node_t *parent, const char *name, mode_t perms,
	uid_t uid, gid_t gid);
/* Recursively delete node and subnodes. Any contained PIDs moved to parent. */
void delnode(cg_node_t *node);

/* Lookup a node by path, or the second-last node of that path. */
cg_node_t *lookupnode(const char *path, bool secondlast);
/* Get full path of node without initial / */
char * nodefullpath(cg_node_t * node);

/* Attach a PID to a CGroup */
int attachpid(cg_node_t *node, pid_t pid);
/* Detach a PID from its owner CGroup and stop tracking it if untrack set */
int detachpid(pid_t pid, bool untrack);

extern cgmgr_t cgmgr;
extern struct fuse_operations cgops;

#endif /* CG_H_ */
