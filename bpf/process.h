/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __PROCESS_H
#define __PROCESS_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127
#define MAX_COMMAND_FILTERS 10
#define MAX_TRACKED_PIDS 1024
#define MAX_COMMAND_LEN 256

enum filter_mode {
	FILTER_MODE_ALL = 0,      /* Trace all processes and all read/write operations */
	FILTER_MODE_PROC = 1,     /* Trace all processes but only read/write for tracked PIDs */
	FILTER_MODE_FILTER = 2,   /* Only trace processes matching filters and their read/write */
};

enum event_type {
	EVENT_TYPE_PROCESS = 0,
	EVENT_TYPE_BASH_READLINE = 1,
	EVENT_TYPE_FILE_OPERATION = 2,
	EVENT_TYPE_CRED_CHANGE = 3,      /* credential/privilege change */
	EVENT_TYPE_NET_CONNECT = 4,      /* network connection */
	EVENT_TYPE_FILE_RENAME = 5,      /* file rename */
	EVENT_TYPE_DIR_CREATE = 6,       /* directory creation */
};

enum file_op_type {
	FILE_OP_OPEN = 0,
	FILE_OP_CLOSE = 1,
	FILE_OP_DELETE = 2,
};

/* Network connection event data */
struct net_connect {
	unsigned short family;           /* AF_INET or AF_INET6 */
	unsigned short port;             /* destination port */
	union {
		unsigned int ipv4;           /* IPv4 address */
		unsigned char ipv6[16];      /* IPv6 address */
	} addr;
};

/* File rename event data */
struct file_rename {
	char oldpath[MAX_FILENAME_LEN];
	char newpath[MAX_FILENAME_LEN];
};

/* Directory creation event data */
struct dir_create {
	char path[MAX_FILENAME_LEN];
	int mode;
};

/*
 * Slim credential structure for tracking privilege changes
 * Reference: tracee's slim_cred_t and https://lwn.net/Articles/636533/
 */
struct slim_cred {
	unsigned int uid;            /* real UID of the task */
	unsigned int gid;            /* real GID of the task */
	unsigned int suid;           /* saved UID of the task */
	unsigned int sgid;           /* saved GID of the task */
	unsigned int euid;           /* effective UID of the task */
	unsigned int egid;           /* effective GID of the task */
	unsigned int fsuid;          /* UID for VFS ops */
	unsigned int fsgid;          /* GID for VFS ops */
	unsigned long long cap_inheritable;  /* caps our children can inherit */
	unsigned long long cap_permitted;    /* caps we're permitted */
	unsigned long long cap_effective;    /* caps we can actually use */
	unsigned long long cap_bset;         /* capability bounding set */
	unsigned long long cap_ambient;      /* ambient capability set */
};

/* Credential change event data */
struct cred_change {
	struct slim_cred old;    /* old credentials (before change) */
	struct slim_cred new;    /* new credentials (after change) */
};

struct event {
	enum event_type type;
	int pid;
	int ppid;
	unsigned exit_code;
	unsigned long long duration_ns;
	unsigned long long timestamp_ns;
	char comm[TASK_COMM_LEN];
	char full_command[MAX_COMMAND_LEN];     /* full command line with args */
	union {
		char filename[MAX_FILENAME_LEN];     /* for process events */
		char command[MAX_COMMAND_LEN];       /* for bash readline events */
		struct {                             /* for file operation events */
			char filepath[MAX_FILENAME_LEN];
			int fd;
			int flags;
			enum file_op_type op_type;  /* open, close, or delete */
		} file_op;
		struct cred_change cred;             /* for credential change events */
		struct net_connect net;              /* for network connection events */
		struct file_rename rename;           /* for file rename events */
		struct dir_create mkdir;             /* for directory creation events */
	};
	bool exit_event;
};

struct command_filter {
	char comm[TASK_COMM_LEN];
};

struct pid_info {
	pid_t pid;
	pid_t ppid;
	bool is_tracked;
};

#endif /* __PROCESS_H */
