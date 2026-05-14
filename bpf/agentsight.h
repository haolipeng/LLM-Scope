/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __AGENTSIGHT_H
#define __AGENTSIGHT_H

// ─── 公共常量 ───────────────────────────────────────────────────────────────────
#define TASK_COMM_LEN 16

// ════════════════════════════════════════════════════════════════════════════════
// Process 部分
// ════════════════════════════════════════════════════════════════════════════════

#define MAX_FILENAME_LEN 127
#define MAX_COMMAND_FILTERS 10
#define MAX_TRACKED_PIDS 1024
#define MAX_COMMAND_LEN 256

enum filter_mode {
    FILTER_MODE_ALL = 0,
    FILTER_MODE_PROC = 1,
    FILTER_MODE_FILTER = 2,
};

enum event_type {
    EVENT_TYPE_PROCESS = 0,
    EVENT_TYPE_BASH_READLINE = 1,
    EVENT_TYPE_FILE_OPERATION = 2,
    EVENT_TYPE_CRED_CHANGE = 3,
    EVENT_TYPE_NET_CONNECT = 4,
    EVENT_TYPE_FILE_RENAME = 5,
    EVENT_TYPE_DIR_CREATE = 6,
};

enum file_op_type {
    FILE_OP_OPEN = 0,
    FILE_OP_CLOSE = 1,
    FILE_OP_DELETE = 2,
};

struct net_connect {
    unsigned short family;
    unsigned short port;
    union {
        unsigned int ipv4;
        unsigned char ipv6[16];
    } addr;
};

struct file_rename {
    char oldpath[MAX_FILENAME_LEN];
    char newpath[MAX_FILENAME_LEN];
};

struct dir_create {
    char path[MAX_FILENAME_LEN];
    int mode;
};

struct slim_cred {
    unsigned int uid;
    unsigned int gid;
    unsigned int suid;
    unsigned int sgid;
    unsigned int euid;
    unsigned int egid;
    unsigned int fsuid;
    unsigned int fsgid;
    unsigned long long cap_inheritable;
    unsigned long long cap_permitted;
    unsigned long long cap_effective;
    unsigned long long cap_bset;
    unsigned long long cap_ambient;
};

struct cred_change {
    struct slim_cred old;
    struct slim_cred new;
};

struct event {
    enum event_type type;
    int pid;
    int ppid;
    unsigned exit_code;
    unsigned long long duration_ns;
    unsigned long long timestamp_ns;
    char comm[TASK_COMM_LEN];
    char full_command[MAX_COMMAND_LEN];
    union {
        char filename[MAX_FILENAME_LEN];
        char command[MAX_COMMAND_LEN];
        struct {
            char filepath[MAX_FILENAME_LEN];
            int fd;
            int flags;
            enum file_op_type op_type;
        } file_op;
        struct cred_change cred;
        struct net_connect net;
        struct file_rename rename;
        struct dir_create mkdir;
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

// ════════════════════════════════════════════════════════════════════════════════
// SSL 部分
// ════════════════════════════════════════════════════════════════════════════════

#define SSL_MAX_BUF_SIZE (512 * 1024)       // 512KB eBPF buffer size (kernel limit)
#define SSL_RINGBUF_SIZE (2 * 1024 * 1024)  // 2MB ring buffer

struct probe_SSL_data_t {
    __u64 timestamp_ns;
    __u64 delta_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __u32 len;
    __u32 buf_size;
    int buf_filled;
    int rw;
    char comm[TASK_COMM_LEN];
    __u8 buf[SSL_MAX_BUF_SIZE];
    int is_handshake;
};

// ════════════════════════════════════════════════════════════════════════════════
// Stdio 部分
// ════════════════════════════════════════════════════════════════════════════════

#define STDIO_MAX_BUF_SIZE 8192
#define STDIO_RINGBUF_SIZE (1024 * 1024)    // 1MB ring buffer

struct stdiocap_event_t {
    __u64 timestamp_ns;
    __u64 delta_ns;
    __u32 pid;
    __u32 tid;
    __u32 uid;
    __s32 fd;
    __u32 len;
    __u32 buf_size;
    __u8 is_read;
    char comm[TASK_COMM_LEN];
    __u8 buf[STDIO_MAX_BUF_SIZE];
};

#endif /* __AGENTSIGHT_H */
