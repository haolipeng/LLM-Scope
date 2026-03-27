// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "process.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, pid_t);
	__type(value, u64);
} exec_start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

const volatile unsigned long long min_duration_ns = 0;

/* Bash readline uretprobe handler */
SEC("uretprobe//usr/bin/bash:readline")
int BPF_URETPROBE(bash_readline, const void *ret)
{
	struct event *e;
	char comm[TASK_COMM_LEN];
	u32 pid;

	if (!ret)
		return 0;

	/* Check if this is actually bash */
	bpf_get_current_comm(&comm, sizeof(comm));
	if (comm[0] != 'b' || comm[1] != 'a' || comm[2] != 's' || comm[3] != 'h' || comm[4] != 0)
		return 0;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* Reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Fill out the sample with bash readline data */
	e->type = EVENT_TYPE_BASH_READLINE;
	e->pid = pid;
	e->ppid = 0; /* Not relevant for bash commands */
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	bpf_probe_read_user_str(&e->command, sizeof(e->command), ret);

	/* Submit to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct task_struct *task;
	unsigned fname_off;
	struct event *e;
	pid_t pid;
	u64 ts;

	/* Get process info */
	pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();

	/* remember time exec() was executed for this PID */
	ts = bpf_ktime_get_ns();
	bpf_map_update_elem(&exec_start, &pid, &ts, BPF_ANY);

	/* don't emit exec events when minimum duration is specified */
	if (min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	e->type = EVENT_TYPE_PROCESS;
	e->exit_event = false;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->timestamp_ns = ts;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(&e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	/* Capture full command line with arguments from mm->arg_start */
	struct mm_struct *mm = BPF_CORE_READ(task, mm);
	unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
	unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
	unsigned long arg_len = arg_end - arg_start;

	/* Limit to buffer size */
	if (arg_len > MAX_COMMAND_LEN - 1)
		arg_len = MAX_COMMAND_LEN - 1;

	/* Read command line from userspace memory */
	if (arg_len > 0) {
		long ret = bpf_probe_read_user_str(&e->full_command, arg_len + 1, (void *)arg_start);
		if (ret < 0) {
			/* Fallback to just comm if we can't read cmdline */
			bpf_probe_read_kernel_str(&e->full_command, sizeof(e->full_command), e->comm);
		} else {
			/* Replace null bytes with spaces for readability */
			for (int i = 0; i < MAX_COMMAND_LEN - 1 && i < ret - 1; i++) {
				if (e->full_command[i] == '\0')
					e->full_command[i] = ' ';
			}
		}
	} else {
		/* No arguments, use comm */
		bpf_probe_read_kernel_str(&e->full_command, sizeof(e->full_command), e->comm);
	}

	/* successfully submit it to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template* ctx)
{
	struct task_struct *task;
	struct event *e;
	pid_t pid, tid;
	u64 id, ts, *start_ts, duration_ns = 0;

	/* get PID and TID of exiting thread/process */
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	tid = (u32)id;

	/* ignore thread exits */
	if (pid != tid)
		return 0;

	/* if we recorded start of the process, calculate lifetime duration */
	start_ts = bpf_map_lookup_elem(&exec_start, &pid);
	ts = bpf_ktime_get_ns();
	if (start_ts)
		duration_ns = ts - *start_ts;
	else if (min_duration_ns)
		return 0;
	bpf_map_delete_elem(&exec_start, &pid);

	/* if process didn't live long enough, return early */
	if (min_duration_ns && duration_ns < min_duration_ns)
		return 0;

	/* reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* fill out the sample with data */
	task = (struct task_struct *)bpf_get_current_task();

	e->type = EVENT_TYPE_PROCESS;
	e->exit_event = true;
	e->duration_ns = duration_ns;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->timestamp_ns = ts;
	e->exit_code = (BPF_CORE_READ(task, exit_code) >> 8) & 0xff;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* send data to user-space for post-processing */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Syscall tracepoint for openat */
SEC("tp/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	pid_t pid;
	char filepath[MAX_FILENAME_LEN];
	int dfd, flags;
	const char *filename;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* Get syscall arguments */
	dfd = (int)ctx->args[0];
	filename = (const char *)ctx->args[1];
	flags = (int)ctx->args[2];

	/* Read filename from user space */
	if (bpf_probe_read_user_str(filepath, sizeof(filepath), filename) < 0)
		return 0;

	/* Reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Fill out the event */
	e->type = EVENT_TYPE_FILE_OPERATION;
	e->pid = pid;
	e->ppid = 0; /* Will be filled if needed */
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Copy filepath and set file open details */
	bpf_probe_read_kernel_str(e->file_op.filepath, sizeof(e->file_op.filepath), filepath);
	e->file_op.fd = -1; /* Will be set on return if needed */
	e->file_op.flags = flags;
	e->file_op.op_type = FILE_OP_OPEN;

	/* Submit to user-space */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Syscall tracepoint for open */
SEC("tp/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	pid_t pid;
	char filepath[MAX_FILENAME_LEN];
	int flags;
	const char *filename;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* Get syscall arguments */
	filename = (const char *)ctx->args[0];
	flags = (int)ctx->args[1];

	/* Read filename from user space */
	if (bpf_probe_read_user_str(filepath, sizeof(filepath), filename) < 0)
		return 0;

	/* Reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Fill out the event */
	e->type = EVENT_TYPE_FILE_OPERATION;
	e->pid = pid;
	e->ppid = 0;
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Copy filepath and set file open details */
	bpf_probe_read_kernel_str(e->file_op.filepath, sizeof(e->file_op.filepath), filepath);
	e->file_op.fd = -1;
	e->file_op.flags = flags;
	e->file_op.op_type = FILE_OP_OPEN;

	/* Submit to user-space */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Syscall tracepoint for unlink */
SEC("tp/syscalls/sys_enter_unlink")
int trace_unlink(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	pid_t pid;
	char filepath[MAX_FILENAME_LEN];
	const char *pathname;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* Get syscall argument: pathname */
	pathname = (const char *)ctx->args[0];

	/* Read pathname from user space */
	if (bpf_probe_read_user_str(filepath, sizeof(filepath), pathname) < 0)
		return 0;

	/* Reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Fill out the event */
	e->type = EVENT_TYPE_FILE_OPERATION;
	e->pid = pid;
	e->ppid = 0;
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Copy filepath and set file delete details */
	bpf_probe_read_kernel_str(e->file_op.filepath, sizeof(e->file_op.filepath), filepath);
	e->file_op.fd = -1;
	e->file_op.flags = 0;
	e->file_op.op_type = FILE_OP_DELETE;

	/* Submit to user-space */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* Syscall tracepoint for unlinkat */
SEC("tp/syscalls/sys_enter_unlinkat")
int trace_unlinkat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	pid_t pid;
	char filepath[MAX_FILENAME_LEN];
	int dfd, flags;
	const char *pathname;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* Get syscall arguments: dfd, pathname, flags */
	dfd = (int)ctx->args[0];
	pathname = (const char *)ctx->args[1];
	flags = (int)ctx->args[2];

	/* Read pathname from user space */
	if (bpf_probe_read_user_str(filepath, sizeof(filepath), pathname) < 0)
		return 0;

	/* Reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Fill out the event */
	e->type = EVENT_TYPE_FILE_OPERATION;
	e->pid = pid;
	e->ppid = 0;
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Copy filepath and set file delete details */
	bpf_probe_read_kernel_str(e->file_op.filepath, sizeof(e->file_op.filepath), filepath);
	e->file_op.fd = dfd;
	e->file_op.flags = flags;  /* AT_REMOVEDIR (0x200) means remove directory */
	e->file_op.op_type = FILE_OP_DELETE;

	/* Submit to user-space */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * Convert kernel_cap_t to u64
 *
 * kernel_cap_t changed across kernel versions:
 *   < 6.3: struct kernel_cap_struct { u32 cap[2]; }  (8 bytes)
 *   >= 6.3: typedef u64 kernel_cap_t                  (8 bytes)
 *
 * Both representations are 8 bytes with identical memory layout on
 * little-endian (x86), so we read the raw 8 bytes using the CO-RE
 * field offset. This avoids accessing .cap[0]/.cap[1] which don't
 * exist on newer kernels.
 */
static __always_inline u64 caps_to_u64(const struct cred *cred, int cap_type)
{
	u64 val = 0;

	switch (cap_type) {
	case 0: /* cap_inheritable */
		bpf_probe_read_kernel(&val, sizeof(val),
			(void *)cred + bpf_core_field_offset(cred->cap_inheritable));
		break;
	case 1: /* cap_permitted */
		bpf_probe_read_kernel(&val, sizeof(val),
			(void *)cred + bpf_core_field_offset(cred->cap_permitted));
		break;
	case 2: /* cap_effective */
		bpf_probe_read_kernel(&val, sizeof(val),
			(void *)cred + bpf_core_field_offset(cred->cap_effective));
		break;
	case 3: /* cap_bset */
		bpf_probe_read_kernel(&val, sizeof(val),
			(void *)cred + bpf_core_field_offset(cred->cap_bset));
		break;
	case 4: /* cap_ambient */
		bpf_probe_read_kernel(&val, sizeof(val),
			(void *)cred + bpf_core_field_offset(cred->cap_ambient));
		break;
	}

	return val;
}

/* Capability type constants */
#define CAP_INHERITABLE 0
#define CAP_PERMITTED   1
#define CAP_EFFECTIVE   2
#define CAP_BSET        3
#define CAP_AMBIENT     4

/*
 * kprobe/commit_creds - Monitor credential changes
 *
 * commit_creds() is the "chokepoint" for all privilege changes:
 * - setuid/setgid system calls
 * - execve of SUID/SGID binaries
 * - kernel exploits that modify credentials
 *
 * By hooking here, we capture ALL privilege escalation attempts
 * with a single probe point.
 *
 * Reference: tracee's trace_commit_creds implementation
 */
SEC("kprobe/commit_creds")
int BPF_KPROBE(trace_commit_creds, struct cred *new_cred)
{
	struct event *e;
	struct task_struct *task;
	const struct cred *old_cred;
	pid_t pid;

	pid = bpf_get_current_pid_tgid() >> 32;
	task = (struct task_struct *)bpf_get_current_task();

	/* Get old credentials from current task (use real_cred for accuracy) */
	old_cred = BPF_CORE_READ(task, real_cred);
	if (!old_cred)
		return 0;

	/* Read old credential values */
	u32 old_uid = BPF_CORE_READ(old_cred, uid.val);
	u32 old_gid = BPF_CORE_READ(old_cred, gid.val);
	u32 old_suid = BPF_CORE_READ(old_cred, suid.val);
	u32 old_sgid = BPF_CORE_READ(old_cred, sgid.val);
	u32 old_euid = BPF_CORE_READ(old_cred, euid.val);
	u32 old_egid = BPF_CORE_READ(old_cred, egid.val);
	u32 old_fsuid = BPF_CORE_READ(old_cred, fsuid.val);
	u32 old_fsgid = BPF_CORE_READ(old_cred, fsgid.val);

	u64 old_cap_inheritable = caps_to_u64(old_cred, CAP_INHERITABLE);
	u64 old_cap_permitted = caps_to_u64(old_cred, CAP_PERMITTED);
	u64 old_cap_effective = caps_to_u64(old_cred, CAP_EFFECTIVE);
	u64 old_cap_bset = caps_to_u64(old_cred, CAP_BSET);
	u64 old_cap_ambient = caps_to_u64(old_cred, CAP_AMBIENT);

	/* Read new credential values */
	u32 new_uid = BPF_CORE_READ(new_cred, uid.val);
	u32 new_gid = BPF_CORE_READ(new_cred, gid.val);
	u32 new_suid = BPF_CORE_READ(new_cred, suid.val);
	u32 new_sgid = BPF_CORE_READ(new_cred, sgid.val);
	u32 new_euid = BPF_CORE_READ(new_cred, euid.val);
	u32 new_egid = BPF_CORE_READ(new_cred, egid.val);
	u32 new_fsuid = BPF_CORE_READ(new_cred, fsuid.val);
	u32 new_fsgid = BPF_CORE_READ(new_cred, fsgid.val);

	u64 new_cap_inheritable = caps_to_u64(new_cred, CAP_INHERITABLE);
	u64 new_cap_permitted = caps_to_u64(new_cred, CAP_PERMITTED);
	u64 new_cap_effective = caps_to_u64(new_cred, CAP_EFFECTIVE);
	u64 new_cap_bset = caps_to_u64(new_cred, CAP_BSET);
	u64 new_cap_ambient = caps_to_u64(new_cred, CAP_AMBIENT);

	/* Only emit event if credentials actually changed */
	if (old_uid == new_uid && old_gid == new_gid &&
	    old_suid == new_suid && old_sgid == new_sgid &&
	    old_euid == new_euid && old_egid == new_egid &&
	    old_fsuid == new_fsuid && old_fsgid == new_fsgid &&
	    old_cap_inheritable == new_cap_inheritable &&
	    old_cap_permitted == new_cap_permitted &&
	    old_cap_effective == new_cap_effective &&
	    old_cap_bset == new_cap_bset &&
	    old_cap_ambient == new_cap_ambient)
		return 0;

	/* Reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Fill out the event */
	e->type = EVENT_TYPE_CRED_CHANGE;
	e->pid = pid;
	e->ppid = BPF_CORE_READ(task, real_parent, tgid);
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Fill old credential details */
	e->cred.old.uid = old_uid;
	e->cred.old.gid = old_gid;
	e->cred.old.suid = old_suid;
	e->cred.old.sgid = old_sgid;
	e->cred.old.euid = old_euid;
	e->cred.old.egid = old_egid;
	e->cred.old.fsuid = old_fsuid;
	e->cred.old.fsgid = old_fsgid;
	e->cred.old.cap_inheritable = old_cap_inheritable;
	e->cred.old.cap_permitted = old_cap_permitted;
	e->cred.old.cap_effective = old_cap_effective;
	e->cred.old.cap_bset = old_cap_bset;
	e->cred.old.cap_ambient = old_cap_ambient;

	/* Fill new credential details */
	e->cred.new.uid = new_uid;
	e->cred.new.gid = new_gid;
	e->cred.new.suid = new_suid;
	e->cred.new.sgid = new_sgid;
	e->cred.new.euid = new_euid;
	e->cred.new.egid = new_egid;
	e->cred.new.fsuid = new_fsuid;
	e->cred.new.fsgid = new_fsgid;
	e->cred.new.cap_inheritable = new_cap_inheritable;
	e->cred.new.cap_permitted = new_cap_permitted;
	e->cred.new.cap_effective = new_cap_effective;
	e->cred.new.cap_bset = new_cap_bset;
	e->cred.new.cap_ambient = new_cap_ambient;

	/* Submit to user-space */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * Syscall tracepoint for connect - Monitor network connections
 * Captures destination IP:Port for TCP/UDP connections
 */
SEC("tp/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	pid_t pid;
	struct sockaddr_in addr4;
	struct sockaddr_in6 addr6;
	struct sockaddr *addr;
	unsigned short family;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* Get sockaddr pointer from syscall args */
	addr = (struct sockaddr *)ctx->args[1];
	if (!addr)
		return 0;

	/* Read address family */
	if (bpf_probe_read_user(&family, sizeof(family), &addr->sa_family) < 0)
		return 0;

	/* Only handle IPv4 and IPv6 */
	if (family != 2 && family != 10)  /* AF_INET=2, AF_INET6=10 */
		return 0;

	/* Reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Fill out the event */
	e->type = EVENT_TYPE_NET_CONNECT;
	e->pid = pid;
	e->ppid = 0;
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	e->net.family = family;

	if (family == 2) {  /* AF_INET */
		if (bpf_probe_read_user(&addr4, sizeof(addr4), addr) < 0) {
			bpf_ringbuf_discard(e, 0);
			return 0;
		}
		e->net.port = __builtin_bswap16(addr4.sin_port);
		e->net.addr.ipv4 = addr4.sin_addr.s_addr;
	} else {  /* AF_INET6 */
		if (bpf_probe_read_user(&addr6, sizeof(addr6), addr) < 0) {
			bpf_ringbuf_discard(e, 0);
			return 0;
		}
		e->net.port = __builtin_bswap16(addr6.sin6_port);
		__builtin_memcpy(e->net.addr.ipv6, &addr6.sin6_addr, 16);
	}

	/* Submit to user-space */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * Syscall tracepoint for rename - Monitor file renames
 */
SEC("tp/syscalls/sys_enter_rename")
int trace_rename(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	pid_t pid;
	const char *oldpath;
	const char *newpath;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* Get syscall arguments */
	oldpath = (const char *)ctx->args[0];
	newpath = (const char *)ctx->args[1];

	/* Reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Fill out the event */
	e->type = EVENT_TYPE_FILE_RENAME;
	e->pid = pid;
	e->ppid = 0;
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Read paths from user space */
	bpf_probe_read_user_str(e->rename.oldpath, sizeof(e->rename.oldpath), oldpath);
	bpf_probe_read_user_str(e->rename.newpath, sizeof(e->rename.newpath), newpath);

	/* Submit to user-space */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * Syscall tracepoint for renameat - Monitor file renames (modern API)
 */
SEC("tp/syscalls/sys_enter_renameat")
int trace_renameat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	pid_t pid;
	const char *oldpath;
	const char *newpath;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* Get syscall arguments: olddfd, oldpath, newdfd, newpath */
	oldpath = (const char *)ctx->args[1];
	newpath = (const char *)ctx->args[3];

	/* Reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Fill out the event */
	e->type = EVENT_TYPE_FILE_RENAME;
	e->pid = pid;
	e->ppid = 0;
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Read paths from user space */
	bpf_probe_read_user_str(e->rename.oldpath, sizeof(e->rename.oldpath), oldpath);
	bpf_probe_read_user_str(e->rename.newpath, sizeof(e->rename.newpath), newpath);

	/* Submit to user-space */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * Syscall tracepoint for renameat2 - Monitor file renames (newest API with flags)
 */
SEC("tp/syscalls/sys_enter_renameat2")
int trace_renameat2(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	pid_t pid;
	const char *oldpath;
	const char *newpath;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* Get syscall arguments: olddfd, oldpath, newdfd, newpath, flags */
	oldpath = (const char *)ctx->args[1];
	newpath = (const char *)ctx->args[3];

	/* Reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Fill out the event */
	e->type = EVENT_TYPE_FILE_RENAME;
	e->pid = pid;
	e->ppid = 0;
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Read paths from user space */
	bpf_probe_read_user_str(e->rename.oldpath, sizeof(e->rename.oldpath), oldpath);
	bpf_probe_read_user_str(e->rename.newpath, sizeof(e->rename.newpath), newpath);

	/* Submit to user-space */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * Syscall tracepoint for mkdir - Monitor directory creation
 */
SEC("tp/syscalls/sys_enter_mkdir")
int trace_mkdir(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	pid_t pid;
	const char *pathname;
	int mode;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* Get syscall arguments */
	pathname = (const char *)ctx->args[0];
	mode = (int)ctx->args[1];

	/* Reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Fill out the event */
	e->type = EVENT_TYPE_DIR_CREATE;
	e->pid = pid;
	e->ppid = 0;
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Read path from user space */
	bpf_probe_read_user_str(e->mkdir.path, sizeof(e->mkdir.path), pathname);
	e->mkdir.mode = mode;

	/* Submit to user-space */
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/*
 * Syscall tracepoint for mkdirat - Monitor directory creation (modern API)
 */
SEC("tp/syscalls/sys_enter_mkdirat")
int trace_mkdirat(struct trace_event_raw_sys_enter *ctx)
{
	struct event *e;
	pid_t pid;
	const char *pathname;
	int mode;

	pid = bpf_get_current_pid_tgid() >> 32;

	/* Get syscall arguments: dfd, pathname, mode */
	pathname = (const char *)ctx->args[1];
	mode = (int)ctx->args[2];

	/* Reserve sample from BPF ringbuf */
	e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e)
		return 0;

	/* Fill out the event */
	e->type = EVENT_TYPE_DIR_CREATE;
	e->pid = pid;
	e->ppid = 0;
	e->exit_code = 0;
	e->duration_ns = 0;
	e->timestamp_ns = bpf_ktime_get_ns();
	e->exit_event = false;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	/* Read path from user space */
	bpf_probe_read_user_str(e->mkdir.path, sizeof(e->mkdir.path), pathname);
	e->mkdir.mode = mode;

	/* Submit to user-space */
	bpf_ringbuf_submit(e, 0);
	return 0;
}


