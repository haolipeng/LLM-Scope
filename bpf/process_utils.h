/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PROCESS_UTILS_H
#define __PROCESS_UTILS_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>

// Forward declarations for BPF types when not in test mode
#ifndef BPF_ANY
#include <bpf/libbpf.h>
typedef uint32_t __u32;
#endif

#include "process.h"

static int read_proc_comm(pid_t pid, char *comm, size_t size)
{
	char path[256];
	FILE *f;
	
	snprintf(path, sizeof(path), "/proc/%d/comm", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;
	
	if (fgets(comm, size, f)) {
		/* Remove trailing newline */
		char *newline = strchr(comm, '\n');
		if (newline)
			*newline = '\0';
	} else {
		fclose(f);
		return -1;
	}
	
	fclose(f);
	return 0;
}

static int read_proc_ppid(pid_t pid, pid_t *ppid)
{
	char path[256];
	FILE *f;
	char line[256];
	
	snprintf(path, sizeof(path), "/proc/%d/stat", pid);
	f = fopen(path, "r");
	if (!f)
		return -1;
	
	if (fgets(line, sizeof(line), f)) {
		/* Parse the stat line to get ppid (4th field) */
		char *token = strtok(line, " ");
		for (int i = 0; i < 3 && token; i++) {
			token = strtok(NULL, " ");
		}
		if (token) {
			*ppid = (pid_t)strtol(token, NULL, 10);
		} else {
			fclose(f);
			return -1;
		}
	} else {
		fclose(f);
		return -1;
	}
	
	fclose(f);
	return 0;
}

static bool command_matches_filter(const char *comm, const char *filter)
{
	return strstr(comm, filter) != NULL;
}

static int count_matching_processes(char **command_list, int command_count, bool trace_all)
{
	DIR *dir;
	struct dirent *entry;
	int count = 0;
	char comm[TASK_COMM_LEN];

	dir = opendir("/proc");
	if (!dir)
		return 0;

	while ((entry = readdir(dir)) != NULL) {
		/* Skip non-numeric entries */
		pid_t pid = (pid_t)strtol(entry->d_name, NULL, 10);
		if (pid <= 0)
			continue;

		if (read_proc_comm(pid, comm, sizeof(comm)) != 0)
			continue;

		if (trace_all) {
			count++;
			continue;
		}

		for (int i = 0; i < command_count; i++) {
			if (command_matches_filter(comm, command_list[i])) {
				count++;
				break;
			}
		}
	}

	closedir(dir);
	return count;
}

#endif /* __PROCESS_UTILS_H */