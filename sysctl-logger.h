#ifndef __SYSCTL_LOGGER_H
#define __SYSCTL_LOGGER_H

/* Maximum length for sysctl name (e.g., "net.ipv4.ip_forward") */
#define MAX_NAME_STR_LEN 48

/* Maximum length for sysctl value string (128 bytes) */
#define MAX_VALUE_STR_LEN 0x80

/* Length of task command name (matches kernel TASK_COMM_LEN) */
#define TASK_COMM_LEN 16

/*
 * Event structure passed from BPF program to userspace via ring buffer.
 * Contains information about a sysctl write operation.
 */
struct sysctl_logger_event {
	int pid;
	int parent_pid;
	bool truncated;
	char comm[TASK_COMM_LEN];
	char parent_comm[TASK_COMM_LEN];
	char name[MAX_NAME_STR_LEN];
	char old_value[MAX_VALUE_STR_LEN];
	char new_value[MAX_VALUE_STR_LEN];
};

#endif /* __SYSCTL_LOGGER_H */
