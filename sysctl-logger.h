#ifndef __SYSCTL_LOGGER_H
#define __SYSCTL_LOGGER_H

#define MAX_NAME_STR_LEN 48
#define MAX_VALUE_STR_LEN 0x40
#define TASK_COMM_LEN 16

struct sysctl_logger_event {
	int pid;
	bool truncated;
	char comm[TASK_COMM_LEN];
	char name[MAX_NAME_STR_LEN];
	char old_value[MAX_VALUE_STR_LEN];
	char new_value[MAX_VALUE_STR_LEN];
};

#endif /* __SYSCTL_LOGGER_H */
