// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook

#include <stdint.h>
#include <string.h>

#include <linux/stddef.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#define MAX_NAME_STR_LEN 32

SEC("cgroup/sysctl")
int sysctl_logger(struct bpf_sysctl *ctx)
{
	char name[MAX_NAME_STR_LEN] = "World";
	int ret;

	//ret = bpf_sysctl_get_name(ctx, name, sizeof(name), 0);
	//if (!ret)
	//	return 0;

	bpf_printk("Hello %s!\n", name);

	return 1;
}

char _license[] SEC("license") = "GPL";
