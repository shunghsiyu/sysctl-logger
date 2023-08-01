// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook

#include <stdint.h>
#include <string.h>

#include <linux/stddef.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#define MAX_NAME_STR_LEN 32
#define MAX_VALUE_STR_LEN 0x40

SEC("cgroup/sysctl")
int sysctl_logger(struct bpf_sysctl *ctx)
{
	char name[MAX_NAME_STR_LEN], old_value[MAX_VALUE_STR_LEN], new_value[MAX_VALUE_STR_LEN];
	int ret;

	/* Ignore reads */
	if (!ctx->write)
		goto out;

	memset(name, 0, sizeof(name));
	ret = bpf_sysctl_get_name(ctx, name, sizeof(name), 0);
	if (!ret)
		goto out;

	ret = bpf_sysctl_get_current_value(ctx, old_value, sizeof(old_value));
	if (!ret)
		goto out;

	ret = bpf_sysctl_get_new_value(ctx, new_value, sizeof(new_value));
	if (!ret)
		goto out;

	bpf_printk("%s: %s -> %s\n", name, old_value, new_value);

out:
	return 1; /* Allow read/write */
}

char _license[] SEC("license") = "GPL";
