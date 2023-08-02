// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook

#include <stdint.h>
#include <string.h>

#include <linux/stddef.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include "sysctl-logger.h"

SEC("cgroup/sysctl")
int sysctl_logger(struct bpf_sysctl *ctx)
{
	struct sysctl_logger_event event;
	int ret;

	/* Ignore reads */
	if (!ctx->write)
		goto out;

	memset(event.name, 0, sizeof(event.name));
	ret = bpf_sysctl_get_name(ctx, event.name, sizeof(event.name), 0);
	if (!ret)
		goto out;

	ret = bpf_sysctl_get_current_value(ctx, event.old_value, sizeof(event.old_value));
	if (!ret)
		goto out;

	ret = bpf_sysctl_get_new_value(ctx, event.new_value, sizeof(event.new_value));
	if (!ret)
		goto out;

	bpf_printk("%s: %s -> %s\n", event.name, event.old_value, event.new_value);

out:
	return 1; /* Allow read/write */
}

char _license[] SEC("license") = "GPL";
