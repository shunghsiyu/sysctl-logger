// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook

#include <stdint.h>
#include <string.h>

#include <linux/stddef.h>
#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>

#include "sysctl-logger.h"

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024 /* 256 KB */);
} rb SEC(".maps");

SEC("cgroup/sysctl")
int sysctl_logger(struct bpf_sysctl *ctx)
{
	struct sysctl_logger_event *event;
	int ret;

	/* Ignore reads */
	if (!ctx->write)
		goto out;

	event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
	if (!event)
		goto out;

	event->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	memset(event->name, 0, sizeof(event->name));
	ret = bpf_sysctl_get_name(ctx, event->name, sizeof(event->name), 0);
	if (!ret)
		goto discard;

	ret = bpf_sysctl_get_current_value(ctx, event->old_value, sizeof(event->old_value));
	if (!ret)
		goto discard;

	ret = bpf_sysctl_get_new_value(ctx, event->new_value, sizeof(event->new_value));
	if (!ret)
		goto discard;

	bpf_ringbuf_submit(event, 0);
	goto out;

discard:
	/* TODO: emit some sort of error message to help diagnose issue when
	 *       discarding. */
	bpf_ringbuf_discard(event, 0);
out:
	return 1; /* Allow read/write */
}

char _license[] SEC("license") = "GPL";
