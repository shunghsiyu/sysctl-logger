// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook

#include <vmlinux.h>
#include <linux/version.h>

#include <linux/errno.h>
#include <bpf/bpf_helpers.h>

#include "sysctl-logger.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,2,0)
#define HAVE_BPF_RCU_READ_LOCK
#endif

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 512 * 1024 /* 256 KB */);
} rb SEC(".maps");

void bpf_rcu_read_lock(void) __ksym;
void bpf_rcu_read_unlock(void) __ksym;

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

	struct task_struct *current = (struct task_struct *)bpf_get_current_task();

#if HAVE_CGROUP_CURRENT_FUNC_PROTO
	event->pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
#else
	bpf_probe_read_kernel(&event->pid, sizeof(event->pid), &current->pid);
	bpf_probe_read_kernel_str(&event->comm, sizeof(event->comm), &current->comm);
#endif /* HAVE_CGROUP_CURRENT_FUNC_PROTO */

	struct task_struct *parent;
#ifdef HAVE_BPF_RCU_READ_LOCK
        bpf_rcu_read_lock();
#endif /*  HAVE_BPF_RCU_READ_LOCK */
	bpf_probe_read_kernel(&parent, sizeof(parent), &current->real_parent);
	bpf_probe_read_kernel(&event->parent_pid, sizeof(event->parent_pid), &parent->pid);
	bpf_probe_read_kernel_str(&event->parent_comm, sizeof(event->parent_comm), &parent->comm);
#ifdef HAVE_BPF_RCU_READ_LOCK
        bpf_rcu_read_unlock();
#endif /*  HAVE_BPF_RCU_READ_LOCK */

	__builtin_memset(event->name, 0, sizeof(event->name));
	ret = bpf_sysctl_get_name(ctx, event->name, sizeof(event->name), 0);
	if (ret < 0) /* Can only be -E2BIG */
		event->truncated = true;

	ret = bpf_sysctl_get_current_value(ctx, event->old_value, sizeof(event->old_value));
	if (ret == -E2BIG) {
		event->truncated = true;
	} else if (ret < 0) { /* -EINVAL  if  current  value  was  unavailable */
		bpf_ringbuf_discard(event, 0);
		goto out;
	}

	ret = bpf_sysctl_get_new_value(ctx, event->new_value, sizeof(event->new_value));
	if (ret < 0) /* Can only be -E2BIG since reads are ignored */
		event->truncated = true;

	bpf_ringbuf_submit(event, 0);
out:
	return 1; /* Allow read/write */
}

char _license[] SEC("license") = "GPL";
