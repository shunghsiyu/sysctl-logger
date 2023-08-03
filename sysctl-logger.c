#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <bpf/bpf.h>
#include "sysctl-logger.h"
#include "sysctl-logger.skel.h"

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
	exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

int get_root_cgroup(void)
{
	int fd;

	fd = open("/sys/fs/cgroup/unified", O_RDONLY);
	if (fd > 0)
		return fd;

	fd = open("/sys/fs/cgroup", O_RDONLY);
	return fd;
}

int handle_ringbuf_event(void *ctx, void *data, size_t data_sz)
{
	const struct sysctl_logger_event *event = (struct sysctl_logger_event*) data;

	printf("%s[%d] changed %s from %s to %s\n", event->comm, event->pid,
			event->name, event->old_value, event->new_value);

	return 0;
}

int main(int argc, char **argv)
{
	struct sysctl_logger_bpf *skel;
	struct ring_buffer *rb = NULL;
	int bpfd, cfgd, err;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	skel = sysctl_logger_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		err = errno;
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set SIGINT signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	if (signal(SIGTERM, sig_int) == SIG_ERR) {
		err = errno;
		fprintf(stderr, "Can't set SIGTERM signal handler: %s\n", strerror(errno));
		goto cleanup;
	}

	cfgd = get_root_cgroup();
	if (cfgd < 0) {
		fprintf(stderr, "Failed to open root CGroup\n");
		err = cfgd;
		goto cleanup;
	}

	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_ringbuf_event, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	bpfd = bpf_program__fd(skel->progs.sysctl_logger);
	err = bpf_prog_attach(bpfd, cfgd, BPF_CGROUP_SYSCTL, BPF_F_ALLOW_MULTI);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program sysctl_logger\n");
		goto cleanup;
	}

	fprintf(stderr, "Begin monitoring sysctl_logger changes.\n");
	while (!exiting) {
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "Error polling ring buffer: %d\n", err);
			break;
		}
	}

	err = bpf_prog_detach2(bpfd, cfgd, BPF_CGROUP_SYSCTL);
	if (err)
		fprintf(stderr, "Failed to detach BPF program sysctl_logger\n");
cleanup:
	sysctl_logger_bpf__destroy(skel);
	return -err;
}
