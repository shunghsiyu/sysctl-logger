#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdbool.h>
#include <bpf/bpf.h>
#include "sysctl-logger.h"
#include "sysctl-logger.skel.h"

static volatile sig_atomic_t exiting = 0;

static struct env {
	bool verbose;
} env;

static void sig_int(int signo)
{
	exiting = 1;
}

/*
 * libbpf_print_fn - Custom print function for libbpf messages
 * @level: Message severity level
 * @format: Printf-style format string
 * @args: Variable arguments list
 *
 * Returns: Number of characters written
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

/*
 * get_root_cgroup - Open the root cgroup directory
 *
 * Tries to open the unified cgroup hierarchy first, then falls back
 * to the legacy cgroup hierarchy.
 *
 * Returns: File descriptor on success, negative value on error
 */
int get_root_cgroup(void)
{
	int fd;

	/* Try unified cgroup hierarchy (cgroup v2) */
	fd = open("/sys/fs/cgroup/unified", O_RDONLY);
	if (fd > 0)
		return fd;

	/* Fall back to legacy cgroup hierarchy */
	fd = open("/sys/fs/cgroup", O_RDONLY);
	return fd;
}

/*
 * handle_ringbuf_event - Process sysctl change events from the ring buffer
 * @ctx: Context (unused)
 * @data: Pointer to event data
 * @data_sz: Size of event data
 *
 * Prints information about sysctl changes to stdout. Only prints events
 * where the value actually changed or where truncation occurred.
 *
 * Returns: 0 on success
 */
int handle_ringbuf_event(void *ctx, void *data, size_t data_sz)
{
	struct sysctl_logger_event event;
	char *warning = "";

	event = *(struct sysctl_logger_event*) data;

	if (event.truncated)
		warning = " (note: truncation has occurred so the name or value may not be complete)";

	/* Remove trailing newlines from values */
	event.old_value[strcspn(event.old_value, "\n")] = 0;
	event.new_value[strcspn(event.new_value, "\n")] = 0;

	/* Only log if values actually changed or if truncation occurred */
	if (event.truncated || strncmp(event.old_value, event.new_value, sizeof(event.new_value))) {
		printf("%s[%d](%s[%d]) initiated change of %s from %s to %s%s\n",
                       event.comm, event.pid, event.parent_comm, event.parent_pid,
                       event.name, ((event.old_value[0] == '\0') ? "''" : event.old_value),
                       ((event.new_value[0] == '\0') ? "''" : event.new_value), warning);
		fflush(stdout);
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_object_open_opts opts = { 0 };
	struct sysctl_logger_bpf *skel = NULL;
	struct ring_buffer *rb = NULL;
	int bpfd, cfgd = -1, err;

	/* Check if running as root */
	if (geteuid() != 0) {
		fprintf(stderr, "This program must be run as root\n");
		return 1;
	}

	if (getenv("DEBUG"))
		env.verbose = true;

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	opts.sz = sizeof(opts);
#if (LIBBPF_MAJOR_VERSION != 0) || (LIBBPF_MINOR_VERSION >= 7)
	if (env.verbose)
		opts.kernel_log_level = 4 | 2 | 1;
#endif
	skel = sysctl_logger_bpf__open_opts(&opts);
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		err = -1;
		goto cleanup;
	}
	err = sysctl_logger_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load BPF skeleton: %s\n", strerror(-err));
		goto cleanup;
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		int saved_errno = errno;
		fprintf(stderr, "Can't set SIGINT signal handler: %s\n", strerror(saved_errno));
		err = -1;
		goto cleanup;
	}

	if (signal(SIGTERM, sig_int) == SIG_ERR) {
		int saved_errno = errno;
		fprintf(stderr, "Can't set SIGTERM signal handler: %s\n", strerror(saved_errno));
		err = -1;
		goto cleanup;
	}

	cfgd = get_root_cgroup();
	if (cfgd < 0) {
		fprintf(stderr, "Failed to open root cgroup: %s\n", strerror(errno));
		err = -1;
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
		fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(-err));
		goto cleanup;
	}

	fprintf(stderr, "Begin monitoring sysctl changes.\n");
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
		fprintf(stderr, "Failed to detach BPF program: %s\n", strerror(-err));
cleanup:
	if (rb)
		ring_buffer__free(rb);
	if (cfgd >= 0)
		close(cfgd);
	sysctl_logger_bpf__destroy(skel);
	return err ? 1 : 0;
}
