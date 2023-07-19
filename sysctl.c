#include <unistd.h>
#include <fcntl.h>
#include <bpf/bpf.h>
#include "sysctl.skel.h"

int get_root_cgroup(void)
{
	int fd;

	fd = open("/sys/fs/cgroup", O_RDONLY);

	return fd;
}

int main(int argc, char **argv)
{
	struct sysctl_bpf *skel;
	int bpfd, cfgd, err;

	skel = sysctl_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		err = errno;
		goto cleanup;
	}

	cfgd = get_root_cgroup();
	if (cfgd < 0) {
		fprintf(stderr, "Failed to open root CGroup\n");
		err = cfgd;
		goto cleanup;
	}

	bpfd = bpf_program__fd(skel->progs.sysctl_logger);
	err = bpf_prog_attach(bpfd, cfgd, BPF_CGROUP_SYSCTL, BPF_F_ALLOW_MULTI);
	if (err) {
		fprintf(stderr, "Failed to attach BPF program sysctl_logger\n");
		goto cleanup;
	}

	fprintf(stderr, "Begin monitoring sysctl changes\n");
	for (;;) {
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	sysctl_bpf__destroy(skel);
	return -err;
}
