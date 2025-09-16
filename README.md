# sysctl-logger

sysctl monitoring with BPF

## Requirements

To run the provided sysctl-logger binary, please install runtime libraries with the following command:

```
sudo zypper install libelf1 zlib
```

Note: if the sysctl-logger is not built with libbpf from submodule, you will need to install libbpf as well.

## Building sysctl-logger

Run the following command to install built-time requirements:

```
sudo zypper install libbpf-devel gcc clang make glibc-devel glibc-devel-32bit bpftool libelf-devel zlib-devel gettext-runtime
```

Then build the binary with

```
make
```

Admittedly, not all distro will supply libbpf-devel; or if they do, it may be too old (though sysctl-logger should work on at least libbpf v0.5+). Currently sysctl-logger is only tested to build to SUSE Enterprise Linux Server 15 SP6+ and openSUSE Leap 15.6+.

## Running

The sysctl-logger binary can simply be executed with

```
sudo ./sysctl-logger
```

If sysctl-logger fails to run, please file a bug report with verbose mode enabled and attach the log

```
sudo DEBUG=1 ./sysctl-logger
```
