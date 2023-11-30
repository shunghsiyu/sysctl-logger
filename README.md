# sysctl-logger

sysctl monitoring with BPF

## Requirements

To run the provided sysctl-logger binary, please install runtime libraries with the following command:

```
sudo zypper install libelf1 zlib
```

Note: if the sysctl-logger is not built with libbpf from submodule, you will need to install libbpf as well.

## Build using libbpf on the system

This is the suggested way of building sysctl-logger, where we will be using the libbpf provided by the distro. First run the following command to install built-time requirements:

```
sudo zypper install libbpf-devel gcc clang make glibc-devel glibc-devel-32bit bpftool libelf-devel zlib-devel gettext-runtime
```

Then build the binary with

```
make FORCE_SYSTEM_LIBBPF=1
```

Admittedly, not all distro will supply libbpf-devel; or if they do, it may be too old (though sysctl-logger should work on at least libbpf v0.5+). If that is the case, please use libbpf in the git submodule as shown in the next section.

## Build using libbpf from submodule

To build the binary using libbpf that was included as a submodule, first run the following command to install built-time requirements:

```
sudo zypper install gcc clang make glibc-devel glibc-devel-32bit bpftool libelf-devel zlib-devel gettext-runtime
```

Then build the binary with

```
make
```

## Running

The sysctl-logger binary can simply be executed with

```
sudo ./sysctl-logger
```

If sysctl-logger fails to run, please file a bug report with verbose mode enabled and attach the log

```
sudo DEBUG=1 ./sysctl-logger
```
