# sysctl-logger

sysctl monitoring with BPF

## Requirements

To run the provided sysctl binary, please install runtime libraries with the following command:

```
sudo zypper install libelf1 zlib
```

## Build

To build the binary, first run the following command to install built-time requirements:

```
sudo zypper install gcc clang make glibc-devel glibc-devel-32bit bpftool libelf-devel zlib-devel
```

Then build the binary with

```
make
```

The sysctl-logger binary can then be executed with

```
sudo ./sysctl
```
