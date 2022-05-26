# Abusing Trust: Mobile Kernel Subversion via TrustZone Rootkits

This repository contains a proof-of-concept implementation of the rootkit techniques described in our paper "Abusing Trust: Mobile Kernel Subversion via TrustZone Rootkits". The rootkit is implemented on top of [OP-TEE](https://www.op-tee.org/). Technically, the rootkit is a so-called "pseudo trusted application" which is compiled and executed as part of the secure world operating system.

Following rootkit functions are implemented and subject to the evaluation:

* Privilege escalation
* Process starvation
* Memory carving


## Setup

### Prerequisites

The host system used for the evaluation needs to be compatible with OP-TEE version 3.11.0 and fulfill all its prerequisites:

* [https://optee.readthedocs.io/en/3.12.0/building/prerequisites.html](https://optee.readthedocs.io/en/3.12.0/building/prerequisites.html)

A Debian-based system is recommended.

Enabling the `randstruct` compiler plugin of the Linux kernel furthermore requires the following packages:

* `libgmp-dev`
* `libmpc-dev`
* `gcc-9-plugin-dev` (or the version matching the respective host compiler)

### Installing the repo tool

Cloning the OP-TEE system requires the `repo` tool to be available.

```
$ curl https://storage.googleapis.com/git-repo-downloads/repo > "${SOME_DIR}/repo"
```

Furthermore, the tool should be added to the `$PATH` environment variable:

```
$ export PATH="${SOME_DIR}:${PATH}"
```

### Downloading OP-TEE

Our rootkit was extensively tested with OP-TEE version 3.11.0 for QEMU in Armv8 mode. `repo` is used to download the necessary repositories:

```
$ repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml -b 3.11.0
$ repo sync
```

### Configuring Linux

By default, only a shallow copy of the Linux repository is cloned by `repo`. The following command unshallows the repository:

```
$ cd linux
$ git fetch --all --unshallow
```

Afterwards, switch to a supported tag of the Linux kernel:

```
$ git checkout <version>
```

Following versions are supported:

* v4.12 to v5.1
* v5.5 to v5.6

Note that `randstruct` is only compatible with Linux version v4.16 or above.

To enable `randstruct`, the `CONFIG_GCC_PLUGIN_RANDSTRUCT` and `CONFIG_GCC_PLUGINS` options need to be enabled in `scripts/gcc-plugins/Kconfig` or `arch/Kconfig` (depending on the used version of Linux).

Booting Linux with `randstruct` enabled requires a manual fix in `linux/drivers/firmware/efi/libstub/random.c`. The `__no_randomize_layout` attribute needs to be added to the `efi_rng_protocol` structure:

```
struct efi_rng_protocol {
    // ...
} __no_randomize_layout;
```

Or the anonymous structure within `efi_rng_protocol` for version v5.6 of the kernel:

```
union efi_rng_protocol {
    struct {
        // ...
    } __no_randomize_layout;
    // ...
};
```

### Integrating the Rootkit

Copy the directory `src/rootkit` to `optee_os/core/pta/`.

Add the following line to `optee_os/core/pta/sub.mk` to include the rootkit trusted application in the build process:

```
subdirs-y += rootkit
```

Copy the directory `src/rootkit_client` to `optee_examples/`.

Copy the directory `src/rootkit_driver` to `linux/drivers/`.

Add the following line to `linux/drivers/Makefile` to include the rootkit module in the build process:

```
obj-y += rootkit_driver/
```

### Building OP-TEE

First, install the necessary toolchain:

```
$ cd build
$ make toolchains
```

The following command builds and runs the OP-TEE system:

```
$ make run
```

It is recommend to append `-jN` to the above command, where `N` represents the number of parallel processes to use for the build.

Once the build process finished, two new terminal windows are opened. These windows represent the interfaces to the normal world and the secure world. The QEMU monitor waits for commands in the original build terminal window. Use the `c` command in the build terminal to boot the system. The user `test` can login in the normal world window without password.


## Evaluation

The provided rootkit client can be invoked from the normal world after a successful login:

```
$ rootkit
```

Rootkit functionality is invoked automatically in the following order:

* Privilege escalation
* Process starvation
* Memory carving

Log output is printed in both terminal windows. After the client finished successfully, the effects of the invoked features can be verified as follows.

### Privilege Escalation

Initially, the `test` user authenticated to the system. After the rootkit execution finished, use the following command in the normal world terminal to verify processes can be launched as `root`:

```
$ id
uid=0(root) gid=0(root)
```

### Process Starvation

The rootkit client forks a process that should be stopped by the TrustZone rootkit. Before and after the execution of the starvation feature, the modification timestamp of a file repeatedly created by the target process is printed. It is expected that the values printed before the invocation are increasing, while the timestamps after the invocation should be constant. Note that a slight delay of the effect is reasonable.

After the rootkit execution finished, use the following command in the normal world terminal to verify the process is in zombie state:

```
$ cat /proc/$(pidof rootkit)/status | grep State
State:  Z (zombie)
```

### Memory Carving

RSA keys found in the normal world memory are displayed in the secure world window. The output should contain at least the following two lines:

```
-----BEGIN RSA PRIVATE KEY----- kernel-test-key -----END RSA PRIVATE KEY-----
-----BEGIN RSA PRIVATE KEY----- user-test-key -----END RSA PRIVATE KEY-----
```

Note that this feature only works on Linux v4.20 and above.
