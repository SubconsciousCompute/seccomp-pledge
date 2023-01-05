# seccomp-pledge

## Introduction
In a nutshell, `seccomp-pledge` is a systems hardening tool that marries `seccomp-BPF` to `pledge` and `unveil`. 

For reference, `seccomp-bpf` is a feature in the Linux kernel that allows specifying filters for system calls spawned by processes in the form of Berkeley Packet Filter (BPF) programs. A configurable set of policies (Allow, Errno, Trap, etc.) determines the kind of filtering that will be applied to system calls intercepted by `seccomp`. This minimizes the attack surface of the kernel that is exposed to userland applications.

`pledge` is a sandboxing mechanism in OpenBSD that restricts the operational capabilities of processes by defining a set of promises that determine the system calls which will be made unavailable to the respective process. It has been ported to Linux as a standalone binary by Justine Tunney. Find more information [here](https://justine.lol/pledge).

`unveil` is another sandboxing mechanism in OpenBSD that is used to provide path permissions to processes. By default, a `pledge` sandbox will restrict access to the entire filesystem for some process. It is possible to allow access to some filesystem path using `unveil` for processes that necessarily require it. The type of permissions granted (read-only, read-write, etc.) can also be specified. Justine Tunney's `pledge` port incorporates support for `unveil`.

This tool upholds the principle of least privilege (PoLP) and limits processes to exactly what they are designed for, disallowng any non-essential operations as desired. It will cause core dumps if the user blocks a syscall that is fundamental to the execution of the process, which implies that the `seccomp` filters need to be constructed with care and `pledge` promises must be chosen appropriately. 

## Supported platforms
Since `seccomp` is Linux-specific, syscall filtering using this feature is supported only on Linux systems. Non-Linux systems will have to proceed without `seccomp-BPF` filters. 

## Features

- Accept the process to be executed (with optional flags) as an argument
- Display the list of syscalls (name and arguments) spawned by the process using `lurk`
- Use `seccompiler` as a high-level interface for defining seccomp-BPF filters
- Install user-defined filters as BPF programs for current and child processes
- Fetch Justine Tunney's Linux port of `pledge` and wrap around command invocations with user-specified flags
- Provide intuitive prompts to simplify the process of constructing `seccomp` filters and selecting `pledge` promises and `unveil` path permissions

## Dependencies

`seccomp-pledge` has the following dependencies:
- [seccompiler](https://github.com/rust-vmm/seccompiler) - Provides easy-to-use Linux seccomp-bpf jailing
- [lurk](https://github.com/JakWai01/lurk) - A pretty (simple) alternative to strace
- [pledge](https://justine.lol/pledge) - Linux port of OpenBSD's `pledge(2)`
- [serde](https://serde.rs) - Framework for (de)serializing data structures in Rust
- [wget](https://www.gnu.org/software/wget/) - Retrieve files from the web using HTTP(S)
- [optional-field](https://github.com/cvpartner/optional-field) - Provides a Rust type for values that can be missing/null

## Installation

To run `seccomp-pledge`, ensure `cargo` is installed on your system. Follow these steps:
```sh
git clone https://github.com/DeviousCilantro/seccomp-pledge.git
cd seccomp-pledge
cargo run --release
```

## License
This software uses the MIT license.
