# syscall-latency-bpf

A minimal eBPF (BCC) based syscall latency profiler.

## Purpose

When troubleshooting performance issues, `perf` often produces noisy results.
This tool aggregates syscall latency in-kernel and reports:

- syscall ID
- count
- average latency
- max latency

## Environment

- Amazon Linux 2023
- BCC

## Install

```bash
sudo dnf install -y bcc python3-bcc kernel-devel clang llvm
```

## Usage

```bash
sudo python3 syscall_latency.py
```

Press Ctrl+C to print stats.


